"""Text-only Responses transport boundary, before provider output reaches Codex.

Never stream unchecked function/tool calls into the authenticated runtime. Requests
advertise no native tools; complete bounded SSE responses are validated first. The
only executable proposals are JSON text parsed later by PRESTIGE's ToolRegistry.
Authentication stays in the SDK/HTTPS transport; headers and bodies are never logged.
"""

import gzip
import http.client
import io
import json
import re
import secrets
import socket
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from prestige.types import PolicyDenied

MAX_RESPONSE = 1024 * 1024
EVENTS = {
    "response.created",
    "response.in_progress",
    "response.queued",
    "response.completed",
    "response.output_item.added",
    "response.output_item.done",
    "response.content_part.added",
    "response.content_part.done",
    "response.output_text.delta",
    "response.output_text.done",
    "response.reasoning_summary_part.added",
    "response.reasoning_summary_part.done",
    "response.reasoning_summary_text.delta",
    "response.reasoning_summary_text.done",
    "response.reasoning_text.delta",
    "response.reasoning_text.done",
    "response.failed",
    "response.incomplete",
    "error",
}
_ALLOWED_SSE_FIELDS = {"data", "event", "id", "retry"}


def text_item(item):
    if not isinstance(item, dict) or item.get("type") not in {"message", "reasoning"}:
        raise PolicyDenied("Inference gateway rejected non-text model output")
    if item["type"] == "message" and item.get("role") != "assistant":
        raise PolicyDenied("Inference gateway rejected non-assistant output")
    for part in item.get("content", []):
        if part.get("type") not in {"output_text", "refusal"}:
            raise PolicyDenied("Inference gateway rejected non-text content")


def _parse_sse_frames(raw: bytes):
    """Strict Server-Sent Events frame parser.

    Only ``data``, ``event``, ``id`` and ``retry`` fields are accepted. Unknown
    fields, ambiguous frames and event/data disagreements are rejected. Multiple
    ``data:`` lines are joined with ``\\n`` per the SSE standard.
    """
    if len(raw) > MAX_RESPONSE:
        raise PolicyDenied("Inference response exceeds gateway limit")
    try:
        text = raw.decode("utf-8-sig")
    except UnicodeError as error:
        raise PolicyDenied("Inference response is not valid UTF-8") from error
    # Normalize all SSE line endings to a single newline.
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    for frame in text.split("\n\n"):
        if not frame:
            continue
        data_lines = []
        fields = {}
        for line in frame.splitlines():
            if not line or line.startswith(":"):
                continue
            if ":" in line:
                name, value = line.split(":", 1)
                if value.startswith(" "):
                    value = value[1:]
            else:
                name = line
                value = ""
            if name not in _ALLOWED_SSE_FIELDS:
                raise PolicyDenied(f"Unexpected SSE field: {name}")
            if name == "data":
                data_lines.append(value)
            else:
                fields[name] = value
        if not data_lines:
            continue
        fields["data"] = "\n".join(data_lines)
        yield fields


def _validate_event(event: dict, event_name: str | None):
    kind = event.get("type")
    if event_name is not None:
        if event_name not in EVENTS:
            raise PolicyDenied(f"Unknown SSE event name: {event_name}")
        if kind != event_name:
            raise PolicyDenied("SSE event name disagrees with data type")
    if kind not in EVENTS:
        label = (
            kind
            if isinstance(kind, str) and re.fullmatch(r"[a-zA-Z0-9_.]{1,100}", kind)
            else "invalid"
        )
        raise PolicyDenied("Inference gateway rejected event: " + label)
    if "item" in event:
        text_item(event["item"])
    if "part" in event and event["part"].get("type") not in {
        "output_text",
        "refusal",
        "summary_text",
        "reasoning_text",
    }:
        raise PolicyDenied("Inference gateway rejected a content part")
    if "response" in event:
        for item in event["response"].get("output", []):
            text_item(item)


def validate_sse(raw: bytes) -> bytes:
    """Return a canonical, reserialized SSE stream or raise PolicyDenied."""
    completed = False
    out = []
    for frame in _parse_sse_frames(raw):
        data = frame["data"]
        if data == "[DONE]":
            # Completion is proven by response.completed; the sentinel adds no value.
            continue
        try:
            event = json.loads(data)
        except ValueError as error:
            raise PolicyDenied("Invalid SSE JSON") from error
        if not isinstance(event, dict):
            raise PolicyDenied("SSE data is not a JSON object")
        if event.get("type") == "response.metadata":
            continue
        event_name = frame.get("event")
        _validate_event(event, event_name)
        if "event" in frame:
            out.append(f"event: {frame['event']}")
        out.append("data: " + json.dumps(event))
        if event.get("type") == "response.completed":
            completed = True
    if not completed:
        raise PolicyDenied("Inference response did not complete; nothing forwarded")
    return "\n\n".join(out).encode() + b"\n\n"


def narrow_request(raw: bytes) -> bytes:
    if len(raw) > 2 * 1024 * 1024:
        raise PolicyDenied("Inference request too large")
    value = json.loads(raw)
    if not isinstance(value, dict) or not isinstance(value.get("input"), list):
        raise PolicyDenied("Invalid Responses request")
    value["tools"] = []
    value["tool_choice"] = "none"
    value["parallel_tool_calls"] = False
    value["stream"] = True
    # Model-authored conversation items cannot smuggle an execution request.
    for item in value["input"]:
        if item.get("type") in {"function_call", "custom_tool_call", "computer_call"}:
            raise PolicyDenied("Executable history is forbidden in inference-only sessions")
    return json.dumps(value, separators=(",", ":")).encode()


class InferenceGate:
    def __init__(self, *, account_type="chatgpt", timeout=120, max_requests=20, transport=None):
        if account_type not in {"chatgpt", "apiKey"}:
            raise PolicyDenied("Unsupported authentication mode for inference gateway")
        self.account_type, self.timeout, self.max_requests = account_type, timeout, max_requests
        self.transport = transport or self._official_transport
        self.count = 0
        self.denials = 0
        self.last_error = None
        self.provider_status = None
        self.provider_error = None
        self.lock = threading.Lock()
        self._socket_lock = threading.Lock()
        self._sockets: set[socket.socket] = set()
        self._timers: set[threading.Timer] = set()
        self._closing = False
        token = secrets.token_urlsafe(32)
        self.route = "/" + token + "/responses"
        gate = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                return None

            def do_POST(self):
                try:
                    if self.path != gate.route or self.headers.get("Transfer-Encoding"):
                        raise PolicyDenied("Unknown gateway route")
                    length = int(self.headers.get("Content-Length", "0"))
                    if not 0 < length <= 2 * 1024 * 1024:
                        raise PolicyDenied("Invalid gateway request length")
                    self.connection.settimeout(gate.timeout)
                    with gate.lock:
                        if gate.count >= gate.max_requests:
                            raise PolicyDenied("Inference request budget exhausted")
                        gate.count += 1
                    request = self.rfile.read(length)
                    if self.headers.get("Content-Encoding") == "gzip":
                        with gzip.GzipFile(fileobj=io.BytesIO(request)) as stream:
                            request = stream.read(2 * 1024 * 1024 + 1)
                    narrowed = narrow_request(request)
                    response = gate.transport(narrowed, self.headers)
                    validated = validate_sse(response)
                    self.send_response(200)
                    self.send_header("Content-Type", "text/event-stream")
                    self.send_header("Content-Length", str(len(validated)))
                    self.end_headers()
                    self.wfile.write(validated)
                except Exception as error:
                    with gate.lock:
                        gate.denials += 1
                        gate.last_error = (
                            str(error) if isinstance(error, PolicyDenied) else type(error).__name__
                        )
                    try:
                        self.send_response(502)
                        self.send_header("Content-Length", "0")
                        self.end_headers()
                    except OSError:
                        pass

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.server.daemon_threads = True
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.base_url = f"http://127.0.0.1:{self.server.server_port}/" + token

    def start(self):
        self.thread.start()
        return self

    def _register_socket(self, sock: socket.socket):
        with self._socket_lock:
            if self._closing:
                raise PolicyDenied("Gate is closing")
            self._sockets.add(sock)

    def _unregister_socket(self, sock: socket.socket):
        with self._socket_lock:
            self._sockets.discard(sock)

    def cancel_sockets(self):
        """Forcibly close active upstream provider sockets without shutting the gate."""
        with self._socket_lock:
            sockets = list(self._sockets)
        for sock in sockets:
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass

    def close(self):
        self._closing = True
        self.cancel_sockets()
        try:
            self.server.shutdown()
        finally:
            self.server.server_close()
        self.thread.join(timeout=2)

    def _official_transport(self, body, headers):
        # Fixed official destination. No discovered URL, redirect, proxy or model field
        # can alter provider egress. TLS authenticates the fixed provider hostname.
        host = "chatgpt.com" if self.account_type == "chatgpt" else "api.openai.com"
        path = "/backend-api/codex/responses" if self.account_type == "chatgpt" else "/v1/responses"
        connection = http.client.HTTPSConnection(host, timeout=self.timeout)
        started = time.monotonic()
        deadline = started + self.timeout
        timer = None
        try:
            connection.connect()
            transport = connection.sock
            if transport is not None:
                self._register_socket(transport)

            def abort():
                try:
                    transport.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass

            timer = threading.Timer(max(0.01, deadline - time.monotonic()), abort)
            timer.daemon = True
            timer.start()
            with self._socket_lock:
                if not self._closing:
                    self._timers.add(timer)
            permitted = {
                "authorization",
                "chatgpt-account-id",
                "openai-organization",
                "openai-project",
                "openai-beta",
                "originator",
                "session_id",
                "version",
                "user-agent",
            }
            forwarded = {key: value for key, value in headers.items() if key.lower() in permitted}
            forwarded.update({"Content-Type": "application/json", "Accept": "text/event-stream"})
            connection.request("POST", path, body=body, headers=forwarded)
            response = connection.getresponse()
            self.provider_status = response.status
            if response.status != 200:
                import re

                try:
                    error = json.loads(response.read(4096)).get("error", {})
                    self.provider_error = {
                        key: value
                        for key in ("code", "param", "type")
                        if isinstance(error, dict)
                        and isinstance((value := error.get(key)), str)
                        and re.fullmatch(r"[a-zA-Z_][a-zA-Z0-9_.]{0,100}", value)
                    }
                except (ValueError, OSError):
                    pass
                raise PolicyDenied(f"Provider HTTP status {response.status}")
            chunks, total = [], 0
            while True:
                block = response.read1(8192)
                if not block:
                    break
                total += len(block)
                if total > MAX_RESPONSE or time.monotonic() > deadline:
                    raise PolicyDenied("Provider size/deadline limit")
                chunks.append(block)
            return b"".join(chunks)
        finally:
            if timer is not None:
                timer.cancel()
                with self._socket_lock:
                    self._timers.discard(timer)
            if transport is not None:
                self._unregister_socket(transport)
            connection.close()
