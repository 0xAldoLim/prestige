"""Text-only Responses transport boundary, before provider output reaches Codex.

Never stream unchecked function/tool calls into the authenticated runtime. Requests
advertise no native tools; complete bounded SSE responses are validated first. The
only executable proposals are JSON text parsed later by PRESTIGE's ToolRegistry.
Authentication stays in the SDK/HTTPS transport; headers and bodies are never logged.
"""

import gzip
import http.client
import json
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


def text_item(item):
    if not isinstance(item, dict) or item.get("type") not in {"message", "reasoning"}:
        raise PolicyDenied("Inference gateway rejected non-text model output")
    if item["type"] == "message" and item.get("role") != "assistant":
        raise PolicyDenied("Inference gateway rejected non-assistant output")
    for part in item.get("content", []):
        if part.get("type") not in {"output_text", "refusal"}:
            raise PolicyDenied("Inference gateway rejected non-text content")


def validate_sse(raw: bytes) -> bytes:
    if len(raw) > MAX_RESPONSE:
        raise PolicyDenied("Inference response exceeds gateway limit")
    # Provider metadata has no role in PRESTIGE inference. Discard it rather
    # than forwarding an unvalidated extension to the authenticated runtime.
    frames = []
    for frame in raw.replace(b"\r\n", b"\n").split(b"\n\n"):
        payloads = [line[5:].strip() for line in frame.splitlines() if line.startswith(b"data:")]
        if any(
            payload != b"[DONE]" and json.loads(payload).get("type") == "response.metadata"
            for payload in payloads
        ):
            continue
        if frame:
            frames.append(frame)
    raw = b"\n\n".join(frames) + b"\n\n"
    completed = False
    for line in raw.decode("utf-8").splitlines():
        if not line.startswith("data:"):
            continue
        data = line[5:].strip()
        if data == "[DONE]":
            continue
        event = json.loads(data)
        kind = event.get("type")
        if kind not in EVENTS:
            import re

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
        if kind == "response.completed":
            completed = True
    if not completed:
        raise PolicyDenied("Inference response did not complete; nothing forwarded")
    return raw


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
                        # Bound inflation separately from compressed size.
                        import io

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

    def close(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)

    def _official_transport(self, body, headers):
        # Fixed official destination. No discovered URL, redirect, proxy or model field
        # can alter provider egress. TLS authenticates the fixed provider hostname.
        host = "chatgpt.com" if self.account_type == "chatgpt" else "api.openai.com"
        path = "/backend-api/codex/responses" if self.account_type == "chatgpt" else "/v1/responses"
        connection = http.client.HTTPSConnection(host, timeout=self.timeout)
        started = time.monotonic()
        timer = None
        try:
            connection.connect()
            transport = connection.sock

            def abort():
                try:
                    transport.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass

            timer = threading.Timer(max(0.01, self.timeout - (time.monotonic() - started)), abort)
            timer.daemon = True
            timer.start()
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
                # Only protocol field names/codes, never provider text, input or headers.
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
                # Preserve a useful status category without private provider error data.
                raise PolicyDenied(f"Provider HTTP status {response.status}")
            chunks, total = [], 0
            while True:
                block = response.read1(8192)
                if not block:
                    break
                total += len(block)
                if total > MAX_RESPONSE or time.monotonic() - started > self.timeout:
                    raise PolicyDenied("Provider size/deadline limit")
                chunks.append(block)
            return b"".join(chunks)
        finally:
            if timer:
                timer.cancel()
            connection.close()
