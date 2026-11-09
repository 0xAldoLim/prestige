import http.client
import json
import socket
import threading
import time

import pytest

from prestige.inference_gate import InferenceGate, narrow_request, validate_sse
from prestige.types import PolicyDenied


def sse(output):
    events = [{"type": "response.output_item.added", "item": item} for item in output]
    events.append({"type": "response.completed", "response": {"output": output}})
    return b"".join(b"data: " + json.dumps(event).encode() + b"\n\n" for event in events)


def test_request_cannot_advertise_native_tools():
    result = json.loads(
        narrow_request(
            json.dumps(
                {"input": [], "tools": [{"type": "web_search"}], "tool_choice": "auto"}
            ).encode()
        )
    )
    assert result["tools"] == [] and result["tool_choice"] == "none"


@pytest.mark.parametrize(
    "tool",
    ["function_call", "custom_tool_call", "computer_call", "web_search_call", "file_search_call"],
)
def test_executable_response_never_reaches_runtime(tool):
    with pytest.raises(PolicyDenied):
        validate_sse(
            sse(
                [
                    {
                        "type": tool,
                        "name": "exec",
                        "arguments": "read credentials; contact scoreboard",
                    }
                ]
            )
        )


def test_text_and_reasoning_are_allowed_but_not_an_execution_channel():
    raw = sse(
        [
            {
                "type": "message",
                "role": "assistant",
                "content": [{"type": "output_text", "text": "malicious words remain data"}],
            }
        ]
    )
    assert validate_sse(raw) == raw
    with pytest.raises(PolicyDenied):
        validate_sse(b'data: {"type":"response.function_call_arguments.delta"}\n\n')


def test_http_gateway_validates_before_forwarding():
    gate = InferenceGate(
        transport=lambda body, headers: sse([{"type": "function_call", "name": "exec"}])
    ).start()
    try:
        connection = http.client.HTTPConnection("127.0.0.1", gate.server.server_port, timeout=2)
        connection.request(
            "POST", gate.route, json.dumps({"input": []}), {"Content-Type": "application/json"}
        )
        response = connection.getresponse()
        assert response.status == 502 and response.read() == b""
        assert gate.denials == 1
        connection.close()
    finally:
        gate.close()


@pytest.mark.parametrize(
    "raw",
    [
        # Unknown SSE event name cannot smuggle a native call.
        b'event: function_call\ndata: {"type":"function_call","name":"exec"}\n\n',
        # Event name must agree with the data type.
        b'event: response.output_item.added\ndata: {"type":"response.completed"}\n\n',
        # Unexpected fields are rejected.
        b'foo: bar\ndata: {"type":"response.completed"}\n\n',
        # Malformed JSON in data is rejected.
        b'data: not json\n\n',
        # Stream without completion is rejected.
        b'data: {"type":"response.in_progress"}\n\n',
    ],
)
def test_strict_sse_rejects_malicious_or_incomplete_frames(raw):
    with pytest.raises(PolicyDenied):
        validate_sse(raw)


def test_comments_and_carriage_returns_are_harmless():
    output = [{"type": "message", "role": "assistant", "content": []}]
    raw = (
        b": comment\r\n"
        b'data: {"type":"response.output_item.added","item":'
        + json.dumps(output[0]).encode()
        + b"}\r\n\r\n"
        + b': another comment\r\ndata: {"type":"response.completed","response":{"output":'
        + json.dumps(output).encode()
        + b"}}\r\n\r\n"
    )
    assert validate_sse(raw) == validate_sse(sse(output))


def test_metadata_frames_are_discarded():
    output = [{"type": "message", "role": "assistant", "content": []}]
    raw = (
        b'data: {"type":"response.metadata","request_id":"r1"}\n\n'
        + sse(output)
    )
    assert validate_sse(raw) == validate_sse(sse(output))


def test_done_sentinel_is_allowed():
    output = [{"type": "message", "role": "assistant", "content": []}]
    raw = sse(output) + b"data: [DONE]\n\n"
    assert validate_sse(raw) == validate_sse(sse(output))


def test_request_budget_is_enforced():
    gate = InferenceGate(max_requests=2, transport=lambda body, headers: sse([])).start()
    try:
        for _ in range(2):
            connection = http.client.HTTPConnection(
                "127.0.0.1", gate.server.server_port, timeout=2
            )
            connection.request(
                "POST", gate.route, json.dumps({"input": []}), {"Content-Type": "application/json"}
            )
            response = connection.getresponse()
            assert response.status == 200
            response.read()
            connection.close()
        connection = http.client.HTTPConnection("127.0.0.1", gate.server.server_port, timeout=2)
        connection.request(
            "POST", gate.route, json.dumps({"input": []}), {"Content-Type": "application/json"}
        )
        response = connection.getresponse()
        assert response.status == 502
        assert gate.denials == 1
        connection.close()
    finally:
        gate.close()


def test_cancel_sockets_shuts_down_active_upstream_sockets():
    gate = InferenceGate().start()
    a, b = socket.socketpair()
    try:
        gate._register_socket(a)
        gate.cancel_sockets()
        # A shut-down socket raises when used.
        with pytest.raises(OSError):
            a.send(b"x")
    finally:
        gate.close()
        a.close()
        b.close()


def test_close_cancels_active_upstream_read(monkeypatch):
    """If an upstream read is blocked, gate.close() must not wait for the timeout."""

    class FakeResponse:
        def __init__(self, sock):
            self.status = 200
            self._sock = sock

        def read1(self, _n):
            try:
                return self._sock.recv(1)
            except OSError:
                return b""

    class FakeConnection:
        def __init__(self, host, timeout=120):
            self.host = host
            self.timeout = timeout
            self.sock = None

        def connect(self):
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.bind(("127.0.0.1", 0))

        def request(self, _method, _path, _body, _headers):
            pass

        def getresponse(self):
            return FakeResponse(self.sock)

        def close(self):
            if self.sock is not None:
                self.sock.close()

    monkeypatch.setattr(http.client, "HTTPSConnection", FakeConnection)
    gate = InferenceGate(timeout=120).start()
    result = {}

    def request():
        try:
            connection = http.client.HTTPConnection(
                "127.0.0.1", gate.server.server_port, timeout=2
            )
            connection.request(
                "POST",
                gate.route,
                json.dumps({"input": []}),
                {"Content-Type": "application/json"},
            )
            response = connection.getresponse()
            result["status"] = response.status
            connection.close()
        except Exception as error:
            result["status"] = type(error).__name__

    thread = threading.Thread(target=request)
    thread.start()
    time.sleep(0.1)
    start = time.monotonic()
    gate.close()
    elapsed = time.monotonic() - start
    thread.join(timeout=2)
    assert elapsed < 1.0
    assert result.get("status") == 502
