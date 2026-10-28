import json

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
    import http.client

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
