import asyncio
import base64
import hashlib
import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from prestige.cli import main
from prestige.openai_backend import OpenAIBackend
from prestige.types import Action, PolicyDenied, PrestigeError


def test_backend_requires_key_and_model():
    with pytest.raises(PrestigeError):
        OpenAIBackend("http://localhost:1234/v1", "", "model")
    with pytest.raises(PrestigeError):
        OpenAIBackend("", "key", "model")


class FakeResponse:
    def __init__(self, status_code, body):
        self.status_code = status_code
        self._body = body

    def raise_for_status(self):
        if self.status_code >= 400:
            import httpx

            raise httpx.HTTPStatusError(
                "err", request=None, response=self
            )  # response arg used for status

    def json(self):
        return self._body


class FakeClient:
    def __init__(self, responses):
        self.responses = responses
        self.closed = False

    async def post(self, path, json=None):
        return self.responses.pop(0)

    async def aclose(self):
        self.closed = True


def _make_backend(responses):
    backend = OpenAIBackend("http://localhost:1234/v1", "test-key", "test-model")
    backend.client = FakeClient(responses)
    return backend


@pytest.mark.asyncio
async def test_backend_parses_valid_response():
    body = {
        "choices": [
            {
                "message": {
                    "content": json.dumps(
                        {
                            "action": {"tool": "inspect", "artifact": "a" * 64, "args": {}},
                            "hypothesis": "look at bytes",
                        }
                    )
                },
                "finish_reason": "stop",
            }
        ],
        "usage": {"prompt_tokens": 10, "completion_tokens": 5},
    }
    backend = _make_backend([FakeResponse(200, body)])
    proposal = await backend.propose({"lane": "fast", "artifacts": []})
    assert isinstance(proposal.action, Action)
    assert proposal.action.tool == "inspect"
    assert proposal.hypothesis == "look at bytes"
    assert proposal.usage.input_tokens == 10
    assert proposal.usage.output_tokens == 5
    assert backend.client.closed is False
    await backend.close()
    assert backend.client is None


@pytest.mark.asyncio
async def test_backend_rejects_malformed_response():
    body = {
        "choices": [
            {
                "message": {
                    "content": json.dumps({"action": None})
                },
                "finish_reason": "stop",
            }
        ]
    }
    backend = _make_backend([FakeResponse(200, body)])
    with pytest.raises(PolicyDenied):
        await backend.propose({})
    await backend.close()


@pytest.mark.asyncio
async def test_backend_rejects_non_json_response():
    body = {
        "choices": [
            {"message": {"content": "not json"}, "finish_reason": "stop"}
        ]
    }
    backend = _make_backend([FakeResponse(200, body)])
    with pytest.raises(PolicyDenied):
        await backend.propose({})
    await backend.close()


@pytest.mark.asyncio
async def test_backend_propagates_http_error():
    backend = OpenAIBackend("http://localhost:1234/v1", "test-key", "test-model")
    backend.client = FakeClient([FakeResponse(401, {})])
    with pytest.raises(PolicyDenied):
        await backend.propose({})
    await backend.close()


@pytest.mark.asyncio
async def test_interrupt_cancels_active_request():
    body = {
        "choices": [
            {
                "message": {
                    "content": json.dumps({"action": None, "hypothesis": "done"})
                },
                "finish_reason": "stop",
            }
        ]
    }

    class SlowClient:
        def __init__(self):
            self.closed = False
            self.post_called = asyncio.Event()

        async def post(self, path, json=None):
            self.post_called.set()
            await asyncio.sleep(10)
            return FakeResponse(200, body)

        async def aclose(self):
            self.closed = True

    backend = OpenAIBackend("http://localhost:1234/v1", "test-key", "test-model")
    backend.client = SlowClient()
    task = asyncio.create_task(backend.propose({}))
    await asyncio.wait_for(backend.client.post_called.wait(), timeout=1)
    await backend.interrupt()
    with pytest.raises(asyncio.CancelledError):
        await task


def test_cli_solve_with_openai_backend_and_mock_endpoint(tmp_path):
    value = b"SYNTHETIC{openai_mock_solve}"
    path = tmp_path / "challenge.txt"
    path.write_bytes(base64.b64encode(value))
    digest = hashlib.sha256(value).hexdigest()

    # Start a minimal OpenAI-compatible mock server.
    responses = []
    server_ready = threading.Event()

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            return None

        def do_POST(self):
            length = int(self.headers.get("Content-Length", "0"))
            self.rfile.read(length)
            body = responses.pop(0)
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(body).encode())

    server = HTTPServer(("127.0.0.1", 0), Handler)
    port = server.server_port

    def serve():
        server_ready.set()
        server.handle_request()
        server.handle_request()
        server.server_close()

    # First response: inspect the artifact. Second: decode base64.
    artifact_digest = hashlib.sha256(path.read_bytes()).hexdigest()
    responses.append(
        {
            "choices": [
                {
                    "message": {
                        "content": json.dumps(
                            {
                                "action": {"tool": "inspect", "artifact": artifact_digest, "args": {}},
                                "hypothesis": "inspect bytes",
                            }
                        )
                    },
                    "finish_reason": "stop",
                }
            ],
            "usage": {"prompt_tokens": 10, "completion_tokens": 5},
        }
    )
    responses.append(
        {
            "choices": [
                {
                    "message": {
                        "content": json.dumps(
                            {
                                "action": {"tool": "base64", "artifact": artifact_digest, "args": {}},
                                "hypothesis": "decode base64",
                            }
                        )
                    },
                    "finish_reason": "stop",
                }
            ],
            "usage": {"prompt_tokens": 20, "completion_tokens": 5},
        }
    )

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    server_ready.wait(timeout=2)

    assert (
        main(
            [
                "--home",
                str(tmp_path / "cli-state"),
                "solve",
                str(path),
                "--backend",
                "openai",
                "--openai-base-url",
                f"http://127.0.0.1:{port}",
                "--openai-api-key",
                "test-key",
                "--openai-model",
                "test-model",
                "--expected-sha256",
                digest,
            ]
        )
        == 0
    )
