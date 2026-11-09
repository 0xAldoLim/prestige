import asyncio
import json

import pytest

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
