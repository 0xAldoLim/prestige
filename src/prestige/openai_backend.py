"""Provider-independent OpenAI-compatible chat backend.

Supports any endpoint exposing `/chat/completions`, including OpenAI, local Ollama
and llama.cpp-compatible servers. Authentication and base URL are explicit; no
Codex SDK or CLI binary is required.
"""

import asyncio
import json
from pathlib import Path

from prestige.codex_sdk import MISSION
from prestige.types import Action, PolicyDenied, PrestigeError, Proposal, Usage


class OpenAIBackend:
    name = "openai"
    session_id = None

    def __init__(
        self,
        base_url: str,
        api_key: str,
        model: str,
        *,
        timeout: float = 120,
        max_tokens: int = 4096,
        workspace: Path | None = None,
    ):
        if not base_url or not model:
            raise PrestigeError("OpenAI backend requires base_url and model")
        if not isinstance(api_key, str) or not api_key:
            raise PolicyDenied("OpenAI backend requires an explicit API key")
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.model = model
        self.timeout = timeout
        self.max_tokens = max_tokens
        self.workspace = workspace or Path(".")
        self.client = None
        self._active = None

    async def start_session(self):
        try:
            import httpx
        except ImportError as error:
            raise PrestigeError("httpx is required for the openai backend") from error
        self.workspace.mkdir(parents=True, exist_ok=True)
        self.client = httpx.AsyncClient(
            base_url=self.base_url,
            headers={"Authorization": f"Bearer {self.api_key}"},
            timeout=httpx.Timeout(self.timeout, connect=10),
        )

    async def propose(self, context: dict) -> Proposal:
        if self.client is None:
            await self.start_session()
        import httpx

        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": MISSION},
                {"role": "user", "content": json.dumps(context, ensure_ascii=True)},
            ],
            "max_tokens": self.max_tokens,
            "response_format": {"type": "json_object"},
        }
        try:
            self._active = asyncio.create_task(self.client.post("/chat/completions", json=payload))
            response = await self._active
            response.raise_for_status()
        except httpx.HTTPStatusError as error:
            raise PolicyDenied(f"Provider HTTP status {error.response.status_code}") from error
        except httpx.RequestError as error:
            raise PrestigeError(f"Provider request failed: {type(error).__name__}") from error
        finally:
            self._active = None
        body = response.json()
        choice = body.get("choices", [{}])[0]
        message = choice.get("message", {})
        content = message.get("content", "")
        finish = choice.get("finish_reason")
        if finish == "content_filter":
            raise PolicyDenied("Provider content filter refused the response")
        if not content:
            raise PolicyDenied("Empty provider response")
        try:
            value = json.loads(content)
        except ValueError as error:
            raise PolicyDenied("Provider response is not valid JSON") from error
        if not isinstance(value, dict) or set(value) != {"action", "hypothesis"}:
            raise PolicyDenied("Malformed model proposal")
        if value["action"] and isinstance(value["action"].get("args"), str):
            value["action"]["args"] = json.loads(value["action"]["args"])
        usage = body.get("usage", {})
        return Proposal(
            Action.parse(value["action"]) if value["action"] else None,
            value["hypothesis"],
            Usage(
                usage.get("prompt_tokens"),
                usage.get("completion_tokens"),
                usage.get("prompt_tokens_details", {}).get("cached_tokens")
                if isinstance(usage.get("prompt_tokens_details"), dict)
                else None,
                None,
            ),
        )

    async def interrupt(self):
        if self._active is not None and not self._active.done():
            self._active.cancel()
            try:
                await self._active
            except asyncio.CancelledError:
                pass

    async def close(self):
        if self.client is not None:
            await self.client.aclose()
            self.client = None
