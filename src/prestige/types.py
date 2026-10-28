"""Small provider-neutral contracts. Model output never constitutes a fact."""

from dataclasses import dataclass, field
from typing import Any, Protocol


class PrestigeError(Exception):
    """A safe, user-facing operational error."""


class PolicyDenied(PrestigeError):
    pass


@dataclass(frozen=True)
class Action:
    tool: str
    artifact: str = ""
    args: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def parse(cls, value: Any) -> "Action":
        if not isinstance(value, dict) or set(value) != {"tool", "artifact", "args"}:
            raise PolicyDenied("Action requires exactly tool, artifact, args")
        if not isinstance(value["tool"], str) or not isinstance(value["artifact"], str):
            raise PolicyDenied("Invalid action identifiers")
        if not isinstance(value["args"], dict):
            raise PolicyDenied("Action args must be an object")
        return cls(**value)


@dataclass(frozen=True)
class Usage:
    input_tokens: int | None = None
    output_tokens: int | None = None
    cached_tokens: int | None = None
    reasoning_tokens: int | None = None

    @property
    def total(self) -> int | None:
        if self.input_tokens is None or self.output_tokens is None:
            return None
        return self.input_tokens + self.output_tokens


@dataclass(frozen=True)
class Proposal:
    action: Action | None
    hypothesis: str
    usage: Usage = field(default_factory=Usage)


class BackendAdapter(Protocol):
    name: str
    session_id: str | None

    async def propose(self, context: dict[str, Any]) -> Proposal: ...
    async def interrupt(self) -> None: ...
    async def close(self) -> None: ...
