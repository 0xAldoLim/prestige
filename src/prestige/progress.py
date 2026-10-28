import hashlib
import time
from dataclasses import asdict, dataclass, field

from prestige.store import encoded
from prestige.types import Action, PrestigeError


def fingerprint(action: Action) -> str:
    # IDs are content hashes: renaming or reordering identical inputs cannot evade repetition.
    return hashlib.sha256(encoded(asdict(action)).encode()).hexdigest()


@dataclass
class Budget:
    max_turns: int
    max_seconds: float
    max_tokens: int | None = None
    turns: int = 0
    tokens: int = 0
    previous_seconds: float = 0
    started: float = field(default_factory=time.monotonic)

    @property
    def elapsed(self):
        return self.previous_seconds + time.monotonic() - self.started

    def check(self):
        if self.turns >= self.max_turns or self.elapsed >= self.max_seconds:
            raise PrestigeError("Turn or wall-time budget exhausted")
        if self.max_tokens is not None and self.tokens >= self.max_tokens:
            raise PrestigeError("Reported token budget exhausted")


@dataclass
class Progress:
    stale: int = 0
    seen: set[str] = field(default_factory=set)

    def observe(self, action: Action, novel: bool, error: bool = False) -> str:
        key = fingerprint(action)
        duplicate = key in self.seen
        self.seen.add(key)
        self.stale = 0 if novel and not duplicate and not error else self.stale + 1
        return "recover" if self.stale >= 2 else "continue"
