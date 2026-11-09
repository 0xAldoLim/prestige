"""Deterministic restrictions. No network or shell escape hatch exists in ToolRegistry."""

import hashlib
import ipaddress
import json
import re
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from urllib.parse import unquote, urlsplit

from prestige.types import PolicyDenied


@dataclass(frozen=True)
class Rules:
    ai_allowed: bool = True
    automation_allowed: bool = True
    remote_allowed: bool = False
    allowed_tools: tuple[str, ...] = (
        "inspect",
        "strings",
        "base64",
        "hex",
        "xor",
        "zip",
        "read",
        "python",
        "command",
        "file",
        "radare2",
    )
    max_turns: int = 12
    max_seconds: float = 120
    max_requests: int = 0
    denied_origins: tuple[str, ...] = ()
    source_hash: str | None = None

    @classmethod
    def load(cls, path: Path | None) -> "Rules":
        if path is None:
            return cls()
        raw = path.read_bytes()
        if len(raw) > 65536:
            raise PolicyDenied("Rules file too large")
        try:
            data = json.loads(raw)
        except (ValueError, UnicodeError) as error:
            raise PolicyDenied(
                "Rules must be explicit JSON; natural-language rules require manual transcription"
            ) from error
        if not isinstance(data, dict) or set(data) - (
            set(cls.__dataclass_fields__) - {"source_hash"}
        ):
            raise PolicyDenied("Unknown rules fields")
        for key in ("ai_allowed", "automation_allowed", "remote_allowed"):
            if key in data and type(data[key]) is not bool:
                raise PolicyDenied("Rule permission values must be booleans")
        for key in ("max_turns", "max_requests"):
            if key in data and (type(data[key]) is not int or data[key] < 0):
                raise PolicyDenied("Rule limits must be nonnegative integers")
        if "max_seconds" in data and (
            type(data["max_seconds"]) not in (float, int) or not 0 < data["max_seconds"] <= 86400
        ):
            raise PolicyDenied("Invalid rule time limit")
        for key in ("allowed_tools", "denied_origins"):
            if key in data:
                if not isinstance(data[key], list) or not all(
                    isinstance(x, str) for x in data[key]
                ):
                    raise PolicyDenied("Invalid rules list")
                data[key] = tuple(data[key])
        result = cls(**data, source_hash=hashlib.sha256(raw).hexdigest())
        result.check()
        return result

    def check(self):
        if not self.ai_allowed or not self.automation_allowed:
            raise PolicyDenied("Event rules prohibit automated solving")

    def snapshot(self):
        return asdict(self)


def canonical_endpoint(url: str) -> tuple[str, str, int, str]:
    if not isinstance(url, str) or len(url) > 2048 or re.search(r"[\s\\\x00-\x1f]", url):
        raise PolicyDenied("Malformed endpoint")
    try:
        parts = urlsplit(url)
        if (
            parts.scheme not in ("http", "https")
            or not parts.hostname
            or parts.username
            or parts.password
        ):
            raise ValueError("scheme or credentials")
        if parts.query or parts.fragment or "%" in parts.netloc:
            raise ValueError("ambiguous endpoint")
        host = parts.hostname.rstrip(".").encode("idna").decode().lower()
        try:
            host = str(ipaddress.ip_address(host))
        except ValueError:
            if not re.fullmatch(r"[a-z0-9.-]+", host) or ".." in host:
                raise ValueError("invalid hostname")
        port = parts.port if parts.port is not None else (443 if parts.scheme == "https" else 80)
        if port == 0:
            raise ValueError("invalid port zero")
        path = parts.path or "/"
        decoded = unquote(path)
        if decoded != path or any(x in (".", "..") for x in path.split("/")) or "//" in path:
            raise ValueError("ambiguous path")
        return parts.scheme, host, port, path
    except (ValueError, UnicodeError) as error:
        raise PolicyDenied("Invalid or ambiguous endpoint") from error


@dataclass(frozen=True)
class ScopePolicy:
    endpoint: str
    denied_origins: tuple[str, ...] = ()
    pinned_ips: tuple[str, ...] = ()
    dedicated_private: bool = False

    def check(self, url: str, resolved_ips: tuple[str, ...] = ()):
        target = canonical_endpoint(self.endpoint)
        candidate = canonical_endpoint(url)
        if candidate != target:
            raise PolicyDenied("Only the exact assigned scheme, host, port and path are allowed")
        if any(candidate[:3] == canonical_endpoint(x)[:3] for x in self.denied_origins):
            raise PolicyDenied("Forbidden platform origin")
        if re.search(
            r"(?:^|[./_-])(ctfd|scoreboard|provision|submission|platform)(?:[./_-]|$)",
            candidate[1] + candidate[3],
        ):
            raise PolicyDenied("Potential competition platform; clarify boundary")
        for address in resolved_ips:
            ip = ipaddress.ip_address(address)
            if not ip.is_global and not self.dedicated_private:
                raise PolicyDenied("Private/metadata address not explicitly dedicated")
        if resolved_ips and (not self.pinned_ips or set(resolved_ips) != set(self.pinned_ips)):
            raise PolicyDenied("DNS addresses differ from the pinned assignment")


@dataclass
class InstanceLease:
    endpoint: str | None = None
    state: str = "not_configured"
    expires_at: float | None = None
    last_good: float | None = None
    failures: int = 0
    checks: int = 0
    next_check: float = 0
    observations: list[dict] = field(default_factory=list)

    def allow_attempt(self, now: float | None = None):
        now = time.time() if now is None else now
        if self.expires_at is not None and now >= self.expires_at:
            self.state = "waiting_for_user"
        if self.state not in {"healthy", "renewed"}:
            raise PolicyDenied("Instance unavailable; provide a fresh dedicated endpoint")

    def observe(self, *, healthy=False, transport_failure=False, now: float | None = None):
        now = time.time() if now is None else now
        self.observations = (
            self.observations
            + [{"at": now, "healthy": healthy, "transport_failure": transport_failure}]
        )[-8:]
        if healthy:
            self.last_good, self.failures, self.state = now, 0, "healthy"
        elif transport_failure:
            self.failures += 1
            self.state = "suspect" if self.failures == 1 else "expired_or_unavailable"
        # An ordinary 404/500 alone is deliberately inconclusive.

    def health_check(self, now: float):
        if self.checks >= 2 or now < self.next_check or self.state != "suspect":
            raise PolicyDenied("Health check budget/backoff exhausted")
        self.checks += 1
        self.next_check = now + 2**self.checks

    def renew(self, endpoint: str):
        ScopePolicy(endpoint).check(endpoint)
        self.endpoint, self.state = endpoint, "renewed"
        self.failures = self.checks = 0
        self.expires_at = self.last_good = None


def require_remote():
    raise PolicyDenied(
        "Remote challenge execution is disabled: no validated endpoint broker is shipped"
    )
