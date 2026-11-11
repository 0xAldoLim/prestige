"""Operator-registered authorized challenge instances and a bounded network broker.

Only explicitly registered instances may be contacted. The model cannot create,
enable or widen a registration. Remote mode is disabled unless the operator sets
``PRESTIGE_REMOTE_ENABLED=1`` or ``remote.enabled=true`` in config.
"""

import http.client
import ipaddress
import json
import re
import socket
import ssl
import threading
import time
from dataclasses import asdict, dataclass
from pathlib import Path

from prestige.config import load_config
from prestige.types import PolicyDenied, PrestigeError

METADATA_IPS = {
    "169.254.169.254",
    "100.100.100.200",
    "fd00:ec2::254",
    "::ffff:169.254.169.254",
}
PROTOCOLS = {"http", "https", "tcp", "ssh"}
METHODS = {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}
_SAFE_REQUEST_HEADERS = {
    "accept",
    "accept-language",
    "authorization",
    "content-type",
    "cookie",
    "origin",
    "referer",
    "user-agent",
    "x-requested-with",
}
_FORBIDDEN_REQUEST_HEADERS = {
    "host",
    "content-length",
    "transfer-encoding",
    "connection",
    "upgrade",
    "proxy-authorization",
    "proxy-connection",
}
_MAX_BODY = 65536
_MAX_RESPONSE = 1048576


class RemoteDenied(PolicyDenied):
    pass


class RemoteExpired(PrestigeError):
    pass


@dataclass(frozen=True)
class Registration:
    id: str
    provenance: str
    protocol: str
    host: str
    port: int
    paths: tuple[str, ...] = ("/",)
    methods: tuple[str, ...] = ("GET", "POST", "HEAD")
    pinned_ips: tuple[str, ...] = ()
    dedicated_private: bool = False
    allowed_actions: tuple[str, ...] = ("http",)
    max_requests: int = 50
    max_concurrency: int = 2
    max_seconds: float = 60.0
    rate_per_second: float = 2.0
    expires_at: float | None = None
    exclusions: tuple[str, ...] = ()
    enabled: bool = False
    max_response_bytes: int = 65536

    @classmethod
    def from_dict(cls, data: dict) -> "Registration":
        if not isinstance(data, dict):
            raise RemoteDenied("Registration must be an object")
        allowed = set(cls.__dataclass_fields__)
        if set(data) - allowed:
            raise RemoteDenied("Unknown registration fields")
        required = {"id", "provenance", "protocol", "host", "port"}
        if required - set(data):
            raise RemoteDenied("Registration is missing required fields")
        registration = cls(
            id=_text(data["id"], "id", 64),
            provenance=_text(data["provenance"], "provenance", 400),
            protocol=_text(data["protocol"], "protocol", 8).lower(),
            host=_host(data["host"]),
            port=_port(data["port"]),
            paths=tuple(_path(item) for item in _list(data.get("paths", ["/"]), "paths")),
            methods=tuple(
                _method(item) for item in _list(data.get("methods", ["GET", "POST", "HEAD"]), "methods")
            ),
            pinned_ips=tuple(_ip(item) for item in _list(data.get("pinned_ips", []), "pinned_ips")),
            dedicated_private=bool(data.get("dedicated_private", False)),
            allowed_actions=tuple(
                _text(item, "allowed_actions", 32)
                for item in _list(data.get("allowed_actions", ["http"]), "allowed_actions")
            ),
            max_requests=_int(data.get("max_requests", 50), "max_requests", 1, 10000),
            max_concurrency=_int(data.get("max_concurrency", 2), "max_concurrency", 1, 16),
            max_seconds=float(
                _number(data.get("max_seconds", 60), "max_seconds", 1, 3600)
            ),
            rate_per_second=float(data.get("rate_per_second", 2.0)),
            expires_at=(
                float(data["expires_at"]) if data.get("expires_at") is not None else None
            ),
            exclusions=tuple(
                _text(item, "exclusions", 200) for item in _list(data.get("exclusions", []), "exclusions")
            ),
            enabled=bool(data.get("enabled", False)),
            max_response_bytes=_int(
                data.get("max_response_bytes", 65536), "max_response_bytes", 1024, _MAX_RESPONSE
            ),
        )
        if registration.protocol not in PROTOCOLS:
            raise RemoteDenied("Unsupported protocol")
        if not 0.1 <= registration.rate_per_second <= 100:
            raise RemoteDenied("Invalid rate limit")
        if registration.protocol in {"tcp", "ssh"} and registration.methods != ("GET", "POST", "HEAD"):
            # Methods are meaningless for stream protocols; ignore but keep deterministic.
            pass
        return registration

    def to_dict(self) -> dict:
        return asdict(self)


def _text(value, field, limit):
    if not isinstance(value, str) or not value.strip() or len(value) > limit:
        raise RemoteDenied(f"Invalid {field}")
    return value.strip()


def _host(value):
    text = _text(value, "host", 253).lower().rstrip(".")
    try:
        return str(ipaddress.ip_address(text))
    except ValueError:
        pass
    if not re.fullmatch(r"[a-z0-9.-]+", text) or ".." in text:
        raise RemoteDenied("Invalid hostname")
    return text


def _port(value):
    if type(value) is not int or not 1 <= value <= 65535:
        raise RemoteDenied("Invalid port")
    return value


def _path(value):
    text = _text(value, "path", 512)
    if not text.startswith("/") or ".." in text.split("/") or "//" in text or "\\" in text:
        raise RemoteDenied("Invalid path prefix")
    return text


def _method(value):
    text = _text(value, "method", 8).upper()
    if text not in METHODS:
        raise RemoteDenied("Invalid HTTP method")
    return text


def _ip(value):
    try:
        return str(ipaddress.ip_address(_text(value, "ip", 64)))
    except ValueError as error:
        raise RemoteDenied("Invalid pinned IP") from error


def _int(value, field, low, high):
    if type(value) is not int or not low <= value <= high:
        raise RemoteDenied(f"Invalid {field}")
    return value


def _number(value, field, low, high):
    if type(value) not in (int, float) or not low <= value <= high:
        raise RemoteDenied(f"Invalid {field}")
    return value


def _list(value, field):
    if not isinstance(value, list):
        raise RemoteDenied(f"{field} must be a list")
    return value


def registration_path(home: Path) -> Path:
    return home / "registrations.json"


def load_registrations(home: Path) -> dict[str, Registration]:
    path = registration_path(home)
    if not path.exists():
        return {}
    if not path.is_file() or path.stat().st_size > 262144:
        raise RemoteDenied("Registration file is invalid or too large")
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (ValueError, UnicodeError) as error:
        raise RemoteDenied("Registration file is not valid JSON") from error
    if not isinstance(data, dict) or data.get("schema_version") != 1:
        raise RemoteDenied("Unsupported registration schema")
    items = data.get("registrations", [])
    if not isinstance(items, list):
        raise RemoteDenied("registrations must be a list")
    result = {}
    for item in items:
        registration = Registration.from_dict(item)
        if registration.id in result:
            raise RemoteDenied("Duplicate registration id")
        result[registration.id] = registration
    return result


def save_registrations(home: Path, registrations: dict[str, Registration]) -> None:
    home.mkdir(parents=True, exist_ok=True)
    payload = json.dumps(
        {
            "schema_version": 1,
            "registrations": [registrations[key].to_dict() for key in sorted(registrations)],
        },
        indent=2,
    )
    tmp = registration_path(home).with_suffix(".tmp")
    tmp.write_text(payload, encoding="utf-8")
    tmp.replace(registration_path(home))


def remote_enabled(home: Path) -> bool:
    import os

    value = os.environ.get("PRESTIGE_REMOTE_ENABLED", "")
    if value.lower() in {"1", "true", "yes"}:
        return True
    return str(load_config(home).get("remote.enabled", "")).lower() in {"1", "true", "yes"}


class RemoteBroker:
    def __init__(self, home: Path, registration: Registration):
        self.home = home
        self.registration = registration
        self._lock = threading.Lock()
        self._active: set[socket.socket] = set()
        self._requests = 0
        self._active_requests = 0
        self._last_request = 0.0
        self._cancelled = False

    # ---- policy helpers -------------------------------------------------
    def _check(self):
        if not remote_enabled(self.home):
            raise RemoteDenied("Remote mode is disabled by the operator")
        if not self.registration.enabled:
            raise RemoteDenied("Registration is disabled")
        if self.registration.expires_at is not None and time.time() >= self.registration.expires_at:
            raise RemoteExpired("Assigned instance has expired; request a fresh registration")
        if self._cancelled:
            raise RemoteExpired("Remote work was cancelled")

    def _consume(self):
        with self._lock:
            if self._cancelled:
                raise RemoteExpired("Remote work was cancelled")
            if self._active_requests >= self.registration.max_concurrency:
                raise RemoteDenied("Concurrent request limit reached for this registration")
            self._active_requests += 1
            self._requests += 1
            if self._requests > self.registration.max_requests:
                self._active_requests -= 1
                raise RemoteDenied("Request budget exhausted for this registration")
            now = time.time()
            minimum = 1.0 / self.registration.rate_per_second
            wait = minimum - (now - self._last_request)
            if wait > 0:
                time.sleep(wait)
            self._last_request = time.time()

    def _finish(self):
        with self._lock:
            self._active_requests = max(0, self._active_requests - 1)

    def _resolve(self) -> list[str]:
        try:
            infos = socket.getaddrinfo(
                self.registration.host, self.registration.port, type=socket.SOCK_STREAM
            )
        except OSError as error:
            raise PrestigeError(f"DNS resolution failed: {error}") from error
        addresses = []
        for info in infos:
            address = str(info[4][0])
            if address not in addresses:
                addresses.append(address)
        pinned = set(self.registration.pinned_ips)
        if pinned and set(addresses) != pinned:
            raise RemoteDenied("Resolved addresses differ from the pinned assignment")
        for address in addresses:
            ip = ipaddress.ip_address(address)
            if str(ip) in METADATA_IPS or address in METADATA_IPS:
                raise RemoteDenied("Cloud metadata address is forbidden")
            if ip.is_link_local or ip.is_multicast or ip.is_reserved or ip.is_unspecified:
                raise RemoteDenied("Forbidden destination address class")
            if not ip.is_global and not self.registration.dedicated_private:
                raise RemoteDenied("Private or loopback destination requires dedicated registration")
        if not addresses:
            raise PrestigeError("No destination address")
        return addresses

    def _connect(self, timeout: float) -> socket.socket:
        address = self._resolve()[0]
        try:
            sock = socket.create_connection(
                (address, self.registration.port), timeout=min(timeout, self.registration.max_seconds)
            )
        except OSError as error:
            raise PrestigeError(f"Connection failed: {error}") from error
        with self._lock:
            self._active.add(sock)
        return sock

    def _release(self, sock):
        with self._lock:
            self._active.discard(sock)
        try:
            sock.close()
        except OSError:
            pass

    # ---- HTTP -----------------------------------------------------------
    def _path_allowed(self, path: str) -> bool:
        if not isinstance(path, str) or not path.startswith("/"):
            return False
        if ".." in path.split("/") or "//" in path or "\\" in path or "%" in path:
            return False
        return any(path == prefix or path.startswith(prefix.rstrip("/") + "/") for prefix in self.registration.paths)

    def _headers(self, headers: dict | None) -> dict:
        result = {"Host": self.registration.host}
        for key, value in (headers or {}).items():
            if not isinstance(key, str) or not isinstance(value, str):
                raise RemoteDenied("Header names and values must be strings")
            lower = key.lower()
            if lower in _FORBIDDEN_REQUEST_HEADERS or lower.startswith("proxy-"):
                raise RemoteDenied(f"Header {key} cannot be set")
            if lower not in _SAFE_REQUEST_HEADERS and not lower.startswith("x-"):
                raise RemoteDenied(f"Header {key} is not allowed")
            if "\r" in value or "\n" in value:
                raise RemoteDenied("Header injection is forbidden")
            result[key] = value
        return result

    def http(
        self,
        method: str,
        path: str,
        headers: dict | None = None,
        body: bytes = b"",
        timeout: float = 10.0,
    ) -> dict:
        self._check()
        if self.registration.protocol not in {"http", "https"}:
            raise RemoteDenied("Registration is not an HTTP service")
        method = method.upper()
        if method not in self.registration.methods:
            raise RemoteDenied("HTTP method is not authorized for this registration")
        if not self._path_allowed(path):
            raise RemoteDenied("Path is outside the registered scope")
        if len(body) > _MAX_BODY:
            raise RemoteDenied("Request body exceeds the bound")
        self._consume()
        sock = self._connect(timeout)
        connection = None
        try:
            if self.registration.protocol == "https":
                context = ssl.create_default_context()
                sock = context.wrap_socket(sock, server_hostname=self.registration.host)
            connection = http.client.HTTPConnection(
                self.registration.host, self.registration.port, timeout=timeout
            )
            connection.sock = sock
            connection.request(
                method, path, body=body or None, headers=self._headers(headers)
            )
            response = connection.getresponse()
            data = response.read(min(self.registration.max_response_bytes, _MAX_RESPONSE))
            location = response.getheader("Location")
            result = {
                "status": response.status,
                "reason": response.reason,
                "headers": {
                    key: value
                    for key, value in response.getheaders()
                    if key.lower()
                    in {"content-type", "content-length", "location", "set-cookie", "server"}
                },
                "bytes": len(data),
                "body": data,
                "followed_redirect": False,
                "redirect_blocked": bool(location and not self._path_allowed(_location_path(location))),
            }
            return result
        except (OSError, http.client.HTTPException) as error:
            raise PrestigeError(f"HTTP request failed: {error}") from error
        finally:
            if connection is not None:
                connection.close()
            self._release(sock)
            self._finish()

    # ---- TCP ------------------------------------------------------------
    def tcp(self, data: bytes, read_bytes: int = 4096, timeout: float = 10.0) -> dict:
        self._check()
        if self.registration.protocol not in {"tcp", "ssh"}:
            raise RemoteDenied("Registration is not a stream service")
        if len(data) > _MAX_BODY:
            raise RemoteDenied("Request data exceeds the bound")
        if type(read_bytes) is not int or not 1 <= read_bytes <= self.registration.max_response_bytes:
            raise RemoteDenied("Invalid read bound")
        self._consume()
        sock = self._connect(timeout)
        received = bytearray()
        try:
            if data:
                sock.sendall(data)
            deadline = time.monotonic() + min(timeout, self.registration.max_seconds)
            while len(received) < read_bytes:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    break
                sock.settimeout(remaining)
                try:
                    chunk = sock.recv(min(4096, read_bytes - len(received)))
                except socket.timeout:
                    break
                if not chunk:
                    break
                received.extend(chunk)
            return {"bytes": len(received), "data": bytes(received)}
        except OSError as error:
            raise PrestigeError(f"TCP exchange failed: {error}") from error
        finally:
            self._release(sock)
            self._finish()

    # ---- lifecycle ------------------------------------------------------
    def status(self) -> dict:
        return {
            "registration_id": self.registration.id,
            "protocol": self.registration.protocol,
            "enabled": self.registration.enabled,
            "remote_enabled": remote_enabled(self.home),
            "expires_at": self.registration.expires_at,
            "expired": bool(
                self.registration.expires_at is not None
                and time.time() >= self.registration.expires_at
            ),
            "requests_used": self._requests,
            "max_requests": self.registration.max_requests,
            "cancelled": self._cancelled,
        }

    def cancel(self) -> int:
        self._cancelled = True
        with self._lock:
            sockets = list(self._active)
        for sock in sockets:
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            self._release(sock)
        return len(sockets)


def _location_path(location: str) -> str:
    from urllib.parse import urlsplit

    try:
        parts = urlsplit(location)
        return parts.path or "/"
    except ValueError:
        return "/"


_BROKERS: dict[str, RemoteBroker] = {}
_BROKERS_LOCK = threading.Lock()


def broker_for(home: Path, registration: Registration) -> RemoteBroker:
    """Shared broker per registration so counters and cancellation survive calls."""
    key = f"{home.resolve()}::{registration.id}"
    with _BROKERS_LOCK:
        broker = _BROKERS.get(key)
        if broker is None or broker.registration != registration:
            broker = RemoteBroker(home, registration)
            _BROKERS[key] = broker
        return broker


def reset_brokers() -> None:
    with _BROKERS_LOCK:
        _BROKERS.clear()
