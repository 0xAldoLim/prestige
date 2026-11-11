"""Operator-registered authorized challenge instances and a bounded network broker.

Only explicitly registered instances may be contacted. The model cannot create,
enable or widen a registration. Remote mode is disabled unless the operator sets
``PRESTIGE_REMOTE_ENABLED=1`` or ``remote.enabled=true`` in config.
"""

import http.client
import ipaddress
import json
import os
import re
import socket
import ssl
import subprocess
import threading
import time
import uuid
from dataclasses import asdict, dataclass
from pathlib import Path

from prestige.config import load_config
from prestige.store import Store
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
    ssh_user: str = ""
    ssh_key_path: str = ""
    ssh_known_hosts: str = ""
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
            ssh_user=str(data.get("ssh_user", "")).strip(),
            ssh_key_path=str(data.get("ssh_key_path", "")).strip(),
            ssh_known_hosts=str(data.get("ssh_known_hosts", "")).strip(),
            enabled=bool(data.get("enabled", False)),
            max_response_bytes=_int(
                data.get("max_response_bytes", 65536), "max_response_bytes", 1024, _MAX_RESPONSE
            ),
        )
        if registration.protocol not in PROTOCOLS:
            raise RemoteDenied("Unsupported protocol")
        if not 0.1 <= registration.rate_per_second <= 100:
            raise RemoteDenied("Invalid rate limit")
        if registration.protocol == "ssh":
            if not registration.ssh_user or not registration.ssh_key_path or not registration.ssh_known_hosts:
                raise RemoteDenied("SSH registration requires user, key and known_hosts")
            key = Path(registration.ssh_key_path).expanduser()
            known = Path(registration.ssh_known_hosts).expanduser()
            if not key.is_file() or not known.is_file():
                raise RemoteDenied("SSH key or known_hosts file is missing")
            if os.name != "nt" and key.stat().st_mode & 0o077:
                raise RemoteDenied("SSH key must not be group/world accessible")
        elif registration.ssh_user or registration.ssh_key_path or registration.ssh_known_hosts:
            raise RemoteDenied("SSH fields are only valid for protocol ssh")
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


class _CancellationMonitor:
    """Abort a live socket when the registration is cancelled or expires.

    The monitor lives in the process that owns the socket, so it works across
    separate PRESTIGE server processes: cancellation is persisted in SQLite and
    each monitor polls the flag.
    """

    def __init__(self, home: Path, registration: Registration, sock: socket.socket):
        self.home = home
        self.registration = registration
        self.sock = sock
        self.sock_lock = threading.Lock()
        self.done = threading.Event()
        self.cancelled = False
        self.thread = threading.Thread(target=self._run, daemon=True)

    def _run(self):
        while not self.done.wait(0.2):
            try:
                if (
                    self.registration.expires_at is not None
                    and time.time() >= self.registration.expires_at
                ):
                    self.cancelled = True
                    self._shutdown()
                    return
                if registration_cancelled(self.home, self.registration.id):
                    self.cancelled = True
                    self._shutdown()
                    return
            except Exception:
                continue

    def update_socket(self, sock: socket.socket):
        with self.sock_lock:
            self.sock = sock

    def _shutdown(self):
        with self.sock_lock:
            sock = self.sock
        try:
            sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        # Closing is the only reliable way to wake a blocking recv on every
        # platform; the supervisor below does not depend on it, but it helps
        # release the blocked worker promptly.
        try:
            sock.close()
        except OSError:
            pass

    def start(self):
        self.thread.start()

    def stop(self):
        self.done.set()
        self.thread.join(timeout=1)


def canonical_request_target(target: str) -> tuple[str, str]:
    """Parse an origin-form HTTP request target into (canonical path, query).

    Percent-encoded paths, absolute/authority forms, fragments, backslashes,
    control/non-ASCII characters, duplicate separators and dot segments are
    rejected. Well-formed query strings are allowed and returned separately so
    exclusions apply to the canonical path, never the raw target.
    """
    if not isinstance(target, str) or not target or len(target) > 2048:
        raise RemoteDenied("Invalid request target")
    if target.startswith(("http://", "https://", "//")):
        raise RemoteDenied("Absolute-form and authority-form targets are forbidden")
    if "#" in target or "\\" in target:
        raise RemoteDenied("Fragments and backslashes are forbidden")
    if any(ord(char) < 0x21 or ord(char) > 0x7E for char in target):
        raise RemoteDenied("Control or non-ASCII characters are forbidden")
    path, separator, query = target.partition("?")
    if not path.startswith("/") or path.startswith("//"):
        raise RemoteDenied("Path must be absolute and single-rooted")
    if "//" in path:
        raise RemoteDenied("Duplicate path separators are forbidden")
    if "%" in path:
        raise RemoteDenied("Percent-encoded paths are forbidden")
    if any(segment in {".", ".."} for segment in path.split("/")):
        raise RemoteDenied("Traversal segments are forbidden")
    if separator and query:
        if "?" in query or "#" in query:
            raise RemoteDenied("Ambiguous query string")
        for index, char in enumerate(query):
            if char == "%" and (
                index + 2 >= len(query)
                or not re.fullmatch(r"[0-9A-Fa-f]{2}", query[index + 1 : index + 3])
            ):
                raise RemoteDenied("Malformed query encoding")
    return path, query


class RemoteBroker:
    def __init__(self, home: Path, registration: Registration):
        self.home = home
        self.registration = registration
        self._lock = threading.Lock()
        self._active: set[socket.socket] = set()

    # ---- policy helpers -------------------------------------------------
    def _check(self, run_id: str | None):
        if not remote_enabled(self.home):
            raise RemoteDenied("Remote mode is disabled by the operator")
        if not self.registration.enabled:
            raise RemoteDenied("Registration is disabled")
        if self.registration.expires_at is not None and time.time() >= self.registration.expires_at:
            raise RemoteExpired("Assigned instance has expired; request a fresh registration")
        if registration_cancelled(self.home, self.registration.id):
            raise RemoteExpired("Remote work was cancelled or revoked")
        if run_id is not None and not is_bound(self.home, run_id, self.registration.id):
            raise RemoteDenied("Target is not bound to this investigation")

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
            if self._excluded_address(address):
                raise RemoteDenied("Destination is explicitly excluded")
        if not addresses:
            raise PrestigeError("No destination address")
        return addresses

    def _excluded_address(self, address: str) -> bool:
        candidate = ipaddress.ip_address(address)
        for exclusion in self.registration.exclusions:
            if exclusion.startswith("/"):
                continue
            try:
                if candidate in ipaddress.ip_network(exclusion, strict=False):
                    return True
            except ValueError:
                if exclusion.lower().rstrip(".") == self.registration.host:
                    return True
        return False

    def _excluded_path(self, path: str) -> bool:
        for exclusion in self.registration.exclusions:
            if not exclusion.startswith("/"):
                continue
            if path == exclusion or path.startswith(exclusion.rstrip("/") + "/"):
                return True
        return False

    def _connect(self, timeout: float) -> socket.socket:
        address = self._resolve()[0]
        if self.registration.expires_at is not None and time.time() >= self.registration.expires_at:
            raise RemoteExpired("Assigned instance expired before connection")
        if registration_cancelled(self.home, self.registration.id):
            raise RemoteExpired("Registration was cancelled before connection")
        try:
            family = socket.AF_INET6 if ":" in address else socket.AF_INET
            sock = socket.socket(family, socket.SOCK_STREAM)
            sock.settimeout(min(timeout, self.registration.max_seconds))
            sock.connect((address, self.registration.port))
        except OSError as error:
            raise PrestigeError(f"Connection failed: {error}") from error
        with self._lock:
            self._active.add(sock)
        return sock

    def _register(self, sock: socket.socket):
        with self._lock:
            self._active.add(sock)

    def _release(self, sock):
        with self._lock:
            self._active.discard(sock)
        try:
            sock.close()
        except OSError:
            pass

    def _supervise(self, operation, monitor, timeout: float):
        """Run a blocking exchange while observing expiry/revocation.

        A socket blocked in ``recv``/``getresponse`` is not reliably
        interrupted by ``shutdown`` from another thread on Windows. The caller
        therefore waits on a short event and aborts as soon as the monitor
        reports expiry or cancellation, regardless of what the worker is doing.
        """
        finished = threading.Event()
        abort = threading.Event()
        outcome: dict = {}

        def run():
            try:
                outcome["result"] = operation(abort)
            except BaseException as error:
                outcome["error"] = error
            finally:
                finished.set()

        thread = threading.Thread(target=run, daemon=True)
        thread.start()
        deadline = time.monotonic() + min(timeout, self.registration.max_seconds) + 1.0
        while not finished.wait(0.1):
            if monitor.cancelled:
                abort.set()
                raise RemoteExpired("Remote request cancelled or instance expired")
            if time.monotonic() >= deadline:
                abort.set()
                raise PrestigeError("Remote request timed out")
        if "error" in outcome:
            error = outcome["error"]
            if monitor.cancelled and isinstance(error, OSError):
                raise RemoteExpired(
                    "Remote request cancelled or instance expired"
                ) from error
            raise error
        return outcome["result"]

    @staticmethod
    def _send_bounded(sock, data, monitor, deadline: float):
        view = memoryview(data)
        while view:
            if monitor.cancelled:
                raise RemoteExpired("Remote request cancelled or instance expired")
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise PrestigeError("TCP send timed out")
            sock.settimeout(min(0.2, remaining))
            try:
                sent = sock.send(view)
            except socket.timeout:
                continue
            if sent == 0:
                raise PrestigeError("TCP connection closed during send")
            view = view[sent:]

    # ---- HTTP -----------------------------------------------------------
    def _path_allowed(self, path: str) -> bool:
        if not isinstance(path, str) or not path.startswith("/") or len(path) > 2048:
            return False
        if any(segment in {".", ".."} for segment in path.split("/")):
            return False
        if "//" in path or "\\" in path or "%" in path or "#" in path or "?" in path:
            return False
        if self._excluded_path(path):
            return False
        return any(
            path == prefix or path.startswith(prefix.rstrip("/") + "/")
            for prefix in self.registration.paths
        )

    def _headers(self, headers: dict | None) -> dict:
        result = {"Host": self.registration.host}
        for key, value in (headers or {}).items():
            if not isinstance(key, str) or not isinstance(value, str):
                raise RemoteDenied("Header names and values must be strings")
            if len(key) > 128 or len(value) > 4096:
                raise RemoteDenied("Header exceeds the bound")
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
        run_id: str | None = None,
    ) -> dict:
        self._check(run_id)
        if self.registration.protocol not in {"http", "https"}:
            raise RemoteDenied("Registration is not an HTTP service")
        method = method.upper()
        if method not in self.registration.methods:
            raise RemoteDenied("HTTP method is not authorized for this registration")
        canonical_path, query = canonical_request_target(path)
        if not self._path_allowed(canonical_path):
            raise RemoteDenied("Path is outside the registered scope or explicitly excluded")
        request_target = canonical_path + (f"?{query}" if query else "")
        if len(body) > _MAX_BODY:
            raise RemoteDenied("Request body exceeds the bound")
        request_headers = self._headers(headers)
        token = reserve(self.home, self.registration, run_id, self.registration.max_seconds)
        sock = None
        monitor = None
        state = {"sock": None, "closed": False}
        state_lock = threading.Lock()
        try:
            sock = self._connect(timeout)
            state["sock"] = sock
            monitor = _CancellationMonitor(self.home, self.registration, sock)
            monitor.start()

            def exchange(abort: threading.Event) -> dict:
                active = sock
                if self.registration.protocol == "https":
                    context = ssl.create_default_context()
                    context.check_hostname = True
                    context.verify_mode = ssl.CERT_REQUIRED
                    context.minimum_version = ssl.TLSVersion.TLSv1_2
                    active = context.wrap_socket(
                        sock, server_hostname=self.registration.host
                    )
                    with state_lock:
                        if state["closed"] or abort.is_set():
                            active.close()
                            raise RemoteExpired(
                                "Remote request cancelled during TLS handshake"
                            )
                        state["sock"] = active
                        self._register(active)
                    monitor.update_socket(active)
                if monitor.cancelled:
                    raise RemoteExpired("Remote request cancelled during TLS handshake")
                connection = http.client.HTTPConnection(
                    self.registration.host, self.registration.port, timeout=timeout
                )
                connection.sock = active
                connection.request(
                    method, request_target, body=body or None, headers=request_headers
                )
                response = connection.getresponse()
                data = response.read(
                    min(self.registration.max_response_bytes, _MAX_RESPONSE)
                )
                location = response.getheader("Location")
                return {
                    "status": response.status,
                    "reason": response.reason,
                    "headers": {
                        key: value
                        for key, value in response.getheaders()
                        if key.lower()
                        in {
                            "content-type",
                            "content-length",
                            "location",
                            "set-cookie",
                            "server",
                        }
                    },
                    "bytes": len(data),
                    "body": data,
                    "followed_redirect": False,
                    "redirect_blocked": bool(
                        location and not self._path_allowed(_location_path(location))
                    ),
                }

            return self._supervise(exchange, monitor, timeout)
        except (OSError, http.client.HTTPException) as error:
            if monitor is not None and monitor.cancelled:
                raise RemoteExpired("Remote request cancelled or instance expired") from error
            raise PrestigeError(f"HTTP request failed: {error}") from error
        finally:
            if monitor is not None:
                monitor.stop()
            with state_lock:
                state["closed"] = True
                active = state["sock"]
            if sock is not None and active is not sock:
                self._release(sock)
            if active is not None:
                self._release(active)
            release(self.home, token)

    # ---- TCP ------------------------------------------------------------
    def tcp(
        self,
        data: bytes,
        read_bytes: int = 4096,
        timeout: float = 10.0,
        run_id: str | None = None,
    ) -> dict:
        self._check(run_id)
        if self.registration.protocol not in {"tcp", "ssh"}:
            raise RemoteDenied("Registration is not a stream service")
        if len(data) > _MAX_BODY:
            raise RemoteDenied("Request data exceeds the bound")
        if type(read_bytes) is not int or not 1 <= read_bytes <= self.registration.max_response_bytes:
            raise RemoteDenied("Invalid read bound")
        token = reserve(self.home, self.registration, run_id, self.registration.max_seconds)
        sock = None
        monitor = None
        received = bytearray()
        try:
            sock = self._connect(timeout)
            monitor = _CancellationMonitor(self.home, self.registration, sock)
            monitor.start()
            deadline = time.monotonic() + min(timeout, self.registration.max_seconds)
            self._send_bounded(sock, data, monitor, deadline)
            while len(received) < read_bytes:
                if monitor.cancelled:
                    raise RemoteExpired("Remote request cancelled or instance expired")
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    break
                sock.settimeout(min(0.2, remaining))
                try:
                    chunk = sock.recv(min(4096, read_bytes - len(received)))
                except socket.timeout:
                    continue
                if not chunk:
                    break
                received.extend(chunk)
            if monitor.cancelled:
                raise RemoteExpired("Remote request cancelled or instance expired")
            return {"bytes": len(received), "data": bytes(received)}
        except OSError as error:
            if monitor is not None and monitor.cancelled:
                raise RemoteExpired("Remote request cancelled or instance expired") from error
            raise PrestigeError(f"TCP exchange failed: {error}") from error
        finally:
            if monitor is not None:
                monitor.stop()
            if sock is not None:
                self._release(sock)
            release(self.home, token)

    # ---- SSH ------------------------------------------------------------
    def ssh(self, command: str, timeout: float = 20.0, run_id: str | None = None) -> dict:
        self._check(run_id)
        if self.registration.protocol != "ssh":
            raise RemoteDenied("Registration is not an SSH service")
        if not isinstance(command, str) or not command.strip() or len(command) > 4096:
            raise RemoteDenied("SSH command is empty or too large")
        token = reserve(self.home, self.registration, run_id, self.registration.max_seconds)
        try:
            address = self._resolve()[0]
            if self.registration.expires_at is not None and time.time() >= self.registration.expires_at:
                raise RemoteExpired("Assigned instance expired before SSH")
            if registration_cancelled(self.home, self.registration.id):
                raise RemoteExpired("Registration was cancelled before SSH")
        except BaseException:
            release(self.home, token)
            raise
        process = None
        stop = threading.Event()
        cancelled = threading.Event()

        def monitor():
            while not stop.wait(0.2):
                expired = (
                    self.registration.expires_at is not None
                    and time.time() >= self.registration.expires_at
                )
                if expired or registration_cancelled(self.home, self.registration.id):
                    cancelled.set()
                    if process is not None:
                        try:
                            process.kill()
                        except OSError:
                            pass
                    return

        thread = threading.Thread(target=monitor, daemon=True)
        thread.start()
        args = [
            "ssh",
            "-F",
            "/dev/null",
            "-T",
            "-i",
            self.registration.ssh_key_path,
            "-o",
            "StrictHostKeyChecking=yes",
            "-o",
            f"UserKnownHostsFile={self.registration.ssh_known_hosts}",
            "-o",
            "BatchMode=yes",
            "-o",
            "IdentitiesOnly=yes",
            "-o",
            "PasswordAuthentication=no",
            "-o",
            "KbdInteractiveAuthentication=no",
            "-o",
            "ForwardAgent=no",
            "-o",
            "ClearAllForwardings=yes",
            "-o",
            "UpdateHostKeys=no",
            "-o",
            f"HostKeyAlias={self.registration.host}",
            "-o",
            "ConnectTimeout=10",
            "-o",
            "ServerAliveInterval=5",
            "-o",
            "ServerAliveCountMax=1",
            "-p",
            str(self.registration.port),
            f"{self.registration.ssh_user}@{address}",
            command,
        ]
        try:
            process = subprocess.Popen(
                args,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            try:
                stdout, stderr = process.communicate(
                    timeout=min(timeout, self.registration.max_seconds)
                )
            except subprocess.TimeoutExpired:
                process.kill()
                stdout, stderr = process.communicate()
                if cancelled.is_set():
                    raise RemoteExpired("Remote request cancelled or instance expired")
                raise PrestigeError("SSH command exceeded its deadline")
            if cancelled.is_set():
                raise RemoteExpired("Remote request cancelled or instance expired")
            return {
                "returncode": process.returncode,
                "stdout": stdout[:32768].decode("utf-8", errors="replace"),
                "stderr": stderr[:8192].decode("utf-8", errors="replace"),
                "cancelled": False,
            }
        except OSError as error:
            raise PrestigeError(f"SSH command failed: {error}") from error
        finally:
            stop.set()
            thread.join(timeout=1)
            release(self.home, token)

    # ---- lifecycle ------------------------------------------------------
    def status(self) -> dict:
        state = remote_state(self.home, self.registration.id)
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
            "requests_used": state["requests"],
            "max_requests": self.registration.max_requests,
            "cancelled": bool(state["cancelled"]),
        }

    def cancel(self) -> int:
        cancel_registration(self.home, self.registration.id)
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


def _pid_alive(pid: int) -> bool:
    if os.name == "nt":
        # Avoid os.kill(pid, 0) on Windows: it can terminate the process.
        return True
    if pid <= 0:
        return False
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    except OSError:
        return False
    return True


def _ensure_state(db, registration_id: str):
    db.execute(
        "INSERT OR IGNORE INTO remote_state(registration_id,requests,last_request,cancelled) "
        "VALUES(?,0,0,0)",
        (registration_id,),
    )


def _cleanup_active(db, now: float, max_seconds: float):
    for row in db.execute("SELECT token,pid,started FROM remote_active").fetchall():
        if now - float(row["started"]) > max_seconds * 2 + 30 or not _pid_alive(
            int(row["pid"])
        ):
            db.execute("DELETE FROM remote_active WHERE token=?", (row["token"],))


def remote_state(home: Path, registration_id: str) -> dict:
    store = Store(home)
    try:
        with store.transaction() as db:
            _ensure_state(db, registration_id)
        rows = store.rows(
            "SELECT requests,last_request,cancelled FROM remote_state WHERE registration_id=?",
            (registration_id,),
        )
        return rows[0] if rows else {"requests": 0, "last_request": 0.0, "cancelled": 0}
    finally:
        store.close()


def registration_cancelled(home: Path, registration_id: str) -> bool:
    return bool(remote_state(home, registration_id)["cancelled"])


def reserve(
    home: Path,
    registration: Registration,
    run_id: str | None,
    max_seconds: float,
) -> str:
    """Atomically reserve request, rate and concurrency capacity in SQLite."""
    store = Store(home)
    token = uuid.uuid4().hex
    try:
        with store.transaction() as db:
            _ensure_state(db, registration.id)
            state = db.execute(
                "SELECT requests,last_request,cancelled FROM remote_state WHERE registration_id=?",
                (registration.id,),
            ).fetchone()
            if state["cancelled"]:
                raise RemoteExpired("Remote work was cancelled or revoked")
            if int(state["requests"]) >= registration.max_requests:
                raise RemoteDenied("Request budget exhausted for this registration")
            now = time.time()
            _cleanup_active(db, now, max_seconds)
            active = db.execute(
                "SELECT COUNT(*) FROM remote_active WHERE registration_id=?",
                (registration.id,),
            ).fetchone()[0]
            if int(active) >= registration.max_concurrency:
                raise RemoteDenied("Concurrent request limit reached for this registration")
            interval = 1.0 / registration.rate_per_second
            slot = max(now, float(state["last_request"]) + interval)
            db.execute(
                "UPDATE remote_state SET requests=requests+1,last_request=? "
                "WHERE registration_id=?",
                (slot, registration.id),
            )
            db.execute(
                "INSERT INTO remote_active(token,registration_id,run_id,pid,started) "
                "VALUES(?,?,?,?,?)",
                (token, registration.id, run_id or "", os.getpid(), now),
            )
        wait = slot - time.time()
        if wait > 0:
            time.sleep(wait)
        if registration.expires_at is not None and time.time() >= registration.expires_at:
            raise RemoteExpired("Assigned instance expired while waiting for capacity")
        if registration_cancelled(home, registration.id):
            raise RemoteExpired("Registration was cancelled while waiting for capacity")
        return token
    except BaseException:
        try:
            release(home, token)
        except Exception:
            pass
        raise
    finally:
        store.close()


def release(home: Path, token: str | None):
    if not token:
        return
    store = Store(home)
    try:
        with store.transaction() as db:
            db.execute("DELETE FROM remote_active WHERE token=?", (token,))
    finally:
        store.close()


def cancel_registration(home: Path, registration_id: str) -> None:
    store = Store(home)
    try:
        with store.transaction() as db:
            _ensure_state(db, registration_id)
            db.execute(
                "UPDATE remote_state SET cancelled=1 WHERE registration_id=?",
                (registration_id,),
            )
            db.execute(
                "DELETE FROM remote_active WHERE registration_id=?", (registration_id,)
            )
    finally:
        store.close()


def bind_target(home: Path, run_id: str, registration_id: str) -> dict:
    store = Store(home)
    try:
        store.run(run_id)
        with store.transaction() as db:
            db.execute(
                "INSERT OR REPLACE INTO remote_bindings(run_id,registration_id,created) "
                "VALUES(?,?,?)",
                (run_id, registration_id, time.time()),
            )
        return {"run_id": run_id, "registration_id": registration_id, "bound": True}
    finally:
        store.close()


def unbind_target(home: Path, run_id: str, registration_id: str) -> dict:
    store = Store(home)
    try:
        with store.transaction() as db:
            count = db.execute(
                "DELETE FROM remote_bindings WHERE run_id=? AND registration_id=?",
                (run_id, registration_id),
            ).rowcount
        return {"run_id": run_id, "registration_id": registration_id, "removed": count > 0}
    finally:
        store.close()


def is_bound(home: Path, run_id: str, registration_id: str) -> bool:
    store = Store(home)
    try:
        rows = store.rows(
            "SELECT 1 FROM remote_bindings WHERE run_id=? AND registration_id=?",
            (run_id, registration_id),
        )
        return bool(rows)
    finally:
        store.close()


def list_bindings(home: Path, run_id: str) -> list[dict]:
    store = Store(home)
    try:
        return store.rows(
            "SELECT registration_id,created FROM remote_bindings WHERE run_id=? "
            "ORDER BY registration_id",
            (run_id,),
        )
    finally:
        store.close()


_BROKERS: dict[str, RemoteBroker] = {}
_BROKERS_LOCK = threading.Lock()


def broker_for(home: Path, registration: Registration) -> RemoteBroker:
    """Shared broker per registration for local socket cancellation."""
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
