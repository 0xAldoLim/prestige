"""Authorized remote-instance scope and broker tests using loopback fixtures only."""

import asyncio
import http.server
import json
import os
import shutil
import socketserver
import ssl
import subprocess
import threading
import time
from contextlib import asynccontextmanager
from pathlib import Path

import anyio
import pytest
from mcp.client.session import ClientSession
from mcp.shared.message import SessionMessage

from prestige.engine import new_run
from prestige.mcp_server import serve_streams
from prestige.remote import (
    Registration,
    RemoteBroker,
    RemoteDenied,
    RemoteExpired,
    load_registrations,
    reset_brokers,
    save_registrations,
)
from prestige.store import Store


class _HTTPHandler(http.server.BaseHTTPRequestHandler):
    hits = 0

    def do_GET(self):
        type(self).hits += 1
        if self.path.startswith("/challenge") or self.path.startswith("/check"):
            self._send(200, b"SYNTHETIC{remote_web}")
        elif self.path == "/redirect":
            self.send_response(302)
            self.send_header("Location", "http://evil.example/secret")
            self.end_headers()
        elif self.path == "/same":
            self.send_response(302)
            self.send_header("Location", "/challenge")
            self.end_headers()
        elif self.path == "/slow":
            time.sleep(4)
            self._send(200, b"slow")
        else:
            self._send(404, b"not found")

    def do_POST(self):
        type(self).hits += 1
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length)
        self._send(200, b"POST:" + body)

    def do_DELETE(self):
        type(self).hits += 1
        self._send(200, b"deleted")

    def _send(self, status, body):
        self.send_response(status)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


class _TCPHandler(socketserver.BaseRequestHandler):
    def handle(self):
        data = self.request.recv(1024)
        self.request.sendall(b"ECHO:" + data)


@pytest.fixture
def http_server():
    _HTTPHandler.hits = 0
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _HTTPHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server.server_address[1]
    finally:
        server.shutdown()
        server.server_close()


@pytest.fixture
def tcp_server():
    server = socketserver.ThreadingTCPServer(("127.0.0.1", 0), _TCPHandler)
    server.daemon_threads = True
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server.server_address[1]
    finally:
        server.shutdown()
        server.server_close()


def _http_registration(port, **overrides):
    data = {
        "id": "web1",
        "provenance": "pytest loopback assignment",
        "protocol": "http",
        "host": "127.0.0.1",
        "port": port,
        "paths": ["/challenge", "/redirect", "/same"],
        "methods": ["GET", "POST"],
        "pinned_ips": ["127.0.0.1"],
        "dedicated_private": True,
        "allowed_actions": ["http"],
        "max_requests": 20,
        "max_concurrency": 2,
        "max_seconds": 10,
        "rate_per_second": 100,
        "enabled": True,
    }
    data.update(overrides)
    return Registration.from_dict(data)


def _tcp_registration(port, **overrides):
    data = {
        "id": "tcp1",
        "provenance": "pytest loopback assignment",
        "protocol": "tcp",
        "host": "127.0.0.1",
        "port": port,
        "paths": ["/"],
        "pinned_ips": ["127.0.0.1"],
        "dedicated_private": True,
        "allowed_actions": ["tcp"],
        "max_requests": 20,
        "max_concurrency": 2,
        "max_seconds": 10,
        "rate_per_second": 100,
        "enabled": True,
    }
    data.update(overrides)
    return Registration.from_dict(data)


@pytest.fixture(autouse=True)
def _remote_env(monkeypatch):
    monkeypatch.setenv("PRESTIGE_REMOTE_ENABLED", "1")
    reset_brokers()
    yield
    reset_brokers()


def test_http_allowed_request(tmp_path, http_server):
    broker = RemoteBroker(tmp_path, _http_registration(http_server))
    result = broker.http("GET", "/challenge")
    assert result["status"] == 200
    assert b"SYNTHETIC{remote_web}" in result["body"]
    assert result["followed_redirect"] is False


def test_http_off_scope_path_and_method_denied(tmp_path, http_server):
    broker = RemoteBroker(tmp_path, _http_registration(http_server))
    with pytest.raises(RemoteDenied):
        broker.http("GET", "/admin")
    with pytest.raises(RemoteDenied):
        broker.http("DELETE", "/challenge")
    with pytest.raises(RemoteDenied):
        broker.http("GET", "/challenge/../admin")


def test_redirect_is_not_followed_or_flagged(tmp_path, http_server):
    broker = RemoteBroker(tmp_path, _http_registration(http_server))
    result = broker.http("GET", "/redirect")
    assert result["status"] == 302
    assert result["followed_redirect"] is False
    assert result["redirect_blocked"] is True
    assert b"secret" not in result["body"]
    same = broker.http("GET", "/same")
    assert same["status"] == 302
    assert same["redirect_blocked"] is False


def test_expired_registration_denied_before_connect(tmp_path, http_server):
    broker = RemoteBroker(
        tmp_path, _http_registration(http_server, expires_at=time.time() - 1)
    )
    before = _HTTPHandler.hits
    with pytest.raises(RemoteExpired):
        broker.http("GET", "/challenge")
    assert _HTTPHandler.hits == before


def test_pinned_ip_and_metadata_destinations_denied(tmp_path, http_server):
    broker = RemoteBroker(
        tmp_path, _http_registration(http_server, pinned_ips=["10.0.0.1"])
    )
    with pytest.raises(RemoteDenied):
        broker.http("GET", "/challenge")
    metadata = _http_registration(
        http_server, host="169.254.169.254", pinned_ips=["169.254.169.254"]
    )
    with pytest.raises(RemoteDenied):
        RemoteBroker(tmp_path, metadata).http("GET", "/challenge")


def test_request_budget_and_cancel(tmp_path, http_server):
    broker = RemoteBroker(tmp_path, _http_registration(http_server, max_requests=1))
    assert broker.http("GET", "/challenge")["status"] == 200
    with pytest.raises(RemoteDenied):
        broker.http("GET", "/challenge")
    broker.cancel()
    with pytest.raises(RemoteExpired):
        broker.http("GET", "/challenge")


def test_tcp_allowed_and_protocol_mismatch(tmp_path, tcp_server):
    broker = RemoteBroker(tmp_path, _tcp_registration(tcp_server))
    result = broker.tcp(b"hello")
    assert result["data"] == b"ECHO:hello"
    with pytest.raises(RemoteDenied):
        broker.http("GET", "/challenge")


def test_remote_disabled_gate(tmp_path, http_server, monkeypatch):
    monkeypatch.delenv("PRESTIGE_REMOTE_ENABLED", raising=False)
    broker = RemoteBroker(tmp_path, _http_registration(http_server))
    with pytest.raises(RemoteDenied):
        broker.http("GET", "/challenge")


@asynccontextmanager
async def _mcp_client(home: Path):
    old = os.environ.copy()
    os.environ.update(
        {
            "PRESTIGE_HOME": str(home),
            "PRESTIGE_ALLOWED_DIRS": str(home.parent),
            "PRESTIGE_REMOTE_ENABLED": "1",
        }
    )
    client_to_server_send, client_to_server_recv = anyio.create_memory_object_stream[
        SessionMessage | Exception
    ](0)
    server_to_client_send, server_to_client_recv = anyio.create_memory_object_stream[
        SessionMessage
    ](0)
    server_task = asyncio.create_task(
        serve_streams(client_to_server_recv, server_to_client_send)
    )
    try:
        async with ClientSession(server_to_client_recv, client_to_server_send) as session:
            await session.initialize()
            yield session
    finally:
        server_task.cancel()
        try:
            await server_task
        except asyncio.CancelledError:
            pass
        os.environ.clear()
        os.environ.update(old)


async def test_mcp_remote_http_records_evidence_and_blocks_off_scope(tmp_path, http_server):
    home = tmp_path / "state"
    save_registrations(home, {"web1": _http_registration(http_server)})
    challenge = tmp_path / "offline.txt"
    challenge.write_bytes(b"offline analysis")
    store = Store(home)
    try:
        run_id = new_run(store, challenge)
    finally:
        store.close()
    from prestige.remote import bind_target

    bind_target(home, run_id, "web1")

    async with _mcp_client(home) as session:
        listed = json.loads(
            (await session.call_tool("prestige_target_list", {})).content[0].text
        )
        assert listed["result"]["registrations"][0]["id"] == "web1"

        allowed = json.loads(
            (
                await session.call_tool(
                    "prestige_remote_http",
                    {
                        "run_id": run_id,
                        "registration_id": "web1",
                        "method": "GET",
                        "path": "/challenge",
                    },
                )
            ).content[0].text
        )
        assert allowed["status"] == "ok"
        assert allowed["result"]["http_status"] == 200
        assert allowed["result"]["encoding"] == "text"
        from prestige.artifacts import Artifacts

        reader = Store(home)
        try:
            assert b"SYNTHETIC{remote_web}" in Artifacts(reader, run_id).read(
                allowed["result"]["artifact"]
            )
        finally:
            reader.close()

        denied = json.loads(
            (
                await session.call_tool(
                    "prestige_remote_http",
                    {
                        "run_id": run_id,
                        "registration_id": "web1",
                        "method": "GET",
                        "path": "/admin",
                    },
                )
            ).content[0].text
        )
        assert denied["status"] == "error"

        cancelled = json.loads(
            (
                await session.call_tool(
                    "prestige_remote_cancel",
                    {"run_id": run_id, "registration_id": "web1"},
                )
            ).content[0].text
        )
        assert cancelled["status"] == "ok"

        after = json.loads(
            (
                await session.call_tool(
                    "prestige_remote_http",
                    {
                        "run_id": run_id,
                        "registration_id": "web1",
                        "method": "GET",
                        "path": "/challenge",
                    },
                )
            ).content[0].text
        )
        assert after["status"] == "error"

    store = Store(home)
    try:
        kinds = [event["kind"] for event in store.events(run_id)]
        assert "remote_request" in kinds
    finally:
        store.close()


async def test_mcp_has_no_target_registration_tool(tmp_path):
    home = tmp_path / "state"
    async with _mcp_client(home) as session:
        tools = await session.list_tools()
        names = {tool.name for tool in tools.tools}
        assert "prestige_target_list" in names
        assert "prestige_target_register" not in names
        assert "prestige_target_enable" not in names


def test_registration_file_validation(tmp_path):
    home = tmp_path / "state"
    home.mkdir()
    (home / "registrations.json").write_text("{bad json")
    with pytest.raises(Exception):
        load_registrations(home)
    with pytest.raises(RemoteDenied):
        Registration.from_dict({"id": "x"})
    with pytest.raises(RemoteDenied):
        Registration.from_dict(
            {
                "id": "x",
                "provenance": "p",
                "protocol": "gopher",
                "host": "example.test",
                "port": 1,
            }
        )


def test_cli_target_registration_roundtrip(tmp_path, capsys):
    from prestige.cli import main

    home = tmp_path / "state"
    spec = {
        "id": "web-cli",
        "provenance": "operator assignment",
        "protocol": "http",
        "host": "127.0.0.1",
        "port": 8080,
        "paths": ["/challenge"],
        "methods": ["GET"],
        "pinned_ips": ["127.0.0.1"],
        "dedicated_private": True,
        "enabled": True,
    }
    path = tmp_path / "registration.json"
    path.write_text(json.dumps(spec))

    assert main(["--home", str(home), "target", "register", str(path)]) == 0
    assert json.loads(capsys.readouterr().out)["registered"] == ["web-cli"]
    assert main(["--home", str(home), "target", "list"]) == 0
    listing = json.loads(capsys.readouterr().out)
    assert listing["registrations"][0]["id"] == "web-cli"

    assert main(["--home", str(home), "target", "disable", "web-cli"]) == 0
    assert json.loads(capsys.readouterr().out)["enabled"] is False
    assert main(["--home", str(home), "target", "enable", "web-cli"]) == 0
    assert json.loads(capsys.readouterr().out)["enabled"] is True
    assert main(["--home", str(home), "target", "revoke", "web-cli"]) == 0
    assert json.loads(capsys.readouterr().out)["revoked"] is True
    assert main(["--home", str(home), "target", "list"]) == 0
    assert json.loads(capsys.readouterr().out)["registrations"] == []


def test_proxy_environment_is_ignored(tmp_path, http_server, monkeypatch):
    broker = RemoteBroker(tmp_path, _http_registration(http_server))
    monkeypatch.setenv("HTTP_PROXY", "http://127.0.0.1:1")
    monkeypatch.setenv("HTTPS_PROXY", "http://127.0.0.1:1")
    result = broker.http("GET", "/challenge")
    assert result["status"] == 200
    assert b"SYNTHETIC{remote_web}" in result["body"]


@pytest.mark.skipif(__import__("shutil").which("openssl") is None, reason="openssl unavailable")
def test_https_rejects_untrusted_certificate(tmp_path, monkeypatch):
    cert = tmp_path / "cert.pem"
    key = tmp_path / "key.pem"
    subprocess.run(
        [
            "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
            "-keyout", str(key), "-out", str(cert), "-days", "1",
            "-subj", "/CN=localhost",
        ],
        capture_output=True,
        check=True,
    )
    httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _HTTPHandler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert, key)
    httpd.socket = context.wrap_socket(httpd.socket, server_side=True)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    try:
        registration = _http_registration(
            httpd.server_address[1], protocol="https", paths=["/challenge"]
        )
        broker = RemoteBroker(tmp_path, registration)
        with pytest.raises(Exception) as error:
            broker.http("GET", "/challenge")
        message = str(error.value).lower()
        assert "certificate" in message or "hostname" in message or "ssl" in message
    finally:
        httpd.shutdown()
        httpd.server_close()


def test_query_strings_do_not_bypass_path_exclusions(tmp_path, http_server):
    registration = _http_registration(
        http_server, paths=["/"], exclusions=["/admin"]
    )
    broker = RemoteBroker(tmp_path, registration)
    for allowed in (
        "/challenge?x=1",
        "/check?code=5a",
        "/check?code=%35a",
    ):
        assert broker.http("GET", allowed)["status"] == 200
    for denied in (
        "/admin?view=1",
        "/admin/?debug=true",
        "/admin/settings?x=1",
        "/challenge/%2e%2e/admin",
        "/challenge/%252e%252e/admin",
        "/challenge%2fadmin",
        "http://127.0.0.1/challenge",
        "//evil.example/challenge",
        "/challenge//x",
        "/challenge#frag",
        "/challenge\x00",
        "/／check",
        "/check?code=%zz",
    ):
        with pytest.raises(RemoteDenied):
            broker.http("GET", denied)


def test_canonical_request_target_rejects_ambiguous_forms():
    from prestige.remote import canonical_request_target

    assert canonical_request_target("/check?code=5a") == ("/check", "code=5a")
    assert canonical_request_target("/check") == ("/check", "")
    for bad in (
        "",
        "check",
        "http://host/check",
        "//host/check",
        "/a/../b",
        "/a/./b",
        "/a//b",
        "/a%2fb",
        "/a#frag",
        "/a\\b",
        "/a?x=%zz",
        "/a?" + chr(0),
        "/a?／",
    ):
        with pytest.raises(RemoteDenied):
            canonical_request_target(bad)


def test_expiry_during_rate_wait_prevents_connection(tmp_path, http_server):
    registration = _http_registration(
        http_server,
        paths=["/challenge"],
        rate_per_second=0.5,
        expires_at=time.time() + 0.4,
    )
    broker = RemoteBroker(tmp_path, registration)
    assert broker.http("GET", "/challenge")["status"] == 200
    hits = _HTTPHandler.hits
    time.sleep(0.1)
    with pytest.raises(RemoteExpired):
        broker.http("GET", "/challenge")
    assert _HTTPHandler.hits == hits
    store = Store(tmp_path)
    try:
        assert store.rows("SELECT * FROM remote_active") == []
    finally:
        store.close()


def test_expiry_cancels_in_flight_http_request(tmp_path, http_server):
    registration = _http_registration(
        http_server, paths=["/slow"], expires_at=time.time() + 1.2
    )
    broker = RemoteBroker(tmp_path, registration)
    start = time.monotonic()
    with pytest.raises(RemoteExpired):
        broker.http("GET", "/slow", timeout=8)
    assert time.monotonic() - start < 4
    store = Store(tmp_path)
    try:
        assert store.rows("SELECT * FROM remote_active") == []
    finally:
        store.close()


def test_cancellation_independent_of_socket_shutdown(tmp_path, http_server, monkeypatch):
    """A blocked recv may ignore shutdown (as on Windows); abort must still be prompt."""
    from prestige.remote import _CancellationMonitor

    monkeypatch.setattr(_CancellationMonitor, "_shutdown", lambda self: None)
    registration = _http_registration(
        http_server, paths=["/slow"], expires_at=time.time() + 1.2
    )
    broker = RemoteBroker(tmp_path, registration)
    start = time.monotonic()
    with pytest.raises(RemoteExpired):
        broker.http("GET", "/slow", timeout=8)
    assert time.monotonic() - start < 4
    store = Store(tmp_path)
    try:
        assert store.rows("SELECT * FROM remote_active") == []
    finally:
        store.close()


async def test_expired_mcp_request_asks_for_operator(tmp_path, http_server):
    home = tmp_path / "state"
    save_registrations(
        home, {"web1": _http_registration(http_server, expires_at=time.time() - 1)}
    )
    challenge = tmp_path / "challenge.txt"
    challenge.write_bytes(b"offline")
    store = Store(home)
    try:
        run_id = new_run(store, challenge)
    finally:
        store.close()
    from prestige.remote import bind_target

    bind_target(home, run_id, "web1")
    async with _mcp_client(home) as session:
        denied = json.loads(
            (
                await session.call_tool(
                    "prestige_remote_http",
                    {"run_id": run_id, "registration_id": "web1", "path": "/challenge"},
                )
            ).content[0].text
        )
        assert denied["status"] == "error"
        status = json.loads(
            (await session.call_tool("prestige_get_status", {"run_id": run_id})).content[0].text
        )
        assert status["status"] == "waiting_for_operator"
        assert status["pending_operator_request"] is not None
        assert "fresh operator registration" in status["pending_operator_request"]["question"]


def _start_https(tmp_path, monkeypatch, san="IP:127.0.0.1", trust=True):
    if not shutil.which("openssl"):
        pytest.skip("openssl unavailable")
    ca_key = tmp_path / "ca.key"
    ca_crt = tmp_path / "ca.crt"
    subprocess.run(
        [
            "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
            "-keyout", str(ca_key), "-out", str(ca_crt), "-days", "1",
            "-subj", "/CN=PRESTIGE Test CA",
            "-addext", "basicConstraints=critical,CA:TRUE",
            "-addext", "keyUsage=critical,keyCertSign,cRLSign",
        ],
        check=True,
        capture_output=True,
    )
    server_key = tmp_path / "server.key"
    server_csr = tmp_path / "server.csr"
    server_crt = tmp_path / "server.crt"
    subprocess.run(
        [
            "openssl", "req", "-newkey", "rsa:2048", "-nodes",
            "-keyout", str(server_key), "-out", str(server_csr),
            "-subj", "/CN=127.0.0.1",
        ],
        check=True,
        capture_output=True,
    )
    ext = tmp_path / "san.cnf"
    ext.write_text(
        f"subjectAltName={san}\n"
        "basicConstraints=CA:FALSE\n"
        "keyUsage=critical,digitalSignature,keyEncipherment\n"
        "extendedKeyUsage=serverAuth\n"
    )
    subprocess.run(
        [
            "openssl", "x509", "-req", "-in", str(server_csr),
            "-CA", str(ca_crt), "-CAkey", str(ca_key), "-CAcreateserial",
            "-out", str(server_crt), "-days", "1", "-extfile", str(ext),
        ],
        check=True,
        capture_output=True,
    )
    httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _HTTPHandler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(server_crt, server_key)
    httpd.socket = context.wrap_socket(httpd.socket, server_side=True)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    if trust:
        monkeypatch.setenv("SSL_CERT_FILE", str(ca_crt))
    else:
        monkeypatch.delenv("SSL_CERT_FILE", raising=False)
    return httpd.server_address[1], httpd


def test_https_valid_request_with_trusted_ca(tmp_path, monkeypatch):
    port, httpd = _start_https(tmp_path, monkeypatch)
    try:
        registration = _http_registration(port, protocol="https", paths=["/challenge"])
        result = RemoteBroker(tmp_path, registration).http("GET", "/challenge")
        assert result["status"] == 200
        assert b"SYNTHETIC" in result["body"]
    finally:
        httpd.shutdown()
        httpd.server_close()


def test_https_hostname_mismatch_rejected(tmp_path, monkeypatch):
    port, httpd = _start_https(tmp_path, monkeypatch, san="DNS:localhost")
    try:
        registration = _http_registration(port, protocol="https", paths=["/challenge"])
        with pytest.raises(Exception) as error:
            RemoteBroker(tmp_path, registration).http("GET", "/challenge")
        assert "certificate" in str(error.value).lower() or "hostname" in str(error.value).lower()
    finally:
        httpd.shutdown()
        httpd.server_close()


def test_https_untrusted_certificate_rejected(tmp_path, monkeypatch):
    port, httpd = _start_https(tmp_path, monkeypatch, trust=False)
    try:
        registration = _http_registration(port, protocol="https", paths=["/challenge"])
        with pytest.raises(Exception) as error:
            RemoteBroker(tmp_path, registration).http("GET", "/challenge")
        assert "certificate" in str(error.value).lower() or "ssl" in str(error.value).lower()
    finally:
        httpd.shutdown()
        httpd.server_close()


def test_https_in_flight_cancellation_releases_lease(tmp_path, monkeypatch):
    port, httpd = _start_https(tmp_path, monkeypatch)
    try:
        registration = _http_registration(
            port, protocol="https", paths=["/slow"], expires_at=time.time() + 1.2
        )
        broker = RemoteBroker(tmp_path, registration)
        start = time.monotonic()
        with pytest.raises(RemoteExpired):
            broker.http("GET", "/slow", timeout=8)
        assert time.monotonic() - start < 4
        store = Store(tmp_path)
        try:
            assert store.rows("SELECT * FROM remote_active") == []
        finally:
            store.close()
    finally:
        httpd.shutdown()
        httpd.server_close()
