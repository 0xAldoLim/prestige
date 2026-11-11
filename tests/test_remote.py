"""Authorized remote-instance scope and broker tests using loopback fixtures only."""

import asyncio
import http.server
import json
import os
import socketserver
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
        if self.path == "/challenge":
            self._send(200, b"SYNTHETIC{remote_web}")
        elif self.path == "/redirect":
            self.send_response(302)
            self.send_header("Location", "http://evil.example/secret")
            self.end_headers()
        elif self.path == "/same":
            self.send_response(302)
            self.send_header("Location", "/challenge")
            self.end_headers()
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
                    {"registration_id": "web1"},
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
