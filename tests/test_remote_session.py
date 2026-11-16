"""Persistent operator-scoped TCP sessions, including binary and stateful flows."""

import os
import socketserver
import struct
import threading
import time

import pytest

from prestige.remote import (
    Registration,
    RemoteBroker,
    RemoteDenied,
    RemoteExpired,
)


class _Interactive(socketserver.BaseRequestHandler):
    def handle(self):
        sock = self.request
        sock.sendall(b"HELLO\n")
        magic = self._recv_exact(sock, 4)
        if magic != b"\x00\x01\x02\x03":
            return
        leak = 0x1234
        sock.sendall(f"LEAK:{leak}\n".encode())
        second = self._recv_exact(sock, 8)
        expected = struct.pack("<Q", leak ^ 0xA5A5)
        if second != expected:
            sock.sendall(b"BAD\n")
            return
        sock.sendall(b"FLAG:SYNTHETIC{interactive_session}\n")
        sock.close()

    @staticmethod
    def _recv_exact(sock, count):
        data = b""
        while len(data) < count:
            chunk = sock.recv(count - len(data))
            if not chunk:
                return b""
            data += chunk
        return data


class _CloseImmediately(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.sendall(b"banner\n")
        self.request.close()


class _Slow(socketserver.BaseRequestHandler):
    def handle(self):
        time.sleep(0.4)
        self.request.sendall(b"slow\n")
        time.sleep(0.5)


@pytest.fixture
def tcp_server_factory():
    servers = []

    def start(handler):
        server = socketserver.ThreadingTCPServer(("127.0.0.1", 0), handler)
        server.daemon_threads = True
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        servers.append(server)
        return server.server_address[1]

    yield start
    for server in servers:
        server.shutdown()
        server.server_close()


def _registration(port, **overrides):
    values = {
        "id": "interactive1",
        "provenance": "pytest loopback interactive assignment",
        "protocol": "tcp",
        "host": "127.0.0.1",
        "port": port,
        "paths": ["/"],
        "pinned_ips": ["127.0.0.1"],
        "dedicated_private": True,
        "allowed_actions": ["tcp"],
        "enabled": True,
        "max_requests": 10,
        "max_concurrency": 2,
        "max_seconds": 10,
    }
    values.update(overrides)
    return Registration.from_dict(values)


def test_persistent_binary_interaction(tmp_path, tcp_server_factory, monkeypatch):
    monkeypatch.setenv("PRESTIGE_REMOTE_ENABLED", "1")
    port = tcp_server_factory(_Interactive)
    broker = RemoteBroker(tmp_path, _registration(port))
    session = broker.open_session(5)
    sid = session["session_id"]
    try:
        banner = broker_session_read(broker, sid, delimiter=b"\n")
        assert banner["data"] == b"HELLO\n"
        broker_session_send(broker, sid, b"\x00\x01\x02\x03")
        leak = broker_session_read(broker, sid, delimiter=b"\n")
        assert leak["data"].startswith(b"LEAK:")
        value = int(leak["data"].decode().strip().split(":", 1)[1])
        broker_session_send(broker, sid, struct.pack("<Q", value ^ 0xA5A5))
        final = broker_session_read(broker, sid, delimiter=b"\n")
        assert b"SYNTHETIC{interactive_session}" in final["data"]
        from prestige.remote import _tcp_session

        assert _tcp_session(sid).summary()["alive"] is True
    finally:
        from prestige.remote import _tcp_session

        _tcp_session(sid).close()


def broker_session_read(broker, sid, **kwargs):
    from prestige.remote import read_tcp_session

    return read_tcp_session(sid, **kwargs)


def broker_session_send(broker, sid, data):
    from prestige.remote import send_tcp_session

    return send_tcp_session(sid, data)


def test_eof_is_reported(tmp_path, tcp_server_factory, monkeypatch):
    monkeypatch.setenv("PRESTIGE_REMOTE_ENABLED", "1")
    port = tcp_server_factory(_CloseImmediately)
    session = RemoteBroker(tmp_path, _registration(port)).open_session(5)
    result = broker_session_read(None, session["session_id"], timeout=2)
    assert result["eof"] is True
    assert result["data"] == b"banner\n"
    from prestige.remote import _tcp_session

    _tcp_session(session["session_id"]).close()


def test_timeout_preserves_stream_for_later_read(tmp_path, tcp_server_factory, monkeypatch):
    monkeypatch.setenv("PRESTIGE_REMOTE_ENABLED", "1")
    port = tcp_server_factory(_Slow)
    session = RemoteBroker(tmp_path, _registration(port)).open_session(5)
    sid = session["session_id"]
    first = broker_session_read(None, sid, timeout=0.1)
    assert first["data"] == b""
    time.sleep(0.4)
    second = broker_session_read(None, sid, timeout=1)
    assert second["data"] == b"slow\n"
    from prestige.remote import _tcp_session

    _tcp_session(sid).close()


def test_expiry_cancels_session(tmp_path, tcp_server_factory, monkeypatch):
    monkeypatch.setenv("PRESTIGE_REMOTE_ENABLED", "1")
    port = tcp_server_factory(_Slow)
    broker = RemoteBroker(tmp_path, _registration(port, expires_at=time.time() + 0.5))
    session = broker.open_session(5)
    sid = session["session_id"]
    time.sleep(0.7)
    with pytest.raises(RemoteExpired):
        broker_session_read(None, sid, timeout=1)
    from prestige.remote import _tcp_session

    _tcp_session(sid).close()


def test_invalid_protocol_and_unbound_run_are_denied(tmp_path, tcp_server_factory, monkeypatch):
    monkeypatch.setenv("PRESTIGE_REMOTE_ENABLED", "1")
    port = tcp_server_factory(_Interactive)
    with pytest.raises(RemoteDenied):
        RemoteBroker(tmp_path, _registration(port, protocol="http")).open_session()
    broker = RemoteBroker(tmp_path, _registration(port))
    with pytest.raises(RemoteDenied):
        broker.open_session(run_id="unbound-run")


@pytest.mark.asyncio
async def test_mcp_session_end_to_end(tmp_path, tcp_server_factory, monkeypatch):
    import asyncio
    import base64
    import json
    from contextlib import asynccontextmanager

    import anyio
    from mcp.client.session import ClientSession
    from mcp.shared.message import SessionMessage

    from prestige.engine import new_run
    from prestige.mcp_server import serve_streams
    from prestige.remote import bind_target, save_registrations
    from prestige.store import Store

    monkeypatch.setenv("PRESTIGE_REMOTE_ENABLED", "1")
    port = tcp_server_factory(_Interactive)
    home = tmp_path / "state"
    registration = _registration(port)
    save_registrations(home, {registration.id: registration})
    challenge = tmp_path / "challenge.txt"
    challenge.write_bytes(b"offline")
    store = Store(home)
    try:
        run_id = new_run(store, challenge)
    finally:
        store.close()
    bind_target(home, run_id, registration.id)

    @asynccontextmanager
    async def client():
        old = os.environ.copy()
        os.environ.update(
            {"PRESTIGE_HOME": str(home), "PRESTIGE_ALLOWED_DIRS": str(tmp_path),
             "PRESTIGE_REMOTE_ENABLED": "1"}
        )
        c2s_s, c2s_r = anyio.create_memory_object_stream[SessionMessage | Exception](0)
        s2c_s, s2c_r = anyio.create_memory_object_stream[SessionMessage](0)
        task = asyncio.create_task(serve_streams(c2s_r, s2c_s))
        try:
            async with ClientSession(s2c_r, c2s_s) as session:
                await session.initialize()
                yield session
        finally:
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass
            os.environ.clear()
            os.environ.update(old)

    async def call(session, name, args):
        return json.loads((await session.call_tool(name, args)).content[0].text)

    async with client() as session:
        opened = await call(
            session,
            "prestige_remote_session_open",
            {"run_id": run_id, "registration_id": registration.id, "timeout": 5},
        )
        sid = opened["result"]["session_id"]
        banner = await call(
            session,
            "prestige_remote_session_read",
            {"run_id": run_id, "session_id": sid, "delimiter_base64": "Cg==", "timeout": 2},
        )
        assert base64.b64decode(banner["result"]["data_base64"]) == b"HELLO\n"
        await call(
            session,
            "prestige_remote_session_send",
            {"run_id": run_id, "session_id": sid, "data_base64": "AAECAw=="},
        )
        leak = await call(
            session,
            "prestige_remote_session_read",
            {"run_id": run_id, "session_id": sid, "delimiter_base64": "Cg==", "timeout": 2},
        )
        value = int(base64.b64decode(leak["result"]["data_base64"]).decode().strip().split(":", 1)[1])
        await call(
            session,
            "prestige_remote_session_send",
            {
                "run_id": run_id,
                "session_id": sid,
                "data_base64": base64.b64encode(struct.pack("<Q", value ^ 0xA5A5)).decode(),
            },
        )
        final = await call(
            session,
            "prestige_remote_session_read",
            {"run_id": run_id, "session_id": sid, "delimiter_base64": "Cg==", "timeout": 2},
        )
        assert b"SYNTHETIC{interactive_session}" in base64.b64decode(final["result"]["data_base64"])
        closed = await call(
            session,
            "prestige_remote_session_close",
            {"run_id": run_id, "session_id": sid},
        )
        assert closed["status"] == "ok"
