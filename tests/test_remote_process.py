"""Multi-process MCP tests for persistent remote accounting and cancellation."""

import asyncio
import http.server
import json
import os
import sys
import threading
import time
from contextlib import asynccontextmanager
from pathlib import Path

import pytest
from mcp import StdioServerParameters
from mcp.client.session import ClientSession
from mcp.client.stdio import stdio_client

from prestige.engine import new_run
from prestige.remote import (
    Registration,
    RemoteBroker,
    RemoteDenied,
    bind_target,
    save_registrations,
)
from prestige.store import Store

REPO = Path(__file__).parent.parent


@pytest.fixture(autouse=True)
def _remote_enabled(monkeypatch):
    monkeypatch.setenv("PRESTIGE_REMOTE_ENABLED", "1")


class _Handler(http.server.BaseHTTPRequestHandler):
    hits = 0

    def do_GET(self):
        type(self).hits += 1
        if self.path == "/challenge":
            self._send(200, b"SYNTHETIC{process_remote}")
        elif self.path == "/public":
            self._send(200, b"public")
        elif self.path == "/admin":
            self._send(200, b"excluded but reachable")
        elif self.path == "/slow":
            time.sleep(4)
            self._send(200, b"slow")
        elif self.path == "/large":
            self._send(200, b"A" * 10000)
        else:
            self._send(404, b"missing")

    def _send(self, status, body):
        try:
            self.send_response(status)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def log_message(self, *args):
        pass


@pytest.fixture
def server():
    _Handler.hits = 0
    httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    httpd.daemon_threads = True
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    try:
        yield httpd.server_address[1]
    finally:
        httpd.shutdown()
        httpd.server_close()


def _registration(port, **overrides):
    data = {
        "id": "web1",
        "provenance": "pytest loopback assignment",
        "protocol": "http",
        "host": "127.0.0.1",
        "port": port,
        "paths": ["/"],
        "methods": ["GET"],
        "pinned_ips": ["127.0.0.1"],
        "dedicated_private": True,
        "allowed_actions": ["http"],
        "max_requests": 20,
        "max_concurrency": 2,
        "max_seconds": 10,
        "rate_per_second": 100,
        "exclusions": [],
        "enabled": True,
    }
    data.update(overrides)
    return Registration.from_dict(data)


def _setup(tmp_path, port, **overrides):
    home = tmp_path / "state"
    save_registrations(home, {"web1": _registration(port, **overrides)})
    challenge = tmp_path / "challenge.txt"
    challenge.write_bytes(b"offline")
    store = Store(home)
    try:
        run_id = new_run(store, challenge)
    finally:
        store.close()
    bind_target(home, run_id, "web1")
    return home, run_id


@asynccontextmanager
async def _process(home: Path):
    env = os.environ.copy()
    env.update(
        {
            "PRESTIGE_HOME": str(home),
            "PRESTIGE_ALLOWED_DIRS": str(home.parent),
            "PRESTIGE_REMOTE_ENABLED": "1",
        }
    )
    params = StdioServerParameters(
        command=sys.executable,
        args=["-m", "prestige", "agent"],
        env=env,
        cwd=str(REPO),
    )
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            yield session


async def _call(session, tool, payload):
    return json.loads((await session.call_tool(tool, payload)).content[0].text)


async def test_request_budget_persists_across_server_processes(tmp_path, server):
    home, run_id = _setup(tmp_path, server, max_requests=1)
    async with _process(home) as session:
        first = await _call(
            session,
            "prestige_remote_http",
            {"run_id": run_id, "registration_id": "web1", "path": "/challenge"},
        )
        assert first["status"] == "ok"
    async with _process(home) as session:
        second = await _call(
            session,
            "prestige_remote_http",
            {"run_id": run_id, "registration_id": "web1", "path": "/challenge"},
        )
        assert second["status"] == "error"
        assert "budget" in second["reason"].lower()
        status = await _call(
            session,
            "prestige_remote_status",
            {"run_id": run_id, "registration_id": "web1"},
        )
        assert status["result"]["requests_used"] == 1


async def test_cancelled_registration_stays_cancelled_after_restart(tmp_path, server):
    home, run_id = _setup(tmp_path, server)
    async with _process(home) as session:
        cancelled = await _call(
            session,
            "prestige_remote_cancel",
            {"run_id": run_id, "registration_id": "web1"},
        )
        assert cancelled["status"] == "ok"
    async with _process(home) as session:
        denied = await _call(
            session,
            "prestige_remote_http",
            {"run_id": run_id, "registration_id": "web1", "path": "/challenge"},
        )
        assert denied["status"] == "error"
        assert "cancelled" in denied["reason"].lower()
        status = await _call(
            session,
            "prestige_remote_status",
            {"run_id": run_id, "registration_id": "web1"},
        )
        assert status["result"]["cancelled"] is True


async def test_concurrency_limit_is_atomic_across_processes(tmp_path, server):
    home, run_id = _setup(tmp_path, server, max_concurrency=1, max_requests=10)

    async def one():
        async with _process(home) as session:
            return await _call(
                session,
                "prestige_remote_http",
                {"run_id": run_id, "registration_id": "web1", "path": "/slow"},
            )

    first, second = await asyncio.gather(one(), one())
    statuses = sorted(item["status"] for item in (first, second))
    assert statuses == ["error", "ok"], (first, second)
    denied = first if first["status"] == "error" else second
    assert "concurrent" in denied["reason"].lower()

    async with _process(home) as session:
        after = await _call(
            session,
            "prestige_remote_http",
            {"run_id": run_id, "registration_id": "web1", "path": "/challenge"},
        )
        assert after["status"] == "ok"


async def test_cancel_aborts_in_flight_request_in_another_process(tmp_path, server):
    home, run_id = _setup(tmp_path, server, max_concurrency=2, max_requests=10)

    async def slow_request():
        async with _process(home) as session:
            return await _call(
                session,
                "prestige_remote_http",
                {"run_id": run_id, "registration_id": "web1", "path": "/slow"},
            )

    task = asyncio.create_task(slow_request())
    await asyncio.sleep(0.8)
    async with _process(home) as session:
        cancelled = await _call(
            session,
            "prestige_remote_cancel",
            {"run_id": run_id, "registration_id": "web1"},
        )
        assert cancelled["status"] == "ok"
    result = await asyncio.wait_for(task, timeout=6)
    assert result["status"] == "error"
    assert "cancelled" in result["reason"].lower() or "expired" in result["reason"].lower()


async def test_exclusion_blocks_matching_allowed_prefix(tmp_path, server):
    home, run_id = _setup(tmp_path, server, paths=["/"], exclusions=["/admin"])
    async with _process(home) as session:
        excluded = await _call(
            session,
            "prestige_remote_http",
            {"run_id": run_id, "registration_id": "web1", "path": "/admin"},
        )
        assert excluded["status"] == "error"
        assert "excluded" in excluded["reason"].lower()
        allowed = await _call(
            session,
            "prestige_remote_http",
            {"run_id": run_id, "registration_id": "web1", "path": "/public"},
        )
        assert allowed["status"] == "ok"


async def test_unbound_run_cannot_use_registration(tmp_path, server):
    home = tmp_path / "state"
    save_registrations(home, {"web1": _registration(server)})
    challenge = tmp_path / "challenge.txt"
    challenge.write_bytes(b"offline")
    store = Store(home)
    try:
        run_id = new_run(store, challenge)
    finally:
        store.close()
    async with _process(home) as session:
        denied = await _call(
            session,
            "prestige_remote_http",
            {"run_id": run_id, "registration_id": "web1", "path": "/challenge"},
        )
        assert denied["status"] == "error"
        assert "bound" in denied["reason"].lower()


def test_connect_failure_releases_concurrency_and_keeps_budget(tmp_path):
    home = tmp_path / "state"
    registration = _registration(1, max_concurrency=1)
    save_registrations(home, {"web1": registration})
    broker = RemoteBroker(home, registration)
    for _ in range(2):
        with pytest.raises(Exception) as error:
            broker.http("GET", "/challenge")
        assert "Concurrent" not in str(error.value)
    store = Store(home)
    try:
        active = store.rows("SELECT * FROM remote_active")
        assert active == []
        state = store.rows("SELECT requests FROM remote_state WHERE registration_id='web1'")
        assert state[0]["requests"] == 2
    finally:
        store.close()


def test_exclusion_does_not_allow_adjacent_path(tmp_path, server):
    registration = _registration(server, paths=["/"], exclusions=["/admin"])
    broker = RemoteBroker(tmp_path, registration)
    with pytest.raises(RemoteDenied):
        broker.http("GET", "/admin")
    with pytest.raises(RemoteDenied):
        broker.http("GET", "/admin/secret")
    assert broker.http("GET", "/public")["status"] == 200


def test_oversized_response_is_bounded(tmp_path, server):
    registration = _registration(server, max_response_bytes=1024)
    result = RemoteBroker(tmp_path, registration).http("GET", "/large")
    assert result["bytes"] <= 1024


async def test_unregistered_competition_host_is_not_reachable(tmp_path):
    home = tmp_path / "state"
    challenge = tmp_path / "challenge.txt"
    challenge.write_bytes(b"offline")
    store = Store(home)
    try:
        run_id = new_run(store, challenge)
    finally:
        store.close()
    async with _process(home) as session:
        listed = await _call(session, "prestige_target_list", {})
        assert listed["result"]["registrations"] == []
        denied = await _call(
            session,
            "prestige_remote_http",
            {
                "run_id": run_id,
                "registration_id": "ctfd-scoreboard",
                "path": "/scoreboard",
            },
        )
        assert denied["status"] == "error"
        assert "unauthorized" in denied["reason"].lower() or "unknown" in denied["reason"].lower()


async def test_rate_limit_persists_across_server_processes(tmp_path, server):
    home, run_id = _setup(
        tmp_path, server, max_requests=5, rate_per_second=0.5, max_concurrency=2
    )
    async with _process(home) as session:
        first = await _call(
            session,
            "prestige_remote_http",
            {"run_id": run_id, "registration_id": "web1", "path": "/challenge"},
        )
        assert first["status"] == "ok"
    store = Store(home)
    try:
        first_state = store.rows(
            "SELECT requests,last_request FROM remote_state WHERE registration_id='web1'"
        )[0]
    finally:
        store.close()
    async with _process(home) as session:
        second = await _call(
            session,
            "prestige_remote_http",
            {"run_id": run_id, "registration_id": "web1", "path": "/challenge"},
        )
        assert second["status"] == "ok"
    store = Store(home)
    try:
        second_state = store.rows(
            "SELECT requests,last_request FROM remote_state WHERE registration_id='web1'"
        )[0]
    finally:
        store.close()
    assert second_state["requests"] == 2
    assert second_state["last_request"] - first_state["last_request"] >= 1.9
