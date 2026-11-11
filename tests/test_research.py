"""Controlled research broker: allowlist, bounds, provenance, cache and MCP/CLI."""

import asyncio
import http.server
import json
import os
import threading
from contextlib import asynccontextmanager
from pathlib import Path

import anyio
import pytest
from mcp.client.session import ClientSession
from mcp.shared.message import SessionMessage

from prestige.config import set_config
from prestige.engine import new_run
from prestige.mcp_server import serve_streams
from prestige.research import ResearchBroker
from prestige.store import Store
from prestige.types import PolicyDenied

DOC = b"RSA nonce reuse can leak the private key. Verify the mechanism locally.\n"


class _Handler(http.server.BaseHTTPRequestHandler):
    hits = 0

    def do_GET(self):
        type(self).hits += 1
        if self.path == "/doc":
            self._send(200, DOC)
        elif self.path == "/redirect":
            self.send_response(302)
            self.send_header("Location", "http://evil.example/secret")
            self.end_headers()
        else:
            self._send(404, b"missing")

    def _send(self, status, body):
        self.send_response(status)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


@pytest.fixture
def server():
    _Handler.hits = 0
    httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    try:
        yield httpd.server_address[1]
    finally:
        httpd.shutdown()
        httpd.server_close()


@pytest.fixture
def home(tmp_path, monkeypatch, server):
    state = tmp_path / "state"
    set_config(state, "research.enabled", "true")
    set_config(state, "research.allowed_hosts", ["127.0.0.1"])
    monkeypatch.setenv("PRESTIGE_RESEARCH_ALLOW_LOOPBACK", "1")
    return state


def test_fetch_provenance_and_cache(home, server):
    broker = ResearchBroker(home)
    url = f"http://127.0.0.1:{server}/doc"
    first = broker.fetch(url)
    assert first["cached"] is False
    assert first["trust"] == "external_untrusted"
    assert len(first["sha256"]) == 64
    assert "nonce" in first["text"]
    hits = _Handler.hits
    second = broker.fetch(url)
    assert second["cached"] is True
    assert _Handler.hits == hits


def test_cache_search(home, server):
    broker = ResearchBroker(home)
    broker.fetch(f"http://127.0.0.1:{server}/doc")
    hits = broker.search("nonce")
    assert hits
    assert hits[0]["source"] == "127.0.0.1"
    assert hits[0]["trust"] == "external_untrusted"


def test_off_allowlist_and_redirect_denied(home, server):
    broker = ResearchBroker(home)
    with pytest.raises(PolicyDenied):
        broker.fetch("https://evil.example/doc")
    with pytest.raises(PolicyDenied):
        broker.fetch(f"http://127.0.0.1:{server}/redirect")


def test_metadata_and_disabled_denied(home, server, monkeypatch):
    broker = ResearchBroker(home)
    broker.allowed.add("169.254.169.254")
    with pytest.raises(PolicyDenied):
        broker.fetch("http://169.254.169.254/doc")
    monkeypatch.setenv("PRESTIGE_RESEARCH_ENABLED", "0")
    set_config(home, "research.enabled", "false")
    with pytest.raises(PolicyDenied):
        broker.fetch(f"http://127.0.0.1:{server}/doc")


@asynccontextmanager
async def _mcp_client(home: Path):
    old = os.environ.copy()
    os.environ.update(
        {
            "PRESTIGE_HOME": str(home),
            "PRESTIGE_ALLOWED_DIRS": str(home.parent),
            "PRESTIGE_RESEARCH_ENABLED": "1",
            "PRESTIGE_RESEARCH_ALLOW_LOOPBACK": "1",
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


async def test_mcp_research_records_evidence(home, server, tmp_path):
    challenge = tmp_path / "challenge.txt"
    challenge.write_bytes(b"offline")
    store = Store(home)
    try:
        run_id = new_run(store, challenge)
    finally:
        store.close()

    async with _mcp_client(home) as session:
        sources = json.loads(
            (await session.call_tool("prestige_research_sources", {})).content[0].text
        )
        assert sources["result"]["enabled"] is True
        assert "127.0.0.1" in sources["result"]["allowed_hosts"]

        fetched = json.loads(
            (
                await session.call_tool(
                    "prestige_research_fetch",
                    {"url": f"http://127.0.0.1:{server}/doc", "run_id": run_id},
                )
            ).content[0].text
        )
        assert fetched["status"] == "ok"
        assert fetched["result"]["artifact"]
        assert "nonce" in fetched["result"]["text"]

        searched = json.loads(
            (
                await session.call_tool(
                    "prestige_research_search", {"query": "nonce"}
                )
            ).content[0].text
        )
        assert searched["result"]

    store = Store(home)
    try:
        kinds = [event["kind"] for event in store.events(run_id)]
        assert "research" in kinds
    finally:
        store.close()


def test_cli_research_sources(home, server, capsys):
    from prestige.cli import main

    assert main(["--home", str(home), "research", "sources"]) == 0
    output = json.loads(capsys.readouterr().out)
    assert output["enabled"] is True
    assert main(["--home", str(home), "research", "fetch", f"http://127.0.0.1:{server}/doc"]) == 0
    body = json.loads(capsys.readouterr().out)
    assert body["trust"] == "external_untrusted"
    assert main(["--home", str(home), "research", "search", "nonce"]) == 0
    hits = json.loads(capsys.readouterr().out)
    assert hits
