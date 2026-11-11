"""Controlled research broker: allowlist, bounds, provenance, cache and MCP/CLI."""

import asyncio
import http.server
import json
import os
import socket
import ssl
import subprocess
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
        elif self.path == "/large":
            self._send(200, b"A" * 10000)
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


def test_config_accepts_json_list_for_research(tmp_path):
    from prestige.config import load_config, set_config

    home = tmp_path / "state"
    set_config(home, "research.allowed_hosts", '["a.example","b.example"]')
    assert load_config(home)["research.allowed_hosts"] == ["a.example", "b.example"]


def test_dns_resolution_is_pinned_for_the_connection(home, server, monkeypatch):
    original = socket.getaddrinfo
    calls = {"count": 0}

    def fake(host, port, *args, **kwargs):
        if host == "127.0.0.1":
            calls["count"] += 1
            if calls["count"] == 1:
                return original(host, port, *args, **kwargs)
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.0.0.1", port))]
        return original(host, port, *args, **kwargs)

    monkeypatch.setattr(socket, "getaddrinfo", fake)
    result = ResearchBroker(home).fetch(f"http://127.0.0.1:{server}/doc")
    assert "nonce" in result["text"]
    assert calls["count"] == 1


def test_proxy_environment_is_ignored(home, server, monkeypatch):
    monkeypatch.setenv("HTTP_PROXY", "http://127.0.0.1:1")
    monkeypatch.setenv("HTTPS_PROXY", "http://127.0.0.1:1")
    result = ResearchBroker(home).fetch(f"http://127.0.0.1:{server}/doc")
    assert "nonce" in result["text"]


def test_oversized_response_is_truncated(home, server):
    result = ResearchBroker(home).fetch(
        f"http://127.0.0.1:{server}/large", max_bytes=1024
    )
    assert result["truncated"] is True
    assert len(result["text"]) <= 16384


def test_connection_failure_is_bounded(home, monkeypatch):
    broker = ResearchBroker(home)
    broker.allowed.add("127.0.0.1")
    with pytest.raises(PolicyDenied):
        broker.fetch("http://127.0.0.1:1/doc")


@pytest.mark.skipif(__import__("shutil").which("openssl") is None, reason="openssl unavailable")
def test_untrusted_tls_certificate_is_rejected(home, tmp_path, monkeypatch):
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
    httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert, key)
    httpd.socket = context.wrap_socket(httpd.socket, server_side=True)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    try:
        with pytest.raises(PolicyDenied) as error:
            ResearchBroker(home).fetch(
                f"https://127.0.0.1:{httpd.server_address[1]}/doc"
            )
        message = str(error.value).lower()
        assert "certificate" in message or "ssl" in message
    finally:
        httpd.shutdown()
        httpd.server_close()
