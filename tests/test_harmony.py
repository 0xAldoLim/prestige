"""Integrated local environment: offline, web query, TCP, expiry and injection."""

import asyncio
import base64
import hashlib
import http.server
import json
import os
import socketserver
import threading
import time
from contextlib import asynccontextmanager
from pathlib import Path

import anyio
from mcp.client.session import ClientSession
from mcp.shared.message import SessionMessage

from prestige.commitments import add_commitment
from prestige.config import set_config
from prestige.engine import new_run
from prestige.mcp_server import serve_streams
from prestige.remote import Registration, bind_target, save_registrations
from prestige.store import Store


class _Web(http.server.BaseHTTPRequestHandler):
    hits = 0

    def do_GET(self):
        type(self).hits += 1
        if self.path.startswith("/challenge/private"):
            self._send(200, b"private")
        elif self.path.startswith("/challenge"):
            self._send(200, b"harmony-web")
        else:
            self._send(404, b"missing")

    def _send(self, status, body):
        self.send_response(status)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


class _TCP(socketserver.BaseRequestHandler):
    def handle(self):
        data = self.request.recv(1024)
        self.request.sendall(b"echo:" + data)


def _skills(root: Path):
    for category in ("crypto", "misc"):
        directory = root / f"ctf-{category}"
        directory.mkdir(parents=True)
        (directory / "SKILL.md").write_text(f"# ctf-{category}\n")
        (directory / "INDEX.md").write_text(
            "# index\n\n## High-signal routes\n\n"
            "| Evidence or symptom | Start with |\n|---|---|\n"
            "| base64 encoding | [tools.md](tools.md) |\n\n"
            "## Cross-category pivots\n\n- pivot.\n"
        )
        (directory / "tools.md").write_text("base64 transform\n")
    (root / "solve-challenge").mkdir()
    (root / "solve-challenge" / "SKILL.md").write_text("# dispatcher\n")


@asynccontextmanager
async def _mcp(home: Path):
    old = os.environ.copy()
    os.environ.update(
        {
            "PRESTIGE_HOME": str(home),
            "PRESTIGE_ALLOWED_DIRS": str(home.parent),
            "PRESTIGE_REMOTE_ENABLED": "1",
        }
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


async def _call(session, tool, payload):
    return json.loads((await session.call_tool(tool, payload)).content[0].text)


async def test_integrated_harmony(tmp_path):
    root = tmp_path / "skills"
    root.mkdir()
    _skills(root)
    home = tmp_path / "state"
    set_config(home, "skills.path", str(root))

    web = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Web)
    threading.Thread(target=web.serve_forever, daemon=True).start()
    tcp = socketserver.ThreadingTCPServer(("127.0.0.1", 0), _TCP)
    tcp.daemon_threads = True
    threading.Thread(target=tcp.serve_forever, daemon=True).start()
    try:
        value = b"SYNTHETIC{harmony_offline}"
        challenge = tmp_path / "challenge.txt"
        challenge.write_bytes(base64.b64encode(value))
        add_commitment(
            home, hashlib.sha256(challenge.read_bytes()).hexdigest(),
            hashlib.sha256(value).hexdigest(),
        )
        base = {
            "provenance": "operator harmony assignment",
            "host": "127.0.0.1",
            "pinned_ips": ["127.0.0.1"],
            "dedicated_private": True,
            "max_requests": 20,
            "max_concurrency": 2,
            "max_seconds": 30,
            "rate_per_second": 100,
            "enabled": True,
        }
        live = Registration.from_dict({
            **base, "id": "web-live", "protocol": "http",
            "port": web.server_address[1], "paths": ["/challenge"],
            "exclusions": ["/challenge/private"], "methods": ["GET"],
            "allowed_actions": ["http"],
        })
        expired = Registration.from_dict({
            **base, "id": "web-expired", "protocol": "http",
            "port": web.server_address[1], "paths": ["/challenge"],
            "methods": ["GET"], "allowed_actions": ["http"],
            "expires_at": time.time() - 1,
        })
        tcp_reg = Registration.from_dict({
            **base, "id": "tcp-live", "protocol": "tcp",
            "port": tcp.server_address[1], "paths": ["/"],
            "allowed_actions": ["tcp"],
        })
        save_registrations(
            home, {"web-live": live, "web-expired": expired, "tcp-live": tcp_reg}
        )
        store = Store(home)
        try:
            run_id = new_run(
                store,
                challenge,
                mode="auto",
                expected=hashlib.sha256(value).hexdigest(),
                max_seconds=300,
            )
        finally:
            store.close()
        for target in ("web-live", "web-expired", "tcp-live"):
            bind_target(home, run_id, target)

        async with _mcp(home) as session:
            resumed = await _call(
                session, "prestige_resume_investigation", {"run_id": run_id}
            )
            assert resumed["status"] == "ready"

            brief = await _call(
                session,
                "prestige_skills_apply",
                {"run_id": run_id, "evidence": "base64 encoding", "query": "base64"},
            )
            assert brief["result"]["primary"] in {"ctf-crypto", "ctf-misc"}

            await _call(
                session,
                "prestige_hypothesis_add",
                {
                    "run_id": run_id,
                    "text": "the artifact is base64",
                    "prediction": "preview SYNTHETIC",
                    "test_tool": "inspect",
                },
            )
            status = await _call(session, "prestige_get_status", {"run_id": run_id})
            artifact = status["artifacts"][0]["id"]

            inspected = await _call(
                session,
                "prestige_run_experiment",
                {"run_id": run_id, "tool": "inspect", "artifact_id": artifact},
            )
            assert inspected["evaluation"]["evaluations"]

            derived = await _call(
                session,
                "prestige_run_experiment",
                {"run_id": run_id, "tool": "base64", "artifact_id": artifact},
            )
            derived_id = derived["result"]["artifact"]
            verified = await _call(
                session,
                "prestige_verify_candidate",
                {
                    "run_id": run_id,
                    "candidate": value.decode(),
                    "artifact_id": derived_id,
                    "derivation_artifact": derived_id,
                },
            )
            assert verified["verified"] is True

            allowed = await _call(
                session,
                "prestige_remote_http",
                {
                    "run_id": run_id, "registration_id": "web-live",
                    "path": "/challenge?code=5a",
                },
            )
            assert allowed["status"] == "ok"
            assert allowed["result"]["http_status"] == 200

            excluded = await _call(
                session,
                "prestige_remote_http",
                {
                    "run_id": run_id, "registration_id": "web-live",
                    "path": "/challenge/private?x=1",
                },
            )
            assert excluded["status"] == "error"

            expired_result = await _call(
                session,
                "prestige_remote_http",
                {
                    "run_id": run_id, "registration_id": "web-expired",
                    "path": "/challenge",
                },
            )
            assert expired_result["status"] == "error"
            after = await _call(session, "prestige_get_status", {"run_id": run_id})
            assert after["status"] == "waiting_for_operator"
            assert after["pending_operator_request"]

            tcp_result = await _call(
                session,
                "prestige_remote_tcp",
                {
                    "run_id": run_id, "registration_id": "tcp-live",
                    "data_base64": base64.b64encode(b"ping").decode(),
                    "read_bytes": 64,
                },
            )
            assert tcp_result["status"] == "ok"
            assert "echo:ping" in (tcp_result["result"].get("text") or "")

            targets = await _call(session, "prestige_target_list", {})
            assert {item["id"] for item in targets["result"]["registrations"]} == {
                "web-live", "web-expired", "tcp-live"
            }
            forbidden = await _call(
                session,
                "prestige_remote_http",
                {
                    "run_id": run_id, "registration_id": "ctfd-scoreboard",
                    "path": "/scoreboard",
                },
            )
            assert forbidden["status"] == "error"

        store = Store(home)
        try:
            kinds = [event["kind"] for event in store.events(run_id)]
            assert "skill_route" in kinds
            assert "hypothesis_evaluation" in kinds
            assert "remote_expired" in kinds
            assert "verified" in kinds
        finally:
            store.close()
    finally:
        web.shutdown()
        web.server_close()
        tcp.shutdown()
        tcp.server_close()
