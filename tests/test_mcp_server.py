import base64
import hashlib
import json
import os
import subprocess
import sys
import time
from pathlib import Path

import anyio
import pytest
from mcp.client.session import ClientSession
from mcp.shared.message import SessionMessage

from prestige.mcp_server import serve_streams


@pytest.fixture
def tmp_home(tmp_path):
    home = tmp_path / "state"
    os.environ["PRESTIGE_HOME"] = str(home)
    return home


async def _mcp_client(tmp_path, env=None):
    """Yield a connected ClientSession backed by in-memory streams."""
    env = env or {}
    env.setdefault("PRESTIGE_HOME", str(tmp_path / "state"))
    client_to_server_send, client_to_server_recv = anyio.create_memory_object_stream[SessionMessage | Exception](0)
    server_to_client_send, server_to_client_recv = anyio.create_memory_object_stream[SessionMessage](0)

    async with anyio.create_task_group() as tg:
        tg.start_soon(serve_streams, client_to_server_recv, server_to_client_send)
        async with ClientSession(server_to_client_recv, client_to_server_send) as session:
            await session.initialize()
            yield session


async def test_mcp_lists_prestige_tools(tmp_path):
    async for session in _mcp_client(tmp_path):
        tools = await session.list_tools()
        names = {t.name for t in tools.tools}
        assert names >= {
            "prestige_create_investigation",
            "prestige_get_status",
            "prestige_run_experiment",
            "prestige_verify_candidate",
        }


async def test_mcp_create_and_status_roundtrip(tmp_path):
    value = b"SYNTHETIC{mcp_roundtrip}"
    path = tmp_path / "challenge.txt"
    path.write_bytes(base64.b64encode(value))
    digest = hashlib.sha256(value).hexdigest()

    async for session in _mcp_client(tmp_path):
        result = await session.call_tool(
            "prestige_create_investigation",
            {"source_path": str(path), "backend": "fake", "expected_sha256": digest},
        )
        data = json.loads(result.content[0].text)
        assert data["status"] == "ready"
        run_id = data["run_id"]

        status = await session.call_tool("prestige_get_status", {"run_id": run_id})
        body = json.loads(status.content[0].text)
        assert body["status"] == "ready"
        assert len(body["artifacts"]) == 1
        assert body["artifacts"][0]["label"] == "challenge.txt"


async def test_mcp_run_experiment_and_record_observation(tmp_path):
    value = b"SYNTHETIC{mcp_experiment}"
    path = tmp_path / "challenge.txt"
    path.write_bytes(base64.b64encode(value))
    digest = hashlib.sha256(value).hexdigest()

    async for session in _mcp_client(tmp_path):
        created = await session.call_tool(
            "prestige_create_investigation",
            {"source_path": str(path), "backend": "fake", "expected_sha256": digest},
        )
        run_id = json.loads(created.content[0].text)["run_id"]

        status = await session.call_tool("prestige_get_status", {"run_id": run_id})
        artifact_id = json.loads(status.content[0].text)["artifacts"][0]["id"]

        result = await session.call_tool(
            "prestige_run_experiment",
            {"run_id": run_id, "tool": "inspect", "artifact_id": artifact_id, "args": {}},
        )
        body = json.loads(result.content[0].text)
        assert body["status"] == "ok"
        assert "sha256" in body["result"]

        status2 = await session.call_tool("prestige_get_status", {"run_id": run_id})
        assert len(json.loads(status2.content[0].text)["observations"]) == 1


async def test_mcp_verify_candidate_with_digest(tmp_path):
    value = b"SYNTHETIC{mcp_verify}"
    path = tmp_path / "challenge.txt"
    path.write_bytes(base64.b64encode(value))
    digest = hashlib.sha256(value).hexdigest()

    async for session in _mcp_client(tmp_path):
        created = await session.call_tool(
            "prestige_create_investigation",
            {"source_path": str(path), "backend": "fake", "expected_sha256": digest},
        )
        run_id = json.loads(created.content[0].text)["run_id"]

        result = await session.call_tool(
            "prestige_verify_candidate",
            {"run_id": run_id, "candidate": value.decode(), "artifact_id": ""},
        )
        body = json.loads(result.content[0].text)
        assert body["verified"] is True


async def test_mcp_investigation_loop_with_derived_evidence(tmp_path):
    """Exercise create -> inspect -> transform -> read -> verify through MCP."""
    value = b"hello-mcp-loop"
    path = tmp_path / "challenge.txt"
    path.write_bytes(base64.b64encode(value))
    digest = hashlib.sha256(value).hexdigest()

    async for session in _mcp_client(tmp_path):
        created = await session.call_tool(
            "prestige_create_investigation",
            {"source_path": str(path), "backend": "fake", "expected_sha256": digest},
        )
        run_id = json.loads(created.content[0].text)["run_id"]

        status = await session.call_tool("prestige_get_status", {"run_id": run_id})
        artifact_id = json.loads(status.content[0].text)["artifacts"][0]["id"]

        inspected = await session.call_tool(
            "prestige_run_experiment",
            {"run_id": run_id, "tool": "inspect", "artifact_id": artifact_id, "args": {}},
        )
        assert json.loads(inspected.content[0].text)["status"] == "ok"

        transformed = await session.call_tool(
            "prestige_run_experiment",
            {"run_id": run_id, "tool": "base64", "artifact_id": artifact_id, "args": {}},
        )
        derived = json.loads(transformed.content[0].text)
        assert derived["status"] == "ok"
        derived_id = derived["result"]["artifact"]

        read = await session.call_tool(
            "prestige_run_experiment",
            {"run_id": run_id, "tool": "read", "artifact_id": derived_id, "args": {}},
        )
        body = json.loads(read.content[0].text)
        assert body["status"] == "ok"
        assert value.decode() in body["result"]["text"]

        verified = await session.call_tool(
            "prestige_verify_candidate",
            {"run_id": run_id, "candidate": value.decode(), "artifact_id": derived_id},
        )
        assert json.loads(verified.content[0].text)["verified"] is True

        final = await session.call_tool("prestige_get_status", {"run_id": run_id})
        final_body = json.loads(final.content[0].text)
        assert len(final_body["observations"]) == 3
        assert len(final_body["candidates"]) == 1
        assert final_body["candidates"][0]["verified"] is True


async def test_mcp_unknown_and_unauthorized_tools_fail_closed(tmp_path):
    path = tmp_path / "challenge.txt"
    path.write_bytes(b"SYNTHETIC{closed}")

    async for session in _mcp_client(tmp_path):
        created = await session.call_tool(
            "prestige_create_investigation",
            {"source_path": str(path), "backend": "fake"},
        )
        run_id = json.loads(created.content[0].text)["run_id"]

        unknown = await session.call_tool(
            "prestige_run_experiment",
            {"run_id": run_id, "tool": "definitely-not-a-tool", "artifact_id": "", "args": {}},
        )
        assert json.loads(unknown.content[0].text)["status"] == "denied"

        missing = await session.call_tool("prestige_get_status", {"run_id": "does-not-exist"})
        assert missing.is_error is True


def test_agent_stdio_smoke(tmp_path):
    """The `prestige agent` CLI starts a stdio MCP server and answers initialize."""
    env = os.environ.copy()
    env["PRESTIGE_HOME"] = str(tmp_path / "state")
    proc = subprocess.Popen(
        [sys.executable, "-m", "prestige", "agent"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        cwd=str(Path(__file__).parent.parent),
        env=env,
    )
    try:
        init = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": "prestige-test", "version": "0.0.1"},
            },
        }
        proc.stdin.write(json.dumps(init) + "\n")
        proc.stdin.flush()
        deadline = time.time() + 10
        line = ""
        while time.time() < deadline and not line.strip():
            line = proc.stdout.readline()
        assert line.strip(), "server did not respond to initialize"
        response = json.loads(line)
        assert response["id"] == 1
        assert response["result"]["serverInfo"]["name"] == "prestige"
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()
