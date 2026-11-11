import asyncio
import base64
import hashlib
import json
import os
import shutil
import subprocess
import sys
import time
from contextlib import asynccontextmanager
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


@asynccontextmanager
async def _mcp_client(tmp_path, env=None):
    """Yield a connected ClientSession backed by in-memory streams."""
    env = env or {}
    env.setdefault("PRESTIGE_HOME", str(tmp_path / "state"))
    env.setdefault("PRESTIGE_ALLOWED_DIRS", str(tmp_path))
    old = os.environ.copy()
    os.environ.update(env)
    client_to_server_send, client_to_server_recv = anyio.create_memory_object_stream[SessionMessage | Exception](0)
    server_to_client_send, server_to_client_recv = anyio.create_memory_object_stream[SessionMessage](0)

    server_task = asyncio.create_task(serve_streams(client_to_server_recv, server_to_client_send))
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


async def test_mcp_lists_prestige_tools(tmp_path):
    async with _mcp_client(tmp_path) as session:
        tools = await session.list_tools()
        names = {t.name for t in tools.tools}
        assert names >= {
            "prestige_create_investigation",
            "prestige_get_status",
            "prestige_run_experiment",
            "prestige_verify_candidate",
            "prestige_start_analysis",
            "prestige_get_analysis",
            "prestige_cancel_analysis",
            "prestige_request_operator",
            "prestige_answer_operator",
            "prestige_resume_investigation",
        }


async def test_mcp_create_and_status_roundtrip(tmp_path):
    value = b"SYNTHETIC{mcp_roundtrip}"
    path = tmp_path / "challenge.txt"
    path.write_bytes(base64.b64encode(value))
    digest = hashlib.sha256(value).hexdigest()

    async with _mcp_client(tmp_path) as session:
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

    async with _mcp_client(tmp_path) as session:
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


async def test_mcp_suppresses_duplicate_deterministic_experiments(tmp_path):
    value = b"SYNTHETIC{mcp_duplicate}"
    path = tmp_path / "challenge.txt"
    path.write_bytes(base64.b64encode(value))
    digest = hashlib.sha256(value).hexdigest()

    async with _mcp_client(tmp_path) as session:
        created = await session.call_tool(
            "prestige_create_investigation",
            {"source_path": str(path), "backend": "fake", "expected_sha256": digest},
        )
        run_id = json.loads(created.content[0].text)["run_id"]
        status = await session.call_tool("prestige_get_status", {"run_id": run_id})
        artifact_id = json.loads(status.content[0].text)["artifacts"][0]["id"]

        payload = {
            "run_id": run_id,
            "tool": "inspect",
            "artifact_id": artifact_id,
            "args": {},
        }
        first = json.loads((await session.call_tool("prestige_run_experiment", payload)).content[0].text)
        second = json.loads((await session.call_tool("prestige_run_experiment", payload)).content[0].text)
        assert first["status"] == "ok" and not first.get("cached")
        assert second["status"] == "ok" and second.get("cached") is True

        status2 = await session.call_tool("prestige_get_status", {"run_id": run_id})
        assert len(json.loads(status2.content[0].text)["observations"]) == 1

        forced = json.loads(
            (
                await session.call_tool(
                    "prestige_run_experiment", {**payload, "force": True}
                )
            ).content[0].text
        )
        assert forced["status"] == "ok" and not forced.get("cached")
        status3 = await session.call_tool("prestige_get_status", {"run_id": run_id})
        assert len(json.loads(status3.content[0].text)["observations"]) == 2


async def test_mcp_verify_candidate_with_digest(tmp_path):
    value = b"SYNTHETIC{mcp_verify}"
    path = tmp_path / "challenge.txt"
    path.write_bytes(base64.b64encode(value))
    digest = hashlib.sha256(value).hexdigest()

    async with _mcp_client(tmp_path) as session:
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
        assert body["stage"] == "independently_verified"
        assert body["reproduced"] is False
        assert body["checker"] == "unavailable"
        assert "candidate" not in body


async def test_mcp_verify_candidate_stages_without_digest(tmp_path):
    value = b"SYNTHETIC{stage_evidence}"
    path = tmp_path / "challenge.txt"
    path.write_bytes(base64.b64encode(value))

    async with _mcp_client(tmp_path) as session:
        created = await session.call_tool(
            "prestige_create_investigation", {"source_path": str(path)}
        )
        run_id = json.loads(created.content[0].text)["run_id"]
        status = await session.call_tool("prestige_get_status", {"run_id": run_id})
        source_id = json.loads(status.content[0].text)["artifacts"][0]["id"]

        derived = await session.call_tool(
            "prestige_run_experiment",
            {"run_id": run_id, "tool": "base64", "artifact_id": source_id, "args": {}},
        )
        derived_id = json.loads(derived.content[0].text)["result"]["artifact"]

        reproduced = json.loads(
            (
                await session.call_tool(
                    "prestige_verify_candidate",
                    {
                        "run_id": run_id,
                        "candidate": value.decode(),
                        "artifact_id": derived_id,
                        "derivation_artifact": derived_id,
                    },
                )
            ).content[0].text
        )
        assert reproduced["verified"] is False
        assert reproduced["expected_available"] is False
        assert reproduced["reproduced"] is True
        assert reproduced["stage"] == "reproduced"
        assert "candidate" not in reproduced

        mismatch = json.loads(
            (
                await session.call_tool(
                    "prestige_verify_candidate",
                    {
                        "run_id": run_id,
                        "candidate": "different",
                        "artifact_id": derived_id,
                        "derivation_artifact": derived_id,
                    },
                )
            ).content[0].text
        )
        assert mismatch["reproduced"] is False
        assert mismatch["stage"] == "derived"


async def test_mcp_investigation_loop_with_derived_evidence(tmp_path):
    """Exercise create -> inspect -> transform -> read -> verify through MCP."""
    value = b"hello-mcp-loop"
    path = tmp_path / "challenge.txt"
    path.write_bytes(base64.b64encode(value))
    digest = hashlib.sha256(value).hexdigest()

    async with _mcp_client(tmp_path) as session:
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

    async with _mcp_client(tmp_path) as session:
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


async def test_mcp_create_rejects_model_defined_backend_and_credentials(tmp_path):
    path = tmp_path / "challenge.txt"
    path.write_bytes(b"data")

    async with _mcp_client(tmp_path) as session:
        for payload in (
            {"source_path": str(path), "backend": "openai"},
            {"source_path": str(path), "backend": "codex"},
            {
                "source_path": str(path),
                "backend": "fake",
                "openai_api_key": "sk-secret",
            },
            {
                "source_path": str(path),
                "backend": "fake",
                "runner_image": "sha256:" + "a" * 64,
            },
        ):
            result = await session.call_tool("prestige_create_investigation", payload)
            assert result.is_error or json.loads(result.content[0].text).get("status") != "ready"


async def test_mcp_create_defaults_to_fake_backend(tmp_path):
    path = tmp_path / "challenge.txt"
    path.write_bytes(b"data")

    async with _mcp_client(tmp_path) as session:
        result = await session.call_tool(
            "prestige_create_investigation", {"source_path": str(path)}
        )
        body = json.loads(result.content[0].text)
        assert body["status"] == "ready"


async def test_mcp_create_rejects_unauthorized_source_path(tmp_path):
    async with _mcp_client(tmp_path) as session:
        result = await session.call_tool(
            "prestige_create_investigation", {"source_path": "/etc/passwd"}
        )
        assert result.is_error or json.loads(result.content[0].text).get("status") != "ready"


async def test_mcp_enforces_tool_attempt_budget(tmp_path):
    path = tmp_path / "challenge.txt"
    path.write_bytes(b"data")

    async with _mcp_client(tmp_path) as session:
        created = await session.call_tool(
            "prestige_create_investigation",
            {"source_path": str(path), "max_turns": 1},
        )
        run_id = json.loads(created.content[0].text)["run_id"]

        status = await session.call_tool("prestige_get_status", {"run_id": run_id})
        artifact_id = json.loads(status.content[0].text)["artifacts"][0]["id"]

        first = await session.call_tool(
            "prestige_run_experiment",
            {"run_id": run_id, "tool": "inspect", "artifact_id": artifact_id, "args": {}},
        )
        assert json.loads(first.content[0].text)["status"] == "ok"

        second = await session.call_tool(
            "prestige_run_experiment",
            {"run_id": run_id, "tool": "inspect", "artifact_id": artifact_id, "args": {}},
        )
        assert json.loads(second.content[0].text)["status"] != "ok"


@pytest.mark.skipif(not shutil.which("opencode"), reason="OpenCode CLI not available")
def test_prestige_agent_permissions_deny_host_tools():
    """The registered prestige agent must not be able to invoke host tools."""
    result = subprocess.run(
        ["opencode", "--standalone", "debug", "agents"],
        capture_output=True,
        text=True,
        cwd=str(Path(__file__).parent.parent),
    )
    assert result.returncode == 0, result.stderr
    agents = json.loads(result.stdout)
    prestige = next((a for a in agents if a["id"] == "prestige"), None)
    assert prestige is not None

    def effective(action: str, resource: str) -> str:
        effect = "deny"
        for rule in prestige["permissions"]:
            action_match = rule["action"] == "*" or _match(rule["action"], action)
            resource_match = rule["resource"] == "*" or _match(rule["resource"], resource)
            if action_match and resource_match:
                effect = rule["effect"]
        return effect

    for action in ("shell", "read", "write", "browser", "skill"):
        assert effective(action, "/tmp/x") == "deny", action
    assert effective("prestige_prestige_create_investigation", "*") == "allow"
    assert effective("prestige_prestige_run_experiment", "*") == "allow"


def _match(pattern: str, value: str) -> bool:
    if pattern.endswith("*"):
        return value.startswith(pattern[:-1])
    return pattern == value


async def test_mcp_operator_request_and_relay(tmp_path):
    path = tmp_path / "challenge.txt"
    path.write_bytes(b"data")

    async with _mcp_client(tmp_path) as session:
        created = await session.call_tool(
            "prestige_create_investigation", {"source_path": str(path)}
        )
        run_id = json.loads(created.content[0].text)["run_id"]

        requested = json.loads(
            (
                await session.call_tool(
                    "prestige_request_operator",
                    {
                        "run_id": run_id,
                        "question": "Is this challenge in scope?",
                        "options": ["yes", "no"],
                    },
                )
            ).content[0].text
        )
        assert requested["status"] == "waiting_for_operator"
        request_id = requested["request_id"]

        status = json.loads(
            (await session.call_tool("prestige_get_status", {"run_id": run_id})).content[0].text
        )
        assert status["status"] == "waiting_for_operator"
        assert status["pending_operator_request"]["request_id"] == request_id

        answered = json.loads(
            (
                await session.call_tool(
                    "prestige_answer_operator",
                    {"run_id": run_id, "request_id": request_id, "answer": "yes"},
                )
            ).content[0].text
        )
        assert answered["status"] == "ready"
        assert answered["trust"] == "operator_relayed"

        status2 = json.loads(
            (await session.call_tool("prestige_get_status", {"run_id": run_id})).content[0].text
        )
        assert status2["status"] == "ready"
        assert status2["pending_operator_request"] is None


async def test_mcp_state_survives_reconnect(tmp_path):
    value = b"SYNTHETIC{reconnect}"
    path = tmp_path / "challenge.txt"
    path.write_bytes(base64.b64encode(value))

    async with _mcp_client(tmp_path) as session:
        created = await session.call_tool(
            "prestige_create_investigation", {"source_path": str(path)}
        )
        run_id = json.loads(created.content[0].text)["run_id"]
        status = await session.call_tool("prestige_get_status", {"run_id": run_id})
        artifact_id = json.loads(status.content[0].text)["artifacts"][0]["id"]
        await session.call_tool(
            "prestige_run_experiment",
            {"run_id": run_id, "tool": "inspect", "artifact_id": artifact_id, "args": {}},
        )

    # A new MCP session must recover the durable investigation state.
    async with _mcp_client(tmp_path) as session:
        status = await session.call_tool("prestige_get_status", {"run_id": run_id})
        body = json.loads(status.content[0].text)
        assert body["run_id"] == run_id
        assert len(body["observations"]) == 1
        assert body["artifacts"][0]["id"] == artifact_id


async def test_mcp_schema_contains_no_provider_credentials(tmp_path):
    async with _mcp_client(tmp_path) as session:
        tools = await session.list_tools()
        schema = json.dumps([tool.input_schema for tool in tools.tools])
        for forbidden in (
            "openai_api_key",
            "anthropic_api_key",
            "PRESTIGE_OPENAI_API_KEY",
            "openai_base_url",
            "openai_model",
        ):
            assert forbidden not in schema
        create = next(tool for tool in tools.tools if tool.name == "prestige_create_investigation")
        backend = create.input_schema["properties"].get("backend")
        assert backend is None or backend.get("enum") == ["fake"]


async def test_mcp_resume_reconstructs_context_without_resetting_budget(tmp_path):
    value = b"SYNTHETIC{resume_context}"
    path = tmp_path / "challenge.txt"
    path.write_bytes(base64.b64encode(value))

    async with _mcp_client(tmp_path) as session:
        created = await session.call_tool(
            "prestige_create_investigation",
            {"source_path": str(path), "max_turns": 3, "max_seconds": 300},
        )
        run_id = json.loads(created.content[0].text)["run_id"]
        status = await session.call_tool("prestige_get_status", {"run_id": run_id})
        artifact_id = json.loads(status.content[0].text)["artifacts"][0]["id"]
        await session.call_tool(
            "prestige_run_experiment",
            {"run_id": run_id, "tool": "inspect", "artifact_id": artifact_id, "args": {}},
        )

        resumed = json.loads(
            (
                await session.call_tool("prestige_resume_investigation", {"run_id": run_id})
            ).content[0].text
        )
        assert resumed["status"] == "ready"
        assert resumed["attempts"] == 1
        assert resumed["remaining_attempts"] == 2
        assert resumed["artifacts"] == 1
        assert len(resumed["recent_observations"]) == 1
        assert resumed["next_actions"]
        assert "reset" not in json.dumps(resumed)


async def test_mcp_resume_surfaces_pending_operator_request(tmp_path):
    path = tmp_path / "challenge.txt"
    path.write_bytes(b"data")

    async with _mcp_client(tmp_path) as session:
        created = await session.call_tool(
            "prestige_create_investigation", {"source_path": str(path)}
        )
        run_id = json.loads(created.content[0].text)["run_id"]
        requested = json.loads(
            (
                await session.call_tool(
                    "prestige_request_operator",
                    {"run_id": run_id, "question": "Need scope confirmation"},
                )
            ).content[0].text
        )
        resumed = json.loads(
            (
                await session.call_tool("prestige_resume_investigation", {"run_id": run_id})
            ).content[0].text
        )
        assert resumed["status"] == "waiting_for_operator"
        assert resumed["pending_operator_request"]["request_id"] == requested["request_id"]
        assert any("answer operator request" in action for action in resumed["next_actions"])


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
