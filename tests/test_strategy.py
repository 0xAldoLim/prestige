"""Operational FAST/AUTO/EXPERT lane differences and explicit escalation."""

import asyncio
import json
import os
from contextlib import asynccontextmanager
from pathlib import Path

import anyio
from mcp.client.session import ClientSession
from mcp.shared.message import SessionMessage

from prestige.mcp_server import serve_streams
from prestige.store import Store
from prestige.strategy import (
    EXPERT_TOOLS,
    FAST_TOOLS,
    expert_rules,
    rules_for_mode,
)


def test_fast_and_expert_rules_differ_operationally():
    fast = rules_for_mode("fast", 20, 500)
    expert = rules_for_mode("expert", 20, 900)
    assert set(fast.allowed_tools) == set(FAST_TOOLS)
    assert "ghidra" not in fast.allowed_tools
    assert "radare2" not in fast.allowed_tools
    assert fast.max_turns == 8
    assert fast.max_seconds == 120
    assert set(expert.allowed_tools) == set(EXPERT_TOOLS)
    assert expert.max_turns == 18
    assert expert.max_seconds == 600
    assert set(fast.allowed_tools) < set(expert.allowed_tools)


def test_auto_starts_fast_and_escalates_without_budget_reset():
    auto = rules_for_mode("auto", 10, 200)
    assert set(auto.allowed_tools) == set(FAST_TOOLS)
    escalated = expert_rules(auto)
    assert set(escalated.allowed_tools) == set(EXPERT_TOOLS)
    assert escalated.max_turns == auto.max_turns
    assert escalated.max_seconds == auto.max_seconds


@asynccontextmanager
async def _mcp_client(home: Path):
    old = os.environ.copy()
    os.environ.update(
        {"PRESTIGE_HOME": str(home), "PRESTIGE_ALLOWED_DIRS": str(home.parent)}
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


async def test_mcp_fast_denies_expert_tool_then_escalates(tmp_path):
    home = tmp_path / "state"
    challenge = tmp_path / "challenge.txt"
    challenge.write_bytes(b"SYNTHETIC{lane_policy}")
    async with _mcp_client(home) as session:
        created = json.loads(
            (
                await session.call_tool(
                    "prestige_create_investigation",
                    {"source_path": str(challenge), "mode": "fast", "max_turns": 3},
                )
            ).content[0].text
        )
        run_id = created["run_id"]
        status = json.loads(
            (await session.call_tool("prestige_get_status", {"run_id": run_id})).content[0].text
        )
        assert status["lane"] == "fast"
        artifact_id = status["artifacts"][0]["id"]

        denied = json.loads(
            (
                await session.call_tool(
                    "prestige_run_experiment",
                    {
                        "run_id": run_id,
                        "tool": "ghidra",
                        "artifact_id": artifact_id,
                        "args": {"mode": "functions"},
                    },
                )
            ).content[0].text
        )
        assert denied["status"] == "denied"
        assert "not authorized" in denied["reason"].lower()

        escalated = json.loads(
            (
                await session.call_tool(
                    "prestige_escalate",
                    {"run_id": run_id, "reason": "need binary analysis"},
                )
            ).content[0].text
        )
        assert escalated["result"]["lane"] == "expert"
        assert "ghidra" in escalated["result"]["allowed_tools"]

        status2 = json.loads(
            (await session.call_tool("prestige_get_status", {"run_id": run_id})).content[0].text
        )
        assert status2["lane"] == "expert"
        assert status2["attempts"] == 2  # denied attempt + escalation attempt
        assert status2["turns"] == 0 or status2["attempts"] >= 2

    store = Store(home)
    try:
        run = store.run(run_id)
        assert "ghidra" in run["settings"]["rules"]["allowed_tools"]
        assert run["settings"]["max_turns"] == 3
        assert "escalation" in [event["kind"] for event in store.events(run_id)]
    finally:
        store.close()


async def test_mcp_expert_starts_with_expert_tools(tmp_path):
    home = tmp_path / "state"
    challenge = tmp_path / "challenge.txt"
    challenge.write_bytes(b"data")
    async with _mcp_client(home) as session:
        created = json.loads(
            (
                await session.call_tool(
                    "prestige_create_investigation",
                    {"source_path": str(challenge), "mode": "expert"},
                )
            ).content[0].text
        )
        run_id = created["run_id"]
    store = Store(home)
    try:
        run = store.run(run_id)
        assert run["lane"] == "expert"
        assert set(run["settings"]["rules"]["allowed_tools"]) == set(EXPERT_TOOLS)
    finally:
        store.close()
