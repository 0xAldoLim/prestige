"""Structured, capped investigation hypotheses."""

import asyncio
import json
import os
from contextlib import asynccontextmanager
from pathlib import Path

import anyio
import pytest
from mcp.client.session import ClientSession
from mcp.shared.message import SessionMessage

from prestige import hypotheses
from prestige.engine import new_run
from prestige.mcp_server import serve_streams
from prestige.store import Store
from prestige.types import PolicyDenied, PrestigeError


@pytest.fixture
def run(store, tmp_path):
    path = tmp_path / "challenge.txt"
    path.write_bytes(b"evidence")
    return new_run(store, path)


def test_hypothesis_records_evidence_and_pivot(store, run):
    record = hypotheses.add(
        store,
        run,
        "The binary uses a custom VM",
        supports=["dispatch table in .rdata"],
        contradicts=["no VM entry trace"],
        prediction="tracing 0x401000 should show opcode dispatch",
        cheapest_test="static disassembly of 0x401000",
        cost="low",
        pivot_if="no dispatch table after two traces",
    )
    assert record["id"]
    assert record["status"] == "active"
    assert hypotheses.active(store, run)[0]["prediction"].startswith("tracing")


def test_at_most_three_active(store, run):
    for index in range(3):
        hypotheses.add(store, run, f"hypothesis {index}")
    with pytest.raises(PolicyDenied):
        hypotheses.add(store, run, "fourth")
    first = hypotheses.active(store, run)[0]
    hypotheses.update(store, run, first["id"], "retired")
    fourth = hypotheses.add(store, run, "fourth")
    assert fourth["status"] == "active"


def test_update_requires_known_id_and_valid_status(store, run):
    with pytest.raises(PrestigeError):
        hypotheses.update(store, run, "missing", "retired")
    record = hypotheses.add(store, run, "x")
    with pytest.raises(PolicyDenied):
        hypotheses.update(store, run, record["id"], "nonsense")
    updated = hypotheses.update(
        store, run, record["id"], "confirmed", contradicts=["decoder replay failed"]
    )
    assert updated["status"] == "confirmed"
    assert updated["contradicts"] == ["decoder replay failed"]


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


async def test_mcp_hypotheses_status_and_resume(tmp_path):
    home = tmp_path / "state"
    challenge = tmp_path / "challenge.txt"
    challenge.write_bytes(b"evidence")
    store = Store(home)
    try:
        run_id = new_run(store, challenge)
    finally:
        store.close()

    async with _mcp_client(home) as session:
        added = json.loads(
            (
                await session.call_tool(
                    "prestige_hypothesis_add",
                    {
                        "run_id": run_id,
                        "text": "XOR key is 0x42",
                        "supports": ["repeating pattern"],
                        "prediction": "plaintext becomes ASCII",
                        "cheapest_test": "xor with 0x42",
                        "cost": "low",
                        "pivot_if": "not ASCII",
                    },
                )
            ).content[0].text
        )
        assert added["result"]["status"] == "active"
        hypothesis_id = added["result"]["id"]

        listed = json.loads(
            (
                await session.call_tool(
                    "prestige_hypotheses_list", {"run_id": run_id}
                )
            ).content[0].text
        )
        assert listed["result"]["active"] == 1

        retired = json.loads(
            (
                await session.call_tool(
                    "prestige_hypothesis_update",
                    {
                        "run_id": run_id,
                        "hypothesis_id": hypothesis_id,
                        "status": "retired",
                    },
                )
            ).content[0].text
        )
        assert retired["result"]["status"] == "retired"

        status = json.loads(
            (await session.call_tool("prestige_get_status", {"run_id": run_id})).content[0].text
        )
        assert status["hypotheses"][0]["id"] == hypothesis_id

        resumed = json.loads(
            (
                await session.call_tool(
                    "prestige_resume_investigation", {"run_id": run_id}
                )
            ).content[0].text
        )
        assert resumed["hypotheses"][0]["status"] == "retired"
