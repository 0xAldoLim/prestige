"""Persistent interactive sessions inside the reviewed Docker worker."""

import asyncio
import json
import os
from contextlib import asynccontextmanager
from pathlib import Path

import anyio
import pytest
from mcp.client.session import ClientSession
from mcp.shared.message import SessionMessage

from prestige.engine import new_run
from prestige.mcp_server import serve_streams
from prestige.store import Store

IMAGE = os.environ.get("PRESTIGE_TEST_IMAGE")

def test_session_rejects_unknown_command_and_image():
    from prestige.sessions import start_session
    from prestige.types import PolicyDenied

    with pytest.raises(PolicyDenied):
        start_session("not-a-digest", None, "python3")
    with pytest.raises(PolicyDenied):
        start_session("sha256:" + "a" * 64, None, "sh")


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


@pytest.mark.skipif(not IMAGE, reason="Explicit local immutable image required")
async def test_mcp_persistent_python_session(tmp_path):
    home = tmp_path / "state"
    from prestige.config import set_config

    set_config(home, "sandbox.image", IMAGE)
    challenge = tmp_path / "challenge.txt"
    challenge.write_bytes(b"offline")
    store = Store(home)
    try:
        run_id = new_run(store, challenge)
    finally:
        store.close()

    async with _mcp_client(home) as session:
        started = json.loads(
            (
                await session.call_tool(
                    "prestige_session_start", {"run_id": run_id, "command": "python3"}
                )
            ).content[0].text
        )
        assert started["status"] == "ok", started
        session_id = started["result"]["session_id"]

        first = json.loads(
            (
                await session.call_tool(
                    "prestige_session_send",
                    {"run_id": run_id, "session_id": session_id, "input": "print(1+1)", "wait": 1.0},
                )
            ).content[0].text
        )
        assert first["status"] == "ok", first
        assert "2" in first["result"]["output"]

        # Second turn proves interpreter state persists.
        await session.call_tool(
            "prestige_session_send",
            {"run_id": run_id, "session_id": session_id, "input": "x = 41", "wait": 0.3},
        )
        third = json.loads(
            (
                await session.call_tool(
                    "prestige_session_send",
                    {"run_id": run_id, "session_id": session_id, "input": "print(x + 1)", "wait": 1.0},
                )
            ).content[0].text
        )
        assert "42" in third["result"]["output"]

        listed = json.loads(
            (await session.call_tool("prestige_session_list", {})).content[0].text
        )
        assert any(item["session_id"] == session_id for item in listed["result"])

        stopped = json.loads(
            (
                await session.call_tool(
                    "prestige_session_stop",
                    {"run_id": run_id, "session_id": session_id},
                )
            ).content[0].text
        )
        assert stopped["result"]["stopped"] is True

    store = Store(home)
    try:
        kinds = [event["kind"] for event in store.events(run_id)]
        assert "session_start" in kinds
        assert "session_send" in kinds
        assert "session_stop" in kinds
    finally:
        store.close()


@pytest.mark.skipif(not IMAGE, reason="Explicit local immutable image required")
async def test_mcp_rejects_disallowed_session_command(tmp_path):
    home = tmp_path / "state"
    from prestige.config import set_config

    set_config(home, "sandbox.image", IMAGE)
    challenge = tmp_path / "challenge.txt"
    challenge.write_bytes(b"offline")
    store = Store(home)
    try:
        run_id = new_run(store, challenge)
    finally:
        store.close()

    async with _mcp_client(home) as session:
        result = await session.call_tool(
            "prestige_session_start", {"run_id": run_id, "command": "sh"}
        )
        body = json.loads(result.content[0].text)
        assert body.get("status") == "error"
