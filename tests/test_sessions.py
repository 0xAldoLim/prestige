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

def test_session_rejects_unknown_command_and_image(tmp_path):
    from prestige.sessions import start_session
    from prestige.types import PolicyDenied

    with pytest.raises(PolicyDenied):
        start_session(tmp_path, "run1", "not-a-digest", None, "python3")
    with pytest.raises(PolicyDenied):
        start_session(tmp_path, "run1", "sha256:" + "a" * 64, None, "sh")


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
            (
                await session.call_tool(
                    "prestige_session_list", {"run_id": run_id}
                )
            ).content[0].text
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
def test_session_ownership_rejects_other_investigation(tmp_path):
    from types import SimpleNamespace

    from prestige import sessions as session_state
    from prestige.types import PolicyDenied

    home = tmp_path / "state"
    session_state._SESSIONS["owned"] = SimpleNamespace(run_id="runA", alive=True)
    try:
        with pytest.raises(PolicyDenied):
            session_state.send_session(home, "runB", "owned", "print(1)")
        with pytest.raises(PolicyDenied):
            session_state.read_session(home, "runB", "owned", 0)
        with pytest.raises(PolicyDenied):
            session_state.stop_session(home, "runB", "owned")
    finally:
        session_state._SESSIONS.pop("owned", None)


def test_orphaned_session_metadata_is_detected(tmp_path):
    from prestige import sessions as session_state

    home = tmp_path / "state"
    challenge = tmp_path / "challenge.txt"
    challenge.write_bytes(b"offline")
    store = Store(home)
    try:
        run_id = new_run(store, challenge)
        with store.transaction() as db:
            db.execute(
                "INSERT INTO sessions(session_id,run_id,container,command,pid,started,status) "
                "VALUES(?,?,?,?,?,?, 'running')",
                ("orphan1", run_id, "prestige-session-orphan1", "python3", 999999, 0.0),
            )
    finally:
        store.close()
    orphans = session_state.recover_sessions(home, run_id)
    assert orphans and orphans[0]["session_id"] == "orphan1"
    store = Store(home)
    try:
        row = store.rows(
            "SELECT status FROM sessions WHERE session_id='orphan1'"
        )[0]
        assert row["status"] == "orphaned"
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
