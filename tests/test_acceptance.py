"""End-to-end MCP acceptance flow across the active investigation features."""

import asyncio
import base64
import hashlib
import json
import os
from contextlib import asynccontextmanager
from pathlib import Path

import anyio
from mcp.client.session import ClientSession
from mcp.shared.message import SessionMessage

from prestige.commitments import add_commitment
from prestige.config import set_config
from prestige.mcp_server import serve_streams
from prestige.store import Store


def _skills_tree(root: Path) -> Path:
    for category in ("misc", "crypto", "reverse"):
        directory = root / f"ctf-{category}"
        directory.mkdir(parents=True)
        (directory / "SKILL.md").write_text(f"# ctf-{category}\n", encoding="utf-8")
        (directory / "INDEX.md").write_text(
            "# index\n\n## High-signal routes\n\n"
            "| Evidence or symptom | Start with |\n|---|---|\n"
            f"| {category} encoding evidence | [tools.md](tools.md) |\n\n"
            "## Cross-category pivots\n\n- pivot onward.\n",
            encoding="utf-8",
        )
        (directory / "tools.md").write_text(
            f"# {category} tools\n\nbase64 encoding workflow and transform.\n",
            encoding="utf-8",
        )
    for entry in ("solve-challenge", "ctf-writeup", "find-skills"):
        directory = root / entry
        directory.mkdir()
        (directory / "SKILL.md").write_text(f"# {entry}\n", encoding="utf-8")
    return root


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


async def test_full_active_investigation_flow(tmp_path):
    home = tmp_path / "state"
    root = _skills_tree(tmp_path / "skills")
    set_config(home, "skills.path", str(root))
    value = b"SYNTHETIC{end_to_end_mcp}"
    challenge = tmp_path / "challenge.txt"
    challenge.write_bytes(base64.b64encode(value))
    add_commitment(
        home,
        hashlib.sha256(challenge.read_bytes()).hexdigest(),
        hashlib.sha256(value).hexdigest(),
    )

    async with _mcp_client(home) as session:
        created = json.loads(
            (
                await session.call_tool(
                    "prestige_create_investigation",
                    {"source_path": str(challenge), "max_turns": 10},
                )
            ).content[0].text
        )
        assert created["status"] == "ready"
        assert created["commitment_applied"] is True
        run_id = created["run_id"]

        brief = json.loads(
            (
                await session.call_tool(
                    "prestige_skills_apply",
                    {
                        "run_id": run_id,
                        "evidence": "base64 encoding transform",
                        "query": "base64",
                    },
                )
            ).content[0].text
        )
        assert brief["result"]["primary"] == "ctf-crypto"

        hypothesis = json.loads(
            (
                await session.call_tool(
                    "prestige_hypothesis_add",
                    {
                        "run_id": run_id,
                        "text": "The artifact is base64-encoded plaintext",
                        "supports": ["base64 alphabet and padding"],
                        "prediction": "decoding yields ASCII",
                        "cheapest_test": "base64 transform",
                        "cost": "low",
                        "pivot_if": "decoded bytes are not ASCII",
                    },
                )
            ).content[0].text
        )
        assert hypothesis["result"]["status"] == "active"

        status = json.loads(
            (await session.call_tool("prestige_get_status", {"run_id": run_id})).content[0].text
        )
        artifact_id = status["artifacts"][0]["id"]

        derived = json.loads(
            (
                await session.call_tool(
                    "prestige_run_experiment",
                    {
                        "run_id": run_id,
                        "tool": "base64",
                        "artifact_id": artifact_id,
                        "args": {},
                    },
                )
            ).content[0].text
        )
        assert derived["status"] == "ok"
        derived_id = derived["result"]["artifact"]

        verified = json.loads(
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
        assert verified["verified"] is True
        assert verified["stage"] == "independently_verified"
        assert verified["reproduced"] is True

        resumed = json.loads(
            (
                await session.call_tool(
                    "prestige_resume_investigation", {"run_id": run_id}
                )
            ).content[0].text
        )
        assert resumed["status"] == "ready"
        assert resumed["attempts"] >= 1
        assert resumed["hypotheses"][0]["id"] == hypothesis["result"]["id"]
        assert resumed["candidates"][0]["verified"] is True

    store = Store(home)
    try:
        kinds = {event["kind"] for event in store.events(run_id)}
        assert {"skill_route", "hypothesis", "observation", "verified"} <= kinds
    finally:
        store.close()
