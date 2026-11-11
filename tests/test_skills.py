"""Owner-skills integration: discovery, routing, search, reads, pivots and MCP wiring."""

import asyncio
import json
import os
from contextlib import asynccontextmanager
from pathlib import Path

import anyio
import pytest
from mcp.client.session import ClientSession
from mcp.shared.message import SessionMessage

from prestige.config import set_config
from prestige.engine import new_run
from prestige.knowledge import CATEGORIES, SkillsBridge
from prestige.mcp_server import serve_streams
from prestige.store import Store
from prestige.types import PolicyDenied

EVIDENCE = {
    "crypto": "RSA modulus and nonce reuse with a signature",
    "reverse": "ELF binary with a custom VM and anti-debug checks",
    "forensics": "pcap capture with a disk image and png metadata",
    "web": "HTTP cookie and SQL injection in a Flask app",
    "pwn": "stack overflow with libc and a ROP chain",
    "misc": "base64 encoding puzzle with unicode",
    "osint": "geolocation from an image and username search",
    "ai-ml": "neural model weights and adversarial prompt injection",
    "malware": "malware loader with C2 beacon and YARA rules",
}


def build_skills(root: Path) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    for category in CATEGORIES:
        directory = root / f"ctf-{category}"
        directory.mkdir()
        (directory / "SKILL.md").write_text(
            f"# ctf-{category}\n\nCategory workflow for {category}.\n", encoding="utf-8"
        )
        (directory / "INDEX.md").write_text(
            "# index\n\n"
            "## High-signal routes\n\n"
            "| Evidence or symptom | Start with |\n"
            "|---|---|\n"
            f"| {category} evidence | [tools.md](tools.md) |\n\n"
            "## Cross-category pivots\n\n"
            f"- {category} followed by a neighboring category.\n",
            encoding="utf-8",
        )
        (directory / "tools.md").write_text(
            f"# {category} tools\n\nUse the {category} workflow. {EVIDENCE[category]}.\n\n"
            "## Details\n\nA bounded reference paragraph.\n",
            encoding="utf-8",
        )
        (directory / "LEARNED.md").write_text(
            f"# learned {category}\n\n- Verified {category} technique.\n", encoding="utf-8"
        )
    for entry in ("solve-challenge", "ctf-writeup", "find-skills"):
        directory = root / entry
        directory.mkdir()
        (directory / "SKILL.md").write_text(f"# {entry}\n", encoding="utf-8")
    return root


@asynccontextmanager
async def _mcp_client(home: Path):
    env = {"PRESTIGE_HOME": str(home), "PRESTIGE_ALLOWED_DIRS": str(home)}
    old = os.environ.copy()
    os.environ.update(env)
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


def test_discover_all_categories_and_entrypoints(tmp_path):
    root = build_skills(tmp_path / "skills")
    discovered = SkillsBridge(root).discover()
    assert discovered["configured"] is True
    assert len(discovered["categories"]) == 9
    assert {item["category"] for item in discovered["categories"]} == set(CATEGORIES)
    assert {item["skill"] for item in discovered["entrypoints"]} == {
        "solve-challenge", "ctf-writeup", "find-skills"
    }


@pytest.mark.parametrize("category", CATEGORIES)
def test_route_each_category(tmp_path, category):
    root = build_skills(tmp_path / "skills")
    routed = SkillsBridge(root).route_problem(EVIDENCE[category])
    assert routed["primary"] == f"ctf-{category}"
    assert routed["primary_category"] == category


def test_route_executable_magic_prefers_reverse(tmp_path):
    root = build_skills(tmp_path / "skills")
    routed = SkillsBridge(root).route_problem("reverse binary anti-debug", magic="7f454c46")
    assert routed["primary"] == "ctf-reverse"
    assert routed["references"]


def test_search_returns_provenance_and_bounds(tmp_path):
    root = build_skills(tmp_path / "skills")
    hits = SkillsBridge(root).search("rsa", limit=3, category="crypto")
    assert hits
    assert hits[0]["path"].startswith("ctf-crypto/")
    assert hits[0]["line"] >= 1
    assert len(hits[0]["sha256"]) == 64
    assert hits[0]["trust"] == "external_untrusted"


def test_read_section_and_traversal_denied(tmp_path):
    root = build_skills(tmp_path / "skills")
    bridge = SkillsBridge(root)
    section = bridge.read_section("ctf-crypto/tools.md", line=1, lines=5)
    assert section["path"] == "ctf-crypto/tools.md"
    assert section["sha256"]
    assert "crypto" in section["text"]
    for bad in ("../outside.md", "/etc/passwd", "ctf-crypto/../../x"):
        with pytest.raises(PolicyDenied):
            bridge.read_section(bad)
    with pytest.raises(PolicyDenied):
        bridge.read_section("ctf-crypto/tools.md", line=1, lines=500)


def test_pivots_and_brief_change_strategy(tmp_path):
    root = build_skills(tmp_path / "skills")
    bridge = SkillsBridge(root)
    assert bridge.pivots("reverse")
    reverse = bridge.brief("ELF binary with anti-debug", query="anti-debug", magic="7f454c46")
    web = bridge.brief("HTTP cookie and SQL injection", query="sql")
    assert reverse["primary"] == "ctf-reverse"
    assert web["primary"] == "ctf-web"
    assert reverse["primary"] != web["primary"]
    assert reverse["trust"] == "external_untrusted"


async def test_mcp_skills_tools_and_strategy_event(tmp_path):
    root = build_skills(tmp_path / "skills")
    home = tmp_path / "state"
    set_config(home, "skills.path", str(root))
    store = Store(home)
    try:
        challenge = tmp_path / "challenge.bin"
        challenge.write_bytes(b"\x7fELF" + b"\x00" * 60)
        run_id = new_run(store, challenge)
    finally:
        store.close()

    async with _mcp_client(home) as session:
        discovered = json.loads(
            (await session.call_tool("prestige_skills_discover", {})).content[0].text
        )
        assert discovered["status"] == "ok"
        assert len(discovered["result"]["categories"]) == 9

        routed = json.loads(
            (
                await session.call_tool(
                    "prestige_skills_route",
                    {"evidence": "ELF binary with anti-debug", "magic_hex": "7f454c46"},
                )
            ).content[0].text
        )
        assert routed["result"]["primary"] == "ctf-reverse"

        searched = json.loads(
            (
                await session.call_tool(
                    "prestige_skills_search", {"query": "reverse", "category": "reverse"}
                )
            ).content[0].text
        )
        assert searched["result"]

        applied = json.loads(
            (
                await session.call_tool(
                    "prestige_skills_apply",
                    {
                        "run_id": run_id,
                        "evidence": "ELF binary with anti-debug",
                        "magic_hex": "7f454c46",
                    },
                )
            ).content[0].text
        )
        assert applied["result"]["primary"] == "ctf-reverse"

    store = Store(home)
    try:
        kinds = [event["kind"] for event in store.events(run_id)]
        assert "skill_route" in kinds
    finally:
        store.close()
