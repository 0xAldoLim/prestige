"""MCP server exposing PRESTIGE's trusted investigation broker to OpenCode.

OpenCode owns the generic agent loop and model transport. PRESTIGE owns:
- investigation identity and scope,
- challenge strategy and tool authorization,
- evidence persistence,
- progress evaluation,
- candidate verification.

The server speaks stdio MCP. It does not open a network listener.
"""

import asyncio
import json
from dataclasses import asdict
from pathlib import Path
from typing import Any

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import CallToolResult, ListToolsResult, TextContent, Tool

from prestige.artifacts import Artifacts, ToolRegistry
from prestige.config import data_home
from prestige.engine import new_run
from prestige.security import Rules
from prestige.store import Store
from prestige.types import Action, PolicyDenied, PrestigeError

_HOME = data_home()


async def _store() -> Store:
    return Store(_HOME)


def _run(store: Store, run_id: str) -> dict:
    return store.run(run_id)


def _redact(value: Any) -> Any:
    """Strip candidate values and secrets from returned context."""
    if isinstance(value, str):
        from prestige.artifacts import redact

        return redact(value)
    if isinstance(value, list):
        return [_redact(x) for x in value]
    if isinstance(value, dict):
        return {k: _redact(v) for k, v in value.items()}
    return value


async def _create_investigation(args: dict) -> dict:
    store = await _store()
    try:
        source = Path(args["source_path"]).resolve()
        backend = args.get("backend", "openai")
        run_id = new_run(
            store,
            source,
            mode=args.get("mode", "auto"),
            backend=backend,
            rules=Rules.load(Path(args["rules_path"])) if args.get("rules_path") else None,
            expected=args.get("expected_sha256"),
            max_turns=args.get("max_turns", 12),
            max_seconds=args.get("max_seconds", 120),
            max_tokens=args.get("max_tokens"),
            live=args.get("live", False),
            runner_image=args.get("runner_image"),
            max_artifact_mib=args.get("max_artifact_mib", 1),
            openai_base_url=args.get("openai_base_url"),
            openai_api_key=args.get("openai_api_key"),
            openai_model=args.get("openai_model"),
        )
        return {"run_id": run_id, "status": "ready"}
    finally:
        store.close()


async def _get_status(args: dict) -> dict:
    store = await _store()
    try:
        run_id = args["run_id"]
        run = _run(store, run_id)
        artifacts = Artifacts(store, run_id)
        material = []
        for item in artifacts.list():
            try:
                prefix = artifacts.view(item["id"], 0, min(4096, item["size"]))
            except PolicyDenied:
                prefix = b""
            material.append(
                {
                    "id": item["id"],
                    "label": item["label"],
                    "bytes": item["size"],
                    "magic_hex": prefix[:16].hex(),
                    "preview": prefix.decode("utf-8", errors="replace")[:512],
                }
            )
        events = store.events(run_id)
        observations = [e["data"] for e in events if e["kind"] == "observation"][-8:]
        hypotheses = [e["data"]["text"] for e in events if e["kind"] == "hypothesis"][-8:]
        progress = [e["data"] for e in events if e["kind"] == "progress"][-3:]
        candidates = [
            {"digest": x["digest"], "verified": bool(x["verified"])}
            for x in store.rows(
                "SELECT digest,verified FROM candidates WHERE run_id=?", (run_id,)
            )
        ]
        return _redact(
            {
                "run_id": run_id,
                "status": run["status"],
                "lane": run["lane"],
                "backend": run["backend"],
                "turns": run["turns"],
                "attempts": run["attempts"],
                "tokens": run["tokens"],
                "seconds": round(run["elapsed"], 3),
                "artifacts": material,
                "observations": observations,
                "hypotheses": hypotheses,
                "progress": progress,
                "candidates": candidates,
            }
        )
    finally:
        store.close()


async def _run_experiment(args: dict) -> dict:
    store = await _store()
    try:
        run_id = args["run_id"]
        run = _run(store, run_id)
        if run["status"] in {"solved", "stopped", "input_rejected"}:
            raise PrestigeError("Investigation is terminal")
        settings = run["settings"]
        rules = Rules(**settings["rules"])
        artifacts = Artifacts(store, run_id)
        runner = None
        if settings.get("runner_image"):
            from prestige.sandbox import WorkspaceRunner

            runner = WorkspaceRunner(settings["runner_image"], artifacts)
        registry = ToolRegistry(artifacts, rules.allowed_tools, runner)
        action = Action(
            args["tool"],
            args.get("artifact_id", ""),
            args.get("args", {}),
        )
        result = await asyncio.to_thread(registry.execute, action)
        store.event(run_id, "observation", {"action": asdict(action), "result": result, "trust": "fact"})
        return _redact({"status": "ok", "result": result})
    except PolicyDenied as error:
        return {"status": "denied", "reason": str(error)}
    except Exception as error:
        return {"status": "error", "reason": f"{type(error).__name__}: {error}"}
    finally:
        store.close()


async def _verify_candidate(args: dict) -> dict:
    store = await _store()
    try:
        run_id = args["run_id"]
        value = args["candidate"].encode("utf-8")
        artifact_id = args.get("artifact_id", "")
        expected = _run(store, run_id)["settings"].get("expected_digest")
        verified = False
        if expected:
            import hashlib

            verified = hashlib.sha256(value).hexdigest() == expected
        store.candidate(run_id, artifact_id, value, verified)
        return {"candidate": args["candidate"], "verified": verified, "expected_available": bool(expected)}
    finally:
        store.close()


_TOOLS: dict[str, tuple[Tool, Any]] = {
    "prestige_create_investigation": (
        Tool(
            name="prestige_create_investigation",
            description="Create a new PRESTIGE investigation for a local challenge.",
            inputSchema={
                "type": "object",
                "required": ["source_path"],
                "additionalProperties": False,
                "properties": {
                    "source_path": {"type": "string"},
                    "mode": {"type": "string", "enum": ["fast", "expert", "auto"]},
                    "backend": {"type": "string", "enum": ["fake", "codex", "openai"]},
                    "rules_path": {"type": "string"},
                    "expected_sha256": {"type": "string"},
                    "max_turns": {"type": "integer"},
                    "max_seconds": {"type": "number"},
                    "max_tokens": {"type": "integer"},
                    "live": {"type": "boolean"},
                    "runner_image": {"type": "string"},
                    "max_artifact_mib": {"type": "integer"},
                    "openai_base_url": {"type": "string"},
                    "openai_api_key": {"type": "string"},
                    "openai_model": {"type": "string"},
                },
            },
        ),
        _create_investigation,
    ),
    "prestige_get_status": (
        Tool(
            name="prestige_get_status",
            description="Get the current investigation state, artifacts, observations and budget.",
            inputSchema={
                "type": "object",
                "required": ["run_id"],
                "additionalProperties": False,
                "properties": {"run_id": {"type": "string"}},
            },
        ),
        _get_status,
    ),
    "prestige_run_experiment": (
        Tool(
            name="prestige_run_experiment",
            description="Execute one authorized PRESTIGE tool and record the observation.",
            inputSchema={
                "type": "object",
                "required": ["run_id", "tool"],
                "additionalProperties": False,
                "properties": {
                    "run_id": {"type": "string"},
                    "tool": {"type": "string"},
                    "artifact_id": {"type": "string"},
                    "args": {"type": "object"},
                },
            },
        ),
        _run_experiment,
    ),
    "prestige_verify_candidate": (
        Tool(
            name="prestige_verify_candidate",
            description="Record a candidate solution and verify it against an expected digest if available.",
            inputSchema={
                "type": "object",
                "required": ["run_id", "candidate"],
                "additionalProperties": False,
                "properties": {
                    "run_id": {"type": "string"},
                    "candidate": {"type": "string"},
                    "artifact_id": {"type": "string"},
                },
            },
        ),
        _verify_candidate,
    ),
}


async def _on_list_tools(_ctx, _params):
    return ListToolsResult(tools=[tool for tool, _ in _TOOLS.values()])


async def _on_call_tool(_ctx, params):
    name = params.name
    arguments = params.arguments or {}
    if name not in _TOOLS:
        return CallToolResult(
            isError=True, content=[TextContent(type="text", text=json.dumps({"error": "unknown tool"}))]
        )
    try:
        result = await _TOOLS[name][1](arguments)
        return CallToolResult(content=[TextContent(type="text", text=json.dumps(result, ensure_ascii=True))])
    except Exception as error:
        return CallToolResult(
            isError=True,
            content=[TextContent(type="text", text=json.dumps({"error": f"{type(error).__name__}: {error}"}))],
        )


def build_server() -> Server:
    return Server("prestige", on_list_tools=_on_list_tools, on_call_tool=_on_call_tool)


async def serve_streams(read_stream, write_stream) -> None:
    """Run the PRESTIGE MCP server over arbitrary transport streams."""
    server = build_server()
    await server.run(read_stream, write_stream, server.create_initialization_options())


async def serve_stdio() -> None:
    """Run the PRESTIGE MCP server over stdio."""
    server = build_server()
    async with stdio_server() as (read_stream, write_stream):
        await server.run(read_stream, write_stream, server.create_initialization_options())


async def main():
    await serve_stdio()


if __name__ == "__main__":
    asyncio.run(main())
