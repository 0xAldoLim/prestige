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
import time
from dataclasses import asdict
from typing import Any

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import CallToolResult, ListToolsResult, TextContent, Tool

from prestige.artifacts import Artifacts, ToolRegistry
from prestige.config import data_home, load_config
from prestige.engine import new_run
from prestige.human import answer_operator, pending_request, request_operator
from prestige.jobs import JobManager
from prestige.policy import validate_source_path
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


def _terminal(run: dict) -> bool:
    return run["status"] in {"solved", "stopped", "input_rejected", "budget_exhausted"}


# Deterministic tools can safely reuse prior evidence for the same inputs.
_DETERMINISTIC_TOOLS = {"inspect", "strings", "read", "file", "zip", "base64", "hex", "xor"}


def _find_cached_observation(store: Store, run_id: str, action: Action) -> Any | None:
    for event in reversed(store.events(run_id)):
        if event["kind"] != "observation":
            continue
        recorded = event["data"].get("action") or {}
        if (
            recorded.get("tool") == action.tool
            and recorded.get("artifact") == action.artifact
            and recorded.get("args") == action.args
        ):
            return event["data"].get("result")
    return None


_STATUS_FIELD_LIMIT = 4096


def _bound_observation(value: Any) -> Any:
    """Bound tool output returned in status so a noisy tool cannot flood context."""
    if isinstance(value, str):
        if len(value) <= _STATUS_FIELD_LIMIT:
            return value
        return value[: _STATUS_FIELD_LIMIT - 32] + "\n...[truncated by prestige]"
    if isinstance(value, list):
        return [_bound_observation(x) for x in value[:_STATUS_FIELD_LIMIT // 8]]
    if isinstance(value, dict):
        return {k: _bound_observation(v) for k, v in value.items()}
    return value


def _check_budget(run: dict, store: Store, run_id: str) -> float:
    """Persistently enforce max_turns and max_seconds for MCP-driven investigations."""
    settings = run["settings"]
    attempts = run["attempts"] + 1
    elapsed = time.time() - run["created"]
    if attempts > settings["max_turns"]:
        store.update(run_id, status="budget_exhausted", attempts=attempts, elapsed=elapsed)
        store.event(run_id, "halted", {"reason": "Tool attempt budget exhausted"})
        raise PrestigeError("Tool attempt budget exhausted")
    if elapsed >= settings["max_seconds"]:
        store.update(run_id, status="budget_exhausted", attempts=attempts, elapsed=elapsed)
        store.event(run_id, "halted", {"reason": "Wall-time budget exhausted"})
        raise PrestigeError("Wall-time budget exhausted")
    store.update(run_id, attempts=attempts, elapsed=elapsed)
    return elapsed


def _cap_timeout(action: Action, remaining: float) -> Action:
    """Ensure per-tool deadlines do not exceed the investigation's remaining budget."""
    if remaining <= 0:
        raise PrestigeError("No budget remaining for this tool")
    if action.tool not in {"radare2", "ghidra", "python", "command"}:
        return action
    defaults = {"radare2": 30, "ghidra": 300, "python": 15, "command": 15}
    requested = action.args.get("timeout", defaults[action.tool])
    if type(requested) not in (int, float) or requested <= 0:
        raise PolicyDenied("Invalid tool timeout")
    capped = min(requested, max(1.0, remaining))
    if capped != requested:
        return Action(action.tool, action.artifact, {**action.args, "timeout": capped})
    return action


async def _create_investigation(args: dict) -> dict:
    store = await _store()
    try:
        source = validate_source_path(args["source_path"], _HOME)
        backend = args.get("backend", "fake")
        if backend != "fake":
            raise PolicyDenied("OpenCode-native investigations use the fake backend")
        # The model may not expand trusted scope: rules, runner images and provider
        # configuration originate from operator-controlled configuration, not tool args.
        for forbidden in ("rules_path", "runner_image", "live", "openai_base_url", "openai_api_key", "openai_model"):
            if args.get(forbidden):
                raise PolicyDenied(f"{forbidden} cannot be set by the model")
        # Isolated execution uses the operator-controlled runner image, never a model-supplied one.
        runner_image = load_config(_HOME).get("sandbox.image")
        # Budgets come from the model request but are capped by a trusted ceiling.
        max_turns = min(max(1, args.get("max_turns", 12)), 1000)
        max_seconds = min(max(1.0, args.get("max_seconds", 120)), 3600)
        rules = Rules(max_turns=max_turns, max_seconds=max_seconds)
        run_id = new_run(
            store,
            source,
            mode=args.get("mode", "auto"),
            backend=backend,
            rules=rules,
            expected=args.get("expected_sha256"),
            max_turns=max_turns,
            max_seconds=max_seconds,
            max_tokens=args.get("max_tokens"),
            runner_image=runner_image,
            max_artifact_mib=args.get("max_artifact_mib", 1),
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
                prefix = artifacts.view(item["id"], 0, min(64, item["size"]))
            except PolicyDenied:
                prefix = b""
            material.append(
                {
                    "id": item["id"],
                    "label": item["label"],
                    "bytes": item["size"],
                    "magic_hex": prefix[:16].hex(),
                    "preview": prefix.decode("utf-8", errors="replace")[:64],
                }
            )
        events = store.events(run_id)
        observations = [
            _bound_observation(e["data"]) for e in events if e["kind"] == "observation"
        ][-8:]
        hypotheses = [e["data"]["text"] for e in events if e["kind"] == "hypothesis"][-8:]
        progress = [_bound_observation(e["data"]) for e in events if e["kind"] == "progress"][-3:]
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
                "pending_operator_request": pending_request(store, run_id),
            }
        )
    finally:
        store.close()


async def _run_experiment(args: dict) -> dict:
    store = await _store()
    try:
        run_id = args["run_id"]
        run = _run(store, run_id)
        if _terminal(run):
            raise PrestigeError("Investigation is terminal")
        elapsed = _check_budget(run, store, run_id)
        settings = run["settings"]
        rules = Rules(**settings["rules"])
        artifacts = Artifacts(store, run_id)
        runner = None
        if settings.get("runner_image"):
            from prestige.sandbox import WorkspaceRunner

            runner = WorkspaceRunner(settings["runner_image"], artifacts)
        registry = ToolRegistry(artifacts, rules.allowed_tools, runner)
        action = _cap_timeout(
            Action(
                args["tool"],
                args.get("artifact_id", ""),
                args.get("args", {}),
            ),
            settings["max_seconds"] - elapsed,
        )
        if action.tool in _DETERMINISTIC_TOOLS and not args.get("force", False):
            cached = _find_cached_observation(store, run_id, action)
            if cached is not None:
                return _redact({"status": "ok", "result": cached, "cached": True})
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
        run = _run(store, run_id)
        if _terminal(run):
            raise PrestigeError("Investigation is terminal")
        _check_budget(run, store, run_id)
        value = args["candidate"].encode("utf-8")
        artifact_id = args.get("artifact_id", "")
        derivation_id = args.get("derivation_artifact", "")
        expected = run["settings"].get("expected_digest")
        verified = False
        if expected:
            import hashlib

            verified = hashlib.sha256(value).hexdigest() == expected
        reproduced = False
        if derivation_id:
            # Byte-level derivation replay: the referenced artifact must contain
            # exactly the candidate bytes. This is not an official checker.
            reproduced = Artifacts(store, run_id).read(derivation_id) == value
        if verified:
            stage = "independently_verified"
        elif reproduced:
            stage = "reproduced"
        elif artifact_id:
            stage = "derived"
        else:
            stage = "discovered"
        store.candidate(run_id, artifact_id, value, verified)
        return {
            "verified": verified,
            "expected_available": bool(expected),
            "reproduced": reproduced,
            "stage": stage,
            "checker": "unavailable",
        }
    except PolicyDenied as error:
        return {"status": "denied", "reason": str(error)}
    except Exception as error:
        return {"status": "error", "reason": f"{type(error).__name__}: {error}"}
    finally:
        store.close()


async def _start_analysis(args: dict) -> dict:
    store = await _store()
    try:
        run_id = args["run_id"]
        run = _run(store, run_id)
        if _terminal(run):
            raise PrestigeError("Investigation is terminal")
        _check_budget(run, store, run_id)
        settings = run["settings"]
        rules = Rules(**settings["rules"])
        manager = JobManager(store, run_id)
        job_id = manager.start(
            args["artifact_id"],
            args["tool"],
            args.get("args", {}),
            rules=rules,
            runner_image=settings.get("runner_image"),
        )
        return {"job_id": job_id, "status": "queued"}
    except PolicyDenied as error:
        return {"status": "denied", "reason": str(error)}
    except Exception as error:
        return {"status": "error", "reason": f"{type(error).__name__}: {error}"}
    finally:
        store.close()


async def _get_analysis(args: dict) -> dict:
    store = await _store()
    try:
        result = JobManager(store, args["run_id"]).get(args["job_id"])
        return _redact({"status": "ok", "result": result})
    except Exception as error:
        return {"status": "error", "reason": f"{type(error).__name__}: {error}"}
    finally:
        store.close()


async def _cancel_analysis(args: dict) -> dict:
    store = await _store()
    try:
        result = JobManager(store, args["run_id"]).cancel(args["job_id"])
        return _redact({"status": "ok", "result": result})
    except Exception as error:
        return {"status": "error", "reason": f"{type(error).__name__}: {error}"}
    finally:
        store.close()


async def _request_operator(args: dict) -> dict:
    store = await _store()
    try:
        run_id = args["run_id"]
        run = _run(store, run_id)
        if _terminal(run):
            raise PrestigeError("Investigation is terminal")
        _check_budget(run, store, run_id)
        payload = request_operator(
            store, run_id, str(args["question"]), args.get("options") or []
        )
        return {
            "status": "waiting_for_operator",
            "request_id": payload["request_id"],
            "question": payload["question"],
            "options": payload["options"],
        }
    except PolicyDenied as error:
        return {"status": "denied", "reason": str(error)}
    except Exception as error:
        return {"status": "error", "reason": f"{type(error).__name__}: {error}"}
    finally:
        store.close()


async def _answer_operator(args: dict) -> dict:
    store = await _store()
    try:
        run_id = args["run_id"]
        _run(store, run_id)
        payload = answer_operator(
            store,
            run_id,
            str(args["request_id"]),
            str(args["answer"]),
            trust="operator_relayed",
        )
        return {
            "status": "ready",
            "request_id": payload["request_id"],
            "trust": payload["trust"],
        }
    except PolicyDenied as error:
        return {"status": "denied", "reason": str(error)}
    except Exception as error:
        return {"status": "error", "reason": f"{type(error).__name__}: {error}"}
    finally:
        store.close()


async def _resume_investigation(args: dict) -> dict:
    """Reconstruct a compact context after a model/session failure.

    This never resets budgets or repeats expensive work; it only summarizes
    durable state and points at the next meaningful action.
    """
    store = await _store()
    try:
        run_id = args["run_id"]
        run = _run(store, run_id)
        settings = run["settings"]
        events = store.events(run_id)
        pending = pending_request(store, run_id)
        jobs = [
            {
                "job_id": row["job_id"],
                "tool": row["tool"],
                "status": row["status"],
                "failure_class": row["failure_class"],
            }
            for row in JobManager(store, run_id).list()
            if row["status"] in {"queued", "running", "failed"}
        ]
        observations = [
            _bound_observation(event["data"])
            for event in events
            if event["kind"] == "observation"
        ][-3:]
        candidates = [
            {"digest": x["digest"], "verified": bool(x["verified"])}
            for x in store.rows(
                "SELECT digest,verified FROM candidates WHERE run_id=?", (run_id,)
            )
        ]
        elapsed = time.time() - run["created"]
        remaining_seconds = max(0.0, settings["max_seconds"] - elapsed)
        remaining_attempts = max(0, settings["max_turns"] - run["attempts"])
        next_actions = []
        if pending:
            next_actions.append(f"answer operator request {pending['request_id']}")
        running = [job for job in jobs if job["status"] in {"queued", "running"}]
        if running:
            next_actions.append(f"poll analysis job {running[0]['job_id']}")
        if remaining_attempts == 0 or remaining_seconds <= 0:
            next_actions.append("budget exhausted; stop and report evidence")
        elif run["status"] == "waiting_for_operator":
            next_actions.append("wait for the operator answer")
        else:
            next_actions.append("run the next discriminating experiment")
        return _redact(
            {
                "run_id": run_id,
                "status": run["status"],
                "lane": run["lane"],
                "backend": run["backend"],
                "artifacts": len(Artifacts(store, run_id).list()),
                "attempts": run["attempts"],
                "remaining_attempts": remaining_attempts,
                "remaining_seconds": round(remaining_seconds, 1),
                "recent_observations": observations,
                "candidates": candidates,
                "pending_operator_request": pending,
                "jobs": jobs,
                "next_actions": next_actions,
            }
        )
    except Exception as error:
        return {"status": "error", "reason": f"{type(error).__name__}: {error}"}
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
                    "backend": {"type": "string", "enum": ["fake"]},
                    "expected_sha256": {"type": "string"},
                    "max_turns": {"type": "integer"},
                    "max_seconds": {"type": "number"},
                    "max_tokens": {"type": "integer"},
                    "max_artifact_mib": {"type": "integer"},
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
            description=(
                "Execute one authorized PRESTIGE tool and record the observation. "
                "Tools: inspect, strings, file, zip, read, base64, hex, xor, radare2, ghidra. "
                "Use zip on an archive to extract member artifacts before analyzing them."
            ),
            inputSchema={
                "type": "object",
                "required": ["run_id", "tool"],
                "additionalProperties": False,
                "properties": {
                    "run_id": {"type": "string"},
                    "tool": {"type": "string"},
                    "artifact_id": {"type": "string"},
                    "args": {"type": "object"},
                    "force": {"type": "boolean"},
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
                    "derivation_artifact": {"type": "string"},
                },
            },
        ),
        _verify_candidate,
    ),
    "prestige_start_analysis": (
        Tool(
            name="prestige_start_analysis",
            description="Start a durable, cached analysis job (ghidra, radare2) without blocking the conversation.",
            inputSchema={
                "type": "object",
                "required": ["run_id", "tool", "artifact_id"],
                "additionalProperties": False,
                "properties": {
                    "run_id": {"type": "string"},
                    "tool": {"type": "string"},
                    "artifact_id": {"type": "string"},
                    "args": {"type": "object"},
                },
            },
        ),
        _start_analysis,
    ),
    "prestige_get_analysis": (
        Tool(
            name="prestige_get_analysis",
            description="Poll the status and result of a durable analysis job.",
            inputSchema={
                "type": "object",
                "required": ["run_id", "job_id"],
                "additionalProperties": False,
                "properties": {
                    "run_id": {"type": "string"},
                    "job_id": {"type": "string"},
                },
            },
        ),
        _get_analysis,
    ),
    "prestige_cancel_analysis": (
        Tool(
            name="prestige_cancel_analysis",
            description="Cancel a queued or running analysis job.",
            inputSchema={
                "type": "object",
                "required": ["run_id", "job_id"],
                "additionalProperties": False,
                "properties": {
                    "run_id": {"type": "string"},
                    "job_id": {"type": "string"},
                },
            },
        ),
        _cancel_analysis,
    ),
    "prestige_request_operator": (
        Tool(
            name="prestige_request_operator",
            description=(
                "Pause an investigation and record a structured question for the human "
                "operator. Use when evidence is genuinely blocked on missing scope, "
                "credentials or an authorization decision."
            ),
            inputSchema={
                "type": "object",
                "required": ["run_id", "question"],
                "additionalProperties": False,
                "properties": {
                    "run_id": {"type": "string"},
                    "question": {"type": "string"},
                    "options": {"type": "array", "items": {"type": "string"}},
                },
            },
        ),
        _request_operator,
    ),
    "prestige_answer_operator": (
        Tool(
            name="prestige_answer_operator",
            description=(
                "Relay a human operator's answer to a pending request. Answers are "
                "recorded as operator_relayed, not as independently verified evidence."
            ),
            inputSchema={
                "type": "object",
                "required": ["run_id", "request_id", "answer"],
                "additionalProperties": False,
                "properties": {
                    "run_id": {"type": "string"},
                    "request_id": {"type": "string"},
                    "answer": {"type": "string"},
                },
            },
        ),
        _answer_operator,
    ),
    "prestige_resume_investigation": (
        Tool(
            name="prestige_resume_investigation",
            description=(
                "Reconstruct a compact context after a model/session failure without "
                "resetting budgets or repeating expensive work."
            ),
            inputSchema={
                "type": "object",
                "required": ["run_id"],
                "additionalProperties": False,
                "properties": {"run_id": {"type": "string"}},
            },
        ),
        _resume_investigation,
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
