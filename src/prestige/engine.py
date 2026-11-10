import asyncio
import json
import os
import uuid
from dataclasses import asdict
from pathlib import Path

from prestige.artifacts import Artifacts, ToolRegistry, redact
from prestige.backends import FakeBackend
from prestige.knowledge import Knowledge, SkillsBridge
from prestige.progress import Budget, Progress, fingerprint
from prestige.security import Rules, require_remote
from prestige.store import Store
from prestige.types import PolicyDenied, PrestigeError
from prestige.verifier import validate_expected_digest, verify_candidates


def new_run(
    store: Store,
    source: Path,
    *,
    mode="auto",
    backend="fake",
    rules=None,
    expected=None,
    max_turns=12,
    max_seconds=120,
    max_tokens=None,
    instance=None,
    live=False,
    runner_image=None,
    max_artifact_mib=1,
    openai_base_url=None,
    openai_api_key=None,
    openai_model=None,
):
    rules = rules or Rules()
    rules.check()
    validate_expected_digest(expected)
    if instance:
        require_remote()
    if mode not in {"auto", "fast", "expert"}:
        raise PrestigeError("Unknown solving mode")
    if (
        not 1 <= max_turns <= 1000
        or not 0 < max_seconds <= 86400
        or (max_tokens is not None and max_tokens < 1)
    ):
        raise PrestigeError("Invalid run budget")
    if live and backend != "codex":
        raise PrestigeError("--live requires the codex backend")
    if backend == "openai" and (not openai_base_url or not openai_api_key or not openai_model):
        raise PrestigeError("openai backend requires base URL, API key and model")
    if runner_image is not None:
        from prestige.sandbox import DockerRunner

        DockerRunner(runner_image)  # validates immutable digest format
    if not 1 <= max_artifact_mib <= 256:
        raise PrestigeError("max-artifact-mib must be between 1 and 256")
    # Provider secrets are never persisted in investigation state.
    run_id = store.create_run(
        mode,
        backend,
        {
            "rules": rules.snapshot(),
            "expected_digest": expected,
            "max_turns": min(max_turns, rules.max_turns),
            "max_seconds": min(max_seconds, rules.max_seconds),
            "max_tokens": max_tokens,
            "live": live,
            "runner_image": runner_image,
            "max_artifact_mib": max_artifact_mib,
            "openai_base_url": openai_base_url,
            "openai_model": openai_model,
        },
    )
    try:
        Artifacts(store, run_id).inventory(source)
    except BaseException:
        store.update(run_id, status="input_rejected")
        raise
    store.event(run_id, "rules", {"restrictions": rules.snapshot(), "remote": "disabled"})
    return run_id


async def solve(
    store: Store,
    run_id: str,
    backend=None,
    skills: SkillsBridge | None = None,
    runner=None,
):
    run = store.run(run_id)
    if run["status"] in {"solved", "stopped", "input_rejected"}:
        raise PrestigeError("Run is terminal; create a new run to change its policy or budget")
    settings = run["settings"]
    if backend is None:
        if run["backend"] == "fake":
            backend = FakeBackend()
        elif run["backend"] == "codex":
            from prestige.codex_sdk import CodexBackend

            backend = CodexBackend(
                store.home / "provider-workspace",
                run["session"],
                live=settings.get("live", False),
            )
        elif run["backend"] == "openai":
            from prestige.openai_backend import OpenAIBackend

            api_key = settings.get("openai_api_key") or os.environ.get("PRESTIGE_OPENAI_API_KEY")
            if not api_key:
                raise PrestigeError(
                    "openai backend requires PRESTIGE_OPENAI_API_KEY or an explicit key"
                )
            backend = OpenAIBackend(
                settings["openai_base_url"],
                api_key,
                settings["openai_model"],
                workspace=store.home / "provider-workspace",
            )
        else:
            raise PrestigeError("Unsupported solver backend")
    artifacts = Artifacts(store, run_id)
    skills = skills or SkillsBridge()
    knowledge = Knowledge(store, skills)
    rules = Rules(**settings["rules"])
    rules.check()
    if runner is None and settings.get("runner_image"):
        from prestige.sandbox import WorkspaceRunner

        runner = WorkspaceRunner(settings["runner_image"], artifacts)
    registry = ToolRegistry(artifacts, rules.allowed_tools, runner)
    budget = Budget(
        settings["max_turns"],
        settings["max_seconds"],
        settings["max_tokens"],
        run["turns"],
        run["tokens"],
        run["elapsed"],
    )
    history = store.events(run_id)
    actions = [event["data"]["action"] for event in history if event["kind"] == "action"]
    progress = Progress(
        seen={event["data"]["fingerprint"] for event in history if event["kind"] == "action"}
    )
    unknown = run["unknown_usage"]
    attempts = run["attempts"]
    owner = uuid.uuid4().hex
    store.acquire(run_id, owner, settings["max_seconds"] + 60)
    store.update(run_id, status="running")
    lane = run["lane"]

    def checkpoint():
        store.update(
            run_id,
            turns=budget.turns,
            tokens=budget.tokens,
            unknown_usage=unknown,
            elapsed=budget.elapsed,
            lane=lane,
            session=backend.session_id,
            attempts=attempts,
        )

    async def monitored(coro):
        task = asyncio.create_task(coro)
        try:
            while not task.done():
                if store.run(run_id)["status"] in {"paused", "stopped"}:
                    raise asyncio.CancelledError
                if budget.elapsed >= budget.max_seconds:
                    raise TimeoutError("Wall-time budget exhausted")
                await asyncio.wait(
                    {task}, timeout=min(0.2, max(0.001, budget.max_seconds - budget.elapsed))
                )
            return task.result()
        finally:
            if not task.done():
                await backend.interrupt()
                task.cancel()
                await asyncio.gather(task, return_exceptions=True)

    try:
        while True:
            if store.run(run_id)["status"] in {"paused", "stopped"}:
                raise asyncio.CancelledError
            if verify_candidates(artifacts, settings["expected_digest"]):
                store.update(run_id, status="solved")
                store.event(run_id, "verified", {"method": "trusted_digest_and_derivation_replay"})
                store.event(run_id, "learning", knowledge.capture(artifacts))
                break
            budget.check()
            material = []
            for item in artifacts.list():
                prefix = artifacts.view(item["id"], 0, min(4096, item["size"]))
                material.append(
                    {
                        "id": item["id"],
                        "bytes": item["size"],
                        "magic_hex": prefix[:16].hex(),
                        "preview": redact(prefix.decode("utf-8", errors="replace")),
                    }
                )
            query = " ".join(x["tool"] for x in actions[-3:]) or "file encoding"
            categories = skills.route(material[0]["magic_hex"] if material else "", query)
            retrieval = knowledge.search(query) or skills.search(query)
            context = {
                "lane": lane,
                "allowed_tools": list(rules.allowed_tools),
                "artifacts": material[-16:],
                "actions": actions[-24:],
                "categories": categories,
                "retrieval": retrieval,
                "observations": [
                    x["data"] for x in store.events(run_id) if x["kind"] == "observation"
                ][-6:],
            }
            store.event(
                run_id,
                "routing",
                {
                    "categories": categories,
                    "sources": [x.get("path", x.get("id")) for x in retrieval],
                },
            )
            attempts += 1
            checkpoint()
            proposal = await monitored(backend.propose(context))
            budget.turns += 1
            if proposal.usage.total is None:
                unknown += 1
            else:
                budget.tokens += proposal.usage.total
            store.event(run_id, "usage", asdict(proposal.usage))
            store.event(
                run_id,
                "hypothesis",
                {"text": redact(proposal.hypothesis[:2000]), "trust": "hypothesis"},
            )
            checkpoint()
            if settings["max_tokens"] is not None and budget.tokens >= settings["max_tokens"]:
                raise PrestigeError("Reported token budget exhausted; last turn may overshoot")
            if proposal.action is None:
                if lane == "fast" and run["mode"] == "auto":
                    lane = "expert"
                    store.event(
                        run_id,
                        "escalation",
                        {"from": "fast", "to": "expert", "evidence_count": len(artifacts.list())},
                    )
                    continue
                store.update(run_id, status="unsolved")
                break
            action = proposal.action
            key = fingerprint(action)
            duplicate = key in progress.seen
            store.event(run_id, "action", {"action": asdict(action), "fingerprint": key})
            actions.append(asdict(action))
            before = len(artifacts.list())
            try:
                if duplicate:
                    raise PolicyDenied("Repeated action suppressed")
                task = asyncio.to_thread(registry.execute, action)
                try:
                    result = await task
                except asyncio.CancelledError:
                    if runner is not None:
                        runner.cancel()
                    raise
                store.event(
                    run_id, "observation", {"action": key, "result": result, "trust": "fact"}
                )
                recovery = progress.observe(action, len(artifacts.list()) > before)
            except PolicyDenied as error:
                store.event(run_id, "policy_denied", {"action": key, "reason": str(error)})
                recovery = progress.observe(action, False, True)
            store.event(
                run_id,
                "progress",
                {
                    "turns": budget.turns,
                    "attempts": attempts,
                    "tokens": budget.tokens,
                    "elapsed": round(budget.elapsed, 3),
                    "novel_artifacts": len(artifacts.list()),
                    "recovery": recovery,
                },
            )
            if recovery == "recover":
                if lane == "fast" and run["mode"] == "auto":
                    lane = "expert"
                    progress.stale = 0
                    store.event(
                        run_id,
                        "escalation",
                        {"from": "fast", "to": "expert", "evidence_count": len(artifacts.list())},
                    )
                else:
                    store.update(run_id, status="unsolved")
                    store.event(
                        run_id,
                        "stalled",
                        {"reason": "No discriminating progress after two actions"},
                    )
                    break
            checkpoint()
    except (asyncio.CancelledError, KeyboardInterrupt):
        await backend.interrupt()
        if store.run(run_id)["status"] != "stopped":
            store.update(run_id, status="paused")
        store.event(run_id, "paused", {"reason": "Interrupted; durable checkpoint retained"})
    except (PrestigeError, TimeoutError) as error:
        store.update(
            run_id, status="blocked" if isinstance(error, PolicyDenied) else "budget_exhausted"
        )
        store.event(run_id, "halted", {"reason": str(error)})
    except Exception as error:
        store.update(run_id, status="failed")
        store.event(run_id, "backend_error", {"type": type(error).__name__})
        raise
    finally:
        checkpoint()
        try:
            await backend.close()
        finally:
            store.release(run_id, owner)
            export_views(store, run_id)
    return report(store, run_id)


def report(store: Store, run_id: str, reveal=False):
    run = store.run(run_id)
    candidates = store.rows(
        "SELECT digest,artifact,verified,value FROM candidates WHERE run_id=?", (run_id,)
    )
    result = {
        "run_id": run_id,
        "status": run["status"],
        "lane": run["lane"],
        "backend": run["backend"],
        "turns": run["turns"],
        "attempts": run["attempts"],
        "known_tokens": run["tokens"],
        "tokens": None if run["unknown_usage"] else run["tokens"],
        "unknown_usage_turns": run["unknown_usage"],
        "seconds": round(run["elapsed"], 3),
        "candidates": [
            {
                "digest": x["digest"],
                "artifact": x["artifact"],
                "verified": bool(x["verified"]),
                **({"value": x["value"].decode("utf-8", errors="replace")} if reveal else {}),
            }
            for x in candidates
        ],
        "remote_enabled": False,
        "last_events": [{"kind": e["kind"], "data": e["data"]} for e in store.events(run_id)[-3:]],
    }
    return result


def export_views(store: Store, run_id: str):
    directory = store.home / "runs" / run_id / "solve"
    directory.mkdir(parents=True, exist_ok=True)
    state = report(store, run_id)
    (directory / "STATE.md").write_text(
        "# Investigation state\n\n```json\n" + json.dumps(state, indent=2) + "\n```\n",
        encoding="utf-8",
    )
    hypotheses = [e["data"]["text"] for e in store.events(run_id) if e["kind"] == "hypothesis"]
    (directory / "HYPOTHESES.md").write_text(
        "# Unverified hypotheses\n\n" + "\n".join("- " + x for x in hypotheses) + "\n",
        encoding="utf-8",
    )
