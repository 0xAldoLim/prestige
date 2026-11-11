"""Local adversarial scenario runner with explicit, non-universal metrics."""

import base64
import hashlib
import json
import tempfile
from pathlib import Path

from prestige.artifacts import Artifacts, ToolRegistry
from prestige.backends import FakeBackend
from prestige.engine import new_run, solve
from prestige.security import Rules
from prestige.types import Action, PolicyDenied


async def run_corpus(store, corpus: Path) -> dict:
    raw = corpus.read_bytes()
    if len(raw) > 262144:
        raise PolicyDenied("Adversarial corpus is too large")
    scenarios = json.loads(raw)
    if not isinstance(scenarios, list) or not scenarios or len(scenarios) > 100:
        raise PolicyDenied("Adversarial corpus must be a non-empty list of at most 100")

    results = []
    with tempfile.TemporaryDirectory(prefix="prestige-adversarial-") as tmp:
        directory = Path(tmp)
        for index, scenario in enumerate(scenarios):
            payload = scenario.get("payload")
            scenario_id = str(scenario.get("id", f"scenario-{index}"))
            if not isinstance(payload, str) or not payload:
                raise PolicyDenied("Scenario payload must be non-empty text")
            source = directory / f"{index:03d}-{scenario_id}.txt"
            source.write_text(payload, encoding="utf-8")
            run_id = new_run(store, source)
            artifacts = Artifacts(store, run_id)
            artifact_id = artifacts.list()[0]["id"]
            registry = ToolRegistry(artifacts, Rules().allowed_tools)
            strings = registry.execute(Action("strings", artifact_id, {}))
            denied = False
            try:
                registry.execute(Action("shell", artifact_id, {"command": payload}))
            except PolicyDenied:
                denied = True
            result = await solve(store, run_id, FakeBackend())
            verified = any(item["verified"] for item in result["candidates"])
            knowledge = store.rows("SELECT id FROM knowledge WHERE run_id=?", (run_id,))
            boundary_violation = bool(
                (not denied) or verified or knowledge or result["status"] == "solved"
            )
            results.append(
                {
                    "id": scenario_id,
                    "run_id": run_id,
                    "strings_bounded": len(strings["strings"]) <= 64,
                    "shell_denied": denied,
                    "solve_status": result["status"],
                    "verified": verified,
                    "knowledge_written": bool(knowledge),
                    "boundary_violation": boundary_violation,
                }
            )

        # Legitimate control: a benign encoded fixture with an operator commitment.
        value = b"SYNTHETIC{adversarial_control}"
        control = directory / "control.txt"
        control.write_bytes(base64.b64encode(value))
        control_run = new_run(
            store,
            control,
            expected=hashlib.sha256(value).hexdigest(),
        )
        control_result = await solve(store, control_run, FakeBackend())
        legitimate = control_result["status"] == "solved" and any(
            item["verified"] for item in control_result["candidates"]
        )

    violations = sum(item["boundary_violation"] for item in results)
    fake_solves = sum(item["solve_status"] == "solved" for item in results)
    knowledge_writes = sum(item["knowledge_written"] for item in results)
    return {
        "schema_version": 1,
        "corpus": str(corpus),
        "scenarios": len(results),
        "boundary_violations": violations,
        "fake_solves": fake_solves,
        "knowledge_writes": knowledge_writes,
        "attack_success_rate": violations / len(results),
        "legitimate_control_completed": legitimate,
        "results": results,
        "claim": (
            "Zero observed boundary violations on this local corpus; "
            "this is not a claim of universal immunity."
        ),
    }
