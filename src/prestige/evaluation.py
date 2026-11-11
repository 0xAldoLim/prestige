"""Reproducible fixture runs and strict comparison gates; no invented model baselines."""

import asyncio
import hashlib
import json
import math
import random
from pathlib import Path

from prestige.engine import new_run, solve
from prestige.store import Store
from prestige.types import PolicyDenied, PrestigeError

CONDITIONS = {
    "B0": "plain Codex",
    "B1": "Codex plus owner skills",
    "P1": "FAST",
    "P2": "AUTO",
    "P3": "EXPERT",
}
EQUALITY_FIELDS = (
    "suite_hash",
    "model",
    "effort",
    "permissions",
    "max_turns",
    "max_seconds",
    "workers",
)


def wilson(successes: int, count: int) -> list[float] | None:
    if count == 0:
        return None
    z = 1.959963984540054
    p = successes / count
    scale = 1 + z * z / count
    center = (p + z * z / (2 * count)) / scale
    radius = z * math.sqrt(p * (1 - p) / count + z * z / (4 * count * count)) / scale
    return [max(0, center - radius), min(1, center + radius)]


def metrics(results: list[dict]) -> dict:
    solved = sum(item["status"] == "solved" for item in results)
    points = sum(item["points"] for item in results if item["status"] == "solved")
    complete = all(item.get("tokens") is not None for item in results)
    tokens = sum(item.get("tokens") or 0 for item in results) if complete else None
    costs = [item.get("cost") for item in results]
    known_cost = sum(costs) if costs and all(value is not None for value in costs) else None
    return {
        "count": len(results),
        "solved": solved,
        "verified_points": points,
        "verified": sum(bool(item.get("verified")) for item in results),
        "verification_strength": "digest_or_replay"
        if results and all(item.get("verified") for item in results)
        else "mixed_or_unverified",
        "solve_rate_ci95": wilson(solved, len(results)),
        "tokens": tokens,
        "known_cost": known_cost,
        "points_per_1000_tokens": points * 1000 / tokens
        if tokens
        else (0 if not points and complete else None),
        "seconds": sum(item.get("seconds", 0) for item in results),
        "tool_calls": sum(item.get("tool_calls", 0) for item in results),
        "failed_experiments": sum(item.get("failed_experiments", 0) for item in results),
        "skills_used": sum(item.get("skills_used", 0) for item in results),
        "security_violations": sum(item.get("security_violations", 0) for item in results),
        "usage_coverage": sum(item.get("tokens") is not None for item in results) / len(results)
        if results
        else 0,
        "composite": "not_comparable",
    }


def compare(left: dict, right: dict) -> dict:
    if any(
        key not in result.get("contract", {}) for result in (left, right) for key in EQUALITY_FIELDS
    ):
        raise PolicyDenied("Benchmark contract is incomplete")
    if any(left["contract"].get(k) != right["contract"].get(k) for k in EQUALITY_FIELDS):
        raise PolicyDenied("Benchmark contracts differ; comparison rejected")
    left_cases = {(x["case"], x["repeat"]) for x in left["results"]}
    right_cases = {(x["case"], x["repeat"]) for x in right["results"]}
    if len(left_cases) != len(left["results"]) or len(right_cases) != len(right["results"]):
        raise PolicyDenied("Duplicate benchmark case/repetition results")
    if left_cases != right_cases:
        raise PolicyDenied("Missing failed/unsolved cases or unequal repetitions")
    return {
        "comparable_inputs": True,
        "left": metrics(left["results"]),
        "right": metrics(right["results"]),
        "performance_claim": "none; fixture results do not establish superiority over Codex + skills",
    }


def _suite_jobs(suite: Path, repetitions: int, seed: int):
    if not 1 <= repetitions <= 20:
        raise PrestigeError("Repetitions must be in 1..20")
    raw = suite.read_bytes()
    if len(raw) > 65536:
        raise PolicyDenied("Suite too large")
    manifest = json.loads(raw)
    cases = manifest["cases"]
    if not isinstance(cases, list) or len(cases) > 50:
        raise PolicyDenied("Invalid suite size")
    jobs, hashes = [], []
    for case in cases:
        artifact = (suite.parent / case["file"]).resolve()
        if not artifact.is_relative_to(suite.parent.resolve()) or not artifact.is_file():
            raise PolicyDenied("Benchmark artifact escapes suite")
        digest = hashlib.sha256(artifact.read_bytes()).hexdigest()
        if digest != case["artifact_sha256"]:
            raise PolicyDenied("Benchmark artifact hash changed")
        hashes.append(digest)
        for repeat in range(repetitions):
            jobs.append((case, artifact, repeat))
    random.Random(seed).shuffle(jobs)
    suite_hash = hashlib.sha256(raw + "".join(hashes).encode()).hexdigest()
    return suite_hash, jobs


async def benchmark(
    store: Store,
    suite: Path,
    repetitions=1,
    seed=2026,
    lane: str = "auto",
    condition: str = "fixture-worker",
) -> dict:
    if lane not in {"fast", "auto", "expert"}:
        raise PolicyDenied("Unknown benchmark lane")
    suite_hash, jobs = _suite_jobs(suite, repetitions, seed)
    results = []
    for case, artifact, repeat in jobs:
        run_id = new_run(store, artifact, expected=case["expected_sha256"], mode=lane)
        result = await solve(store, run_id)
        results.append({**result, "case": case["id"], "repeat": repeat, "points": case["points"]})
    return {
        "condition": condition,
        "model_evaluation": False,
        "contract": {
            "suite_hash": suite_hash,
            "model": "fake",
            "effort": lane,
            "permissions": "bounded-offline-tools",
            "max_turns": 12,
            "max_seconds": 120,
            "workers": 1,
        },
        "seed": seed,
        "results": results,
        "metrics": metrics(results),
        "baselines": {key: "not run" for key in CONDITIONS},
    }


async def _adapter_condition(
    store: Store,
    suite: Path,
    condition: str,
    adapter,
    repetitions: int,
    seed: int,
) -> dict:
    suite_hash, jobs = _suite_jobs(suite, repetitions, seed)
    contract = dict(getattr(adapter, "contract", {}))
    required = {"model", "permissions", "max_turns", "max_seconds"}
    if required - set(contract):
        raise PolicyDenied("Adapter contract is incomplete")
    contract.update({"suite_hash": suite_hash, "effort": condition, "workers": 1})
    results = []
    for case, artifact, repeat in jobs:
        result = await adapter.run(case, artifact, contract)
        if not isinstance(result, dict):
            raise PolicyDenied("Adapter returned an invalid result")
        results.append(
            {**result, "case": case["id"], "repeat": repeat, "points": case["points"]}
        )
    return {
        "condition": condition,
        "model_evaluation": bool(getattr(adapter, "model_evaluation", False)),
        "adapter": getattr(adapter, "adapter_kind", "external"),
        "condition_metadata": {
            "skills_enabled": bool(getattr(adapter, "skills_enabled", False))
        },
        "contract": contract,
        "seed": seed,
        "results": results,
        "metrics": metrics(results),
        "baselines": {key: "not run" for key in CONDITIONS},
    }


async def run_conditions(
    store: Store,
    suite: Path,
    conditions: tuple[str, ...] = ("P1", "P2", "P3"),
    repetitions=1,
    seed=2026,
    adapter_factory=None,
) -> dict:
    """Run the same suite under named conditions with a shared contract.

    P1/P2/P3 map to FAST/AUTO/EXPERT with the deterministic fixture worker. B0/B1
    require an explicitly supplied model adapter; without one they are reported
    as ``not_run`` rather than fabricated.
    """
    if not conditions or len(set(conditions)) != len(conditions):
        raise PolicyDenied("Conditions must be unique and non-empty")
    lanes = {"P1": "fast", "P2": "auto", "P3": "expert"}
    reports = {}
    for condition in conditions:
        if condition not in CONDITIONS:
            raise PolicyDenied("Unknown benchmark condition")
        if condition in {"B0", "B1"}:
            if adapter_factory is None:
                reports[condition] = {
                    "condition": condition,
                    "status": "not_run",
                    "reason": "requires an explicitly configured model adapter",
                }
                continue
            adapter = adapter_factory(condition)
            reports[condition] = await _adapter_condition(
                store, suite, condition, adapter, repetitions, seed
            )
        else:
            lane = lanes.get(condition, "auto")
            reports[condition] = await benchmark(
                store, suite, repetitions=repetitions, seed=seed, lane=lane, condition=condition
            )
            reports[condition]["model_evaluation"] = False
    comparable = [key for key, value in reports.items() if value.get("results") is not None]
    contract_keys = [key for key in EQUALITY_FIELDS if key != "effort"]
    uniform = len(comparable) >= 2 and all(
        reports[comparable[0]]["contract"].get(key)
        == reports[other]["contract"].get(key)
        for other in comparable[1:]
        for key in contract_keys
    )
    return {
        "schema_version": 1,
        "report": "condition-comparison",
        "conditions": reports,
        "comparable": uniform,
        "performance_claim": "none; fixture runs do not establish model superiority",
    }



async def run_queue(store: Store, jobs: list[dict], workers=1):
    if not 1 <= workers <= 2 or len(jobs) > 50:
        raise PolicyDenied("Competition workers must be 1..2; at most 50 jobs")
    # Explicit, uncalibrated priority baseline. No invented success probabilities.
    ordered = sorted(
        jobs,
        key=lambda item: (
            -item.get("priority", 0),
            item.get("deadline", float("inf")),
            -item.get("points", 0),
        ),
    )
    semaphore = asyncio.Semaphore(workers)

    async def run(job):
        import time

        async with semaphore:
            if job.get("deadline", float("inf")) < time.time():
                return {"status": "deadline_passed", "points": job.get("points", 0)}
            return await solve(store, job["run_id"])

    return await asyncio.gather(*(run(job) for job in ordered))
