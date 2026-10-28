import asyncio
import base64
import hashlib
import json

import pytest

from prestige.artifacts import Artifacts
from prestige.backends import FakeBackend
from prestige.cli import main
from prestige.engine import new_run, report, solve
from prestige.knowledge import Knowledge, SkillsBridge
from prestige.types import Action, PolicyDenied, Proposal, Usage


async def test_solve_replay_learning_and_restart(store, challenge):
    path, digest, value = challenge
    run_id = new_run(store, path, expected=digest)
    result = await solve(store, run_id)
    assert result["status"] == "solved"
    assert result["tokens"] is None  # fake is not a paid model with zero-cost tokens
    assert "value" not in result["candidates"][0]
    assert report(store, run_id, True)["candidates"][0]["value"] == value.decode()
    records = Knowledge(store, SkillsBridge()).search("base64")
    assert len(records) == 1
    assert value.decode() not in json.dumps(records)
    assert (store.home / "runs" / run_id / "solve" / "STATE.md").exists()
    assert not store.rows("SELECT * FROM leases")


async def test_regex_is_never_proof(store, tmp_path):
    path = tmp_path / "decoy.txt"
    path.write_text("SYNTHETIC{fake_success}")
    run_id = new_run(store, path)
    result = await solve(store, run_id)
    assert result["status"] == "unsolved"
    assert result["candidates"] and not any(x["verified"] for x in result["candidates"])
    assert not store.rows("SELECT * FROM knowledge")


async def test_escalation_preserves_evidence(store, tmp_path):
    value = b"SYNTHETIC{nested_proof}"
    path = tmp_path / "nested.txt"
    path.write_bytes(base64.b64encode(value).hex().encode())
    run_id = new_run(store, path, expected=hashlib.sha256(value).hexdigest())

    class PausingFake(FakeBackend):
        calls = 0

        async def propose(self, context):
            self.calls += 1
            if self.calls == 2:
                return Proposal(None, "Need a second lane")
            return await super().propose(context)

    result = await solve(store, run_id, PausingFake())
    assert result["status"] == "solved" and result["lane"] == "expert"
    assert len(Artifacts(store, run_id).list()) == 3
    assert len([x for x in store.events(run_id) if x["kind"] == "escalation"]) == 1


async def test_repeated_actions_suppressed(store, challenge):
    path, _, _ = challenge
    run_id = new_run(store, path, mode="expert")
    artifact = Artifacts(store, run_id).list()[0]["id"]

    class Stalled(FakeBackend):
        async def propose(self, context):
            return Proposal(Action("inspect", artifact), "same hypothesis")

    result = await solve(store, run_id, Stalled())
    assert result["status"] == "unsolved"
    assert any("Repeated" in str(x) for x in store.events(run_id))


async def test_pause_and_resume(store, challenge):
    path, digest, _ = challenge
    run_id = new_run(store, path, expected=digest)

    class Slow(FakeBackend):
        interrupted = False

        async def propose(self, context):
            await asyncio.sleep(10)

        async def interrupt(self):
            self.interrupted = True

    worker = Slow()
    task = asyncio.create_task(solve(store, run_id, worker))
    await asyncio.sleep(0.05)
    store.update(run_id, status="paused")
    assert (await task)["status"] == "paused"
    assert worker.interrupted
    assert (await solve(store, run_id))["status"] == "solved"


async def test_timeout_cancels(store, challenge):
    path, _, _ = challenge
    run_id = new_run(store, path, max_seconds=0.02)

    class Slow(FakeBackend):
        async def propose(self, context):
            await asyncio.sleep(5)

    assert (await solve(store, run_id, Slow()))["status"] == "budget_exhausted"
    assert not store.rows("SELECT * FROM leases")


async def test_reported_usage_is_not_subscription_dollars(store, challenge):
    path, _, _ = challenge
    run_id = new_run(store, path, max_tokens=10)

    class Metered(FakeBackend):
        async def propose(self, context):
            return Proposal(None, "stop", Usage(7, 5, 3, 2))

    result = await solve(store, run_id, Metered())
    assert result["tokens"] == 12  # cached/reasoning are subcategories, not counted twice
    assert result["status"] == "budget_exhausted"


async def test_live_codex_fails_closed_without_starting_runtime(store, challenge):
    path, _, _ = challenge
    run_id = new_run(store, path, backend="codex")
    assert (await solve(store, run_id))["status"] == "blocked"


def test_cli_roundtrip(tmp_path, challenge, capsys):
    path, digest, _ = challenge
    args = ["--home", str(tmp_path / "cli-state")]
    assert main(args + ["solve", str(path), "--backend", "fake", "--expected-sha256", digest]) == 0
    output = json.loads(capsys.readouterr().out)
    assert output["status"] == "solved"
    assert main(args + ["report", output["run_id"]]) == 0
    assert "value" not in json.loads(capsys.readouterr().out)["candidates"][0]


def test_remote_disabled_even_with_rules(store, challenge):
    with pytest.raises(PolicyDenied):
        new_run(store, challenge[0], instance="https://instance.example:8443/")


async def test_backend_crash_retains_artifacts_and_can_resume(store, challenge):
    path, digest, _ = challenge
    run = new_run(store, path, expected=digest)

    class Crash(FakeBackend):
        async def propose(self, context):
            raise RuntimeError("synthetic backend interruption")

    with pytest.raises(RuntimeError):
        await solve(store, run, Crash())
    assert store.run(run)["status"] == "failed"
    assert not store.rows("SELECT * FROM leases")
    assert (await solve(store, run))["status"] == "solved"


async def test_two_worker_queue_is_bounded_and_reproducible(store, challenge):
    from prestige.evaluation import run_queue

    path, digest, _ = challenge
    jobs = [
        {"run_id": new_run(store, path, expected=digest), "points": points} for points in (100, 200)
    ]
    results = await run_queue(store, jobs, workers=2)
    assert all(result["status"] == "solved" for result in results)
    assert len(store.rows("SELECT * FROM knowledge")) == 1
    with pytest.raises(PolicyDenied):
        await run_queue(store, jobs, workers=3)
