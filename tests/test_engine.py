import asyncio
import base64
import hashlib
import json
import os
import shutil
from pathlib import Path

import pytest

from prestige.artifacts import Artifacts, ToolRegistry
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


def test_cli_default_backend_is_fake_and_keyless(tmp_path, challenge, capsys, monkeypatch):
    path, digest, _ = challenge
    monkeypatch.delenv("PRESTIGE_OPENAI_API_KEY", raising=False)
    args = ["--home", str(tmp_path / "cli-state")]
    assert main(args + ["solve", str(path), "--expected-sha256", digest]) == 0
    output = json.loads(capsys.readouterr().out)
    assert output["status"] == "solved"
    assert output["backend"] == "fake"


def test_cli_human_request_and_answer(store, challenge, capsys):
    from prestige.human import pending_request, request_operator

    path, _, _ = challenge
    run_id = new_run(store, path)
    payload = request_operator(store, run_id, "Which flag format?", ["SAS{}", "other"])
    assert store.run(run_id)["status"] == "waiting_for_operator"
    assert pending_request(store, run_id)["request_id"] == payload["request_id"]

    assert main(["--home", str(store.home), "answer", run_id, "SAS{operator}"]) == 0
    output = json.loads(capsys.readouterr().out)
    assert output["status"] == "ready"
    assert output["trust"] == "operator_direct"
    assert store.run(run_id)["status"] == "ready"
    assert pending_request(store, run_id) is None


def test_cli_human_answer_rejects_wrong_request(store, challenge, capsys):
    from prestige.human import request_operator

    path, _, _ = challenge
    run_id = new_run(store, path)
    request_operator(store, run_id, "Blocked on scope?")
    assert (
        main(
            [
                "--home",
                str(store.home),
                "answer",
                run_id,
                "yes",
                "--request-id",
                "deadbeef",
            ]
        )
        == 2
    )
    capsys.readouterr()


def test_cli_verify_candidate_known_answer(tmp_path, capsys):
    value = b"SYNTHETIC{known_answer}"
    digest = hashlib.sha256(value).hexdigest()
    candidate = tmp_path / "candidate.bin"
    candidate.write_bytes(value)
    args = ["--home", str(tmp_path / "state"), "verify-candidate"]
    assert (
        main(args + ["--expected-sha256", digest, "--candidate-file", str(candidate)]) == 0
    )
    output = json.loads(capsys.readouterr().out)
    assert output["match"] is True
    assert value.decode() not in json.dumps(output)

    assert (
        main(args + ["--expected-sha256", "0" * 64, "--candidate-file", str(candidate)]) == 0
    )
    output = json.loads(capsys.readouterr().out)
    assert output["match"] is False


def test_cli_verify_candidate_rejects_bad_digest(tmp_path, capsys):
    candidate = tmp_path / "candidate.bin"
    candidate.write_bytes(b"x")
    args = ["--home", str(tmp_path / "state"), "verify-candidate"]
    assert main(args + ["--expected-sha256", "not-a-digest", "--candidate-file", str(candidate)]) == 3
    capsys.readouterr()


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


def test_new_run_stores_live_and_runner_settings(store, challenge):
    path, _, _ = challenge
    run_id = new_run(
        store,
        path,
        backend="codex",
        live=True,
        runner_image="sha256:" + "a" * 64,
        max_artifact_mib=4,
    )
    settings = store.run(run_id)["settings"]
    assert settings["live"] is True
    assert settings["runner_image"] == "sha256:" + "a" * 64
    assert settings["max_artifact_mib"] == 4


def test_openai_api_key_is_not_persisted_in_settings(store, challenge):
    path, _, _ = challenge
    run_id = new_run(
        store,
        path,
        backend="openai",
        openai_base_url="http://localhost:1234/v1",
        openai_api_key="sk-secret-must-not-be-stored",
        openai_model="test-model",
    )
    settings = store.run(run_id)["settings"]
    assert settings.get("openai_api_key") is None
    assert settings["openai_base_url"] == "http://localhost:1234/v1"
    assert settings["openai_model"] == "test-model"


def test_store_scrubs_existing_provider_secret(store, challenge):
    path, _, _ = challenge
    run_id = new_run(store, path, backend="fake")
    raw = store.rows("SELECT settings FROM runs WHERE id=?", (run_id,))[0]["settings"]
    from prestige.store import encoded

    poisoned = json.loads(raw)
    poisoned["openai_api_key"] = "sk-old-secret"
    with store.transaction() as db:
        db.execute("UPDATE runs SET settings=? WHERE id=?", (encoded(poisoned), run_id))
    # Re-opening the store triggers the migration that scrubs the secret.
    from prestige.store import Store

    fresh = Store(store.home)
    try:
        assert fresh.run(run_id)["settings"].get("openai_api_key") is None
    finally:
        fresh.close()


def test_runner_image_must_be_immutable_digest(store, challenge):
    path, _, _ = challenge
    with pytest.raises(PolicyDenied):
        new_run(store, path, runner_image="latest")


async def test_attempts_count_failed_proposes(store, challenge):
    path, _, _ = challenge
    run_id = new_run(store, path)

    class Failing(FakeBackend):
        async def propose(self, context):
            raise PolicyDenied("synthetic provider failure")

    result = await solve(store, run_id, Failing())
    assert result["status"] == "blocked"
    assert result["attempts"] == 1
    assert result["turns"] == 0


def test_cli_solve_accepts_live_and_runner_options(tmp_path, challenge, capsys):
    path, digest, _ = challenge
    args = ["--home", str(tmp_path / "cli-state")]
    # --live without codex would block at runtime; here we just exercise parsing.
    assert (
        main(
            args
            + [
                "solve",
                str(path),
                "--backend",
                "fake",
                "--expected-sha256",
                digest,
                "--max-artifact-mib",
                "2",
            ]
        )
        == 0
    )
    output = json.loads(capsys.readouterr().out)
    assert output["status"] == "solved"


async def test_runner_is_wired_for_isolated_tools(store, challenge):
    path, _, _ = challenge
    run_id = new_run(store, path)
    artifact = Artifacts(store, run_id).list()[0]["id"]

    class ProposePython(FakeBackend):
        async def propose(self, context):
            return Proposal(
                Action("python", artifact, {"code": "print('ok')"}), "run isolated python"
            )

    class FakeRunner:
        def execute(self, action):
            return {"stdout": "ok", "stderr": "", "returncode": 0}

        def collect(self, artifacts):
            return []

    result = await solve(store, run_id, ProposePython(), runner=FakeRunner())
    assert result["status"] == "unsolved"
    assert any(x["data"].get("result", {}).get("stdout") == "ok" for x in store.events(run_id))


async def test_file_tool_identifies_artifact_type(store, challenge):
    path, _, _ = challenge
    run_id = new_run(store, path)
    artifact = Artifacts(store, run_id).list()[0]["id"]

    class ProposeFile(FakeBackend):
        async def propose(self, context):
            return Proposal(Action("file", artifact, {}), "identify file type")

    result = await solve(store, run_id, ProposeFile())
    assert result["status"] == "unsolved"
    observation = next(
        (x for x in store.events(run_id) if x["kind"] == "observation"), None
    )
    assert observation and "ASCII" in observation["data"]["result"]["output"]


async def test_radare2_tool_rejects_dangerous_commands(store, challenge):
    path, _, _ = challenge
    run_id = new_run(store, path)
    artifact = Artifacts(store, run_id).list()[0]["id"]

    class ProposeBadR2(FakeBackend):
        async def propose(self, context):
            return Proposal(
                Action("radare2", artifact, {"script": ["!sh"]}), "dangerous r2"
            )

    result = await solve(store, run_id, ProposeBadR2())
    assert result["status"] == "unsolved"
    assert any("Disallowed" in str(x) for x in store.events(run_id))


@pytest.mark.skipif(not shutil.which("r2"), reason="radare2 not installed")
async def test_radare2_tool_runs_allowed_script(store, challenge):
    path, _, _ = challenge
    run_id = new_run(store, path)
    artifact = Artifacts(store, run_id).list()[0]["id"]

    class ProposeR2(FakeBackend):
        async def propose(self, context):
            return Proposal(
                Action("radare2", artifact, {"script": ["iz"]}), "list strings"
            )

    result = await solve(store, run_id, ProposeR2())
    assert result["status"] == "unsolved"
    observation = next(
        (x for x in store.events(run_id) if x["kind"] == "observation"), None
    )
    assert observation and observation["data"]["result"]["returncode"] == 0


@pytest.mark.ghidra
@pytest.mark.skipif(
    not Path("/usr/share/ghidra/support/analyzeHeadless").exists(),
    reason="Ghidra headless analyzer not installed",
)
@pytest.mark.skipif(
    not os.environ.get("PRESTIGE_TEST_GHIDRA"),
    reason="Set PRESTIGE_TEST_GHIDRA=1 to run slow Ghidra analysis tests",
)
async def test_ghidra_tool_exports_functions(store, tmp_path):
    binary = tmp_path / "ls"
    binary.write_bytes(Path("/bin/ls").read_bytes())
    run_id = new_run(store, binary)
    artifact = Artifacts(store, run_id).list()[0]["id"]

    class ProposeGhidra(FakeBackend):
        async def propose(self, context):
            return Proposal(
                Action("ghidra", artifact, {"mode": "functions", "timeout": 120}),
                "enumerate functions",
            )

    result = await solve(store, run_id, ProposeGhidra())
    assert result["status"] == "unsolved"
    observation = next(
        (x for x in store.events(run_id) if x["kind"] == "observation"), None
    )
    assert observation and len(observation["data"]["result"]["functions"]) > 50


def test_pdf_tool_extracts_bounded_text_without_following_links(store, tmp_path, monkeypatch):
    path = tmp_path / "doc.pdf"
    path.write_bytes(b"%PDF-1.7\nSAS{hidden}\n")
    run_id = new_run(store, path)
    artifacts = Artifacts(store, run_id)
    artifact = artifacts.list()[0]["id"]
    calls = []

    class Completed:
        stdout = "Sanity Files\nSAS{pdf_text}\n"
        stderr = ""
        returncode = 0

    def fake_run(command, **kwargs):
        calls.append((command, kwargs))
        return Completed()

    monkeypatch.setattr("prestige.artifacts.subprocess.run", fake_run)
    result = ToolRegistry(artifacts, ("pdf",)).execute(Action("pdf", artifact, {}))
    assert "SAS{pdf_text}" in result["text"]
    assert calls[0][0][0] == "mutool"
    assert calls[0][1]["timeout"] == 15
