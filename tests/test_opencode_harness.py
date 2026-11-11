"""Optional OpenCode harness construction and real-state reporting."""

import json
import os
import stat

import pytest

from prestige.engine import new_run
from prestige.opencode_harness import (
    available,
    command,
    run_case,
    run_pair_live,
    summarize_home,
)
from prestige.store import Store


def _fake(tmp_path, body: str):
    path = tmp_path / "opencode"
    path.write_text("#!/bin/sh\n" + body)
    path.chmod(path.stat().st_mode | stat.S_IXUSR)
    return str(path)


POSIX_FAKE = pytest.mark.skipif(
    os.name == "nt", reason="POSIX shell-script fixture; harness itself is cross-platform"
)


def test_command_uses_restricted_agent_and_json_format():
    argv = command("solve the local challenge", "provider/model")
    assert argv[:7] == [
        "opencode",
        "run",
        "--standalone",
        "--agent",
        "prestige",
        "--format",
        "json",
    ]
    assert "--archived" in argv
    assert argv[-3:] == ["--model", "provider/model", "solve the local challenge"]


@POSIX_FAKE
def test_run_case_records_raw_process_result(tmp_path):
    executable = _fake(
        tmp_path, 'printf \'{"sessionID":"ses_test","text":"done"}\\n\'\n'
    )
    home = tmp_path / "state"
    result = run_case(
        home, "solve", executable=executable, timeout=10, cwd=tmp_path
    )
    assert result["status"] == "completed"
    assert result["returncode"] == 0
    assert result["parsed"] == {"sessionID": "ses_test", "text": "done"}
    assert result["model_inference_observed"] is True
    assert "not a verified solve" in result["note"]


@POSIX_FAKE
def test_run_case_failure_is_not_a_solve(tmp_path):
    executable = _fake(tmp_path, "echo provider unavailable >&2\nexit 2\n")
    result = run_case(tmp_path / "state", "solve", executable=executable, timeout=10)
    assert result["status"] == "failed"
    assert result["returncode"] == 2
    assert "provider unavailable" in result["stderr"]


def test_run_case_missing_executable_is_not_run(tmp_path):
    result = run_case(tmp_path / "state", "solve", executable=str(tmp_path / "absent"))
    assert result["status"] == "not_run"
    assert available(str(tmp_path / "absent")) is False


def test_summarize_home_reads_real_state(tmp_path):
    home = tmp_path / "state"
    challenge = tmp_path / "challenge.txt"
    challenge.write_bytes(b"offline")
    store = Store(home)
    try:
        run_id = new_run(store, challenge, max_turns=2)
        store.update(run_id, status="unsolved")
    finally:
        store.close()
    summary = summarize_home(home)
    assert summary["count"] == 1
    assert summary["runs"][0]["run_id"] == run_id
    assert summary["runs"][0]["status"] == "unsolved"


@POSIX_FAKE
def test_run_pair_live_reports_both_processes(tmp_path):
    executable = _fake(tmp_path, 'printf \'{"text":"ok"}\\n\'\n')
    home = tmp_path / "state"
    result = run_pair_live(
        home,
        "clean prompt",
        "adversarial prompt",
        model=None,
        timeout=10,
        executable=executable,
        cwd=tmp_path,
    )
    assert result["clean"]["status"] == "completed"
    assert result["adversarial"]["status"] == "completed"
    assert result["clean_state"]["count"] == 0
    assert result["adversarial_state"]["count"] == 0
    assert "no solve" in result["claim"]


@POSIX_FAKE
def test_live_provider_result_is_not_inferred_from_stdout(tmp_path):
    """A model claiming success in text does not create a verified run."""
    executable = _fake(
        tmp_path,
        'printf \'{"text":"I solved it: SYNTHETIC{fake}"}\\n\'\n',
    )
    home = tmp_path / "state"
    result = run_case(home, "solve", executable=executable, timeout=10)
    assert result["status"] == "completed"
    summary = summarize_home(home)
    assert summary["count"] == 0
    assert "SYNTHETIC" not in json.dumps(summary)
