"""Benchmark isolation, solution-blind views and measured OpenCode events."""

import json
import os
import stat
from pathlib import Path

import pytest

from prestige.ctf_benchmark import (
    inventory,
    load_answers,
    parse_jsonl,
    prepare_view,
    run_condition,
    run_matrix,
)

POSIX = pytest.mark.skipif(os.name == "nt", reason="POSIX fake executable fixture")


def _corpus(tmp_path):
    root = tmp_path / "corpus"
    challenge = (
        root
        / "competitions"
        / "2026"
        / "sasctf-quals-2026"
        / "challenges"
        / "demo"
    )
    (challenge / "static").mkdir(parents=True)
    (challenge / "server").mkdir()
    (challenge / "README.md").write_text("# Demo\n\nplayer description\n")
    (challenge / "static" / "artifact.bin").write_bytes(b"player bytes")
    (challenge / "server" / "secret.py").write_text("FLAG='SAS{operator_secret}'\n")
    (challenge / "manifest.json").write_text(
        json.dumps(
            {
                "id": "demo",
                "title": "Demo",
                "categories": ["misc"],
                "preparation_status": "ready",
                "player_files": ["static/artifact.bin"],
                "operator_files": [{"path": "server/secret.py"}],
                "missing_or_external_dependencies": [],
            }
        )
    )
    return root


def test_inventory_and_solution_blind_view(tmp_path):
    root = _corpus(tmp_path)
    items = inventory(root)
    assert items[0]["id"] == "demo"
    assert items[0]["player_files"] == ["static/artifact.bin"]
    output = tmp_path / "views"
    result = prepare_view(root, output)
    assert result["count"] == 1
    view = output / "demo"
    assert (view / "README.md").is_file()
    assert (view / "challenge" / "static" / "artifact.bin").read_bytes() == b"player bytes"
    assert not any("server" in path.relative_to(view).parts for path in view.rglob("*"))
    assert not any("operator_secret" in path.read_text(errors="ignore") for path in view.rglob("*") if path.is_file())


def test_parse_jsonl_measures_real_usage():
    lines = [
        json.dumps(
            {
                "type": "step_finish",
                "sessionID": "ses_test",
                "part": {
                    "tokens": {
                        "input": 100,
                        "output": 20,
                        "reasoning": 5,
                        "cache": {"read": 1000, "write": 50},
                    },
                    "cost": 0.25,
                },
            }
        ),
        json.dumps(
            {
                "type": "tool_use",
                "sessionID": "ses_test",
                "part": {"tool": "shell", "state": {"status": "error"}},
            }
        ),
        json.dumps(
            {"type": "text", "sessionID": "ses_test", "part": {"text": "SAS{fake}"}}
        ),
    ]
    parsed = parse_jsonl("\n".join(lines))
    assert parsed["tokens"]["input"] == 100
    assert parsed["tokens"]["cache_read"] == 1000
    assert parsed["total_tokens"] == 120
    assert parsed["cost"] == 0.25
    assert parsed["tool_calls"] == 1
    assert parsed["failed_tools"] == 1
    assert parsed["model_inference_observed"] is True


def test_private_answers_are_validated(tmp_path):
    path = tmp_path / "answers.json"
    path.write_text(json.dumps({"demo": {"sha256": "a" * 64}}))
    assert load_answers(path) == {"demo": "a" * 64}
    path.write_text(json.dumps({"demo": {"sha256": "not-a-digest"}}))
    with pytest.raises(ValueError):
        load_answers(path)


@POSIX
def test_run_condition_uses_isolated_pwd_and_env(tmp_path):
    script = tmp_path / "opencode"
    script.write_text(
        "#!/bin/sh\n"
        "printf '%s\\n' \"{\\\"type\\\":\\\"step_finish\\\",\\\"sessionID\\\":\\\"ses_fake\\\","
        "\\\"part\\\":{\\\"tokens\\\":{\\\"input\\\":10,\\\"output\\\":2,\\\"reasoning\\\":1,"
        "\\\"cache\\\":{\\\"read\\\":0,\\\"write\\\":0}},\\\"cost\\\":0}}\"\n"
        "printf '%s\\n' \"{\\\"type\\\":\\\"text\\\",\\\"sessionID\\\":\\\"ses_fake\\\","
        "\\\"part\\\":{\\\"text\\\":\\\"SAS{fake}\\\"}}\"\n"
        "printf '%s' \"$PWD:$OPENCODE_SESSION_ID\" > env.txt\n"
    )
    script.chmod(script.stat().st_mode | stat.S_IXUSR)
    view = tmp_path / "view"
    (view / "challenge").mkdir(parents=True)
    (view / "README.md").write_text("demo")
    (view / "challenge" / "f").write_bytes(b"x")
    answer = {"demo": "a" * 64}
    result = run_condition(
        view,
        "A",
        model="fake/model",
        output=tmp_path / "out",
        answers=answer,
        challenge="demo",
        seconds=30,
        executable=str(script),
    )
    assert result["status"] == "completed"
    assert result["parsed"]["total_tokens"] == 12
    assert result["verified"] is False
    env_line = (Path(result["workdir"]) / "env.txt").read_text()
    assert env_line.startswith(result["workdir"] + ":")
    assert env_line.endswith(":")


def _fake_with_submission(tmp_path, flag: str | None):
    script = tmp_path / "opencode"
    body = '#!/bin/sh\n'
    body += 'printf \'%s\\n\' \'{"type":"step_finish","sessionID":"ses_fake","part":{"tokens":{"input":10,"output":2,"reasoning":1,"cache":{"read":0,"write":0}},"cost":0}}\'\n'
    body += 'printf \'%s\\n\' \'{"type":"text","sessionID":"ses_fake","part":{"text":"intermediate SAS{not_a_submission}"}}\'\n'
    if flag is not None:
        body += f'printf \'%s\\n\' \'{{"flag":"{flag}"}}\' > "$PRESTIGE_BENCH_SUBMISSION"\n'
    script.write_text(body)
    script.chmod(script.stat().st_mode | stat.S_IXUSR)
    return str(script)


@POSIX
def test_explicit_submission_is_the_only_verified_answer(tmp_path):
    import hashlib

    view = tmp_path / "view"
    (view / "challenge").mkdir(parents=True)
    (view / "README.md").write_text("demo")
    (view / "challenge" / "f").write_bytes(b"x")
    expected = hashlib.sha256(b"SAS{correct}").hexdigest()
    output = tmp_path / "out"
    result = run_condition(
        view,
        "A",
        model="fake/model",
        output=output,
        answers={"demo": expected},
        challenge="demo",
        seconds=30,
        executable=_fake_with_submission(tmp_path, "SAS{correct}"),
    )
    assert result["status"] == "completed"
    assert result["submission_status"] == "valid"
    assert result["verified"] is True
    assert result["verified_by"] == "operator_submission_digest"


@POSIX
def test_intermediate_text_without_submission_is_not_a_solve(tmp_path):
    import hashlib

    view = tmp_path / "view"
    (view / "challenge").mkdir(parents=True)
    (view / "README.md").write_text("demo")
    (view / "challenge" / "f").write_bytes(b"x")
    result = run_condition(
        view,
        "A",
        model="fake/model",
        output=tmp_path / "out-missing",
        answers={"demo": hashlib.sha256(b"SAS{correct}").hexdigest()},
        challenge="demo",
        seconds=30,
        executable=_fake_with_submission(tmp_path, None),
    )
    assert result["submission_status"] == "missing"
    assert result["verified"] is False
    assert result["candidate_digests"] == []


@POSIX
def test_wrong_submission_is_recorded_separately(tmp_path):
    import hashlib

    view = tmp_path / "view"
    (view / "challenge").mkdir(parents=True)
    (view / "README.md").write_text("demo")
    (view / "challenge" / "f").write_bytes(b"x")
    result = run_condition(
        view,
        "A",
        model="fake/model",
        output=tmp_path / "out-wrong",
        answers={"demo": hashlib.sha256(b"SAS{correct}").hexdigest()},
        challenge="demo",
        seconds=30,
        executable=_fake_with_submission(tmp_path, "SAS{wrong}"),
    )
    assert result["submission_status"] == "wrong"
    assert result["verified"] is False
    assert len(result["wrong_candidate_digests"]) == 1


def test_read_submission_rejects_malformed_and_large(tmp_path):
    from prestige.ctf_benchmark import read_submission

    missing = tmp_path / "missing.json"
    assert read_submission(missing)["status"] == "missing"
    bad = tmp_path / "bad.json"
    bad.write_text("not json")
    assert read_submission(bad)["status"] == "invalid"
    empty = tmp_path / "empty.json"
    empty.write_text('{"flag": ""}')
    assert read_submission(empty)["status"] == "invalid"
    valid = tmp_path / "valid.json"
    valid.write_text('{"flag": "SAS{ok}"}')
    parsed = read_submission(valid)
    assert parsed["status"] == "valid"
    assert parsed["sha256"]
    assert parsed["candidate"] == "SAS{ok}"


@POSIX
def test_repetitions_and_resume_do_not_duplicate_runs(tmp_path):
    import hashlib

    view = tmp_path / "view"
    (view / "challenge").mkdir(parents=True)
    (view / "README.md").write_text("demo")
    (view / "challenge" / "f").write_bytes(b"x")
    (tmp_path / "views").mkdir()
    import shutil

    shutil.copytree(view, tmp_path / "views" / "demo")
    script = tmp_path / "opencode"
    script.write_text(
        "#!/bin/sh\n"
        "printf '%s\\n' '{\"flag\":\"SAS{correct}\"}' > \"$PRESTIGE_BENCH_SUBMISSION\"\n"
    )
    script.chmod(script.stat().st_mode | stat.S_IXUSR)
    kwargs = dict(
        model="fake/model",
        output=tmp_path / "out",
        answers={"demo": hashlib.sha256(b"SAS{correct}").hexdigest()},
        skills=None,
        seconds=30,
        executable=str(script),
        repetitions=2,
        seed=1,
        resume=True,
    )
    first = run_matrix(tmp_path / "views", ["demo"], ["A"], **kwargs)
    assert first["attempts"] == 2
    second = run_matrix(tmp_path / "views", ["demo"], ["A"], **kwargs)
    assert second["attempts"] == 2
    assert len({(r["condition"], r["attempt"]) for r in second["results"]}) == 2


def test_eligibility_inventory_separates_ready_from_verified():
    path = Path(__file__).parent.parent / "benchmark-results" / "sasctf-2026-eligibility.json"
    data = json.loads(path.read_text())
    assert data["directories"] == 23
    assert data["ready_packages"] == 15
    assert data["verified_eligible"] == 1
    eligible = [item for item in data["challenges"] if item["benchmark_eligible"]]
    assert [item["id"] for item in eligible] == ["welcome-sanity-files"]
    assert all(item["exclusion_reason"] for item in data["challenges"] if not item["benchmark_eligible"])
    priority = [item["id"] for item in sorted(
        (item for item in data["challenges"] if item["priority"]), key=lambda item: item["priority"]
    )]
    assert priority == [
        "rev-fpga", "pwn-snaking", "web-gav", "rev-cerum", "mlw-backfloppa", "net-incident-67"
    ]


def test_preflight_checks_fail_closed(tmp_path):
    from prestige.ctf_benchmark import preflight

    view = tmp_path / "views"
    view.mkdir()
    result = preflight(
        model="provider/model",
        views=view,
        answers={"demo": "a" * 64},
        executable=str(tmp_path / "missing"),
    )
    assert result["ok"] is False
    assert result["checks"]["model"] is True
    assert result["checks"]["executable"] is False


def test_aggregate_treats_timeouts_as_failures_and_preserves_censoring():
    from prestige.ctf_benchmark import aggregate

    results = [
        {"condition": "A", "challenge": "c", "verified": True, "seconds": 10,
         "status": "completed", "submission_status": "valid", "parsed": {}, "prestige_state": {}},
        {"condition": "A", "challenge": "c", "verified": False, "seconds": 30,
         "status": "timed_out", "submission_status": "missing", "parsed": {}, "prestige_state": {}},
        {"condition": "B", "challenge": "c", "verified": False, "seconds": 20,
         "status": "completed", "submission_status": "wrong", "parsed": {}, "prestige_state": {}},
    ]
    summary = aggregate(results)
    assert summary["by_condition"]["A"]["solve_rate"] == 0.5
    assert summary["by_condition"]["A"]["timeouts"] == 1
    assert summary["by_condition"]["A"]["median_seconds"] == 20
    assert summary["by_condition"]["B"]["submission_statuses"]["wrong"] == 1


def test_interactive_mode_requires_and_uses_a_checker(tmp_path):
    view = tmp_path / "view"
    (view / "challenge").mkdir(parents=True)
    (view / "README.md").write_text("demo")
    (view / "challenge" / "f").write_bytes(b"x")
    script = _fake_with_submission(tmp_path, "SAS{interactive}")
    with pytest.raises(ValueError):
        run_condition(
            view, "A", model="fake/model", output=tmp_path / "a",
            answers={}, challenge="demo", seconds=10,
            executable=script, mode="interactive",
        )
    result = run_condition(
        view, "A", model="fake/model", output=tmp_path / "b",
        answers={}, challenge="demo", seconds=10, executable=script,
        mode="interactive", checker=lambda value: {"accepted": value == "SAS{interactive}"},
    )
    assert result["verified"] is True
    assert result["verified_by"] == "interactive_checker"
    assert result["checker_result"]["accepted"] is True
