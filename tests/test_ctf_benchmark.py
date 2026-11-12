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
