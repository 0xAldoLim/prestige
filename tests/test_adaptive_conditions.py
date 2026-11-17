"""Adaptive DD/KE/DP benchmark configuration and public redaction tests."""

import json

from prestige.ctf_benchmark import (
    ADAPTIVE_AGENTS,
    BENCHMARK_CONDITIONS,
    _agent_config,
    _command,
    _prompt,
    public_result,
    public_summary,
)


def _paths(tmp_path):
    home = tmp_path / "state"
    allowed = tmp_path / "run"
    submission = allowed / "submission.json"
    return home, allowed, submission


def test_adaptive_conditions_are_registered():
    assert {"A", "B", "C", "D", "DD", "KE", "DP"} <= set(BENCHMARK_CONDITIONS)
    assert ADAPTIVE_AGENTS == {"DD": "bench", "KE": "orchestrator", "DP": "prestige"}


def test_dd_pins_free_deepseek_direct_without_prestige(tmp_path):
    home, allowed, submission = _paths(tmp_path)
    config = _agent_config("DD", home, allowed, submission)
    agent = config["agents"]["bench"]
    assert agent["model"] == "opencode/deepseek-v4.1-flash-free"
    assert agent["mode"] == "primary"
    assert "mcp" not in config


def test_ke_uses_checked_in_kimi_orchestrator_and_deepseek_executor(tmp_path):
    home, allowed, submission = _paths(tmp_path)
    config = _agent_config("KE", home, allowed, submission)
    orchestrator = config["agents"]["orchestrator"]
    executor = config["agents"]["executor"]
    assert orchestrator["model"] == "opencode-go/kimi-k3.1-pro"
    assert orchestrator["mode"] == "primary"
    assert executor["model"] == "opencode/deepseek-v4.1-flash-free"
    assert executor["mode"] == "subagent"
    assert "mcp" not in config
    resources = {rule.get("resource") for rule in orchestrator["permissions"]}
    assert "executor" in resources
    assert "prestige" not in resources
    assert "prestige` subagent" not in orchestrator["system"].lower()


def test_dp_pins_deepseek_prestige_and_mcp_only(tmp_path):
    home, allowed, submission = _paths(tmp_path)
    config = _agent_config("DP", home, allowed, submission, endpoint={"registration_id": "jsvc", "port": 31337})
    agent = config["agents"]["prestige"]
    assert agent["model"] == "opencode/deepseek-v4.1-flash-free"
    mcp = config["mcp"]["prestige"]
    assert mcp["command"] == ["python", "-m", "prestige", "agent"]
    assert mcp["environment"]["PRESTIGE_HOME"] == str(home)
    assert mcp["environment"]["PRESTIGE_BENCH_SUBMISSION"] == str(submission)
    assert mcp["environment"]["PRESTIGE_REMOTE_ENABLED"] == "1"
    permissions = agent["permissions"]
    assert permissions[0] == {"action": "*", "resource": "*", "effect": "deny"}
    assert {"action": "prestige_*", "resource": "*", "effect": "allow"} in permissions


def test_adaptive_commands_pin_agent_and_skip_global_model_override():
    for condition, agent in ADAPTIVE_AGENTS.items():
        command = _command("unused/model", "opencode", condition, agent)
        assert command[command.index("--agent") + 1] == agent
        assert "--model" not in command
    legacy = _command("provider/model", "opencode", "A", "bench")
    assert legacy[legacy.index("--model") + 1] == "provider/model"


def test_adaptive_prompts_keep_conditions_separate(tmp_path):
    view = tmp_path / "view"
    view.mkdir()
    source = view / "challenge"
    source.mkdir()
    submission = tmp_path / "submission.json"
    skills = tmp_path / "skills"
    dd = _prompt("DD", view, skills, 180, source, submission)
    ke = _prompt("KE", view, skills, 180, source, submission)
    dp = _prompt("DP", view, skills, 180, source, submission, {"registration_id": "jsvc", "port": 31337})
    assert "prestige_" not in dd
    assert "executor" in ke.lower()
    assert "prestige_target_bind" not in ke
    assert "prestige_create_investigation" in dp
    assert "prestige_target_bind" in dp


def test_public_redaction_removes_answer_hashes_and_private_paths():
    answer_hash = "a" * 64
    result = {
        "challenge": "pwn-jsculator",
        "condition": "DP",
        "verified": True,
        "submitted_sha256": answer_hash,
        "candidate_digests": [answer_hash],
        "wrong_candidate_digests": [],
        "final_text_sha256": "b" * 64,
        "state_dir": "/home/operator/private-state",
        "workdir": "/home/operator/private-work",
        "submission_path": "/home/operator/submission.json",
        "checker_result": {"candidate_hash": answer_hash, "accepted": True},
        "prestige_state": {"candidate_match": True, "runs": 1, "statuses": ["ready"]},
        "config": {"mcp": {"environment": {"PRESTIGE_HOME": "/home/operator/state"}}},
        "parsed": {"tool_calls": 3},
    }
    public = public_result(result)
    assert public["verified"] is True
    assert public["prestige_state"]["runs"] == 1
    assert public["public_redacted"] is True
    text = json.dumps(public, sort_keys=True)
    assert answer_hash not in text
    assert "submitted_sha256" not in public
    assert "candidate_digests" not in public
    assert "candidate_match" not in public["prestige_state"]
    assert "config" not in public
    assert "/home/operator" not in text
    summary = public_summary({"attempts": 1, "results": [result]})
    summary_text = json.dumps(summary, sort_keys=True)
    assert answer_hash not in summary_text
    assert "submitted_sha256" not in summary_text
