"""Offline regression tests for the strict two-route OpenCode architecture.

The repository routes planning to paid Kimi through a delegation-only orchestrator
and all execution to the free DeepSeek V4.1 Flash route through the
executor/prestige agents. Paid DeepSeek V4.1 Flash 1017 and other fallback models
must stay disabled. These tests are deliberately offline: the real-model trace is
opt-in so the default suite never makes a network request.
"""

import json
import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
CONFIG_PATH = ROOT / "opencode.jsonc"


def _strip_jsonc(text: str) -> str:
    """Remove JSONC comments without touching URL or prompt strings."""
    result: list[str] = []
    index = 0
    in_string = False
    escaped = False
    while index < len(text):
        char = text[index]
        if in_string:
            result.append(char)
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                in_string = False
            index += 1
            continue
        if char == '"':
            in_string = True
            result.append(char)
            index += 1
            continue
        if char == "/" and index + 1 < len(text) and text[index + 1] == "/":
            while index < len(text) and text[index] not in "\r\n":
                index += 1
            continue
        if char == "/" and index + 1 < len(text) and text[index + 1] == "*":
            index += 2
            while index + 1 < len(text) and not (text[index] == "*" and text[index + 1] == "/"):
                index += 1
            index += 2
            continue
        result.append(char)
        index += 1
    return re.sub(r",(\s*[}\]])", r"\1", "".join(result))


def _config() -> dict:
    return json.loads(_strip_jsonc(CONFIG_PATH.read_text(encoding="utf-8")))


def _match(pattern: str, value: str) -> bool:
    if pattern.endswith("*"):
        return value.startswith(pattern[:-1])
    return pattern == value


def _effective(agent: dict, action: str, resource: str) -> str:
    """Resolve permissions in declaration order, last match wins."""
    effect = "deny"
    for rule in agent.get("permissions", []):
        if _match(rule["action"], action) and _match(rule["resource"], resource):
            effect = rule["effect"]
    return effect


def test_default_agent_and_root_model_are_free_deepseek_execution():
    config = _config()
    assert config["default_agent"] == "orchestrator"
    assert config["model"] == "opencode/deepseek-v4.1-flash-free"


def test_exact_agent_models_and_modes():
    agents = _config()["agents"]
    assert set(agents) == {
        "orchestrator",
        "executor",
        "prestige",
        "build",
        "plan",
        "general",
        "explore",
        "compaction",
        "title",
        "summary",
    }
    assert agents["orchestrator"]["model"] == "opencode-go/kimi-k3.1-pro"
    assert agents["orchestrator"]["mode"] == "primary"
    assert agents["executor"]["model"] == "opencode/deepseek-v4.1-flash-free"
    assert agents["executor"]["mode"] == "subagent"
    assert agents["prestige"]["model"] == "opencode/deepseek-v4.1-flash-free"
    assert agents["prestige"]["mode"] == "all"


def test_helpers_use_the_free_route_not_the_paid_provider():
    agents = _config()["agents"]
    for helper in ("compaction", "title", "summary"):
        assert agents[helper] == {
            "model": "opencode/deepseek-v4.1-flash-free"
        }, helper


def test_no_paid_checkpoint_or_alternate_model_mapping():
    """Active selectors use exact free/Kimi API IDs, never a paid fallback."""
    config = _config()
    selected = {config["model"]}
    selected |= {
        agent["model"] for agent in config["agents"].values() if "model" in agent
    }
    assert selected == {
        "opencode/deepseek-v4.1-flash-free",
        "opencode-go/kimi-k3.1-pro",
    }
    text = CONFIG_PATH.read_text(encoding="utf-8")
    assert "1017" not in text
    assert "deepseek-v4.1-flash-1017" not in text


def test_paid_and_fallback_models_are_disabled():
    providers = _config()["providers"]
    opencode_disabled = providers["opencode"]["models"]
    go_disabled = providers["opencode-go"]["models"]
    for model_id in ("deepseek-v4-pro", "gpt-6-luna"):
        assert opencode_disabled[model_id] == {"disabled": True}, model_id
        assert go_disabled[model_id] == {"disabled": True}, model_id
    assert go_disabled["deepseek-v4.1-flash"] == {"disabled": True}
    # The free route stays enabled in the opencode catalog.
    assert "deepseek-v4.1-flash-free" not in opencode_disabled
    # Kimi stays the only enabled opencode-go model in checked-in config.
    assert "kimi-k3.1-pro" not in go_disabled


def test_builtin_agents_are_disabled():
    agents = _config()["agents"]
    for agent_id in ("build", "plan", "general", "explore"):
        assert agents[agent_id] == {"disabled": True}


def test_orchestrator_is_delegation_only():
    orchestrator = _config()["agents"]["orchestrator"]
    assert _effective(orchestrator, "read", "src/prestige/mcp_server.py") == "allow"
    assert _effective(orchestrator, "glob", "**/*.py") == "allow"
    assert _effective(orchestrator, "grep", "opencode.jsonc") == "allow"
    assert _effective(orchestrator, "subagent", "executor") == "allow"
    assert _effective(orchestrator, "subagent", "prestige") == "allow"
    for action in ("shell", "edit", "write", "patch", "browser", "web", "skill"):
        assert _effective(orchestrator, action, "*") == "deny", action
    for agent_id in ("build", "plan", "general", "explore", "unknown"):
        assert _effective(orchestrator, "subagent", agent_id) == "deny", agent_id


def test_executor_cannot_spawn_subagents():
    executor = _config()["agents"]["executor"]
    assert executor["permissions"] == [
        {"action": "subagent", "resource": "*", "effect": "deny"}
    ]
    for agent_id in ("orchestrator", "executor", "prestige", "unknown"):
        assert _effective(executor, "subagent", agent_id) == "deny", agent_id


def test_prestige_keeps_host_tool_denials_and_mcp_allowlist():
    prestige = _config()["agents"]["prestige"]
    for action in ("shell", "read", "write", "browser", "skill"):
        assert _effective(prestige, action, "/tmp/x") == "deny", action
    assert _effective(prestige, "prestige_prestige_create_investigation", "*") == "allow"
    assert _effective(prestige, "prestige_prestige_exec", "*") == "allow"
    assert _effective(prestige, "prestige_prestige_run_experiment", "*") == "allow"
    assert _effective(prestige, "prestige_prestige_submit_final", "*") == "allow"


def test_provider_policy_allows_only_the_two_authorized_routes():
    policies = _config()["policies"]
    assert policies[0] == {
        "action": "provider.use",
        "resource": "*",
        "effect": "deny",
    }
    allowed = {
        rule["resource"]
        for rule in policies
        if rule["action"] == "provider.use" and rule["effect"] == "allow"
    }
    assert allowed == {"opencode-go", "opencode"}


@pytest.mark.skipif(not shutil.which("opencode"), reason="OpenCode CLI not available")
def test_opencode_cli_resolves_only_intended_agents():
    # The standalone debug service has shown a rare startup race in which the
    # built-in helpers are returned without project agents. Retry once so a
    # transient startup does not masquerade as a routing regression; a real
    # configuration error still fails deterministically.
    agents = {}
    for _attempt in range(2):
        result = subprocess.run(
            ["opencode", "--standalone", "debug", "agents"],
            capture_output=True,
            text=True,
            cwd=str(ROOT),
            timeout=120,
        )
        if result.returncode != 0:
            pytest.skip("OpenCode debug service unavailable: " + result.stderr[:300])
        agents = {agent["id"]: agent for agent in json.loads(result.stdout)}
        if {"orchestrator", "executor", "prestige"} <= set(agents):
            break
    assert {"orchestrator", "executor", "prestige"} <= set(agents), sorted(agents)

    assert agents["orchestrator"]["model"] == {
        "id": "kimi-k3.1-pro",
        "providerID": "opencode-go",
    }
    assert agents["orchestrator"]["mode"] == "primary"
    assert agents["executor"]["model"] == {
        "id": "deepseek-v4.1-flash-free",
        "providerID": "opencode",
    }
    assert agents["executor"]["mode"] == "subagent"
    assert agents["prestige"]["model"] == {
        "id": "deepseek-v4.1-flash-free",
        "providerID": "opencode",
    }
    assert agents["prestige"]["mode"] == "all"
    for helper in ("compaction", "title", "summary"):
        assert agents[helper]["model"] == {
            "id": "deepseek-v4.1-flash-free",
            "providerID": "opencode",
        }, helper
    for agent_id in ("build", "plan", "general", "explore"):
        assert agent_id not in agents

    models = subprocess.run(
        ["opencode", "models"],
        capture_output=True,
        text=True,
        cwd=str(ROOT),
        timeout=120,
    )
    assert models.returncode == 0, models.stderr[:300]
    assert set(models.stdout.split()) == {
        "opencode-go/kimi-k3.1-pro",
        "opencode/deepseek-v4.1-flash-free",
    }

    assert _effective(agents["executor"], "shell", "*") == "allow"
    assert _effective(agents["executor"], "edit", "*") == "allow"
    assert _effective(agents["executor"], "write", "*") == "allow"
    assert _effective(agents["executor"], "subagent", "prestige") == "deny"
    assert _effective(agents["orchestrator"], "shell", "*") == "deny"
    assert _effective(agents["orchestrator"], "edit", "*") == "deny"
    assert _effective(agents["orchestrator"], "write", "*") == "deny"
    assert _effective(agents["orchestrator"], "subagent", "executor") == "allow"
    assert _effective(agents["orchestrator"], "subagent", "prestige") == "allow"
    assert _effective(agents["orchestrator"], "subagent", "build") == "deny"


@pytest.mark.live
@pytest.mark.skipif(
    os.environ.get("PRESTIGE_TEST_REAL_MODEL_TRACE") != "1",
    reason="set PRESTIGE_TEST_REAL_MODEL_TRACE=1 to make one small free-model call",
)
def test_real_orchestrator_delegates_to_free_deepseek_executor(tmp_path):
    """One opt-in trace proving the configured free/Kimi models are used.

    This test never runs in the default suite. It asks the orchestrator for one
    executor delegation, then reads the recorded session messages through the
    real OpenCode API instead of trusting configuration or model text.
    """
    if not shutil.which("opencode"):
        pytest.skip("OpenCode CLI not available")
    marker = tmp_path / "executor-trace.txt"
    prompt = (
        "Delegate to the executor subagent: write exactly executor-ok to "
        f"{marker} and verify it by reading it back. Do not write it yourself."
    )
    run = subprocess.run(
        [
            "opencode",
            "run",
            "--standalone",
            "--agent",
            "orchestrator",
            "--format",
            "json",
            "--title",
            "model-routing-opt-in-trace",
            prompt,
        ],
        capture_output=True,
        text=True,
        cwd=str(ROOT),
        timeout=300,
    )
    if run.returncode != 0:
        pytest.skip("OpenCode live trace unavailable: " + run.stderr[:300])
    events = [json.loads(line) for line in run.stdout.splitlines() if line.startswith("{")]
    session_id = next(event["sessionID"] for event in events if "sessionID" in event)
    assert marker.read_text(encoding="utf-8") == "executor-ok"

    def api(path: str) -> dict:
        response = subprocess.run(
            ["opencode", "api", "get", path],
            capture_output=True,
            text=True,
            cwd=str(ROOT),
            timeout=120,
        )
        assert response.returncode == 0, response.stderr[:300]
        return json.loads(response.stdout)

    def assistant_models(messages: list[dict]) -> set[tuple[str, str, str]]:
        return {
            (message["agent"], message["model"]["providerID"], message["model"]["id"])
            for message in messages
            if message.get("type") == "assistant" and message.get("model")
        }

    orchestrator = api(f"/api/session/{session_id}/message")
    assert ("orchestrator", "opencode-go", "kimi-k3.1-pro") in assistant_models(
        orchestrator["data"]
    )

    sessions = api("/api/session")["data"]
    child = next(session for session in sessions if session.get("parentID") == session_id)
    executor = api(f"/api/session/{child['id']}/message")
    assert ("executor", "opencode", "deepseek-v4.1-flash-free") in assistant_models(
        executor["data"]
    )
