"""Fair condition-comparison harness; no fabricated model results."""

import json
import sys
from pathlib import Path

import pytest

from prestige.evaluation import run_conditions
from prestige.types import PolicyDenied

SUITE = Path(__file__).parent.parent / "benchmarks" / "synthetic" / "suite.json"


async def test_p1_p2_p3_share_contract_except_lane(store):
    report = await run_conditions(store, SUITE, ("P1", "P2", "P3"))
    assert report["comparable"] is True
    assert report["performance_claim"].startswith("none")
    conditions = report["conditions"]
    assert set(conditions) == {"P1", "P2", "P3"}
    case_sets = []
    for name in ("P1", "P2", "P3"):
        item = conditions[name]
        assert item["model_evaluation"] is False
        assert item["results"]
        case_sets.append({(entry["case"], entry["repeat"]) for entry in item["results"]})
    assert case_sets[0] == case_sets[1] == case_sets[2]
    base = conditions["P1"]["contract"]
    for name in ("P2", "P3"):
        other = conditions[name]["contract"]
        for key in ("suite_hash", "model", "permissions", "max_turns", "max_seconds", "workers"):
            assert other[key] == base[key]
        assert other["effort"] != base["effort"]


async def test_b0_b1_are_not_fabricated_without_adapter(store):
    report = await run_conditions(store, SUITE, ("B0", "B1"))
    assert report["comparable"] is False
    for name in ("B0", "B1"):
        assert report["conditions"][name]["status"] == "not_run"
        assert "adapter" in report["conditions"][name]["reason"]


async def test_duplicate_or_unknown_conditions_rejected(store):
    with pytest.raises(PolicyDenied):
        await run_conditions(store, SUITE, ("P1", "P1"))
    with pytest.raises(PolicyDenied):
        await run_conditions(store, SUITE, ("P9",))


def test_cli_conditions_output(tmp_path, capsys):
    from prestige.cli import main

    output = tmp_path / "conditions.json"
    assert (
        main(
            [
                "--home",
                str(tmp_path / "state"),
                "benchmark",
                "conditions",
                "--suite",
                str(SUITE),
                "--conditions",
                "P1,P2",
                "--output",
                str(output),
            ]
        )
        == 0
    )
    body = output.read_text()
    assert '"comparable": true' in body
    assert '"model_evaluation": false' in body
    capsys.readouterr()


class FixtureAdapter:
    """Deterministic adapter used only to test benchmark plumbing."""

    model_evaluation = False
    adapter_kind = "fixture"
    contract = {
        "model": "fixture-baseline",
        "permissions": "bounded-offline-tools",
        "max_turns": 12,
        "max_seconds": 120,
    }

    def __init__(self, condition):
        self.skills_enabled = condition == "B1"

    async def run(self, case, artifact, contract):
        return {
            "status": "solved" if self.skills_enabled else "unsolved",
            "tokens": None,
            "seconds": 0.01,
            "tool_calls": 1,
            "failed_experiments": 0,
            "skills_used": 1 if self.skills_enabled else 0,
            "security_violations": 0,
            "verified": self.skills_enabled,
            "candidates": [],
        }


async def test_b0_b1_adapter_plumbing_without_fabricated_usage(store):
    report = await run_conditions(
        store, SUITE, ("B0", "B1"), adapter_factory=FixtureAdapter
    )
    assert report["comparable"] is True
    b0 = report["conditions"]["B0"]
    b1 = report["conditions"]["B1"]
    assert b0["adapter"] == "fixture"
    assert b0["model_evaluation"] is False
    assert b0["condition_metadata"]["skills_enabled"] is False
    assert b1["condition_metadata"]["skills_enabled"] is True
    assert b0["metrics"]["tokens"] is None
    assert b0["metrics"]["usage_coverage"] == 0
    assert b1["metrics"]["solved"] > 0
    assert b0["contract"]["model"] == b1["contract"]["model"]
    assert b0["contract"]["effort"] != b1["contract"]["effort"]
    assert b0["metrics"]["tool_calls"] == len(b0["results"])
    assert b0["metrics"]["security_violations"] == 0


def _fake_runner(tmp_path, malformed=False):
    script = tmp_path / "runner.py"
    if malformed:
        script.write_text("print('not json')\n")
    else:
        script.write_text(
            "import json, sys\n"
            "payload = json.load(sys.stdin)\n"
            "skills = bool(payload.get('skills_enabled'))\n"
            "print(json.dumps({\n"
            "  'status': 'solved' if skills else 'unsolved',\n"
            "  'tokens': None,\n"
            "  'seconds': 0.01,\n"
            "  'tool_calls': 3 if skills else 1,\n"
            "  'failed_experiments': 0,\n"
            "  'skills_used': 1 if skills else 0,\n"
            "  'security_violations': 0,\n"
            "  'verified': skills,\n"
            "  'candidates': [],\n"
            "}))\n"
        )
    return [sys.executable, str(script)]


async def test_command_adapter_b0_b1_plumbing(store, tmp_path):
    from prestige.benchmark_adapter import CommandConditionAdapter

    command = _fake_runner(tmp_path)

    def factory(condition):
        return CommandConditionAdapter(command, condition, "operator-model", 12, 120)

    report = await run_conditions(
        store, SUITE, ("B0", "B1"), adapter_factory=factory
    )
    assert report["comparable"] is True
    b0 = report["conditions"]["B0"]
    b1 = report["conditions"]["B1"]
    assert b0["adapter"] == "operator-command"
    assert b0["model_evaluation"] is True
    assert b0["metrics"]["tokens"] is None
    assert b0["metrics"]["usage_coverage"] == 0
    assert b1["metrics"]["solved"] > 0
    assert b1["condition_metadata"]["skills_enabled"] is True
    assert b0["contract"]["model"] == b1["contract"]["model"]


async def test_command_adapter_malformed_output_is_failure(tmp_path):
    from prestige.benchmark_adapter import CommandConditionAdapter

    command = _fake_runner(tmp_path, malformed=True)
    adapter = CommandConditionAdapter(command, "B1", "operator-model")
    result = await adapter.run(
        {"id": "case"}, tmp_path / "artifact.bin", adapter.contract
    )
    assert result["status"] == "failed"
    assert result["tokens"] is None
    assert result["failed_experiments"] == 1
    assert "JSON" in result["error"]


def test_cli_conditions_with_operator_adapter(tmp_path, capsys):
    from prestige.cli import main

    command = _fake_runner(tmp_path)
    output = tmp_path / "adapter-conditions.json"
    assert (
        main(
            [
                "--home",
                str(tmp_path / "state"),
                "benchmark",
                "conditions",
                "--suite",
                str(SUITE),
                "--conditions",
                "B0,B1",
                "--adapter-command",
                " ".join(command),
                "--adapter-model",
                "operator-model",
                "--output",
                str(output),
            ]
        )
        == 0
    )
    body = json.loads(output.read_text())
    assert body["comparable"] is True
    assert body["conditions"]["B0"]["adapter"] == "operator-command"
    capsys.readouterr()
