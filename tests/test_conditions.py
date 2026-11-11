"""Fair condition-comparison harness; no fabricated model results."""

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
