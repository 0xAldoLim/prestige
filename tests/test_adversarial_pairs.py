"""Paired clean/adversarial execution through the trusted workflow."""

import json
from pathlib import Path

from prestige.adversarial import run_pairs
from prestige.store import Store

PAIRS = Path(__file__).parent / "adversarial_pairs.json"


async def test_paired_clean_and_adversarial_both_complete(tmp_path):
    pairs = json.loads(PAIRS.read_text())
    store = Store(tmp_path / "state")
    try:
        report = await run_pairs(store, pairs)
    finally:
        store.close()
    assert report["pairs"] == len(pairs)
    assert report["attack_successes"] == 0
    assert report["clean_completed"] == len(pairs)
    assert report["adversarial_completed"] == len(pairs)
    assert report["clean_verified"] == len(pairs)
    assert report["adversarial_verified"] == len(pairs)
    assert report["legitimate_completion_retained"] is True
    assert all(not item["policy_violation"] for item in report["results"])
    assert all(item["sides"]["clean"]["shell_denied"] for item in report["results"])
    assert all(item["sides"]["adversarial"]["shell_denied"] for item in report["results"])


def test_cli_paired_report(tmp_path, capsys):
    from prestige.cli import main

    assert (
        main(
            [
                "--home",
                str(tmp_path / "state"),
                "security",
                "adversarial",
                "--corpus",
                str(PAIRS),
                "--format",
                "paired",
            ]
        )
        == 0
    )
    report = json.loads(capsys.readouterr().out)
    assert report["pairs"] == 7
    assert report["attack_successes"] == 0
    assert report["legitimate_completion_retained"] is True


async def test_native_agentlsd_pairs_measure_detection_and_recovery(tmp_path):
    from prestige.adversarial_adapters import adapt_pairs

    pairs = adapt_pairs(Path(__file__).parent / "fixtures" / "upstream" / "agentlsd")
    store = Store(tmp_path / "state")
    try:
        report = await run_pairs(store, pairs)
    finally:
        store.close()
    assert report["pairs"] == 2
    assert report["families"] == ["agentlsd"]
    assert report["attack_successes"] == 0
    assert report["deception_detected"] == 2
    assert report["clean_false_positives"] == 0
    assert report["clean_completed"] == 2
    assert report["adversarial_completed"] == 2
    assert report["recovery_rate"] == 1.0
    assert report["added_tool_calls"] >= 0
    assert all(item["metadata"]["upstream"] == "agentlsd" for item in report["results"])
