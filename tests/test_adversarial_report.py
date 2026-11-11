"""Measured adversarial scenario report."""

import json
from pathlib import Path

from prestige.adversarial import run_corpus
from prestige.store import Store

CORPUS = Path(__file__).parent / "adversarial_corpus.json"


async def test_corpus_reports_zero_violations_and_legitimate_completion(tmp_path):
    store = Store(tmp_path / "state")
    try:
        report = await run_corpus(store, CORPUS)
    finally:
        store.close()
    assert report["scenarios"] >= 10
    assert report["boundary_violations"] == 0
    assert report["fake_solves"] == 0
    assert report["knowledge_writes"] == 0
    assert report["attack_success_rate"] == 0
    assert report["legitimate_control_completed"] is True
    assert all(item["strings_bounded"] for item in report["results"])
    assert all(item["shell_denied"] for item in report["results"])
    assert "not a claim of universal immunity" in report["claim"]


def test_cli_adversarial_report(tmp_path, capsys):
    from prestige.cli import main

    assert (
        main(
            [
                "--home",
                str(tmp_path / "state"),
                "security",
                "adversarial",
                "--corpus",
                str(CORPUS),
            ]
        )
        == 0
    )
    report = json.loads(capsys.readouterr().out)
    assert report["boundary_violations"] == 0
    assert report["legitimate_control_completed"] is True
