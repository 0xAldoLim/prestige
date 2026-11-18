"""Shared final-submission placeholder checks and benchmark reader regression tests."""

import json

import pytest

from prestige.ctf_benchmark import read_submission
from prestige.submission import placeholder_reason


@pytest.mark.parametrize(
    "candidate",
    [
        "UNSOLVED",
        "unknown",
        "NO_FLAG",
        "not found",
        "TBD",
        "TODO",
        "placeholder",
        "N/A",
        "none",
        "NULL",
        "  No Flag  ",
    ],
)
def test_obvious_placeholders_are_rejected(candidate):
    assert placeholder_reason(candidate)


@pytest.mark.parametrize(
    "candidate",
    [
        "SAS{normal_flag_value}",
        "flag{static_deployment_default}",
        "FLAG{decoy_from_compose_yaml}",
        "picoCTF{example_but_flag_shaped}",
        "plain-text-answer",
        "not_a_flag_but_a_real_candidate",
        "no_flag_here_but_still_real",
    ],
)
def test_flag_shaped_and_plain_candidates_are_not_blocked(candidate):
    assert placeholder_reason(candidate) is None


def test_read_submission_preserves_size_empty_and_control_controls(tmp_path):
    path = tmp_path / "submission.json"
    path.write_text(json.dumps({"flag": ""}), encoding="utf-8")
    assert read_submission(path)["status"] == "invalid"
    path.write_text(json.dumps({"flag": "A" * 513}), encoding="utf-8")
    assert read_submission(path)["status"] == "invalid"
    path.write_text(json.dumps({"flag": "SAS{bad\x01control}"}), encoding="utf-8")
    assert read_submission(path)["status"] == "invalid"
    path.write_text("x" * 4097, encoding="utf-8")
    assert read_submission(path)["status"] == "invalid"


def test_read_submission_rejects_placeholders_but_keeps_nested_checks(tmp_path):
    path = tmp_path / "submission.json"
    path.write_text(json.dumps({"flag": "TBD"}), encoding="utf-8")
    assert read_submission(path)["status"] == "invalid"

    path.write_text(json.dumps({"flag": {"flag": "SAS{nested}"}}), encoding="utf-8")
    result = read_submission(path)
    # A nested object is not a string and remains invalid.
    assert result["status"] == "invalid"

    path.write_text(json.dumps({"flag": "SAS{shape_valid_for_checker}"}), encoding="utf-8")
    result = read_submission(path)
    assert result["status"] == "valid"
    assert result["candidate"] == "SAS{shape_valid_for_checker}"
