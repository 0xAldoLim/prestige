"""Deterministic progress signals used for bounded escalation guidance."""

import time

from prestige import hypotheses
from prestige.engine import new_run
from prestige.human import request_operator
from prestige.progress import assess, remaining_budget
from prestige.strategy import rules_for_mode


def _observation(store, run_id, *, tool="inspect", args=None, result=None):
    store.event(
        run_id,
        "observation",
        {
            "action": {"tool": tool, "artifact": "", "args": args or {}},
            "result": result if result is not None else {"output": "x"},
            "trust": "fact",
        },
    )


def test_remaining_budget_uses_first_attempt_clock(store, tmp_path):
    path = tmp_path / "challenge.txt"
    path.write_bytes(b"data")
    run_id = new_run(
        store,
        path,
        mode="auto",
        rules=rules_for_mode("auto", 8, 300),
        max_turns=8,
        max_seconds=300,
    )

    untouched = remaining_budget(store.run(run_id))
    assert untouched["clock_started"] is False
    assert untouched["remaining_seconds"] == 300

    store.update(run_id, attempts=2, started=time.time() - 250)
    started = remaining_budget(store.run(run_id))
    assert started["clock_started"] is True
    assert started["remaining_attempts"] == 6
    assert 40 <= started["remaining_seconds"] <= 60


def test_easy_direct_work_is_not_escalated(store, tmp_path):
    path = tmp_path / "challenge.txt"
    path.write_bytes(b"data")
    run_id = new_run(store, path, mode="fast", max_turns=8, max_seconds=120)
    _observation(
        run_id=run_id,
        store=store,
        result={"stdout": "decoded answer"},
    )
    result = assess(store, run_id)
    assert result["state"] == "exploring"
    assert result["recommendation"] == "continue"


def test_productive_similar_output_is_not_misclassified(store, tmp_path):
    path = tmp_path / "challenge.txt"
    path.write_bytes(b"data")
    run_id = new_run(store, path, mode="auto", max_turns=30, max_seconds=300)
    for step in range(4):
        # Same tool and argument shape, but every interaction reveals a new
        # protocol state. This is difficult but productive work.
        _observation(
            store,
            run_id,
            tool="command",
            args={"argv": ["interact"]},
            result={"stdout": f"stage-{step}"},
        )
    result = assess(store, run_id)
    assert result["state"] == "productive"
    assert result["recommendation"] == "continue"
    assert result["repeated_actions_recent"] >= 2
    assert result["new_results_recent"] >= 3


def test_repeated_identical_evidence_is_detected(store, tmp_path):
    path = tmp_path / "challenge.txt"
    path.write_bytes(b"data")
    run_id = new_run(store, path, mode="fast", max_turns=8, max_seconds=120)
    for _ in range(4):
        _observation(store, run_id, result={"output": "same"})
    result = assess(store, run_id)
    assert result["state"] == "loop_suspected"
    assert result["recommendation"] == "escalate"
    assert result["repeated_results_recent"] >= 3


def test_repeated_different_tools_with_same_output_stall(store, tmp_path):
    path = tmp_path / "challenge.txt"
    path.write_bytes(b"data")
    run_id = new_run(store, path, mode="auto", max_turns=30, max_seconds=300)
    for tool in ("inspect", "strings", "read", "inspect"):
        _observation(store, run_id, tool=tool, result={"output": "same"})
    result = assess(store, run_id)
    # Distinct action signatures, but no new information.
    assert result["state"] == "no_progress"
    assert result["recommendation"] == "escalate"


def test_low_budget_reports_limits_instead_of_escalating(store, tmp_path):
    path = tmp_path / "challenge.txt"
    path.write_bytes(b"data")
    run_id = new_run(store, path, mode="fast", max_turns=3, max_seconds=120)
    for _ in range(3):
        _observation(store, run_id, result={"output": "same"})
    store.update(run_id, attempts=2, started=time.time())
    result = assess(store, run_id)
    assert result["state"] == "loop_suspected"
    assert result["budget"]["remaining_attempts"] == 1
    assert result["recommendation"] == "report_limits"


def test_terminal_and_operator_states_are_bounded(store, tmp_path):
    path = tmp_path / "challenge.txt"
    path.write_bytes(b"data")
    run_id = new_run(store, path, mode="auto", max_turns=8, max_seconds=120)
    request_operator(store, run_id, "Confirm scope")
    waiting = assess(store, run_id)
    assert waiting["state"] == "awaiting_operator"
    assert waiting["recommendation"] == "await_operator"

    store.update(run_id, status="budget_exhausted")
    exhausted = assess(store, run_id)
    assert exhausted["state"] == "terminal"
    assert exhausted["recommendation"] == "report_limits"

    store.update(run_id, status="solved")
    solved = assess(store, run_id)
    assert solved["state"] == "terminal"
    assert solved["recommendation"] == "stop"


def test_contradicted_hypotheses_recommend_a_new_test(store, tmp_path):
    path = tmp_path / "challenge.txt"
    path.write_bytes(b"data")
    run_id = new_run(store, path, mode="auto", max_turns=8, max_seconds=120)
    record = hypotheses.add(store, run_id, "first guess", test_tool="inspect")
    hypotheses.update(
        store, run_id, record["id"], trusted=True, confidence="contradicted"
    )
    _observation(store, run_id, result={"stdout": "unrelated"})
    result = assess(store, run_id)
    assert result["hypotheses"]["contradicted"] == 1
    assert result["recommendation"] == "change_test"
