import hashlib
import time
from dataclasses import asdict, dataclass, field

from prestige import human
from prestige.store import Store, encoded
from prestige.types import Action, PrestigeError

# Number of recent observations inspected when classifying progress. Small enough
# to ignore early exploration, large enough to expose a repeated loop.
_RECENT_WINDOW = 5

_TERMINAL_STATUSES = {"solved", "stopped", "input_rejected", "budget_exhausted"}


def fingerprint(action: Action) -> str:
    # IDs are content hashes: renaming or reordering identical inputs cannot evade repetition.
    return hashlib.sha256(encoded(asdict(action)).encode()).hexdigest()


def remaining_budget(run: dict, now: float | None = None) -> dict:
    """Authoritative remaining budget for an MCP investigation.

    Wall time starts at the first tool attempt (``runs.started``), matching
    ``mcp_server._check_budget``. Runs that have not attempted a tool yet retain
    their full wall-time budget regardless of how long ago they were created.
    """
    settings = run["settings"]
    current = time.time() if now is None else now
    prior_elapsed = float(run.get("elapsed") or 0.0)
    started = run.get("started")
    if started is None:
        elapsed = prior_elapsed
        clock_started = False
    else:
        elapsed = max(0.0, current - float(started))
        clock_started = True
    max_seconds = float(settings["max_seconds"])
    max_turns = int(settings["max_turns"])
    attempts = int(run["attempts"])
    return {
        "attempts": attempts,
        "max_turns": max_turns,
        "remaining_attempts": max(0, max_turns - attempts),
        "elapsed_seconds": round(elapsed, 3),
        "max_seconds": max_seconds,
        "remaining_seconds": round(max(0.0, max_seconds - elapsed), 3),
        "clock_started": clock_started,
        "attempt_limited": attempts >= max_turns,
        "time_limited": elapsed >= max_seconds,
    }


def _action_signature(action: dict) -> str:
    return hashlib.sha256(
        encoded(
            {
                "tool": action.get("tool", ""),
                "artifact": action.get("artifact", ""),
                "args": action.get("args", {}),
            }
        ).encode()
    ).hexdigest()


def _result_signature(result) -> str:
    return hashlib.sha256(encoded(result).encode()).hexdigest()


def _failed(result) -> bool:
    if not isinstance(result, dict):
        return False
    if result.get("status") in {"denied", "error"}:
        return True
    return result.get("returncode") not in (None, 0)


def assess(store: Store, run_id: str) -> dict:
    """Summarize durable evidence without planning or choosing tools.

    The signal is deliberately conservative: only repeated identical
    action/result signatures with no novel output are treated as stagnation.
    Different outputs from the same tool (for example successive interactive
    protocol replies) remain productive. The returned recommendation is
    advisory; it never changes lane, model, provider or scope by itself.
    """
    run = store.run(run_id)
    events = store.events(run_id)
    observations = [event["data"] for event in events if event["kind"] == "observation"]
    artifacts = store.rows(
        "SELECT id,parent FROM artifacts WHERE run_id=?", (run_id,)
    )
    derived_artifacts = sum(1 for item in artifacts if item["parent"])

    hypothesis_records = {}
    for event in events:
        if event["kind"] == "hypothesis" and event["data"].get("id"):
            hypothesis_records[event["data"]["id"]] = event["data"]
    active = [item for item in hypothesis_records.values() if item.get("status") == "active"]
    confidences = [item.get("confidence", "unresolved") for item in active]
    evaluations = [event["data"] for event in events if event["kind"] == "hypothesis_evaluation"]
    evaluator_recommendations = sorted(
        {
            item.get("recommendation")
            for item in evaluations[-8:]
            if item.get("recommendation")
        }
    )

    action_signatures = []
    result_signatures = []
    failures = []
    for data in observations:
        action_signatures.append(_action_signature(data.get("action") or {}))
        result_signatures.append(_result_signature(data.get("result") or {}))
        failures.append(_failed(data.get("result") or {}))

    window = min(_RECENT_WINDOW, len(observations))
    recent_actions = action_signatures[-window:] if window else []
    recent_results = result_signatures[-window:] if window else []
    prior_actions = set(action_signatures[:-window]) if window else set()
    prior_results = set(result_signatures[:-window]) if window else set()

    # Count novelty relative to everything before the recent window, but also
    # require diversity inside the window: four identical replies are a loop
    # even when the first of them is technically new.
    distinct_recent = len(set(recent_results))
    novel_recent = len({digest for digest in recent_results if digest not in prior_results})
    stale_recent = sum(1 for digest in recent_results if digest in prior_results)
    repeated_actions = 0
    seen_actions = set(prior_actions)
    for signature in recent_actions:
        if signature in seen_actions:
            repeated_actions += 1
        seen_actions.add(signature)
    repeated_results = window - distinct_recent

    budget = remaining_budget(run)
    pending = human.pending_request(store, run_id)

    if run["status"] in _TERMINAL_STATUSES:
        state = "terminal"
    elif pending:
        state = "awaiting_operator"
    elif not observations:
        state = "not_started"
    elif window < 3:
        state = "exploring"
    elif distinct_recent <= 1 or novel_recent == 0:
        state = "loop_suspected" if repeated_actions >= 2 else "no_progress"
    else:
        state = "productive"

    if state == "terminal":
        recommendation = "report_limits" if run["status"] == "budget_exhausted" else "stop"
    elif state == "awaiting_operator":
        recommendation = "await_operator"
    elif state == "not_started":
        recommendation = "continue"
    elif state in {"no_progress", "loop_suspected"}:
        if budget["remaining_attempts"] <= 1 or budget["remaining_seconds"] <= 15:
            recommendation = "report_limits"
        elif (
            run["lane"] != "expert"
            and budget["remaining_attempts"] >= 2
            and budget["remaining_seconds"] > 30
        ):
            recommendation = "escalate"
        else:
            recommendation = "change_test"
    elif active and all(confidence == "contradicted" for confidence in confidences):
        # The current hypotheses were falsified. This is informative, but the
        # next step is a revised test, not more budget or a wider scope.
        recommendation = "change_test"
    else:
        recommendation = "continue"

    return {
        "state": state,
        "recommendation": recommendation,
        "observations": len(observations),
        "recent_window": window,
        "new_results_recent": novel_recent,
        "distinct_results_recent": distinct_recent,
        "stale_results_recent": stale_recent,
        "repeated_actions_recent": repeated_actions,
        "repeated_results_recent": repeated_results,
        "failed_observations_recent": sum(failures[-window:]) if window else 0,
        "derived_artifacts": derived_artifacts,
        "hypotheses": {
            "active": len(active),
            "supported": sum(1 for value in confidences if value == "supported"),
            "contradicted": sum(1 for value in confidences if value == "contradicted"),
            "inconclusive": sum(1 for value in confidences if value == "inconclusive"),
            "unresolved": sum(1 for value in confidences if value == "unresolved"),
        },
        "evaluator_recommendations": evaluator_recommendations,
        "budget": budget,
    }


@dataclass
class Budget:
    max_turns: int
    max_seconds: float
    max_tokens: int | None = None
    turns: int = 0
    tokens: int = 0
    previous_seconds: float = 0
    started: float = field(default_factory=time.monotonic)

    @property
    def elapsed(self):
        return self.previous_seconds + time.monotonic() - self.started

    def check(self):
        if self.turns >= self.max_turns or self.elapsed >= self.max_seconds:
            raise PrestigeError("Turn or wall-time budget exhausted")
        if self.max_tokens is not None and self.tokens >= self.max_tokens:
            raise PrestigeError("Reported token budget exhausted")


@dataclass
class Progress:
    stale: int = 0
    seen: set[str] = field(default_factory=set)

    def observe(self, action: Action, novel: bool, error: bool = False) -> str:
        key = fingerprint(action)
        duplicate = key in self.seen
        self.seen.add(key)
        self.stale = 0 if novel and not duplicate and not error else self.stale + 1
        return "recover" if self.stale >= 2 else "continue"
