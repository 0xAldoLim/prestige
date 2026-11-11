"""Structured, capped investigation hypotheses.

Each hypothesis records supporting and contradicting evidence, a predicted
observation, the cheapest discriminating test, resource cost and a pivot condition.
At most three may be active at once; events are append-only and the latest record
per id is authoritative.
"""

import uuid

from prestige.store import Store
from prestige.types import PolicyDenied, PrestigeError

MAX_ACTIVE = 3
STATUSES = {"active", "retired", "confirmed", "rejected"}
MAX_TEXT = 500
MAX_ITEM = 300
MAX_ITEMS = 5
CONFIDENCES = {"unresolved", "supported", "contradicted", "inconclusive"}
EVALUATOR_FIELDS = {
    "actual_experiment_result",
    "confidence",
    "evidence",
    "last_evaluated_seq",
}


def _text(value, field, limit=MAX_TEXT, required=False):
    if value is None and not required:
        return ""
    if not isinstance(value, str) or (required and not value.strip()) or len(value) > limit:
        raise PolicyDenied(f"Invalid hypothesis {field}")
    return value.strip()


def _items(value, field):
    if value is None:
        return []
    if not isinstance(value, list) or len(value) > MAX_ITEMS:
        raise PolicyDenied(f"Invalid hypothesis {field}")
    return [_text(item, field, MAX_ITEM) for item in value]


def latest(store: Store, run_id: str) -> list[dict]:
    records = {}
    order = []
    for event in store.events(run_id):
        if event["kind"] != "hypothesis":
            continue
        data = event["data"]
        hypothesis_id = data.get("id")
        if not hypothesis_id:
            continue
        if hypothesis_id not in records:
            order.append(hypothesis_id)
        records[hypothesis_id] = data
    return [records[hypothesis_id] for hypothesis_id in order]


def active(store: Store, run_id: str) -> list[dict]:
    return [item for item in latest(store, run_id) if item.get("status") == "active"]


def add(
    store: Store,
    run_id: str,
    text: str,
    supports: list[str] | None = None,
    contradicts: list[str] | None = None,
    prediction: str = "",
    cheapest_test: str = "",
    cost: str = "",
    pivot_if: str = "",
    test_tool: str = "",
    test_artifact: str = "",
    test_args: dict | None = None,
) -> dict:
    if len(active(store, run_id)) >= MAX_ACTIVE:
        raise PolicyDenied(
            f"At most {MAX_ACTIVE} hypotheses may be active; retire or reject one first"
        )
    record = {
        "id": uuid.uuid4().hex[:10],
        "text": _text(text, "text", required=True),
        "status": "active",
        "supports": _items(supports, "supports"),
        "contradicts": _items(contradicts, "contradicts"),
        "prediction": _text(prediction, "prediction"),
        "cheapest_test": _text(cheapest_test, "cheapest_test"),
        "cost": _text(cost, "cost"),
        "pivot_if": _text(pivot_if, "pivot_if"),
        "test_tool": _text(test_tool, "test_tool", 64),
        "test_artifact": _text(test_artifact, "test_artifact", 64),
        "test_args": dict(test_args or {}),
        "confidence": "unresolved",
        "actual_experiment_result": "",
        "evidence": [],
        "last_evaluated_seq": 0,
    }
    store.event(run_id, "hypothesis", record)
    return record


def update(
    store: Store,
    run_id: str,
    hypothesis_id: str,
    status: str | None = None,
    trusted: bool = False,
    **fields,
) -> dict:
    records = {item["id"]: item for item in latest(store, run_id)}
    if hypothesis_id not in records:
        raise PrestigeError("Unknown hypothesis id")
    record = dict(records[hypothesis_id])
    if not trusted and (set(fields) & EVALUATOR_FIELDS):
        raise PolicyDenied("Only the evidence evaluator may set confidence or evidence fields")
    if status is not None:
        if status not in STATUSES:
            raise PolicyDenied("Invalid hypothesis status")
        if (
            status == "active"
            and record.get("status") != "active"
            and len(active(store, run_id)) >= MAX_ACTIVE
        ):
            raise PolicyDenied(
                f"At most {MAX_ACTIVE} hypotheses may be active; retire or reject one first"
            )
        record["status"] = status
    for field in ("supports", "contradicts"):
        if field in fields:
            record[field] = _items(fields[field], field)
    for field in ("text", "prediction", "cheapest_test", "cost", "pivot_if"):
        if field in fields:
            record[field] = _text(fields[field], field, required=(field == "text"))
    for field in ("test_tool", "test_artifact"):
        if field in fields:
            record[field] = _text(fields[field], field, 64)
    if "test_args" in fields:
        if not isinstance(fields["test_args"], dict):
            raise PolicyDenied("Invalid hypothesis test_args")
        record["test_args"] = dict(fields["test_args"])
    if trusted:
        if "confidence" in fields:
            if fields["confidence"] not in CONFIDENCES:
                raise PolicyDenied("Invalid hypothesis confidence")
            record["confidence"] = fields["confidence"]
        if "actual_experiment_result" in fields:
            record["actual_experiment_result"] = _text(
                fields["actual_experiment_result"], "actual_experiment_result"
            )
        if "evidence" in fields:
            record["evidence"] = _items(fields["evidence"], "evidence")
        if "last_evaluated_seq" in fields:
            record["last_evaluated_seq"] = int(fields["last_evaluated_seq"])
    merged = {
        key: record.get(key)
        for key in (
            "id",
            "text",
            "status",
            "supports",
            "contradicts",
            "prediction",
            "cheapest_test",
            "cost",
            "pivot_if",
            "test_tool",
            "test_artifact",
            "test_args",
            "confidence",
            "actual_experiment_result",
            "evidence",
            "last_evaluated_seq",
        )
    }
    store.event(run_id, "hypothesis", merged)
    return merged
