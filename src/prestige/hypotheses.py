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
    }
    store.event(run_id, "hypothesis", record)
    return record


def update(
    store: Store,
    run_id: str,
    hypothesis_id: str,
    status: str | None = None,
    **fields,
) -> dict:
    records = {item["id"]: item for item in latest(store, run_id)}
    if hypothesis_id not in records:
        raise PrestigeError("Unknown hypothesis id")
    record = dict(records[hypothesis_id])
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
    merged = {
        key: record[key]
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
        )
    }
    store.event(run_id, "hypothesis", merged)
    return merged
