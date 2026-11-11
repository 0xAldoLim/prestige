"""Adapters for local adversarial scenario files.

No network access is used. A local, operator-supplied JSON/JSONL file in a known
shape is converted into the simple ``{id, payload}`` corpus used by
``prestige security adversarial``. Unrecognized shapes fail closed.
"""

import json
from pathlib import Path

from prestige.types import PolicyDenied


def _records(path: Path) -> list[dict]:
    raw = path.read_text(encoding="utf-8")
    if not raw.strip():
        return []
    try:
        loaded = json.loads(raw)
    except ValueError:
        loaded = None
    if isinstance(loaded, list):
        return [item for item in loaded if isinstance(item, dict)]
    if isinstance(loaded, dict):
        for key in ("scenarios", "tasks", "cases", "records"):
            if isinstance(loaded.get(key), list):
                return [item for item in loaded[key] if isinstance(item, dict)]
        return [loaded]
    records = []
    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue
        item = json.loads(line)
        if isinstance(item, dict):
            records.append(item)
    return records


def _payload(item: dict) -> str | None:
    for key in ("payload", "adversarial", "attack", "injection", "prompt", "content"):
        value = item.get(key)
        if isinstance(value, str) and value.strip():
            return value
    attacks = item.get("attacks")
    if isinstance(attacks, list):
        pieces = []
        for attack in attacks:
            if isinstance(attack, str):
                pieces.append(attack)
            elif isinstance(attack, dict):
                for key in ("prompt", "injection", "content", "payload"):
                    if isinstance(attack.get(key), str):
                        pieces.append(attack[key])
                        break
        if pieces:
            return "\n".join(pieces)
    return None


def adapt(path: Path, format: str = "auto") -> list[dict]:
    if not path.is_file() or path.stat().st_size > 1048576:
        raise PolicyDenied("Adversarial scenario file is missing or too large")
    if format not in {"auto", "prestige", "agentdojo", "agentlsd", "gray-swan"}:
        raise PolicyDenied("Unknown adversarial scenario format")
    records = _records(path)
    result = []
    for index, item in enumerate(records):
        payload = _payload(item)
        if not payload:
            if format == "prestige" or item.get("id") or item.get("payload"):
                raise PolicyDenied("Scenario is missing a usable payload")
            continue
        identifier = str(
            item.get("id")
            or item.get("task_id")
            or item.get("case")
            or f"{format}-{index}"
        )[:80]
        if format == "agentlsd" and item.get("clean") and item.get("adversarial"):
            payload = str(item["adversarial"])
        result.append({"id": identifier, "payload": payload})
    if not result:
        raise PolicyDenied("No adversarial scenarios were adapted")
    return result
