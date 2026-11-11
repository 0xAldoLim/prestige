"""Operator-controlled verification commitments.

The solving model must never be able to declare its own expected answer digest.
Commitments map an immutable source-artifact SHA-256 to an expected candidate
SHA-256 and live in the operator state directory, outside MCP tool arguments.
"""

import json
import re
from pathlib import Path

from prestige.types import PrestigeError

_DIGEST = re.compile(r"[a-f0-9]{64}")
_MAX_BYTES = 65536


def commitment_path(home: Path) -> Path:
    return home / "commitments.json"


def load_commitments(home: Path) -> dict[str, str]:
    path = commitment_path(home)
    if not path.exists():
        return {}
    if not path.is_file() or path.stat().st_size > _MAX_BYTES:
        raise PrestigeError("Verification commitment file is invalid or too large")
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (ValueError, UnicodeError) as error:
        raise PrestigeError("Verification commitment file is not valid JSON") from error
    if not isinstance(data, dict) or set(data) - {"schema_version", "commitments"}:
        raise PrestigeError("Unknown verification commitment fields")
    if data.get("schema_version") != 1:
        raise PrestigeError("Unsupported verification commitment schema")
    commitments = data.get("commitments", {})
    if not isinstance(commitments, dict):
        raise PrestigeError("commitments must be an object")
    result = {}
    for artifact, expected in commitments.items():
        if not isinstance(artifact, str) or not _DIGEST.fullmatch(artifact):
            raise PrestigeError("Invalid artifact digest in commitments")
        if not isinstance(expected, str) or not _DIGEST.fullmatch(expected):
            raise PrestigeError("Invalid expected digest in commitments")
        result[artifact] = expected
    return result


def save_commitments(home: Path, commitments: dict[str, str]) -> None:
    for artifact, expected in commitments.items():
        if not _DIGEST.fullmatch(artifact) or not _DIGEST.fullmatch(expected):
            raise PrestigeError("Digests must be 64 lowercase hex characters")
    home.mkdir(parents=True, exist_ok=True)
    payload = json.dumps(
        {"schema_version": 1, "commitments": dict(sorted(commitments.items()))},
        indent=2,
    )
    tmp = commitment_path(home).with_suffix(".tmp")
    tmp.write_text(payload, encoding="utf-8")
    tmp.replace(commitment_path(home))


def expected_for(home: Path, artifact_sha256: str) -> str | None:
    if not isinstance(artifact_sha256, str) or not _DIGEST.fullmatch(artifact_sha256):
        return None
    return load_commitments(home).get(artifact_sha256)


def add_commitment(home: Path, artifact_sha256: str, expected_sha256: str) -> dict:
    commitments = load_commitments(home)
    commitments[artifact_sha256] = expected_sha256
    save_commitments(home, commitments)
    return {"artifact_sha256": artifact_sha256, "expected_sha256": expected_sha256}


def remove_commitment(home: Path, artifact_sha256: str) -> dict:
    commitments = load_commitments(home)
    removed = commitments.pop(artifact_sha256, None)
    save_commitments(home, commitments)
    return {"artifact_sha256": artifact_sha256, "removed": removed is not None}


def list_commitments(home: Path) -> list[dict]:
    return [
        {"artifact_sha256": artifact, "expected_sha256": expected}
        for artifact, expected in sorted(load_commitments(home).items())
    ]
