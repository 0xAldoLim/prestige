"""A trusted expected digest is independent of model claims and challenge decoys."""

import hashlib
import hmac
import io
import json
import re
import zipfile

from prestige.artifacts import FLAG, MAX_FILE, Artifacts, transform
from prestige.types import PolicyDenied


def validate_expected_digest(value: str | None):
    if value is not None and not re.fullmatch(r"[a-f0-9]{64}", value):
        raise PolicyDenied("Expected flag digest must be a lowercase SHA256 supplied by the user")


def replay(artifacts: Artifacts, artifact_id: str, depth=0) -> bytes:
    if depth > 24:
        raise PolicyDenied("Derivation chain too deep")
    item = next(x for x in artifacts.list() if x["id"] == artifact_id)
    stored = artifacts.read(artifact_id)
    if item["parent"] is None:
        return stored
    parent = replay(artifacts, item["parent"], depth + 1)
    operation = json.loads(item["transform"])
    if operation["tool"] == "zip":
        with zipfile.ZipFile(io.BytesIO(parent)) as archive:
            with archive.open(operation["member"]) as stream:
                result = stream.read(MAX_FILE + 1)
    else:
        result = transform(parent, operation["tool"], operation["args"])
    if result != stored:
        raise PolicyDenied("Independent derivation replay failed")
    return result


def verify_candidates(artifacts: Artifacts, expected: str | None) -> bool:
    validate_expected_digest(expected)
    solved = False
    for item in artifacts.list():
        data = artifacts.read(item["id"])
        for match in FLAG.finditer(data):
            value = match.group()
            digest_matches = expected is not None and hmac.compare_digest(
                hashlib.sha256(value).hexdigest(), expected
            )
            verified = digest_matches and value in replay(artifacts, item["id"])
            artifacts.store.candidate(artifacts.run_id, item["id"], value, verified)
            solved |= verified
    return solved
