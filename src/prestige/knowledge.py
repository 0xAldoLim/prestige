"""Read-only skills retrieval and narrow, evidence-gated local learning."""

import hashlib
import json
import re
from datetime import datetime, timezone
from importlib.resources import files
from pathlib import Path

from jsonschema import Draft202012Validator

from prestige.artifacts import FLAG, redact, regular_file
from prestige.store import Store, encoded
from prestige.verifier import replay

CATEGORIES = ("crypto", "reverse", "forensics", "web", "pwn", "misc", "osint", "ai-ml", "malware")


class SkillsBridge:
    def __init__(self, root: Path | None = None):
        self.root = root.resolve() if root else None

    def search(self, query: str, limit=3) -> list[dict]:
        """Lexical fallback never runs scripts or follows links outside the configured corpus."""
        if not self.root or not self.root.is_dir():
            return []
        anchors = set(re.findall(r"[a-z0-9_-]{3,}", query.lower()))
        hits = []
        count = 0
        for category in CATEGORIES:
            directory = self.root / f"ctf-{category}"
            if not directory.is_dir() or not directory.resolve().is_relative_to(self.root):
                continue
            for path in directory.rglob("*.md"):
                count += 1
                if count > 3000:
                    break
                if (
                    not path.resolve().is_relative_to(self.root)
                    or not regular_file(path)
                    or path.stat().st_size > 256000
                ):
                    continue
                data = path.read_bytes()
                text = data.decode("utf-8", errors="replace")
                # Small sections, with their original path/line and hash retained.
                lines = text.splitlines()
                for start in range(0, len(lines), 24):
                    section = "\n".join(lines[start : start + 24])
                    score = len(anchors & set(re.findall(r"[a-z0-9_-]{3,}", section.lower())))
                    if score:
                        hits.append(
                            {
                                "path": path.relative_to(self.root).as_posix(),
                                "line": start + 1,
                                "sha256": hashlib.sha256(data).hexdigest(),
                                "score": score,
                                "text": redact(section[:2400]),
                                "trust": "external_untrusted",
                            }
                        )
        return sorted(hits, key=lambda x: (-x["score"], x["path"], x["line"]))[: min(4, limit)]

    def route(self, magic: str, observation: str) -> list[str]:
        result = []
        if magic.startswith(("7f454c46", "4d5a")):
            result.append("reverse")
        if magic.startswith(("504b", "d4c3b2a1", "0a0d0d0a", "89504e47")):
            result.append("forensics")
        for category, anchors in {
            "crypto": ("rsa", "nonce", "cipher", "xor", "base64", "hex"),
            "web": ("http", "cookie", "html", "sql"),
            "pwn": ("stack", "libc", "overflow"),
        }.items():
            if any(anchor in observation.lower() for anchor in anchors):
                result.append(category)
        return list(dict.fromkeys(result))[:3] or ["misc"]


class Knowledge:
    def __init__(self, store: Store, skills: SkillsBridge):
        self.store, self.skills = store, skills

    def search(self, query: str) -> list[dict]:
        anchors = set(query.lower().split())
        records = self.store.rows("SELECT id,record,status FROM knowledge WHERE status='accepted'")
        return [
            {"id": x["id"], "record": json.loads(x["record"]), "status": x["status"]}
            for x in records
            if any(word in x["record"].lower() for word in anchors)
        ][:4]

    def capture(self, artifacts) -> dict:
        verified = self.store.rows(
            "SELECT * FROM candidates WHERE run_id=? AND verified=1", (artifacts.run_id,)
        )
        if not verified:
            return {"status": "withheld", "reason": "No independently verified result"}
        candidate = verified[0]
        if candidate["value"] not in replay(artifacts, candidate["artifact"]):
            return {"status": "withheld", "reason": "Verification replay changed"}
        by_id = {x["id"]: x for x in artifacts.list()}
        item, operations = by_id[candidate["artifact"]], []
        while item["parent"]:
            operation = json.loads(item["transform"])
            operations.append(operation["tool"])
            item = by_id[item["parent"]]
        operations.reverse()
        if not operations:
            return {
                "status": "withheld",
                "reason": "Literal candidate retrieval is not a reusable technique",
            }
        # Only deterministic, understood operations have an automatic generalizer.
        if set(operations) - {"base64", "hex", "xor", "zip"}:
            return {"status": "withheld", "reason": "No reviewed generalizer for these operations"}
        mechanism = " -> ".join(operations)
        record_id = hashlib.sha256(mechanism.encode()).hexdigest()
        if self.store.rows("SELECT id FROM knowledge WHERE id=?", (record_id,)):
            return {"status": "duplicate", "id": record_id}
        # Conservative review gate: known neighboring techniques are not automatically novel.
        neighbors = self.skills.search(" ".join(operations))
        status = "inbox" if neighbors else "accepted"
        record = {
            "title": "Reproducible bounded decoding: " + mechanism,
            "category": "ctf-misc",
            "subcategories": ["encoding"],
            "trigger_conditions": ["Observed bytes pass the strict input parser for each stage"],
            "challenge_context": "Local bounded artifact decoding",
            "observed_problem": "Nested transformations obscure a candidate",
            "technique": mechanism,
            "core_insight": "Test the encoding hypothesis and retain byte-exact derivation evidence",
            "commands_or_code": "Apply the named ToolRegistry transforms; replay the chain before trusting output",
            "verification_evidence": "Artifact derivation replay and independently user-supplied digest matched",
            "resulting_primitive": "Reversible byte decoding",
            "flag_verified": True,
            "failure_modes": [
                "Decoy strings also decode successfully",
                "Incorrect encoding or XOR parameter",
            ],
            "when_not_to_use": [
                "No observed encoding evidence",
                "No independent verifier for the result",
            ],
            "related_existing_techniques": [x["path"] for x in neighbors],
            "source_type": "verified_local_solve",
            "source_reference": "prestige:" + artifacts.run_id,
            "confidence": "verified",
            "date_added": datetime.now(timezone.utc).date().isoformat(),
            "materially_contributed": True,
            "understood": True,
            "reproducible": True,
            "reusable": True,
            "variant_dimensions": {
                "parser": "strict bounded bytes",
                "oracle": "trusted SHA256 commitment",
            },
            "review_reason": "Related skills require novelty review"
            if neighbors
            else "New to this local store; not a claim of global novelty",
        }
        serialized = encoded(record)
        if FLAG.search(serialized.encode()) or re.search(
            r"https?://|password|api_key|bearer", serialized, re.I
        ):
            return {"status": "withheld", "reason": "Sanitization gate"}
        schema = json.loads(
            files("prestige").joinpath("data/learning.schema.json").read_text(encoding="utf-8")
        )
        Draft202012Validator(schema).validate(record)
        with self.store.transaction() as db:
            db.execute(
                "INSERT OR IGNORE INTO knowledge VALUES(?,?,?,?)",
                (record_id, artifacts.run_id, serialized, status),
            )
        return {"status": status, "id": record_id}
