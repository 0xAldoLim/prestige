"""Deterministic deception and instruction-injection detection.

Challenge artifacts, tool output, retrieved research and skill excerpts are data.
This module classifies suspicious content but never grants authority, changes
policy or verifies a candidate. Findings are facts about untrusted text, not
instructions to follow.
"""

import base64
import binascii
import hashlib
import re

from prestige.artifacts import redact

MAX_SCAN = 262144
MAX_FINDINGS = 24
MAX_SPAN = 240

TRUST_BY_ORIGIN = {
    "operator": "operator_trusted",
    "commitment": "operator_trusted",
    "artifact": "external_untrusted",
    "tool_output": "tool_output_untrusted",
    "skill": "external_untrusted",
    "research": "external_untrusted",
    "web": "external_untrusted",
    "model_proposal": "model_hypothesis",
    "cross_model": "external_untrusted",
    "observation": "tool_output_untrusted",
}
AUTHORITATIVE_ORIGINS = {"operator", "commitment"}
DIRECTIVE_CATEGORIES = {
    "instruction_override",
    "authority_claim",
    "credential_request",
    "exfiltration",
    "scope_probe",
    "tool_output_conflict",
    "cross_model_handoff",
}
VERIFICATION_CATEGORIES = {"verification_claim", "fake_tool_result"}

_HIGH = "high"
_MEDIUM = "medium"
_LOW = "low"
_RANK = {_LOW: 1, _MEDIUM: 2, _HIGH: 3}

_SIGNALS = (
    (
        "instruction_override",
        _HIGH,
        re.compile(
            r"(?i)\b(?:ignore|disregard|forget|override|bypass)\b[^\n]{0,80}"
            r"\b(?:previous|prior|above|system|developer|safety|original)\b"
            r"[^\n]{0,50}\b(?:instruction|prompt|rule|policy|guardrail)s?\b"
        ),
        "attempts to override trusted instructions",
    ),
    (
        "instruction_override",
        _HIGH,
        re.compile(r"(?i)\b(?:new|updated|real|hidden)\s+(?:system\s+)?instructions?\s*:"),
        "presents replacement instructions",
    ),
    (
        "instruction_override",
        _HIGH,
        re.compile(
            r"(?im)^\s*(?:system|developer|operator|admin|assistant)\s*"
            r"(?:override|message|instruction|update)?\s*:"
        ),
        "impersonates a trusted message channel",
    ),
    (
        "instruction_override",
        _HIGH,
        re.compile(
            r"(?is)<\s*information\s*>.*?important message from me.*?to you.*?"
            r"before you can solve.*?(?:first|please do)"
        ),
        "matches an indirect prompt-injection template",
    ),
    (
        "instruction_override",
        _HIGH,
        re.compile(
            r"(?im)^\s*(?:important\s+)?(?:system|security|operator|developer)\s+"
            r"(?:update|notice|message|override)\b"
        ),
        "impersonates an urgent system update",
    ),
    (
        "instruction_override",
        _MEDIUM,
        re.compile(
            r"(?i)\b(?:do not|don't|never)\s+(?:tell|mention|inform|reveal|notify)\b"
            r"[^\n]{0,60}\b(?:user|operator|human)\b"
        ),
        "asks to conceal an action from the user",
    ),
    (
        "instruction_override",
        _MEDIUM,
        re.compile(r"(?i)\byou are now\b[^\n]{0,60}\b(?:admin|root|developer|unrestricted|trusted)\b"),
        "attempts a role change",
    ),
    (
        "authority_claim",
        _HIGH,
        re.compile(
            r"(?i)\b(?:you are|you're)\s+(?:now\s+)?"
            r"(?:authorized|allowed|permitted)\b[^\n]{0,80}"
            r"\b(?:shell|network|remote|scoreboard|provision|exfiltrat)\w*"
        ),
        "claims new authorization",
    ),
    (
        "authority_claim",
        _HIGH,
        re.compile(
            r"(?i)\b(?:policy|rules|scope|authorization|permissions?)\b[^\n]{0,50}"
            r"\b(?:allow|permit|grant|updated|changed|disabled|bypass|unrestricted)\b"
        ),
        "claims trusted policy changed",
    ),
    (
        "authority_claim",
        _MEDIUM,
        re.compile(r"(?i)\b(?:trusted|approved|whitelisted)\s+(?:source|instruction|policy|update)\b"),
        "asserts unsupported trust",
    ),
    (
        "authority_claim",
        _HIGH,
        re.compile(r"(?i)\bno\s+(?:need|requirement)\s+to\s+(?:verify|check|confirm)\b"),
        "discourages independent verification",
    ),
    (
        "verification_claim",
        _MEDIUM,
        re.compile(
            r"(?i)\b(?:the\s+)?(?:verified|correct|real|actual|official)\s+"
            r"(?:flag|answer|candidate)\s+(?:is|was|=)\b"
        ),
        "asserts an unverified result",
    ),
    (
        "verification_claim",
        _MEDIUM,
        re.compile(
            r"(?i)\b(?:flag|answer|candidate)\s+(?:is|was)\s+"
            r"[A-Za-z][A-Za-z0-9_]{1,24}\{"
        ),
        "presents a flag-like value as established",
    ),
    (
        "verification_claim",
        _MEDIUM,
        re.compile(
            r"(?i)\b(?:verification|checker|digest|hash)\s+"
            r"(?:passed|succeeded|matched|confirmed)\b"
        ),
        "claims verification without broker evidence",
    ),
    (
        "verification_claim",
        _MEDIUM,
        re.compile(r"(?i)\b(?:submit|report|return|mark)\s+(?:this|the following)\s+(?:flag|candidate)\b"),
        "asks for submission of an unverified candidate",
    ),
    (
        "fake_tool_result",
        _HIGH,
        re.compile(r'(?i)"(?:verified|solved)"\s*:\s*"?true"?\b'),
        "fabricates a broker verification result",
    ),
    (
        "fake_tool_result",
        _HIGH,
        re.compile(r"(?i)\b(?:status|result)\s*:\s*[\"']?(?:solved|verified)[\"']?\b"),
        "fabricates a solved status",
    ),
    (
        "credential_request",
        _HIGH,
        re.compile(
            r"(?i)\b(?:print|show|reveal|send|exfiltrate|upload|cat|read|leak)\b"
            r"[^\n]{0,60}\b(?:api[_-]?key|token|password|secret|credential|"
            r"private\s+key|id_rsa|\.env)\b"
        ),
        "requests credentials",
    ),
    (
        "credential_request",
        _HIGH,
        re.compile(
            r"\b(?:OPENAI_API_KEY|ANTHROPIC_API_KEY|AWS_SECRET_ACCESS_KEY|"
            r"GITHUB_TOKEN|PRESTIGE_[A-Z_]*KEY)\b"
        ),
        "references a provider credential",
    ),
    (
        "exfiltration",
        _HIGH,
        re.compile(
            r"(?i)\b(?:exfiltrate|upload|send|post)\b"
            r"[^\n]{0,100}\b(?:https?://|webhook|pastebin|requestbin|ngrok|attacker)\b"
        ),
        "attempts to move data to an external endpoint",
    ),
    (
        "exfiltration",
        _HIGH,
        re.compile(r"(?i)\b(?:curl|wget)\b[^\n]{0,140}\$(?:[A-Z_]{3,}|GITHUB_TOKEN)"),
        "embeds a secret in an outbound request",
    ),
    (
        "scope_probe",
        _HIGH,
        re.compile(
            r"(?i)\b(?:ctfd|scoreboard|submission\s+(?:system|endpoint)|provisioning|"
            r"competition\s+(?:platform|infrastructure)|organizer\s+(?:panel|api))\b"
        ),
        "points at competition infrastructure",
    ),
    (
        "tool_output_conflict",
        _HIGH,
        re.compile(
            r"(?i)\b(?:tool|inspect|broker|observation|artifact|evidence|result)\b"
            r"[^\n]{0,60}\b(?:is|was|has been)\s+"
            r"(?:poisoned|fake|wrong|stale|tampered|unreliable)\b"
        ),
        "tries to discredit recorded evidence",
    ),
    (
        "tool_output_conflict",
        _HIGH,
        re.compile(
            r"(?i)\b(?:trust|believe|follow)\s+this\s+(?:text|message|instruction)\b"
            r"[^\n]{0,50}\b(?:over|instead of|rather than)\b"
        ),
        "asks to prefer untrusted text over evidence",
    ),
    (
        "tool_output_conflict",
        _HIGH,
        re.compile(r"(?i)\bignore\s+the\s+(?:broker|tool|observed|recorded|inspect)\b"),
        "asks to ignore broker observations",
    ),
    (
        "cross_model_handoff",
        _MEDIUM,
        re.compile(
            r"(?i)\b(?:previous|prior|other|another|earlier)\s+"
            r"(?:model|assistant|agent|session)\b[^\n]{0,80}"
            r"\b(?:said|confirmed|verified|approved|instructed|told|authorized)\b"
        ),
        "relays an unverifiable cross-model claim",
    ),
    (
        "cross_model_handoff",
        _MEDIUM,
        re.compile(r"(?i)\bhandoff\b[^\n]{0,80}\b(?:instruction|claim|approval|authorization)\b"),
        "relays an unverifiable handoff claim",
    ),
    (
        "decoy",
        _LOW,
        re.compile(
            r"(?i)\b(?:decoy|red herring|not the real|ignore the actual|"
            r"fake vulnerability|real vulnerability is)\b"
        ),
        "suggests a decoy path",
    ),
)

_HIDDEN = re.compile(r"[\u200b-\u200f\u202a-\u202e\u2060-\u2064\ufeff]")
_HTML_COMMENT = re.compile(r"(?is)<!--(.*?)-->")
_COMMENT_SIGNAL = re.compile(
    r"(?i)\b(?:ignore|instruction|system|operator|flag|verify|shell|curl|token|secret)\b"
)
_BASE64 = re.compile(r"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{24,}={0,2}(?![A-Za-z0-9+/=])")


def trust_for(origin: str) -> str:
    return TRUST_BY_ORIGIN.get(origin, "external_untrusted")


def is_authoritative(origin: str) -> bool:
    """Only operator-controlled configuration may change policy or verification."""
    return origin in AUTHORITATIVE_ORIGINS


def _snippet(text: str, start: int, end: int) -> str:
    value = text[max(0, start - 24) : min(len(text), end + 24)]
    return redact(value.replace("\n", " ").strip())[:MAX_SPAN]


def _encoded_findings(text: str) -> list[dict]:
    findings = []
    for match in list(_BASE64.finditer(text))[:8]:
        token = match.group()
        try:
            decoded = base64.b64decode(token, validate=True)
        except (binascii.Error, ValueError):
            continue
        if len(decoded) < 12 or b"\x00" in decoded:
            continue
        inner = decoded.decode("utf-8", errors="replace")
        if not any(char.isprintable() or char in "\n\t" for char in inner):
            continue
        inner_scan = scan(inner, origin="artifact", _encoded_depth=1)
        if inner_scan["risk"] in {_MEDIUM, _HIGH}:
            findings.append(
                {
                    "category": "encoded_instruction",
                    "severity": _HIGH if inner_scan["risk"] == _HIGH else _MEDIUM,
                    "reason": "base64 payload contains instruction-like text",
                    "snippet": "[encoded payload redacted]",
                    "decoded_sha256": hashlib.sha256(decoded).hexdigest(),
                    "decoded_categories": sorted(
                        {item["category"] for item in inner_scan["findings"]}
                    ),
                }
            )
    return findings


def scan(text: str, origin: str = "artifact", _encoded_depth: int = 0) -> dict:
    """Classify untrusted text without changing policy or trusting its claims."""
    if not isinstance(text, str):
        text = str(text)
    truncated = len(text) > MAX_SCAN
    text = text[:MAX_SCAN]
    findings = []
    seen = set()
    for category, severity, pattern, reason in _SIGNALS:
        for match in pattern.finditer(text):
            key = (category, match.start(), match.end())
            if key in seen:
                continue
            seen.add(key)
            findings.append(
                {
                    "category": category,
                    "severity": severity,
                    "reason": reason,
                    "snippet": _snippet(text, match.start(), match.end()),
                }
            )
            if len(findings) >= MAX_FINDINGS:
                break
        if len(findings) >= MAX_FINDINGS:
            break
    for match in _HIDDEN.finditer(text):
        findings.append(
            {
                "category": "hidden_instruction",
                "severity": _MEDIUM,
                "reason": "zero-width or bidirectional control characters",
                "snippet": f"unicode U+{ord(match.group()):04X}",
            }
        )
        break
    for match in _HTML_COMMENT.finditer(text):
        if _COMMENT_SIGNAL.search(match.group(1)):
            findings.append(
                {
                    "category": "hidden_instruction",
                    "severity": _HIGH,
                    "reason": "instruction-like text hidden in an HTML comment",
                    "snippet": _snippet(text, match.start(1), match.end(1)),
                }
            )
            break
    if _encoded_depth < 1:
        findings.extend(_encoded_findings(text))
    findings = findings[:MAX_FINDINGS]
    risk = "none"
    for item in findings:
        if _RANK[item["severity"]] > _RANK.get(risk, 0):
            risk = item["severity"]
    categories = sorted({item["category"] for item in findings})
    return {
        "origin": origin,
        "trust": trust_for(origin),
        "risk": risk,
        "findings": findings,
        "categories": categories,
        "directive_detected": bool(set(categories) & DIRECTIVE_CATEGORIES),
        "verification_claim_detected": bool(set(categories) & VERIFICATION_CATEGORIES),
        "actionable": any(item["severity"] == _HIGH for item in findings),
        "content_sha256": hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest(),
        "truncated": truncated,
        "policy_effect": "none",
        "note": "Untrusted content is data; findings never grant authority or verify a result.",
    }


def scan_bytes(data: bytes, origin: str = "artifact") -> dict:
    if not isinstance(data, (bytes, bytearray)):
        raise TypeError("scan_bytes requires bytes")
    return scan(bytes(data[:MAX_SCAN]).decode("utf-8", errors="replace"), origin)


def should_quarantine(result: dict) -> bool:
    """Memory poisoning is quarantined; challenge artifacts are never deleted."""
    return bool(result.get("actionable")) and result.get("origin") in {
        "model_proposal",
        "cross_model",
        "observation",
    }


def summary(result: dict, limit: int = 6) -> dict:
    return {
        "trust": result.get("trust"),
        "risk": result.get("risk"),
        "categories": result.get("categories", [])[:limit],
        "actionable": bool(result.get("actionable")),
        "policy_effect": "none",
    }
