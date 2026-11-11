"""Source trust boundaries.

Policy, authorization, budgets and verification digests are operator-controlled.
Text from artifacts, tools, skills, research, models and model handoffs is data.
This module centralizes that distinction so callers cannot accidentally promote
untrusted text into authority.
"""

from prestige import deception
from prestige.artifacts import redact
from prestige.types import PolicyDenied

DATA_ONLY = "data_only"
AUTHORITATIVE = "operator_authority"


class TrustBoundary:
    @staticmethod
    def trust(origin: str) -> str:
        return deception.trust_for(origin)

    @staticmethod
    def can_authorize(origin: str) -> bool:
        return deception.is_authoritative(origin)

    @staticmethod
    def require_authority(origin: str) -> None:
        if not deception.is_authoritative(origin):
            raise PolicyDenied("Untrusted content cannot change policy or verification")

    @staticmethod
    def label(text: str, origin: str, **metadata) -> dict:
        result = deception.scan(text, origin)
        return {
            **metadata,
            "origin": origin,
            "trust": result["trust"],
            "deception": deception.summary(result),
            "instruction_authority": DATA_ONLY
            if not deception.is_authoritative(origin)
            else AUTHORITATIVE,
        }

    @staticmethod
    def context_item(text: str, origin: str, **metadata) -> dict:
        labelled = TrustBoundary.label(text, origin, **metadata)
        labelled["text"] = redact(text[:4096])
        return labelled

    @staticmethod
    def quarantine_reason(result: dict) -> str:
        categories = ",".join(result.get("categories", [])) or "unknown"
        return f"deception risk={result.get('risk')} categories={categories}"[:300]
