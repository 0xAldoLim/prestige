"""Shared final-submission shape checks.

Only obviously non-answer placeholders are rejected here. The validator never
imposes a flag syntax: any other non-empty, bounded string is passed to the
independent operator checker, which alone decides correctness.
"""

import re

# Exact normalized values only. Normalization lowercases and removes separators
# so ``NO_FLAG``, ``no flag`` and ``N/A`` are covered without matching real
# flag-shaped candidates such as ``SAS{no_flag}`` or a static decoy.
PLACEHOLDER_VALUES = frozenset(
    {
        "unsolved",
        "unknown",
        "noflag",
        "notfound",
        "tbd",
        "todo",
        "placeholder",
        "na",
        "none",
        "null",
    }
)

PLACEHOLDER_REASON = (
    "Final candidate is an obvious placeholder; submit the actual flag value "
    "derived from the challenge"
)


def normalise(candidate: str) -> str:
    """Return a comparable token without changing the submitted value."""
    return re.sub(r"[^a-z0-9]+", "", candidate.strip().lower())


def placeholder_reason(candidate: str) -> str | None:
    """Return a rejection reason for an exact obvious placeholder, else None."""
    if not isinstance(candidate, str):
        return None
    return PLACEHOLDER_REASON if normalise(candidate) in PLACEHOLDER_VALUES else None
