"""Operational FAST/AUTO/EXPERT lane policy.

FAST uses only cheap deterministic tools. AUTO starts FAST and can explicitly
escalate to EXPERT. EXPERT adds isolated execution and binary-analysis tools.
Budgets are capped by the lane, and escalation never grants extra wall time or
attempts already spent.
"""

from dataclasses import replace

from prestige.security import Rules
from prestige.types import PolicyDenied

FAST_TOOLS = (
    "inspect",
    "strings",
    "read",
    "file",
    "base64",
    "hex",
    "xor",
    "zip",
)
EXPERT_TOOLS = FAST_TOOLS + ("python", "command", "radare2", "ghidra")

LANE_MAX_TURNS = {"fast": 8, "auto": 12, "expert": 18}
LANE_MAX_SECONDS = {"fast": 120.0, "auto": 300.0, "expert": 600.0}


def lane_for_mode(mode: str) -> str:
    if mode == "fast":
        return "fast"
    if mode == "expert":
        return "expert"
    if mode == "auto":
        return "fast"
    raise PolicyDenied("Unknown investigation mode")


def rules_for_mode(mode: str, max_turns: int, max_seconds: float) -> Rules:
    lane = lane_for_mode(mode)
    effective_turns = min(max(1, max_turns), LANE_MAX_TURNS[mode])
    effective_seconds = min(max(1.0, max_seconds), LANE_MAX_SECONDS[mode])
    tools = EXPERT_TOOLS if lane == "expert" else FAST_TOOLS
    return Rules(
        allowed_tools=tools,
        max_turns=effective_turns,
        max_seconds=effective_seconds,
    )


def expert_rules(rules: Rules) -> Rules:
    return replace(rules, allowed_tools=EXPERT_TOOLS)


def lane_summary(rules: Rules) -> dict:
    return {
        "allowed_tools": list(rules.allowed_tools),
        "max_turns": rules.max_turns,
        "max_seconds": rules.max_seconds,
    }
