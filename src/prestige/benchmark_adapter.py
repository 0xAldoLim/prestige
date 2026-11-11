"""Reusable benchmark adapter for operator-supplied baseline runners.

PRESTIGE does not grant the baseline agent host permissions. The operator points
B0/B1 at an approved command/agent; PRESTIGE passes the case, artifact, condition
and budget contract over stdin and records only the returned measured result.
Missing usage stays unknown.
"""

import json
import os
import subprocess
import time


class CommandConditionAdapter:
    model_evaluation = True
    adapter_kind = "operator-command"

    def __init__(
        self,
        command: list[str],
        condition: str,
        model: str,
        max_turns: int = 12,
        max_seconds: int = 120,
    ):
        if not isinstance(command, list) or not command or not all(
            isinstance(item, str) and item for item in command
        ):
            raise ValueError("Adapter command must be a non-empty list of strings")
        if condition not in {"B0", "B1"}:
            raise ValueError("Command adapter supports B0/B1 only")
        if not isinstance(model, str) or not model:
            raise ValueError("Adapter model label is required")
        if not 1 <= max_turns <= 1000 or not 1 <= max_seconds <= 3600:
            raise ValueError("Invalid adapter budget")
        self.command = command
        self.condition = condition
        self.skills_enabled = condition == "B1"
        self.contract = {
            "model": model,
            "permissions": "operator-supplied-baseline",
            "max_turns": max_turns,
            "max_seconds": max_seconds,
        }

    async def run(self, case: dict, artifact, contract: dict) -> dict:
        payload = {
            "case": case,
            "artifact": str(artifact),
            "condition": self.condition,
            "skills_enabled": self.skills_enabled,
            "max_turns": contract["max_turns"],
            "max_seconds": contract["max_seconds"],
        }
        env = os.environ.copy()
        env.update(
            {
                "PRESTIGE_BENCH_CASE": str(case.get("id", "")),
                "PRESTIGE_BENCH_ARTIFACT": str(artifact),
                "PRESTIGE_BENCH_CONDITION": self.condition,
                "PRESTIGE_BENCH_SKILLS": "1" if self.skills_enabled else "0",
            }
        )
        started = time.monotonic()
        try:
            completed = subprocess.run(
                self.command,
                input=json.dumps(payload),
                capture_output=True,
                text=True,
                timeout=contract["max_seconds"] + 30,
                env=env,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as error:
            return self._failed(case, time.monotonic() - started, error)
        elapsed = time.monotonic() - started
        if completed.returncode != 0:
            return self._failed(
                case, elapsed, f"adapter exited {completed.returncode}: {completed.stderr[-300:]}"
            )
        try:
            data = json.loads(completed.stdout)
        except (ValueError, UnicodeError) as error:
            return self._failed(case, elapsed, f"adapter output is not JSON: {error}")
        if not isinstance(data, dict):
            return self._failed(case, elapsed, "adapter output must be an object")
        status = data.get("status")
        if status not in {"solved", "unsolved", "failed", "budget_exhausted"}:
            return self._failed(case, elapsed, "adapter status is invalid")
        tokens = data.get("tokens")
        if type(tokens) is not int or tokens < 0:
            tokens = None
        cost = data.get("cost")
        if type(cost) not in (int, float) or cost < 0:
            cost = None
        return {
            "status": status,
            "tokens": tokens,
            "cost": cost,
            "seconds": float(data.get("seconds", elapsed)),
            "tool_calls": int(data.get("tool_calls", 0)),
            "failed_experiments": int(data.get("failed_experiments", 0)),
            "skills_used": int(data.get("skills_used", 0)),
            "security_violations": int(data.get("security_violations", 0)),
            "verified": bool(data.get("verified", False)),
            "candidates": data.get("candidates", []),
        }

    @staticmethod
    def _failed(case, elapsed: float, error) -> dict:
        return {
            "status": "failed",
            "tokens": None,
            "cost": None,
            "seconds": elapsed,
            "tool_calls": 0,
            "failed_experiments": 1,
            "skills_used": 0,
            "security_violations": 0,
            "verified": False,
            "candidates": [],
            "error": str(error)[:500],
        }
