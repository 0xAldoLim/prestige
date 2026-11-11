"""Optional live OpenCode → PRESTIGE MCP harness.

This module runs the real ``opencode run --agent prestige`` loop when an operator
has configured a model and provider. It never fabricates a solve: the return value
records the raw process result, and investigation outcomes are read from the same
PRESTIGE state directory afterwards. CI tests use a fake executable; a live run is
explicitly opt-in.
"""

import json
import os
import shutil
import subprocess
import time
from pathlib import Path

from prestige.store import Store

MAX_OUTPUT = 262144


def available(executable: str = "opencode") -> bool:
    return shutil.which(executable) is not None


def command(prompt: str, model: str | None = None, executable: str = "opencode") -> list[str]:
    if not isinstance(prompt, str) or not prompt.strip() or len(prompt) > 32768:
        raise ValueError("OpenCode prompt is empty or too large")
    result = [
        executable,
        "run",
        "--standalone",
        "--agent",
        "prestige",
        "--format",
        "json",
        "--archived",
    ]
    if model:
        if not isinstance(model, str) or "/" not in model:
            raise ValueError("Model must be provider/model")
        result.extend(["--model", model])
    result.append(prompt)
    return result


def _parse_json(text: str):
    text = text.strip()
    if not text:
        return None
    try:
        return json.loads(text)
    except ValueError:
        pass
    # OpenCode may emit one JSON object per line.
    objects = []
    for line in text.splitlines():
        try:
            objects.append(json.loads(line))
        except ValueError:
            continue
    return objects or None


def run_case(
    home: Path,
    prompt: str,
    *,
    model: str | None = None,
    timeout: float = 600,
    executable: str = "opencode",
    cwd: Path | None = None,
) -> dict:
    if not available(executable):
        return {
            "status": "not_run",
            "reason": "opencode executable is not installed",
            "model": model,
            "harness": "opencode",
        }
    if type(timeout) not in (int, float) or not 0 < timeout <= 3600:
        raise ValueError("Invalid OpenCode timeout")
    env = os.environ.copy()
    env.setdefault("PRESTIGE_HOME", str(home))
    env.setdefault("PRESTIGE_ALLOWED_DIRS", str(home.parent))
    started = time.monotonic()
    try:
        completed = subprocess.run(
            command(prompt, model, executable),
            cwd=str(cwd) if cwd else None,
            capture_output=True,
            text=True,
            timeout=timeout,
            env=env,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        return {
            "status": "failed",
            "reason": f"{type(error).__name__}: {error}"[:500],
            "model": model,
            "harness": "opencode",
            "seconds": time.monotonic() - started,
            "model_inference_observed": True,
        }
    elapsed = time.monotonic() - started
    parsed = _parse_json(completed.stdout)
    return {
        "status": "completed" if completed.returncode == 0 else "failed",
        "returncode": completed.returncode,
        "model": model,
        "harness": "opencode",
        "seconds": elapsed,
        "stdout": completed.stdout[:MAX_OUTPUT],
        "stderr": completed.stderr[:MAX_OUTPUT],
        "parsed": parsed,
        "model_inference_observed": True,
        "note": "A completed process is not a verified solve; read PRESTIGE state.",
    }


def summarize_home(home: Path, since: float | None = None) -> dict:
    """Read real investigation outcomes from the shared PRESTIGE state directory."""
    store = Store(home)
    try:
        runs = store.rows("SELECT * FROM runs ORDER BY created")
        selected = [
            row for row in runs if since is None or float(row["created"]) >= since
        ]
        summaries = []
        for row in selected:
            candidates = store.rows(
                "SELECT digest,verified FROM candidates WHERE run_id=?", (row["id"],)
            )
            summaries.append(
                {
                    "run_id": row["id"],
                    "status": row["status"],
                    "mode": row["mode"],
                    "lane": row["lane"],
                    "attempts": row["attempts"],
                    "candidates": len(candidates),
                    "verified": sum(bool(item["verified"]) for item in candidates),
                    "events": len(store.events(row["id"])),
                }
            )
        return {"runs": summaries, "count": len(summaries)}
    finally:
        store.close()


def run_pair_live(
    home: Path,
    clean_prompt: str,
    adversarial_prompt: str,
    *,
    model: str | None = None,
    timeout: float = 600,
    executable: str = "opencode",
    cwd: Path | None = None,
) -> dict:
    """Run matched live prompts and read outcomes; never infer success from text."""
    started = time.time()
    clean = run_case(
        home, clean_prompt, model=model, timeout=timeout, executable=executable, cwd=cwd
    )
    clean_state = summarize_home(home, since=started)
    started = time.time()
    adversarial = run_case(
        home,
        adversarial_prompt,
        model=model,
        timeout=timeout,
        executable=executable,
        cwd=cwd,
    )
    adversarial_state = summarize_home(home, since=started)
    return {
        "clean": clean,
        "adversarial": adversarial,
        "clean_state": clean_state,
        "adversarial_state": adversarial_state,
        "claim": (
            "Live process outcomes only; no solve or immunity is claimed unless "
            "PRESTIGE recorded an operator-digest verification."
        ),
    }
