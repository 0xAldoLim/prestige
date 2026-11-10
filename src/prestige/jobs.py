"""Durable, resumable analysis jobs for expensive static-analysis tools.

Jobs run outside the OpenCode conversation, are persisted in SQLite, support
cancellation, and cache results by artifact digest + tool + normalized arguments.
"""

import hashlib
import json
import threading
import time
import uuid

from prestige.artifacts import Artifacts, ToolRegistry
from prestige.security import Rules
from prestige.store import Store
from prestige.types import Action, PolicyDenied, PrestigeError

_MAX_RESULT_BYTES = 128 * 1024


def _cache_key(artifact_id: str, tool: str, args: dict) -> str:
    payload = json.dumps(
        {"artifact": artifact_id, "tool": tool, "args": args},
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(payload.encode()).hexdigest()


def _classify_failure(error: Exception) -> str:
    import subprocess

    if isinstance(error, subprocess.TimeoutExpired):
        return "tool_timeout"
    if isinstance(error, PolicyDenied):
        return "policy_denied"
    if isinstance(error, PrestigeError):
        return "prestige_error"
    return f"{type(error).__name__}"


def _bound_result(result: dict) -> dict:
    """Truncate oversized text fields before persisting or returning."""
    out = {}
    for key, value in result.items():
        if isinstance(value, str) and len(value) > _MAX_RESULT_BYTES:
            value = value[: _MAX_RESULT_BYTES - 32] + "\n...[truncated]"
        out[key] = value
    return out


class JobManager:
    def __init__(self, store: Store, run_id: str):
        self.home = store.home
        self.run_id = run_id
        self._lock = threading.Lock()

    def _with_store(self, fn):
        store = Store(self.home)
        try:
            return fn(store)
        finally:
            store.close()

    def _job_row(self, store: Store, job_id: str) -> dict | None:
        rows = store.rows("SELECT * FROM jobs WHERE job_id=?", (job_id,))
        return rows[0] if rows else None

    def list(self) -> list[dict]:
        return self._with_store(
            lambda store: store.rows("SELECT * FROM jobs WHERE run_id=?", (self.run_id,))
        )

    def start(
        self,
        artifact_id: str,
        tool: str,
        args: dict,
        rules: Rules | None = None,
        runner_image: str | None = None,
    ) -> str:
        run = self._with_store(lambda store: store.run(self.run_id))
        if run["status"] in {"solved", "stopped", "input_rejected", "budget_exhausted"}:
            raise PrestigeError("Investigation is terminal")
        settings = run["settings"]
        rules = rules or Rules(**settings["rules"])
        if tool not in rules.allowed_tools:
            raise PolicyDenied(f"Tool {tool} is not authorized by event rules")

        # Validate artifact membership before scheduling.
        self._with_store(
            lambda store: Artifacts(store, self.run_id).resolve_path(artifact_id)
        )

        cache_key = _cache_key(artifact_id, tool, args)
        cached = self._with_store(
            lambda store: store.rows(
                "SELECT job_id FROM jobs WHERE run_id=? AND cache_key=? AND status='completed'",
                (self.run_id, cache_key),
            )
        )
        if cached:
            return cached[0]["job_id"]

        job_id = uuid.uuid4().hex[:16]

        def insert_queued(store: Store):
            with store.transaction() as db:
                db.execute(
                    "INSERT INTO jobs(run_id,job_id,artifact_id,tool,args,cache_key,status) "
                    "VALUES(?,?,?,?,?,?,?)",
                    (
                        self.run_id,
                        job_id,
                        artifact_id,
                        tool,
                        json.dumps(args, sort_keys=True),
                        cache_key,
                        "queued",
                    ),
                )

        self._with_store(insert_queued)
        threading.Thread(
            target=self._run,
            args=(job_id, artifact_id, tool, args, cache_key, runner_image),
            daemon=True,
        ).start()
        return job_id

    def _run(self, job_id: str, artifact_id: str, tool: str, args: dict, cache_key: str, runner_image: str | None):
        store = Store(self.home)
        try:
            with self._lock:
                if self._job_row(store, job_id)["status"] == "cancelled":
                    return
            with store.transaction() as db:
                db.execute(
                    "UPDATE jobs SET status='running', started=? WHERE job_id=?",
                    (time.time(), job_id),
                )

            run = store.run(self.run_id)
            artifacts = Artifacts(store, self.run_id)
            runner = None
            if runner_image:
                from prestige.sandbox import WorkspaceRunner

                runner = WorkspaceRunner(runner_image, artifacts)
            registry = ToolRegistry(artifacts, Rules(**run["settings"]["rules"]).allowed_tools, runner)
            action = Action(tool, artifact_id, args)
            result = registry.execute(action)
            bounded = _bound_result(result)

            with self._lock:
                current = self._job_row(store, job_id)
                if current and current["status"] == "cancelled":
                    return
                with store.transaction() as db:
                    db.execute(
                        "UPDATE jobs SET status='completed', finished=?, result=? WHERE job_id=?",
                        (time.time(), json.dumps(bounded, ensure_ascii=True), job_id),
                    )
        except Exception as error:
            with store.transaction() as db:
                db.execute(
                    "UPDATE jobs SET status='failed', finished=?, error=?, failure_class=? WHERE job_id=?",
                    (
                        time.time(),
                        str(error)[:2048],
                        _classify_failure(error),
                        job_id,
                    ),
                )
        finally:
            store.close()

    def get(self, job_id: str) -> dict:
        row = self._with_store(lambda store: self._job_row(store, job_id))
        if not row:
            raise PrestigeError("Unknown job ID")
        result = row.get("result")
        return {
            "job_id": row["job_id"],
            "artifact_id": row["artifact_id"],
            "tool": row["tool"],
            "status": row["status"],
            "started": row["started"],
            "finished": row["finished"],
            "result": json.loads(result) if result else None,
            "error": row["error"],
            "failure_class": row["failure_class"],
            "output_artifact": row["output_artifact"],
        }

    def cancel(self, job_id: str) -> dict:
        def do(store: Store):
            row = self._job_row(store, job_id)
            if not row:
                raise PrestigeError("Unknown job ID")
            if row["status"] in {"queued", "running"}:
                with store.transaction() as db:
                    db.execute(
                        "UPDATE jobs SET status='cancelled', finished=? WHERE job_id=?",
                        (time.time(), job_id),
                    )
            return self.get(job_id)

        return self._with_store(do)
