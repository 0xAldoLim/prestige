import time

import pytest

from prestige.artifacts import Artifacts
from prestige.engine import new_run
from prestige.jobs import JobManager
from prestige.store import Store
from prestige.types import PolicyDenied


def test_job_manager_starts_and_completes_fast_analysis(store, challenge):
    run_id = new_run(store, challenge[0])
    artifact_id = Artifacts(store, run_id).list()[0]["id"]

    manager = JobManager(store, run_id)
    job_id = manager.start(artifact_id, "strings", {})
    assert job_id

    deadline = time.time() + 5
    while time.time() < deadline:
        status = manager.get(job_id)
        if status["status"] in {"completed", "failed"}:
            break
        time.sleep(0.05)

    assert status["status"] == "completed"
    assert status["result"]["strings"]


def test_job_manager_caches_identical_analysis(store, challenge):
    run_id = new_run(store, challenge[0])
    artifact_id = Artifacts(store, run_id).list()[0]["id"]

    manager = JobManager(store, run_id)
    first = manager.start(artifact_id, "strings", {})
    second = manager.start(artifact_id, "strings", {})
    assert first == second


def test_job_manager_persists_across_store_reopen(store, challenge, tmp_path):
    run_id = new_run(store, challenge[0])
    artifact_id = Artifacts(store, run_id).list()[0]["id"]

    manager = JobManager(store, run_id)
    job_id = manager.start(artifact_id, "strings", {})

    deadline = time.time() + 5
    while time.time() < deadline:
        if manager.get(job_id)["status"] == "completed":
            break
        time.sleep(0.05)

    fresh = Store(store.home)
    try:
        fresh_manager = JobManager(fresh, run_id)
        status = fresh_manager.get(job_id)
        assert status["status"] == "completed"
        assert status["result"]["strings"]
    finally:
        fresh.close()


def test_job_manager_rejects_unknown_artifact(store, challenge):
    run_id = new_run(store, challenge[0])
    manager = JobManager(store, run_id)
    with pytest.raises(PolicyDenied):
        manager.start("a" * 64, "strings", {})
