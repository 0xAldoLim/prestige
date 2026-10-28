import concurrent.futures
import json

import pytest

from prestige.engine import new_run
from prestige.evaluation import compare, metrics, wilson
from prestige.store import Store
from prestige.types import PolicyDenied, PrestigeError


def test_concurrent_durable_events(store, challenge):
    run = new_run(store, challenge[0])

    def write(worker):
        connection = Store(store.home)
        for index in range(10):
            connection.event(run, "test", {"worker": worker}, key=f"{worker}-{index}")
        connection.close()

    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
        list(executor.map(write, range(4)))
    assert len([x for x in store.events(run) if x["kind"] == "test"]) == 40
    store.event(run, "test", {}, key="0-0")
    assert len([x for x in store.events(run) if x["kind"] == "test"]) == 40


def test_lease_exclusion_and_transaction_rollback(store, challenge):
    run = new_run(store, challenge[0])
    store.acquire(run, "first")
    with pytest.raises(PrestigeError):
        store.acquire(run, "second")
    store.release(run, "wrong")
    with pytest.raises(PrestigeError):
        store.acquire(run, "second")
    store.release(run, "first")
    store.acquire(run, "second")
    with pytest.raises(RuntimeError):
        with store.transaction() as db:
            db.execute("UPDATE runs SET status='corrupt' WHERE id=?", (run,))
            raise RuntimeError()
    assert store.run(run)["status"] == "ready"


def test_metrics_zero_unknown_and_confidence():
    assert wilson(0, 0) is None
    assert wilson(5, 10)[0] < 0.5 < wilson(5, 10)[1]
    rows = [{"status": "unsolved", "points": 100, "tokens": 0, "seconds": 1}]
    assert metrics(rows)["points_per_1000_tokens"] == 0
    rows[0].update(status="solved", tokens=None)
    assert metrics(rows)["points_per_1000_tokens"] is None
    assert metrics(rows)["composite"] == "not_comparable"


def test_comparators_cannot_hide_changed_permissions_or_failures():
    base = {
        "contract": {
            "suite_hash": "a",
            "model": "same",
            "effort": "same",
            "permissions": "same",
            "max_turns": 10,
            "max_seconds": 60,
            "workers": 1,
        },
        "results": [
            {
                "case": "one",
                "repeat": 0,
                "status": "unsolved",
                "points": 100,
                "tokens": 10,
                "seconds": 1,
            }
        ],
    }
    other = json.loads(json.dumps(base))
    assert compare(base, other)["comparable_inputs"]
    other["contract"]["permissions"] = "more"
    with pytest.raises(PolicyDenied):
        compare(base, other)
    other = json.loads(json.dumps(base))
    other["results"].append(other["results"][0])
    with pytest.raises(PolicyDenied):
        compare(base, other)
    other = json.loads(json.dumps(base))
    other["results"] = []
    with pytest.raises(PolicyDenied):
        compare(base, other)


def test_stale_lease_recovered_but_live_owner_preserved(store, challenge):
    run = new_run(store, challenge[0])
    store.acquire(run, "crashed", duration=-1)
    store.acquire(run, "new-worker")
    assert store.rows("SELECT owner FROM leases WHERE run_id=?", (run,))[0]["owner"] == "new-worker"
