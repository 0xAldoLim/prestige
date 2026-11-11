"""Evidence-based hypothesis evaluation independent of model claims."""

import asyncio
import json
import os
from contextlib import asynccontextmanager
from pathlib import Path

import anyio
import pytest
from mcp.client.session import ClientSession
from mcp.shared.message import SessionMessage

from prestige import hypotheses
from prestige.evaluator import evaluate
from prestige.mcp_server import serve_streams
from prestige.store import Store
from prestige.types import PolicyDenied


@asynccontextmanager
async def _mcp_client(home: Path):
    old = os.environ.copy()
    os.environ.update(
        {"PRESTIGE_HOME": str(home), "PRESTIGE_ALLOWED_DIRS": str(home.parent)}
    )
    client_to_server_send, client_to_server_recv = anyio.create_memory_object_stream[
        SessionMessage | Exception
    ](0)
    server_to_client_send, server_to_client_recv = anyio.create_memory_object_stream[
        SessionMessage
    ](0)
    server_task = asyncio.create_task(
        serve_streams(client_to_server_recv, server_to_client_send)
    )
    try:
        async with ClientSession(server_to_client_recv, client_to_server_send) as session:
            await session.initialize()
            yield session
    finally:
        server_task.cancel()
        try:
            await server_task
        except asyncio.CancelledError:
            pass
        os.environ.clear()
        os.environ.update(old)


async def _create(session, path):
    body = json.loads(
        (
            await session.call_tool(
                "prestige_create_investigation",
                {"source_path": str(path), "mode": "fast", "max_turns": 12},
            )
        ).content[0].text
    )
    run_id = body["run_id"]
    status = json.loads(
        (await session.call_tool("prestige_get_status", {"run_id": run_id})).content[0].text
    )
    return run_id, status["artifacts"][0]["id"]


async def test_predictions_confirmed_contradicted_and_unresolved(tmp_path):
    home = tmp_path / "state"
    challenge = tmp_path / "challenge.txt"
    challenge.write_bytes(b"hello-world")
    async with _mcp_client(home) as session:
        run_id, artifact = await _create(session, challenge)

        first = json.loads(
            (
                await session.call_tool(
                    "prestige_hypothesis_add",
                    {
                        "run_id": run_id,
                        "text": "inspect exposes the literal content",
                        "prediction": "preview hello-world",
                        "test_tool": "inspect",
                        "test_artifact": artifact,
                    },
                )
            ).content[0].text
        )
        second = json.loads(
            (
                await session.call_tool(
                    "prestige_hypothesis_add",
                    {
                        "run_id": run_id,
                        "text": "read does not expose the literal content",
                        "prediction": "read output absent",
                        "contradicts": ["hello-world"],
                        "test_tool": "read",
                        "test_artifact": artifact,
                    },
                )
            ).content[0].text
        )
        third = json.loads(
            (
                await session.call_tool(
                    "prestige_hypothesis_add",
                    {
                        "run_id": run_id,
                        "text": "strings will expose a marker",
                        "prediction": "marker",
                        "test_tool": "strings",
                        "test_artifact": artifact,
                    },
                )
            ).content[0].text
        )

        inspected = json.loads(
            (
                await session.call_tool(
                    "prestige_run_experiment",
                    {
                        "run_id": run_id,
                        "tool": "inspect",
                        "artifact_id": artifact,
                        "args": {},
                    },
                )
            ).content[0].text
        )
        assert inspected["evaluation"]["evaluations"][0]["confidence"] == "supported"

        read = json.loads(
            (
                await session.call_tool(
                    "prestige_run_experiment",
                    {
                        "run_id": run_id,
                        "tool": "read",
                        "artifact_id": artifact,
                        "args": {},
                    },
                )
            ).content[0].text
        )
        by_id = {item["id"]: item for item in read["evaluation"]["evaluations"]}
        assert by_id[second["result"]["id"]]["confidence"] == "contradicted"

        evaluated = json.loads(
            (
                await session.call_tool(
                    "prestige_evaluate_hypotheses", {"run_id": run_id}
                )
            ).content[0].text
        )
        by_id = {item["id"]: item for item in evaluated["result"]["evaluations"]}
        assert by_id[third["result"]["id"]]["confidence"] == "unresolved"
        assert by_id[third["result"]["id"]]["recommendation"] == "run_planned_test"
        assert first["result"]["id"] in by_id
        assert second["result"]["id"] in by_id

    store = Store(home)
    try:
        records = {item["id"]: item for item in hypotheses.latest(store, run_id)}
        assert records[first["result"]["id"]]["confidence"] == "supported"
        assert records[second["result"]["id"]]["confidence"] == "contradicted"
        assert records[first["result"]["id"]]["evidence"]
        assert "hypothesis_evaluation" in [event["kind"] for event in store.events(run_id)]
    finally:
        store.close()


async def test_tool_failure_is_inconclusive_not_falsification(tmp_path):
    home = tmp_path / "state"
    challenge = tmp_path / "challenge.txt"
    challenge.write_bytes(b"hello-world")
    async with _mcp_client(home) as session:
        run_id, artifact = await _create(session, challenge)
        created = json.loads(
            (
                await session.call_tool(
                    "prestige_hypothesis_add",
                    {
                        "run_id": run_id,
                        "text": "hex decoding succeeds",
                        "prediction": "hex output",
                        "test_tool": "hex",
                        "test_artifact": artifact,
                    },
                )
            ).content[0].text
        )
        failed = json.loads(
            (
                await session.call_tool(
                    "prestige_run_experiment",
                    {"run_id": run_id, "tool": "hex", "artifact_id": artifact, "args": {}},
                )
            ).content[0].text
        )
        assert failed["status"] == "denied"
        evaluated = json.loads(
            (
                await session.call_tool(
                    "prestige_evaluate_hypotheses", {"run_id": run_id}
                )
            ).content[0].text
        )
        item = evaluated["result"]["evaluations"][0]
        assert item["id"] == created["result"]["id"]
        assert item["recommendation"] == "run_planned_test"
    store = Store(home)
    try:
        record = [item for item in hypotheses.latest(store, run_id)][0]
        assert record["confidence"] == "unresolved"
    finally:
        store.close()


async def test_duplicate_experiment_is_reported(tmp_path):
    home = tmp_path / "state"
    challenge = tmp_path / "challenge.txt"
    challenge.write_bytes(b"hello-world")
    async with _mcp_client(home) as session:
        run_id, artifact = await _create(session, challenge)
        await session.call_tool(
            "prestige_hypothesis_add",
            {
                "run_id": run_id,
                "text": "inspect exposes content",
                "prediction": "preview hello-world",
                "test_tool": "inspect",
                "test_artifact": artifact,
            },
        )
        await session.call_tool(
            "prestige_run_experiment",
            {"run_id": run_id, "tool": "inspect", "artifact_id": artifact, "args": {}},
        )
        forced = json.loads(
            (
                await session.call_tool(
                    "prestige_run_experiment",
                    {
                        "run_id": run_id,
                        "tool": "inspect",
                        "artifact_id": artifact,
                        "args": {},
                        "force": True,
                    },
                )
            ).content[0].text
        )
        evaluations = forced["evaluation"]["evaluations"]
        assert any(item["duplicate"] for item in evaluations)
        assert any(item["recommendation"] == "revise_duplicate_experiment" for item in evaluations)


def test_model_cannot_set_evaluator_fields(store, tmp_path):
    path = tmp_path / "challenge.txt"
    path.write_bytes(b"data")
    from prestige.engine import new_run

    run_id = new_run(store, path)
    record = hypotheses.add(store, run_id, "claim")
    with pytest.raises(PolicyDenied):
        hypotheses.update(store, run_id, record["id"], confidence="supported")
    with pytest.raises(PolicyDenied):
        hypotheses.update(store, run_id, record["id"], evidence=["seq:99"])


def test_evaluation_state_survives_store_reopen(store, tmp_path):
    path = tmp_path / "challenge.txt"
    path.write_bytes(b"hello-world")
    from prestige.engine import new_run

    run_id = new_run(store, path)
    record = hypotheses.add(
        store,
        run_id,
        "inspect exposes content",
        prediction="preview hello-world",
        test_tool="inspect",
    )
    store.event(
        run_id,
        "observation",
        {
            "action": {"tool": "inspect", "artifact": "", "args": {}},
            "result": {"preview": "hello-world", "sha256": "x"},
            "trust": "fact",
        },
    )
    first = evaluate(store, run_id)
    assert first["evaluations"][0]["confidence"] == "supported"
    fresh = Store(store.home)
    try:
        reloaded = {item["id"]: item for item in hypotheses.latest(fresh, run_id)}
        assert reloaded[record["id"]]["confidence"] == "supported"
        assert reloaded[record["id"]]["evidence"]
    finally:
        fresh.close()


def test_fast_lane_escalation_recommendation(store, tmp_path):
    path = tmp_path / "challenge.txt"
    path.write_bytes(b"hello-world")
    from prestige.engine import new_run

    run_id = new_run(store, path, mode="fast")
    hypotheses.add(store, run_id, "needs a test", test_tool="strings")
    result = evaluate(store, run_id)
    assert result["recommendation"] == "escalate"
