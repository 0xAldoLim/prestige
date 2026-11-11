"""Operator-controlled verification commitments; the model cannot supply them."""

import asyncio
import base64
import hashlib
import json
import os
from contextlib import asynccontextmanager
from pathlib import Path

import anyio
import pytest
from mcp.client.session import ClientSession
from mcp.shared.message import SessionMessage

from prestige.commitments import (
    add_commitment,
    expected_for,
    list_commitments,
    load_commitments,
    remove_commitment,
)
from prestige.mcp_server import serve_streams
from prestige.types import PrestigeError


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


def test_commitment_add_list_remove(tmp_path):
    home = tmp_path / "state"
    artifact = "a" * 64
    expected = "b" * 64
    add_commitment(home, artifact, expected)
    assert expected_for(home, artifact) == expected
    assert list_commitments(home) == [
        {"artifact_sha256": artifact, "expected_sha256": expected}
    ]
    assert remove_commitment(home, artifact)["removed"] is True
    assert expected_for(home, artifact) is None


@pytest.mark.parametrize(
    "payload",
    [
        "{not json",
        json.dumps({"schema_version": 2, "commitments": {}}),
        json.dumps({"schema_version": 1, "commitments": {"short": "b" * 64}}),
        json.dumps({"schema_version": 1, "commitments": {"a" * 64: "nothex"}}),
        json.dumps({"unknown": True}),
    ],
)
def test_commitment_file_validation(tmp_path, payload):
    home = tmp_path / "state"
    home.mkdir()
    (home / "commitments.json").write_text(payload)
    with pytest.raises(PrestigeError):
        load_commitments(home)


async def test_model_cannot_supply_expected_digest(tmp_path):
    home = tmp_path / "state"
    value = b"SYNTHETIC{model_commitment}"
    source = tmp_path / "challenge.txt"
    source.write_bytes(base64.b64encode(value))

    async with _mcp_client(home) as session:
        result = await session.call_tool(
            "prestige_create_investigation",
            {
                "source_path": str(source),
                "expected_sha256": hashlib.sha256(value).hexdigest(),
            },
        )
        body = json.loads(result.content[0].text)
        assert result.is_error or body.get("status") != "ready"


async def test_operator_commitment_is_applied_and_verified(tmp_path):
    home = tmp_path / "state"
    value = b"SYNTHETIC{operator_commitment}"
    source = tmp_path / "challenge.txt"
    source.write_bytes(base64.b64encode(value))
    artifact_digest = hashlib.sha256(source.read_bytes()).hexdigest()
    expected = hashlib.sha256(value).hexdigest()
    add_commitment(home, artifact_digest, expected)

    async with _mcp_client(home) as session:
        created = await session.call_tool(
            "prestige_create_investigation", {"source_path": str(source)}
        )
        body = json.loads(created.content[0].text)
        assert body["status"] == "ready"
        assert body["commitment_applied"] is True
        assert body["artifact_sha256"] == artifact_digest
        run_id = body["run_id"]

        verified = json.loads(
            (
                await session.call_tool(
                    "prestige_verify_candidate",
                    {"run_id": run_id, "candidate": value.decode()},
                )
            ).content[0].text
        )
        assert verified["verified"] is True
        assert verified["stage"] == "independently_verified"

        wrong = json.loads(
            (
                await session.call_tool(
                    "prestige_verify_candidate",
                    {"run_id": run_id, "candidate": "SYNTHETIC{wrong}"},
                )
            ).content[0].text
        )
        assert wrong["verified"] is False


async def test_wrong_operator_commitment_does_not_verify(tmp_path):
    home = tmp_path / "state"
    value = b"SYNTHETIC{real_value}"
    source = tmp_path / "challenge.txt"
    source.write_bytes(base64.b64encode(value))
    artifact_digest = hashlib.sha256(source.read_bytes()).hexdigest()
    add_commitment(home, artifact_digest, hashlib.sha256(b"other").hexdigest())

    async with _mcp_client(home) as session:
        created = await session.call_tool(
            "prestige_create_investigation", {"source_path": str(source)}
        )
        run_id = json.loads(created.content[0].text)["run_id"]
        result = json.loads(
            (
                await session.call_tool(
                    "prestige_verify_candidate",
                    {"run_id": run_id, "candidate": value.decode()},
                )
            ).content[0].text
        )
        assert result["verified"] is False


def test_cli_commitment_roundtrip(tmp_path, capsys):
    from prestige.cli import main

    home = tmp_path / "state"
    artifact = "c" * 64
    expected = "d" * 64
    assert main(["--home", str(home), "commitment", "add", artifact, expected]) == 0
    output = json.loads(capsys.readouterr().out)
    assert output["artifact_sha256"] == artifact
    assert main(["--home", str(home), "commitment", "list"]) == 0
    listing = json.loads(capsys.readouterr().out)
    assert listing == [{"artifact_sha256": artifact, "expected_sha256": expected}]
    assert main(["--home", str(home), "commitment", "remove", artifact]) == 0
    capsys.readouterr()
