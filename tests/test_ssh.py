"""Explicitly scoped SSH adapter with operator key/known-hosts and pinned args."""

import asyncio
import json
import os
from contextlib import asynccontextmanager
from pathlib import Path

import anyio
import pytest
from mcp.client.session import ClientSession
from mcp.shared.message import SessionMessage

from prestige.engine import new_run
from prestige.mcp_server import serve_streams
from prestige.remote import (
    Registration,
    RemoteBroker,
    RemoteDenied,
    RemoteExpired,
    bind_target,
    save_registrations,
)
from prestige.store import Store


@pytest.fixture(autouse=True)
def _remote_enabled(monkeypatch):
    monkeypatch.setenv("PRESTIGE_REMOTE_ENABLED", "1")


def _ssh_registration(tmp_path, port=2222, **overrides):
    key = tmp_path / "id_test"
    key.write_text("fake-key")
    key.chmod(0o600)
    known = tmp_path / "known_hosts"
    known.write_text("127.0.0.1 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFake\n")
    data = {
        "id": "ssh1",
        "provenance": "pytest loopback SSH assignment",
        "protocol": "ssh",
        "host": "127.0.0.1",
        "port": port,
        "paths": ["/"],
        "pinned_ips": ["127.0.0.1"],
        "dedicated_private": True,
        "allowed_actions": ["ssh"],
        "ssh_user": "challenge",
        "ssh_key_path": str(key),
        "ssh_known_hosts": str(known),
        "enabled": True,
    }
    data.update(overrides)
    return Registration.from_dict(data)


def _fake_ssh(tmp_path, monkeypatch):
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    args_file = tmp_path / "ssh-args.txt"
    script = bin_dir / "ssh"
    script.write_text(
        "#!/bin/sh\n"
        f"printf '%s\\n' \"$@\" > {args_file}\n"
        "echo FAKE_SSH_OK\n"
    )
    script.chmod(0o755)
    monkeypatch.setenv("PATH", f"{bin_dir}:{os.environ.get('PATH', '')}")
    return args_file


def test_ssh_registration_requires_operator_key_and_known_hosts(tmp_path):
    with pytest.raises(RemoteDenied):
        Registration.from_dict(
            {
                "id": "ssh-missing",
                "provenance": "p",
                "protocol": "ssh",
                "host": "127.0.0.1",
                "port": 22,
            }
        )


def test_ssh_adapter_pins_destination_and_uses_batch_mode(tmp_path, monkeypatch):
    args_file = _fake_ssh(tmp_path, monkeypatch)
    broker = RemoteBroker(tmp_path, _ssh_registration(tmp_path))
    result = broker.ssh("echo hello")
    assert result["returncode"] == 0
    assert "FAKE_SSH_OK" in result["stdout"]
    args = args_file.read_text()
    assert "StrictHostKeyChecking=yes" in args
    assert "BatchMode=yes" in args
    assert "HostKeyAlias=127.0.0.1" in args
    assert "challenge@127.0.0.1" in args
    assert "echo hello" in args
    assert "-L" not in args and "-R" not in args and "-D" not in args


def test_ssh_cancelled_registration_denied(tmp_path, monkeypatch):
    _fake_ssh(tmp_path, monkeypatch)
    broker = RemoteBroker(tmp_path, _ssh_registration(tmp_path))
    broker.cancel()
    with pytest.raises(RemoteExpired):
        broker.ssh("id")


@asynccontextmanager
async def _mcp_client(home: Path):
    old = os.environ.copy()
    os.environ.update(
        {
            "PRESTIGE_HOME": str(home),
            "PRESTIGE_ALLOWED_DIRS": str(home.parent),
            "PRESTIGE_REMOTE_ENABLED": "1",
        }
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


async def test_mcp_ssh_records_evidence(tmp_path, monkeypatch):
    _fake_ssh(tmp_path, monkeypatch)
    home = tmp_path / "state"
    registration = _ssh_registration(tmp_path)
    save_registrations(home, {"ssh1": registration})
    challenge = tmp_path / "challenge.txt"
    challenge.write_bytes(b"offline")
    store = Store(home)
    try:
        run_id = new_run(store, challenge)
    finally:
        store.close()
    bind_target(home, run_id, "ssh1")

    async with _mcp_client(home) as session:
        result = json.loads(
            (
                await session.call_tool(
                    "prestige_remote_ssh",
                    {
                        "run_id": run_id,
                        "registration_id": "ssh1",
                        "command": "echo hello",
                    },
                )
            ).content[0].text
        )
        assert result["status"] == "ok"
        assert result["result"]["returncode"] == 0
        assert "FAKE_SSH_OK" in result["result"]["stdout"]
        assert result["result"]["artifact"]

    store = Store(home)
    try:
        kinds = [event["kind"] for event in store.events(run_id)]
        assert "remote_request" in kinds
    finally:
        store.close()
