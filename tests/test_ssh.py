"""Explicitly scoped SSH adapter with operator key/known-hosts and pinned args."""

import asyncio
import getpass
import json
import os
import shutil
import socket
import subprocess
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

pytestmark = pytest.mark.skipif(
    os.name == "nt", reason="POSIX ssh adapter test uses a shell fake-ssh fixture"
)


@pytest.fixture(autouse=True)
def _remote_enabled(monkeypatch):
    monkeypatch.setenv("PRESTIGE_REMOTE_ENABLED", "1")


def _ssh_registration(tmp_path, port=2222, **overrides):
    key = tmp_path / "id_test_default"
    key.write_text("fake-key")
    key.chmod(0o600)
    known = tmp_path / "known_hosts_default"
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


@pytest.mark.skipif(
    os.name == "nt"
    or os.environ.get("PRESTIGE_TEST_SSHD") != "1"
    or not shutil.which("sshd")
    or not shutil.which("ssh-keygen"),
    reason="Set PRESTIGE_TEST_SSHD=1 with a local sshd/ssh-keygen to run the real endpoint test",
)
def test_real_loopback_sshd(tmp_path):
    root = tmp_path / "sshd"
    root.mkdir()
    subprocess.run(["ssh-keygen", "-t", "ed25519", "-f", str(root / "host_key"), "-N", "", "-q"], check=True)
    subprocess.run(["ssh-keygen", "-t", "ed25519", "-f", str(root / "client_key"), "-N", "", "-q"], check=True)
    (root / "authorized_keys").write_text((root / "client_key.pub").read_text())
    (root / "authorized_keys").chmod(0o600)
    (root / "client_key").chmod(0o600)
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    user = getpass.getuser()
    (root / "sshd_config").write_text(
        f"""Port {port}
ListenAddress 127.0.0.1
HostKey {root / 'host_key'}
PidFile {root / 'sshd.pid'}
AuthorizedKeysFile {root / 'authorized_keys'}
PasswordAuthentication no
PubkeyAuthentication yes
PermitRootLogin no
UsePAM no
StrictModes no
AllowUsers {user}
LogLevel QUIET
"""
    )
    process = subprocess.Popen(
        ["/usr/sbin/sshd", "-D", "-f", str(root / "sshd_config"), "-E", str(root / "sshd.log")],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        deadline = __import__("time").time() + 5
        while __import__("time").time() < deadline:
            with socket.socket() as probe:
                try:
                    probe.connect(("127.0.0.1", port))
                    break
                except OSError:
                    __import__("time").sleep(0.1)
        else:
            pytest.skip("sshd did not start")
        scan = subprocess.run(
            ["ssh-keyscan", "-p", str(port), "127.0.0.1"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        host_key = None
        for line in scan.stdout.splitlines():
            fields = line.split()
            if len(fields) >= 2 and fields[1] == "ssh-ed25519":
                host_key = " ".join(fields[1:])
                break
        if not host_key:
            pytest.skip("could not obtain the sshd host key")
        (root / "known_hosts").write_text(
            f"127.0.0.1 {host_key}\n[127.0.0.1]:{port} {host_key}\n"
        )
        registration = _ssh_registration(
            root,
            port=port,
            ssh_user=user,
            ssh_key_path=str(root / "client_key"),
            ssh_known_hosts=str(root / "known_hosts"),
        )
        result = RemoteBroker(root, registration).ssh("id -un && echo SSH_OK")
        assert result["returncode"] == 0, result
        assert user in result["stdout"]
        assert "SSH_OK" in result["stdout"]
    finally:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()
