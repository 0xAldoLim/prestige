"""Opt-in offline container runner. Never mounts source directories or provider credentials."""

import json
import re
import subprocess
import threading
import time
import uuid

from prestige.types import PolicyDenied, PrestigeError

PROBE = r"""
import json, os, socket, subprocess, sys
assert os.getuid() == 65534
assert socket.if_nameindex() == [(1, 'lo')]
assert not os.path.exists('/var/run/docker.sock')
assert not os.path.exists('/root/.codex/auth.json')
checks = {}
def blocked(name, fn):
    try:
        fn()
    except OSError:
        checks[name] = True
    else:
        checks[name] = False
blocked('tcp', lambda: socket.create_connection(('192.0.2.1', 443), 0.3))
blocked('dns', lambda: socket.getaddrinfo('prestige-denied.invalid', 443))
child = subprocess.run([sys.executable, '-c',
    "import socket; socket.create_connection(('192.0.2.1',443),.3)"], capture_output=True, timeout=3)
checks['child_tcp'] = child.returncode != 0
blocked('root_write', lambda: open('/prestige-write-test', 'w'))
assert all(checks.values()), checks
print(json.dumps({'isolated': True, 'checks': checks}))
"""


class DockerRunner:
    def __init__(self, image: str):
        if not re.fullmatch(r"sha256:[a-f0-9]{64}|[a-z0-9./_-]+@sha256:[a-f0-9]{64}", image):
            raise PolicyDenied("Use an existing immutable Docker image digest; no automatic pull")
        self.image = image
        self.verified = False

    def argv(self, name: str):
        return [
            "docker",
            "run",
            "--rm",
            "--pull=never",
            "--name",
            name,
            "--network=none",
            "--read-only",
            "--user",
            "65534:65534",
            "--cap-drop=ALL",
            "--security-opt=no-new-privileges",
            "--pids-limit=32",
            "--memory=256m",
            "--cpus=1",
            "--ulimit",
            "fsize=1048576:1048576",
            "--tmpfs",
            "/tmp:rw,noexec,nosuid,nodev,size=16m",
            "--workdir",
            "/tmp",
            "--env",
            "HOME=/tmp",
            "-i",
            self.image,
            "python3",
            "-I",
            "-",
        ]

    def _run(self, script: str, timeout: float) -> dict:
        if len(script.encode()) > 65536 or not 0 < timeout <= 30:
            raise PolicyDenied("Script or time budget exceeded")
        name = "prestige-" + uuid.uuid4().hex
        args = self.argv(name)
        args[2:2] = ["--log-driver=none"]
        process = None
        chunks = {"stdout": bytearray(), "stderr": bytearray()}
        overflow = threading.Event()
        readers = []

        def drain(stream, key):
            while data := stream.read(4096):
                if len(chunks[key]) + len(data) > 32768:
                    overflow.set()
                    return
                chunks[key].extend(data)

        try:
            process = subprocess.Popen(
                args, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE
            )
            for key in chunks:
                reader = threading.Thread(
                    target=drain, args=(getattr(process, key), key), daemon=True
                )
                reader.start()
                readers.append(reader)

            # Writing stdin in its own thread keeps the wall deadline effective if Docker stalls.
            def feed():
                try:
                    process.stdin.write(script.encode())
                    process.stdin.close()
                except (BrokenPipeError, OSError):
                    pass

            writer = threading.Thread(target=feed, daemon=True)
            writer.start()
            deadline = time.monotonic() + timeout
            while process.poll() is None:
                if overflow.wait(0.02):
                    raise PolicyDenied("Container output exceeded limit")
                if time.monotonic() >= deadline:
                    raise PrestigeError("Container timed out and was removed")
            for reader in readers:
                reader.join(timeout=1)
            if overflow.is_set():
                raise PolicyDenied("Container output exceeded limit")
            return {
                "returncode": process.returncode,
                **{
                    key: bytes(value).decode("utf-8", errors="replace")
                    for key, value in chunks.items()
                },
            }
        finally:
            try:
                subprocess.run(
                    ["docker", "rm", "--force", name], capture_output=True, timeout=10, check=False
                )
            finally:
                if process is not None:
                    if process.poll() is None:
                        process.kill()
                    process.wait(timeout=5)
                    for reader in readers:
                        reader.join(timeout=1)
                    for stream in (process.stdin, process.stdout, process.stderr):
                        if not stream.closed:
                            stream.close()

    def audit(self) -> dict:
        result = self._run(PROBE, 20)
        if result["returncode"]:
            raise PolicyDenied("Container isolation probe failed: " + result["stderr"][:500])
        evidence = json.loads(result["stdout"])
        self.verified = evidence.get("isolated") is True and all(
            evidence.get("checks", {}).values()
        )
        if not self.verified:
            raise PolicyDenied("Container audit incomplete")
        return evidence

    def run(self, script: str, timeout=10):
        if not self.verified:
            self.audit()
        return self._run(script, timeout)
