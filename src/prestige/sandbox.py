"""Offline execution with exact artifact/workspace mounts and no provider credentials."""

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
        self.active = set()
        self.active_lock = threading.Lock()

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
        with self.active_lock:
            self.active.add(name)
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
            with self.active_lock:
                self.active.discard(name)
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

    def cancel(self):
        with self.active_lock:
            names = list(self.active)
        for name in names:
            subprocess.run(
                ["docker", "rm", "--force", name], capture_output=True, timeout=10, check=False
            )


class WorkspaceRunner(DockerRunner):
    """Persist files between bounded calls; mount only this run's blobs and output.

    Execution processes are recreated on each call. Interactive debugger processes
    are not yet persistent. The image must be locally reviewed and immutable.
    """

    COMMANDS = {
        "file",
        "strings",
        "readelf",
        "objdump",
        "nm",
        "xxd",
        "gdb",
        "tshark",
        "7z",
        "unzip",
        "python3",
        "sage",
        "radare2",
        "r2",
        "binwalk",
        "exiftool",
        "analyzeHeadless",
        "sha256sum",
    }

    def __init__(self, image, artifacts):
        from pathlib import Path

        super().__init__(image)
        self.input = artifacts.root.resolve(strict=True)
        self.output = artifacts.root.parent / "workspace"
        self.output.mkdir(exist_ok=True, mode=0o777)
        self.output.chmod(0o777)
        if self.output.is_symlink() or not self.output.resolve().is_relative_to(
            artifacts.root.parent.resolve()
        ):
            raise PolicyDenied("Workspace root escaped investigation directory")
        self.output = Path(self.output.resolve())
        if any("," in str(path) for path in (self.input, self.output)):
            raise PolicyDenied("Docker mount paths containing commas are unsupported")
        self.file_limit = artifacts.max_file

    def argv(self, name):
        args = super().argv(name)
        args[args.index("fsize=1048576:1048576")] = f"fsize={self.file_limit}:{self.file_limit}"
        args[args.index("--workdir") + 1] = "/work/output"
        args[-4:-4] = [
            "--mount",
            f"type=bind,src={self.input},dst=/work/input,readonly",
            "--mount",
            f"type=bind,src={self.output},dst=/work/output",
        ]
        return args

    def execute(self, action):
        args = dict(action.args)
        timeout = args.pop("timeout", 15)
        if type(timeout) not in (int, float) or not 0 < timeout <= 30:
            raise PolicyDenied("Tool timeout must be in (0,30] seconds")
        if action.tool == "python":
            if set(args) != {"code"} or not isinstance(args["code"], str):
                raise PolicyDenied("Python tool requires exactly code and optional timeout")
            return self.run(args["code"], timeout)
        if action.tool == "command":
            argv = args.get("argv")
            if (
                set(args) - {"argv", "stdin"}
                or not isinstance(argv, list)
                or not argv
                or not all(isinstance(x, str) and len(x) <= 4096 for x in argv)
            ):
                raise PolicyDenied("Invalid command arguments")
            if (
                argv[0] not in self.COMMANDS
                or len(argv) > 64
                or not isinstance(args.get("stdin", ""), str)
            ):
                raise PolicyDenied("Command is not in the security-tool allowlist")
            script = (
                "import subprocess,sys\na="
                + repr(argv)
                + "\nr=subprocess.run(a,input="
                + repr(args.get("stdin", ""))
                + ",text=True,capture_output=False,timeout="
                + repr(timeout)
                + ")\nsys.exit(r.returncode)\n"
            )
            return self.run(script, min(30, timeout + 1))
        raise PolicyDenied("Unsupported isolated tool")

    def collect(self, artifacts):
        import os

        from prestige.artifacts import regular_file, safe_label

        result, total, count = [], 0, 0
        for directory, dirs, files in os.walk(self.output, followlinks=False):
            count += len(dirs) + len(files)
            if count > 128:
                raise PolicyDenied("Tool output file budget exceeded")
            for name in dirs + files:
                path = __import__("pathlib").Path(directory) / name
                if path.is_symlink() or getattr(path.lstat(), "st_file_attributes", 0) & 0x400:
                    raise PolicyDenied("Linked tool outputs are forbidden")
            for name in files:
                path = __import__("pathlib").Path(directory) / name
                if not regular_file(path):
                    raise PolicyDenied("Non-regular tool output")
                total += path.stat().st_size
                if path.stat().st_size > artifacts.max_file or total > artifacts.max_total:
                    raise PolicyDenied("Tool output byte budget exceeded")
                label = path.relative_to(self.output).as_posix()
                safe_label(label)
                with path.open("rb") as stream:
                    data = stream.read(artifacts.max_file + 1)
                result.append(
                    {"path": "/work/output/" + label, "artifact": artifacts.add(data, label)}
                )
        return result
