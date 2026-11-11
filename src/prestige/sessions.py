"""Persistent interactive sessions inside the reviewed Docker worker.

A session is a long-lived ``docker exec -i`` process attached to a container that
already has the run's input mounted read-only and output mounted writable. It keeps
interpreter/debugger state across model turns without exposing host networking or a
Docker socket to the process itself.
"""

import subprocess
import threading
import time
import uuid

from prestige.sandbox import WorkspaceRunner
from prestige.types import PolicyDenied, PrestigeError

ALLOWED_COMMANDS = {
    "python3": ["python3", "-u", "-i"],
    "gdb": ["gdb", "-q"],
    "radare2": ["radare2", "-q", "-"],
    "r2": ["r2", "-q", "-"],
}
MAX_BUFFER = 256 * 1024
MAX_INPUT = 16384
MAX_WAIT = 5.0

_SESSIONS: dict[str, "Session"] = {}
_LOCK = threading.Lock()


class Session:
    def __init__(self, session_id: str, name: str, command: str, process, container: str):
        self.session_id = session_id
        self.name = name
        self.command = command
        self.process = process
        self.container = container
        self.buffer = bytearray()
        self.total = 0
        self.alive = True
        self.lock = threading.Lock()
        self.reader = threading.Thread(target=self._drain, daemon=True)

    def _drain(self):
        import os

        try:
            fd = self.process.stdout.fileno()
            while True:
                chunk = os.read(fd, 4096)
                if not chunk:
                    break
                with self.lock:
                    self.buffer.extend(chunk)
                    self.total += len(chunk)
                    if len(self.buffer) > MAX_BUFFER:
                        del self.buffer[: len(self.buffer) - MAX_BUFFER]
        finally:
            self.alive = False

    def write(self, text: str):
        if not self.alive:
            raise PrestigeError("Session is not running")
        with self.lock:
            try:
                self.process.stdin.write((text + "\n").encode("utf-8"))
                self.process.stdin.flush()
            except (BrokenPipeError, OSError) as error:
                self.alive = False
                raise PrestigeError("Session input failed") from error
            return self.total

    def read(self, cursor: int) -> dict:
        with self.lock:
            if type(cursor) is not int or cursor < 0:
                raise PolicyDenied("Invalid session cursor")
            retained_start = max(0, self.total - len(self.buffer))
            if cursor < retained_start:
                cursor = retained_start
            offset = cursor - retained_start
            data = bytes(self.buffer[offset:])
            return {
                "session_id": self.session_id,
                "cursor": self.total,
                "output": data.decode("utf-8", errors="replace")[:MAX_INPUT],
                "alive": self.alive,
            }

    def stop(self) -> dict:
        self.alive = False
        try:
            self.process.stdin.close()
        except Exception:
            pass
        try:
            self.process.terminate()
            self.process.wait(timeout=5)
        except Exception:
            try:
                self.process.kill()
            except Exception:
                pass
        subprocess.run(
            ["docker", "rm", "--force", self.container],
            capture_output=True,
            timeout=10,
            check=False,
        )
        return {"session_id": self.session_id, "stopped": True}

    def summary(self) -> dict:
        return {
            "session_id": self.session_id,
            "command": self.command,
            "container": self.container,
            "alive": self.alive,
            "cursor": self.total,
        }


def _image_ok(image: str) -> bool:
    import re

    return bool(
        re.fullmatch(r"sha256:[a-f0-9]{64}|[a-z0-9./_-]+@sha256:[a-f0-9]{64}", image)
    )


def start_session(image: str, artifacts, command: str = "python3") -> dict:
    if not _image_ok(image):
        raise PolicyDenied("Use an existing immutable Docker image digest")
    if command not in ALLOWED_COMMANDS:
        raise PolicyDenied("Session command is not allowlisted")
    session_id = uuid.uuid4().hex[:16]
    name = "prestige-session-" + session_id
    runner = WorkspaceRunner(image, artifacts)
    base = runner.argv(name)
    # base ends with [image, "python3", "-I", "-"]; keep isolation flags and mounts.
    args = base[:-3]
    args.insert(2, "-d")
    args.extend(["sleep", "infinity"])
    created = subprocess.run(args, capture_output=True, text=True, timeout=60, check=False)
    if created.returncode != 0:
        raise PrestigeError("Session container failed: " + created.stderr[-500:])
    try:
        process = subprocess.Popen(
            ["docker", "exec", "-i", name, *ALLOWED_COMMANDS[command]],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        )
    except OSError as error:
        subprocess.run(["docker", "rm", "--force", name], capture_output=True, check=False)
        raise PrestigeError("Session process failed to start") from error
    session = Session(session_id, name, command, process, name)
    session.reader.start()
    with _LOCK:
        _SESSIONS[session_id] = session
    time.sleep(0.8)
    return session.summary()


def _session(session_id: str) -> Session:
    with _LOCK:
        session = _SESSIONS.get(session_id)
    if session is None:
        raise PrestigeError("Unknown session id")
    return session


def send_session(session_id: str, text: str, wait: float = 0.8) -> dict:
    if not isinstance(text, str) or len(text) > MAX_INPUT:
        raise PolicyDenied("Session input is invalid or too large")
    if type(wait) not in (int, float) or not 0 <= wait <= MAX_WAIT:
        raise PolicyDenied("Invalid session wait")
    session = _session(session_id)
    cursor = session.write(text)
    time.sleep(float(wait))
    result = session.read(cursor)
    return result


def read_session(session_id: str, cursor: int) -> dict:
    return _session(session_id).read(cursor)


def stop_session(session_id: str) -> dict:
    session = _session(session_id)
    result = session.stop()
    with _LOCK:
        _SESSIONS.pop(session_id, None)
    return result


def list_sessions() -> list[dict]:
    with _LOCK:
        sessions = list(_SESSIONS.values())
    return [session.summary() for session in sessions]


def reset_sessions() -> None:
    for session_id in list(_SESSIONS):
        try:
            stop_session(session_id)
        except Exception:
            pass
