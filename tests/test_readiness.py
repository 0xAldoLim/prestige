"""Focused tests for the bounded benchmark TCP readiness probe."""

from __future__ import annotations

import socket
import threading
import time

import pytest

from prestige.readiness import wait_for_tcp_service


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


class _Server:
    """Tiny loopback server whose per-connection behaviour is scripted."""

    def __init__(self, behaviour, port: int | None = None):
        self.port = port or _free_port()
        self.behaviour = behaviour
        self.connections = 0
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._listener: socket.socket | None = None
        self._held: list[socket.socket] = []

    def __enter__(self):
        self._thread.start()
        deadline = time.monotonic() + 2
        while self._listener is None and time.monotonic() < deadline:
            time.sleep(0.005)
        return self

    def __exit__(self, *exc):
        self._stop.set()
        if self._listener is not None:
            self._listener.close()
        for held in self._held:
            held.close()
        self._thread.join(timeout=2)

    def _run(self):
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(("127.0.0.1", self.port))
        listener.listen(8)
        listener.settimeout(0.05)
        self._listener = listener
        while not self._stop.is_set():
            try:
                connection, _ = listener.accept()
            except (socket.timeout, OSError):
                continue
            self.connections += 1
            try:
                self.behaviour(connection, self.connections)
            except OSError:
                pass


def _send_banner(connection, _index):
    connection.sendall(b"BANNER\n")
    connection.close()


def _close_empty(connection, _index):
    connection.close()


def test_connection_refused_then_ready():
    port = _free_port()
    ready = threading.Event()

    def delayed():
        time.sleep(0.35)
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            listener.bind(("127.0.0.1", port))
            listener.listen(1)
            ready.set()
            connection, _ = listener.accept()
            connection.sendall(b"READY\n")
            connection.close()

    thread = threading.Thread(target=delayed, daemon=True)
    thread.start()
    try:
        assert wait_for_tcp_service(port, 3.0, retry_delay=0.05)
    finally:
        thread.join(timeout=2)
    assert ready.is_set()


def test_immediate_eof_then_banner_is_ready_after_retry():
    def behaviour(connection, index):
        if index <= 2:
            connection.close()
        else:
            connection.sendall(b"BANNER\n")
            connection.close()

    with _Server(behaviour) as server:
        assert wait_for_tcp_service(server.port, 3.0, retry_delay=0.02)
    assert server.connections >= 3


def test_silent_open_socket_is_not_ready_by_default():
    def behaviour(connection, _index):
        connection.settimeout(0.02)
        while True:
            try:
                if not connection.recv(64):
                    return
            except socket.timeout:
                continue
            except OSError:
                return

    with _Server(behaviour) as server:
        started = time.monotonic()
        assert not wait_for_tcp_service(
            server.port, 0.6, read_timeout=0.15, retry_delay=0.01
        )
        assert time.monotonic() - started < 2.0
    assert server.connections >= 2


def test_silent_open_socket_can_be_accepted_when_data_is_not_expected():
    def behaviour(connection, _index):
        connection.settimeout(0.02)
        while True:
            try:
                if not connection.recv(64):
                    return
            except socket.timeout:
                continue
            except OSError:
                return

    with _Server(behaviour) as server:
        assert wait_for_tcp_service(
            server.port, 1.0, expect_data=False, read_timeout=0.1, retry_delay=0.01
        )


def test_repeated_eof_never_becomes_ready():
    with _Server(_close_empty) as server:
        started = time.monotonic()
        assert not wait_for_tcp_service(
            server.port, 0.6, read_timeout=0.1, retry_delay=0.02
        )
        assert time.monotonic() - started < 2.0
    assert server.connections >= 2


def test_probe_rejects_invalid_arguments():
    with pytest.raises(ValueError):
        wait_for_tcp_service(0)
    with pytest.raises(ValueError):
        wait_for_tcp_service(1, -1)
