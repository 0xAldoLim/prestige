"""Bounded TCP service-readiness probes for the benchmark harness.

A listening socket is not proof that a restarted service is ready: Docker's
published-port proxy can accept a connection while the backend is still
starting, then close it without sending anything.  The probe therefore keeps
retrying until the protocol's own first read (normally a banner or greeting)
arrives, and never treats an immediate EOF or a silent open socket as ready
when data is expected.

The helper is deliberately transport-only.  It does not authorise a
destination; callers remain responsible for operator registration, scope and
process isolation.
"""

from __future__ import annotations

import socket
import time

DEFAULT_CONNECT_TIMEOUT = 2.0
DEFAULT_READ_TIMEOUT = 2.0
DEFAULT_RETRY_DELAY = 0.25


def wait_for_tcp_service(
    port: int,
    timeout: float = 30.0,
    *,
    host: str = "127.0.0.1",
    expect_data: bool = True,
    connect_timeout: float = DEFAULT_CONNECT_TIMEOUT,
    read_timeout: float = DEFAULT_READ_TIMEOUT,
    retry_delay: float = DEFAULT_RETRY_DELAY,
) -> bool:
    """Return True only when the TCP service becomes ready before ``timeout``.

    Readiness rules:

    * connection refused/reset, or an immediate EOF before any data: retry;
    * non-empty data: ready (all benchmark services send a banner or protocol
      greeting);
    * connection accepted but silent for ``read_timeout``: ready only when
      ``expect_data`` is False.  The benchmark calls use the default ``True``
      because a bare open socket during a restart is not service readiness;
    * the overall deadline is bounded; no attempt can extend it.

    ``timeout`` bounds the whole probe.  Per-attempt timeouts are clamped to
    the remaining deadline so a slow connect cannot overshoot it.
    """
    if timeout < 0:
        raise ValueError("timeout must be non-negative")
    if port <= 0 or port > 65535:
        raise ValueError("port must be in 1..65535")
    if connect_timeout <= 0 or read_timeout <= 0 or retry_delay < 0:
        raise ValueError("per-attempt timeouts must be positive")

    deadline = time.monotonic() + timeout
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return False
        try:
            with socket.create_connection(
                (host, port), timeout=min(connect_timeout, remaining)
            ) as sock:
                sock.settimeout(min(read_timeout, max(remaining, 0.001)))
                try:
                    data = sock.recv(256)
                except socket.timeout:
                    # The peer accepted but sent nothing.  A real protocol
                    # greeting is required unless the caller opted out.
                    if not expect_data:
                        return True
                except OSError:
                    pass
                else:
                    if data:
                        return True
                    # Immediate EOF: the proxy accepted before the backend was
                    # ready.  Retry rather than collapsing to a false negative.
        except OSError:
            pass
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return False
        time.sleep(min(retry_delay, remaining))
