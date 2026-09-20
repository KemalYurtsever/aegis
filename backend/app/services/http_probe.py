"""Small HTTP probes with a cumulative I/O deadline, not an idle timeout."""
import http.client
import io
import math
import socket
import time
from contextlib import contextmanager


def _remaining(deadline: float) -> float:
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise TimeoutError("HTTP probe deadline exceeded")
    return remaining


class _DeadlineReader(io.RawIOBase):
    def __init__(self, sock, deadline):
        super().__init__()
        self._socket = sock
        self._deadline = deadline
        # Retain the real makefile's socket reference. HTTPConnection may
        # close/relinquish its socket before a Connection: close body is read.
        self._raw = sock.makefile("rb", buffering=0)

    def readable(self):
        return True

    def readinto(self, buffer):
        self._socket.settimeout(_remaining(self._deadline))
        return self._raw.readinto(buffer)

    def close(self):
        try:
            self._raw.close()
        finally:
            super().close()


class _DeadlineSocket:
    def __init__(self, sock, deadline):
        self._socket = sock
        self._deadline = deadline

    def __getattr__(self, name):
        return getattr(self._socket, name)

    def sendall(self, data):
        self._socket.settimeout(_remaining(self._deadline))
        return self._socket.sendall(data)

    def makefile(self, mode, buffering=None):
        if mode != "rb":
            raise ValueError("HTTP probe only supports a binary response reader")
        return io.BufferedReader(_DeadlineReader(self._socket, self._deadline))


@contextmanager
def bounded_http_response(host, port, *, secure=False, context=None,
                          method="GET", path="/", headers=None, timeout_seconds=3.0):
    """For literal registered IPs; no redirects, proxy, body upload or retries.

    Both TLS handshake and every buffered status/header/body receive consume
    the same budget. No abandoned worker or watchdog thread is created.
    """
    if not math.isfinite(timeout_seconds) or timeout_seconds <= 0:
        raise ValueError("HTTP probe timeout must be finite and positive")
    deadline = time.monotonic() + timeout_seconds
    connection_class = http.client.HTTPSConnection if secure else http.client.HTTPConnection
    kwargs = {"context": context} if secure else {}
    connection = connection_class(host, port, timeout=_remaining(deadline), **kwargs)
    response = None

    def connect_with_budget(address, timeout, source_address=None):
        sock = socket.create_connection(address, timeout=_remaining(deadline), source_address=source_address)
        try:
            # HTTPSConnection wraps this socket next. SSL's handshake timeout
            # uses the remaining total budget, not the original idle timeout.
            sock.settimeout(_remaining(deadline))
            return sock
        except BaseException:
            sock.close()
            raise

    # HTTPConnection's connection factory is the narrow shared TCP/TLS hook.
    connection._create_connection = connect_with_budget
    try:
        connection.connect()
        connection.sock = _DeadlineSocket(connection.sock, deadline)
        connection.request(method, path, headers=headers or {})
        response = connection.getresponse()
        yield response
    finally:
        if response is not None:
            response.close()
        connection.close()
