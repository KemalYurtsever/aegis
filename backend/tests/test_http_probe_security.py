"""Controlled loopback replies; never query the operator's network or database."""
import asyncio
import socket
import threading
import time
import shutil
import ssl
import subprocess
from pathlib import Path
from contextlib import contextmanager

import pytest

from app.models import Device, ServiceCheck
from app.scheduler import PeriodicMonitor
from app.services.service_check_service import probe_service
from app.services.vulnerability_service import _http_headers


@contextmanager
def reply_server(initial: bytes, drip: bytes = b"", delay: float = 0.02, tls_context=None):
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    listener.settimeout(2)
    port = listener.getsockname()[1]
    stop = threading.Event()

    def serve():
        try:
            connection, _ = listener.accept()
            if tls_context is not None:
                connection.settimeout(2)
                try:
                    connection = tls_context.wrap_socket(connection, server_side=True)
                except OSError:
                    connection.close()
                    return
            with connection:
                connection.settimeout(2)
                request = b""
                while b"\r\n\r\n" not in request:
                    part = connection.recv(4096)
                    if not part:
                        return
                    request += part
                connection.sendall(initial)
                for byte in drip:
                    if stop.wait(delay):
                        break
                    connection.sendall(bytes([byte]))
        except OSError:
            pass  # A timed-out probe deliberately disconnects.

    worker = threading.Thread(target=serve, daemon=True)
    worker.start()
    try:
        yield port
    finally:
        stop.set()
        listener.close()
        worker.join(timeout=3)
        assert not worker.is_alive(), "controlled reply fixture leaked a worker"


def check_for(port):
    return ServiceCheck(
        name="Synthetic HTTP", check_type="HTTP", port=port, path="/", is_active=True,
        device=Device(name="Loopback fixture", ip_address="127.0.0.1", device_type="Server"),
    )


@pytest.mark.parametrize("reply", [
    b"NOT_HTTP\r\n",
    b"HTTP/1.1 200 OK\r\n" + b"X-Test: a\r\n" * 101 + b"\r\n",
    b"HTTP/1.1 200 OK\r\nX-Test: " + b"a" * 65537 + b"\r\n\r\n",
    b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nx",
], ids=["bad-status", "too-many-headers", "long-header", "incomplete-chunk"])
def test_malformed_reply_is_a_failed_probe_not_an_exception(reply):
    with reply_server(reply) as port:
        result = probe_service(check_for(port), timeout_seconds=0.5)
    assert result.status == "DOWN"
    assert result.diagnostic_reason == "protocol_error"


@pytest.mark.parametrize("initial,drip", [
    (b"", b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"),
    (b"HTTP/1.1 200 OK\r\nX-Test: ", b"a" * 24 + b"\r\nContent-Length: 0\r\n\r\n"),
    (b"HTTP/1.1 200 OK\r\nContent-Length: 24\r\nConnection: close\r\n\r\n", b"a" * 24),
    (b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n", b"18\r\n" + b"a" * 24 + b"\r\n0\r\n\r\n"),
], ids=["status", "header", "close-body", "chunked-body"])
def test_slow_drip_has_a_total_deadline(initial, drip):
    with reply_server(initial, drip) as port:
        started = time.monotonic()
        result = probe_service(check_for(port), timeout_seconds=0.15)
        elapsed = time.monotonic() - started
    assert result.status == "DOWN"
    assert result.diagnostic_reason == "timeout"
    assert elapsed < 0.5, f"total probe deadline exceeded: {elapsed}"


@pytest.mark.parametrize("status", [200, 404, 500])
def test_valid_http_status_and_connection_close_remain_up(status):
    reply = f"HTTP/1.1 {status} Synthetic\r\nContent-Length: 4\r\nConnection: close\r\n\r\ntest".encode()
    with reply_server(reply) as port:
        result = probe_service(check_for(port), timeout_seconds=0.5)
    assert result.status == "UP"
    assert result.http_status_code == status


@pytest.mark.parametrize("initial,drip", [
    (b"", b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"),
    (b"HTTP/1.1 200 OK\r\nX-Test: ", b"a" * 24 + b"\r\n\r\n"),
], ids=["status", "header"])
def test_vulnerability_head_uses_the_same_total_deadline(initial, drip):
    with reply_server(initial, drip) as port:
        started = time.monotonic()
        with pytest.raises(TimeoutError):
            _http_headers("127.0.0.1", port, False, timeout_seconds=0.15)
        assert time.monotonic() - started < 0.5


def test_vulnerability_head_preserves_lowercase_headers():
    with reply_server(b"HTTP/1.1 200 OK\r\nServer: synthetic/1.0\r\nContent-Length: 100\r\n\r\n") as port:
        assert _http_headers("127.0.0.1", port, False, timeout_seconds=0.5)["server"] == "synthetic/1.0"


def test_monitor_batch_stores_bad_and_healthy_siblings(client):
    from sqlalchemy import select
    from app.models import ServiceResult
    from app.services.service_check_service import run_and_store_service_checks

    with reply_server(b"NOT_HTTP\r\n") as bad, reply_server(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n") as good:
        with client.app.state.session_factory() as db:
            device = Device(name="Batch fixture", ip_address="127.0.0.1", device_type="Server")
            checks = [ServiceCheck(name=name, device=device, port=port, check_type="HTTP", path="/")
                      for name, port in [("bad", bad), ("good", good)]]
            db.add_all(checks)
            db.commit()
            results = run_and_store_service_checks(checks, db)
            assert [result.status for result in results] == ["DOWN", "UP"]
            assert len(list(db.scalars(select(ServiceResult)))) == 2


def test_monitor_recovers_a_failed_cycle_and_preserves_cancellation():
    monitor = PeriodicMonitor(None, interval_seconds=0.01)
    recovered = threading.Event()
    calls = []

    def cycle():
        calls.append(True)
        if len(calls) == 1:
            raise ValueError("synthetic cycle failure")
        recovered.set()
        return 0

    monitor.run_cycle = cycle

    async def exercise():
        monitor.start()
        try:
            for _ in range(100):
                if recovered.is_set():
                    break
                await asyncio.sleep(0.01)
            assert recovered.is_set()
            assert monitor.is_running
        finally:
            await monitor.stop()
        assert not monitor.is_running

    asyncio.run(exercise())


def test_tls_verification_and_unverified_evidence_collection_are_preserved(tmp_path, monkeypatch):
    executable = shutil.which("openssl")
    if not executable:
        bundled = Path("C:/Program Files/Git/usr/bin/openssl.exe")
        executable = str(bundled) if bundled.exists() else None
    if not executable:
        pytest.skip("Local OpenSSL required to generate an ephemeral TLS fixture")
    cert, key = tmp_path / "cert.pem", tmp_path / "key.pem"
    subprocess.run([executable, "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
                    "-subj", "/CN=localhost", "-addext", "subjectAltName=IP:127.0.0.1",
                    "-keyout", str(key), "-out", str(cert)],
                   check=True, timeout=20, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_context.load_cert_chain(cert, key)
    reply = b"HTTP/1.1 200 OK\r\nServer: synthetic-tls/1.0\r\nContent-Length: 4\r\nConnection: close\r\n\r\ntest"
    with reply_server(reply, tls_context=server_context) as port:
        check = check_for(port)
        check.check_type = "HTTPS"
        assert probe_service(check, timeout_seconds=1).diagnostic_reason == "tls_error"
    with reply_server(reply, tls_context=server_context) as port:
        assert _http_headers("127.0.0.1", port, True, timeout_seconds=1)["server"] == "synthetic-tls/1.0"
    trusted_context = ssl.create_default_context(cafile=str(cert))
    monkeypatch.setattr("app.services.service_check_service.ssl.create_default_context", lambda: trusted_context)
    with reply_server(reply, tls_context=server_context) as port:
        check = check_for(port)
        check.check_type = "HTTPS"
        assert probe_service(check, timeout_seconds=1).status == "UP"
    with reply_server(b"HTTP/1.1 200 OK\r\nContent-Length: 24\r\nConnection: close\r\n\r\n", b"a" * 24,
                      tls_context=server_context) as port:
        check = check_for(port)
        check.check_type = "HTTPS"
        assert probe_service(check, timeout_seconds=0.15).diagnostic_reason == "timeout"
