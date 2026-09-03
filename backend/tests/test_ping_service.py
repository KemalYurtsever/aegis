import subprocess

from app.services.ping_service import build_ping_command, check_ip, parse_latency


def test_builds_safe_windows_command():
    assert build_ping_command("192.168.56.20", 2, "Windows") == [
        "ping", "-n", "1", "-w", "2000", "192.168.56.20"
    ]


def test_builds_safe_linux_command():
    assert build_ping_command("2001:0db8::1", 1.2, "Linux") == [
        "ping", "-c", "1", "-W", "2", "2001:db8::1"
    ]


def test_parses_windows_and_unix_latency():
    assert parse_latency("Reply from 127.0.0.1: time<1ms TTL=128") == 0.5
    assert parse_latency("64 bytes from host: time=2.14 ms") == 2.14


def test_successful_check_uses_shell_false(monkeypatch):
    captured = {}

    def fake_run(command, **kwargs):
        captured["command"] = command
        captured["kwargs"] = kwargs
        return subprocess.CompletedProcess(command, 0, stdout="Reply time=1ms", stderr="")

    monkeypatch.setattr("app.services.ping_service.subprocess.run", fake_run)
    result = check_ip("127.0.0.1")

    assert result.status == "ONLINE"
    assert result.latency_ms == 1.0
    assert captured["kwargs"]["shell"] is False
    assert isinstance(captured["command"], list)


def test_timeout_is_offline(monkeypatch):
    def fake_run(command, **_kwargs):
        raise subprocess.TimeoutExpired(command, timeout=3)

    monkeypatch.setattr("app.services.ping_service.subprocess.run", fake_run)
    result = check_ip("192.0.2.1")

    assert result.status == "OFFLINE"
    assert result.latency_ms is None
    assert result.diagnostic_reason == "process_timeout"
