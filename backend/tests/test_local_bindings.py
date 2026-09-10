from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]


def test_hybrid_launcher_binds_every_http_service_to_loopback():
    launcher = (PROJECT_ROOT / "start-hybrid.ps1").read_text(encoding="utf-8")

    assert '"--host", "0.0.0.0"' not in launcher
    assert launcher.count('"--host", "127.0.0.1"') == 3
    assert '"--", "--host", "127.0.0.1"' in launcher
    for port in (5173, 8001, 8002, 3000, 9090):
        assert f"Assert-LoopbackListener -Port {port}" in launcher or (
            port == 8001 and "Assert-LoopbackListener -Port $backendPort" in launcher
        ) or (
            port == 8002 and "Assert-LoopbackListener -Port $agentPort" in launcher
        )


def test_docker_published_ports_are_loopback_only():
    compose = (PROJECT_ROOT / "docker-compose.yml").read_text(encoding="utf-8")
    observability = (PROJECT_ROOT / "docker-compose.observability.yml").read_text(encoding="utf-8")

    for port in (8000, 5173, 9090, 3000):
        assert f'"127.0.0.1:{port}:' in compose
    for port in (9090, 3000):
        assert f'"127.0.0.1:{port}:' in observability
    assert '"0.0.0.0:' not in compose
    assert '"0.0.0.0:' not in observability
