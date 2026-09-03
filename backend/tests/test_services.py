from types import SimpleNamespace

from app.services.discovery_service import LocalNetwork
from app.services.port_scan_service import COMMON_TCP_PORTS, OpenPort
from app.services.service_check_service import ServiceProbeResult


DEVICE = {
    "name": "Web Host", "ip_address": "198.18.56.60", "device_type": "Server",
    "description": None, "is_active": True,
}


def test_service_check_crud_run_and_history(client, monkeypatch):
    device = client.post("/api/devices", json=DEVICE).json()
    created = client.post(
        f"/api/devices/{device['id']}/service-checks",
        json={"name": "Web API", "check_type": "HTTP", "port": 8080, "path": "/health", "is_active": True},
    )
    assert created.status_code == 201
    check = created.json()
    assert check["current_status"] == "UNKNOWN"

    monkeypatch.setattr(
        "app.services.service_check_service.probe_service",
        lambda _check: ServiceProbeResult("UP", 12.5, 200),
    )
    result = client.post(f"/api/service-checks/{check['id']}/run")
    assert result.status_code == 201
    assert result.json()["status"] == "UP"
    assert result.json()["http_status_code"] == 200

    listed = client.get(f"/api/devices/{device['id']}/service-checks").json()
    assert listed[0]["current_status"] == "UP"
    assert listed[0]["last_response_time_ms"] == 12.5
    assert len(client.get(f"/api/service-checks/{check['id']}/history").json()) == 1

    updated = client.put(
        f"/api/service-checks/{check['id']}",
        json={"name": "HTTPS API", "check_type": "HTTPS", "port": 443, "path": "/", "is_active": False},
    )
    assert updated.status_code == 200
    assert updated.json()["port"] == 443
    assert updated.json()["is_active"] is False

    assert client.delete(f"/api/service-checks/{check['id']}").status_code == 204
    assert client.get(f"/api/service-checks/{check['id']}/history").status_code == 404


def test_service_check_validation(client):
    device = client.post("/api/devices", json=DEVICE).json()
    response = client.post(
        f"/api/devices/{device['id']}/service-checks",
        json={"name": "Bad", "check_type": "HTTP", "port": 70000, "path": "//external", "is_active": True},
    )
    assert response.status_code == 422


def test_common_port_scan_is_bounded_and_returns_open_ports(client, monkeypatch):
    device = client.post("/api/devices", json=DEVICE).json()
    monkeypatch.setattr(
        "app.routers.services.scan_common_tcp_ports",
        lambda target: [OpenPort(port=22, service="SSH", response_time_ms=1.25)],
    )

    response = client.post(f"/api/devices/{device['id']}/scan-ports")

    assert response.status_code == 200
    assert response.json()["target_ip"] == DEVICE["ip_address"]
    assert response.json()["scanned_ports"] == list(COMMON_TCP_PORTS)
    assert response.json()["open_ports"] == [{"port": 22, "service": "SSH", "response_time_ms": 1.25}]


def test_common_port_scan_allows_registered_target_on_authorized_public_lan(client, monkeypatch):
    public_device = client.post(
        "/api/devices",
        json={**DEVICE, "name": "Building host", "ip_address": "198.19.4.14"},
    ).json()
    monkeypatch.setattr(
        "app.services.scan_policy.get_settings",
        lambda: SimpleNamespace(allow_public_lan_discovery=True, authorized_lab_mode=False),
    )
    monkeypatch.setattr(
        "app.services.scan_policy.get_primary_private_network",
        lambda: LocalNetwork("Wi-Fi", "8.8.8.8", "198.19.4.0/24", "198.19.4.1"),
    )
    monkeypatch.setattr("app.routers.services.scan_common_tcp_ports", lambda _target: [])

    response = client.post(f"/api/devices/{public_device['id']}/scan-ports")

    assert response.status_code == 200
    assert response.json()["target_ip"] == "198.19.4.14"


def test_common_port_scan_rejects_public_target_outside_authorized_lan(client, monkeypatch):
    public_device = client.post(
        "/api/devices",
        json={**DEVICE, "name": "Unrelated public host", "ip_address": "8.8.8.8"},
    ).json()
    monkeypatch.setattr(
        "app.services.scan_policy.get_settings",
        lambda: SimpleNamespace(allow_public_lan_discovery=True, authorized_lab_mode=False),
    )
    monkeypatch.setattr(
        "app.services.scan_policy.get_primary_private_network",
        lambda: LocalNetwork("Wi-Fi", "8.8.8.8", "198.19.4.0/24", "198.19.4.1"),
    )

    response = client.post(f"/api/devices/{public_device['id']}/scan-ports")

    assert response.status_code == 400
    assert response.json()["detail"] == "Scanning is restricted to the connected authorized LAN"


def test_service_statistics_calculate_availability_and_response_time(client, monkeypatch):
    device = client.post("/api/devices", json=DEVICE).json()
    check = client.post(
        f"/api/devices/{device['id']}/service-checks",
        json={"name": "SSH", "check_type": "TCP", "port": 22, "path": "/", "is_active": True},
    ).json()
    results = iter([ServiceProbeResult("UP", 10.0), ServiceProbeResult("DOWN", None, diagnostic_reason="timeout"), ServiceProbeResult("UP", 20.0)])
    monkeypatch.setattr("app.services.service_check_service.probe_service", lambda _check: next(results))
    for _ in range(3):
        client.post(f"/api/service-checks/{check['id']}/run")

    response = client.get(f"/api/service-checks/{check['id']}/statistics")

    assert response.status_code == 200
    body = response.json()
    assert body["total_checks"] == 3
    assert body["up_checks"] == 2
    assert body["down_checks"] == 1
    assert body["availability_percent"] == 66.67
    assert body["average_response_time_ms"] == 15.0
    assert body["current_status"] == "UP"
    assert body["last_checked_at"] is not None


def test_empty_service_statistics_are_unknown(client):
    device = client.post("/api/devices", json=DEVICE).json()
    check = client.post(
        f"/api/devices/{device['id']}/service-checks",
        json={"name": "SSH", "check_type": "TCP", "port": 22, "path": "/", "is_active": True},
    ).json()

    response = client.get(f"/api/service-checks/{check['id']}/statistics")

    assert response.status_code == 200
    assert response.json() == {
        "service_check_id": check["id"], "total_checks": 0, "up_checks": 0, "down_checks": 0,
        "availability_percent": None, "average_response_time_ms": None,
        "current_status": "UNKNOWN", "last_checked_at": None,
    }


def test_service_overview_prioritizes_failures_and_counts_active_checks(client, monkeypatch):
    first = client.post("/api/devices", json=DEVICE).json()
    second = client.post(
        "/api/devices",
        json={**DEVICE, "name": "Database Host", "ip_address": "198.18.56.61"},
    ).json()
    up_check = client.post(
        f"/api/devices/{first['id']}/service-checks",
        json={"name": "Web API", "check_type": "HTTP", "port": 8080, "path": "/health", "is_active": True},
    ).json()
    down_check = client.post(
        f"/api/devices/{second['id']}/service-checks",
        json={"name": "Database", "check_type": "TCP", "port": 5432, "path": "/", "is_active": True},
    ).json()
    client.post(
        f"/api/devices/{second['id']}/service-checks",
        json={"name": "Paused", "check_type": "TCP", "port": 9000, "path": "/", "is_active": False},
    )
    results = iter([
        ServiceProbeResult("UP", 8.5, 200),
        ServiceProbeResult("DOWN", None, diagnostic_reason="connection refused"),
    ])
    monkeypatch.setattr("app.services.service_check_service.probe_service", lambda _check: next(results))
    client.post(f"/api/service-checks/{up_check['id']}/run")
    client.post(f"/api/service-checks/{down_check['id']}/run")

    response = client.get("/api/service-checks/overview")

    assert response.status_code == 200
    overview = response.json()
    assert overview["total_services"] == 3
    assert overview["active_services"] == 2
    assert overview["up_services"] == 1
    assert overview["down_services"] == 1
    assert overview["unknown_services"] == 0
    assert overview["services"][0]["name"] == "Database"
    assert overview["services"][0]["current_status"] == "DOWN"
    assert overview["services"][0]["diagnostic_reason"] == "connection refused"
    assert overview["services"][-1]["is_active"] is False
