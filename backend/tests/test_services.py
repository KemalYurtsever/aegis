from app.services.port_scan_service import OpenPort, PortScanResult
from app.services.service_check_service import ServiceProbeResult


DEVICE = {
    "name": "Web Host", "ip_address": "198.18.56.60", "device_type": "Server",
    "description": None, "is_active": True,
}


def test_service_check_crud_run_and_history(client, admin_headers, monkeypatch):
    device = client.post("/api/devices", json=DEVICE, headers=admin_headers).json()
    created = client.post(
        f"/api/devices/{device['id']}/service-checks",
        headers=admin_headers,
        json={"name": "Web API", "check_type": "HTTP", "port": 8080, "path": "/health", "is_active": True},
    )
    assert created.status_code == 201
    check = created.json()
    assert check["current_status"] == "UNKNOWN"

    monkeypatch.setattr(
        "app.services.service_check_service.probe_service",
        lambda _check: ServiceProbeResult("UP", 12.5, 200),
    )
    result = client.post(f"/api/service-checks/{check['id']}/run", headers=admin_headers)
    assert result.status_code == 201
    assert result.json()["status"] == "UP"
    assert result.json()["http_status_code"] == 200

    listed = client.get(f"/api/devices/{device['id']}/service-checks", headers=admin_headers).json()
    assert listed[0]["current_status"] == "UP"
    assert listed[0]["last_response_time_ms"] == 12.5
    assert len(client.get(f"/api/service-checks/{check['id']}/history", headers=admin_headers).json()) == 1

    updated = client.put(
        f"/api/service-checks/{check['id']}",
        headers=admin_headers,
        json={"name": "HTTPS API", "check_type": "HTTPS", "port": 443, "path": "/", "is_active": False},
    )
    assert updated.status_code == 200
    assert updated.json()["port"] == 443
    assert updated.json()["is_active"] is False

    assert client.delete(f"/api/service-checks/{check['id']}", headers=admin_headers).status_code == 204
    assert client.get(f"/api/service-checks/{check['id']}/history", headers=admin_headers).status_code == 404


def test_service_check_validation(client, admin_headers):
    device = client.post("/api/devices", json=DEVICE, headers=admin_headers).json()
    response = client.post(
        f"/api/devices/{device['id']}/service-checks",
        headers=admin_headers,
        json={"name": "Bad", "check_type": "HTTP", "port": 70000, "path": "//external", "is_active": True},
    )
    assert response.status_code == 422


def test_nmap_top_port_scan_returns_open_ports(client, admin_headers, monkeypatch):
    device = client.post("/api/devices", json=DEVICE, headers=admin_headers).json()
    monkeypatch.setattr(
        "app.routers.services.scan_nmap_top_tcp_ports",
        lambda target: PortScanResult(
            scanned_ports=list(range(1, 1001)),
            open_ports=[OpenPort(port=22, service="ssh", response_time_ms=None)],
            scanner="Nmap top ports",
            duration_ms=1250.0,
        ),
    )

    response = client.post(f"/api/devices/{device['id']}/scan-ports", headers=admin_headers)

    assert response.status_code == 200
    assert response.json()["target_ip"] == DEVICE["ip_address"]
    assert response.json()["scanned_port_count"] == 1000
    assert response.json()["scanner"] == "Nmap top ports"
    assert response.json()["duration_ms"] == 1250.0
    assert response.json()["open_ports"] == [{"port": 22, "service": "ssh", "response_time_ms": None}]


def test_common_port_scan_allows_any_registered_lab_target(client, admin_headers, monkeypatch):
    public_device = client.post(
        "/api/devices",
        headers=admin_headers, json={**DEVICE, "name": "Building host", "ip_address": "198.19.4.14"},
    ).json()
    monkeypatch.setattr(
        "app.routers.services.scan_nmap_top_tcp_ports",
        lambda _target: PortScanResult([], [], "Socket fallback", 1.0),
    )

    response = client.post(f"/api/devices/{public_device['id']}/scan-ports", headers=admin_headers)

    assert response.status_code == 200
    assert response.json()["target_ip"] == "198.19.4.14"


def test_common_port_scan_requires_admin(client, admin_headers):
    public_device = client.post(
        "/api/devices",
        headers=admin_headers, json={**DEVICE, "name": "Unrelated public host", "ip_address": "8.8.8.8"},
    ).json()
    response = client.post(f"/api/devices/{public_device['id']}/scan-ports")

    assert response.status_code == 401


def test_operator_cannot_configure_or_run_network_service_probes(client, admin_headers):
    device = client.post("/api/devices", json=DEVICE, headers=admin_headers).json()
    check = client.post(
        f"/api/devices/{device['id']}/service-checks",
        headers=admin_headers,
        json={"name": "SSH", "check_type": "TCP", "port": 22, "path": "/", "is_active": True},
    ).json()
    created = client.post(
        "/api/auth/users",
        headers=admin_headers,
        json={"username": "probe-operator", "password": "operator-password-is-long", "role": "OPERATOR"},
    )
    assert created.status_code == 201
    login = client.post(
        "/api/auth/login",
        json={"username": "probe-operator", "password": "operator-password-is-long"},
    )
    operator_headers = {"Authorization": f"Bearer {login.json()['token']}"}

    create_response = client.post(
        f"/api/devices/{device['id']}/service-checks",
        headers=operator_headers,
        json={"name": "HTTP", "check_type": "TCP", "port": 80, "path": "/", "is_active": True},
    )
    update_response = client.put(
        f"/api/service-checks/{check['id']}",
        headers=operator_headers,
        json={"name": "HTTP", "check_type": "TCP", "port": 80, "path": "/", "is_active": True},
    )
    run_response = client.post(f"/api/service-checks/{check['id']}/run", headers=operator_headers)

    assert create_response.status_code == 403
    assert update_response.status_code == 403
    assert run_response.status_code == 403
    assert client.delete(f"/api/service-checks/{check['id']}", headers=operator_headers).status_code == 403
    assert len(client.get(f"/api/devices/{device['id']}/service-checks", headers=admin_headers).json()) == 1


def test_service_statistics_calculate_availability_and_response_time(client, admin_headers, monkeypatch):
    device = client.post("/api/devices", json=DEVICE, headers=admin_headers).json()
    check = client.post(
        f"/api/devices/{device['id']}/service-checks",
        headers=admin_headers,
        json={"name": "SSH", "check_type": "TCP", "port": 22, "path": "/", "is_active": True},
    ).json()
    results = iter([ServiceProbeResult("UP", 10.0), ServiceProbeResult("DOWN", None, diagnostic_reason="timeout"), ServiceProbeResult("UP", 20.0)])
    monkeypatch.setattr("app.services.service_check_service.probe_service", lambda _check: next(results))
    for _ in range(3):
        client.post(f"/api/service-checks/{check['id']}/run", headers=admin_headers)

    response = client.get(f"/api/service-checks/{check['id']}/statistics", headers=admin_headers)

    assert response.status_code == 200
    body = response.json()
    assert body["total_checks"] == 3
    assert body["up_checks"] == 2
    assert body["down_checks"] == 1
    assert body["availability_percent"] == 66.67
    assert body["average_response_time_ms"] == 15.0
    assert body["current_status"] == "UP"
    assert body["last_checked_at"] is not None


def test_empty_service_statistics_are_unknown(client, admin_headers):
    device = client.post("/api/devices", json=DEVICE, headers=admin_headers).json()
    check = client.post(
        f"/api/devices/{device['id']}/service-checks",
        headers=admin_headers,
        json={"name": "SSH", "check_type": "TCP", "port": 22, "path": "/", "is_active": True},
    ).json()

    response = client.get(f"/api/service-checks/{check['id']}/statistics", headers=admin_headers)

    assert response.status_code == 200
    assert response.json() == {
        "service_check_id": check["id"], "total_checks": 0, "up_checks": 0, "down_checks": 0,
        "availability_percent": None, "average_response_time_ms": None,
        "current_status": "UNKNOWN", "last_checked_at": None,
    }


def test_service_overview_prioritizes_failures_and_counts_active_checks(client, admin_headers, monkeypatch):
    first = client.post("/api/devices", json=DEVICE, headers=admin_headers).json()
    second = client.post(
        "/api/devices",
        headers=admin_headers,
        json={**DEVICE, "name": "Database Host", "ip_address": "198.18.56.61"},
    ).json()
    up_check = client.post(
        f"/api/devices/{first['id']}/service-checks",
        headers=admin_headers,
        json={"name": "Web API", "check_type": "HTTP", "port": 8080, "path": "/health", "is_active": True},
    ).json()
    down_check = client.post(
        f"/api/devices/{second['id']}/service-checks",
        headers=admin_headers,
        json={"name": "Database", "check_type": "TCP", "port": 5432, "path": "/", "is_active": True},
    ).json()
    client.post(
        f"/api/devices/{second['id']}/service-checks",
        headers=admin_headers,
        json={"name": "Paused", "check_type": "TCP", "port": 9000, "path": "/", "is_active": False},
    )
    results = iter([
        ServiceProbeResult("UP", 8.5, 200),
        ServiceProbeResult("DOWN", None, diagnostic_reason="connection refused"),
    ])
    monkeypatch.setattr("app.services.service_check_service.probe_service", lambda _check: next(results))
    client.post(f"/api/service-checks/{up_check['id']}/run", headers=admin_headers)
    client.post(f"/api/service-checks/{down_check['id']}/run", headers=admin_headers)

    response = client.get("/api/service-checks/overview", headers=admin_headers)

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
