from app.services.port_scan_service import OpenPort


def admin_headers(client):
    response = client.post(
        "/api/auth/setup",
        json={"username": "path-admin", "password": "correct-horse-battery-staple"},
    )
    assert response.status_code == 201
    client.app.state.auth_required = True
    return {"Authorization": f"Bearer {response.json()['token']}"}


def create_device(client, headers, name, address, criticality="MEDIUM"):
    response = client.post(
        "/api/devices",
        headers=headers,
        json={
            "name": name,
            "ip_address": address,
            "device_type": "Server",
            "criticality": criticality,
            "device_group": "Production lab",
            "is_active": True,
        },
    )
    assert response.status_code == 201
    return response.json()


def test_attack_path_overview_has_clear_empty_state(client):
    headers = admin_headers(client)

    response = client.get("/api/security/attack-paths", headers=headers)

    assert response.status_code == 200
    assert response.json()["assessed_devices"] == 0
    assert response.json()["candidate_paths"] == 0
    assert response.json()["paths"] == []


def test_attack_paths_correlate_entry_exposure_with_critical_asset(client, monkeypatch):
    headers = admin_headers(client)
    entry = create_device(client, headers, "Remote gateway", "198.18.77.10")
    target = create_device(
        client, headers, "Domain controller", "198.18.77.20", criticality="CRITICAL"
    )
    monkeypatch.setattr(
        "app.services.vulnerability_service.scan_common_tcp_ports",
        lambda _ip: [OpenPort(3389, "RDP", 1.0)],
    )

    scan = client.post(
        f"/api/devices/{entry['id']}/vulnerability-scans", headers=headers
    )
    response = client.get("/api/security/attack-paths", headers=headers)

    assert scan.status_code == 201
    assert response.status_code == 200
    body = response.json()
    assert body["assessed_devices"] == 1
    assert body["candidate_paths"] == 1
    path = body["paths"][0]
    assert path["entry_device_id"] == entry["id"]
    assert path["target_device_id"] == target["id"]
    assert path["entry_port"] == 3389
    assert path["severity"] == "CRITICAL"
    assert "shared device group Production lab" in path["rationale"]


def test_attack_path_overview_is_admin_only(client):
    headers = admin_headers(client)
    created = client.post(
        "/api/auth/users",
        headers=headers,
        json={
            "username": "path-operator",
            "password": "operator-password-is-long",
            "role": "OPERATOR",
        },
    )
    assert created.status_code == 201
    login = client.post(
        "/api/auth/login",
        json={"username": "path-operator", "password": "operator-password-is-long"},
    )

    response = client.get(
        "/api/security/attack-paths",
        headers={"Authorization": f"Bearer {login.json()['token']}"},
    )

    assert response.status_code == 403
