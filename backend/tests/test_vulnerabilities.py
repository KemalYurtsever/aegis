from types import SimpleNamespace

from app.services.discovery_service import LocalNetwork
from app.services.port_scan_service import OpenPort
from app.services.vulnerability_service import TlsPosture

DEVICE = {"name": "Lab server", "ip_address": "198.18.1.50", "device_type": "Server", "is_active": True}


def admin_headers(client):
    response = client.post(
        "/api/auth/setup",
        json={"username": "scan-admin", "password": "correct-horse-battery-staple"},
    )
    assert response.status_code == 201
    client.app.state.auth_required = True
    return {"Authorization": f"Bearer {response.json()['token']}"}


def test_defensive_scan_records_service_and_header_findings(client, monkeypatch):
    headers = admin_headers(client)
    device = client.post("/api/devices", json=DEVICE, headers=headers).json()
    monkeypatch.setattr("app.services.vulnerability_service.scan_common_tcp_ports", lambda _ip: [OpenPort(445, "SMB", 1.0), OpenPort(80, "HTTP", 1.2)])
    monkeypatch.setattr("app.services.vulnerability_service._http_headers", lambda *_args: {"server": "test"})
    response = client.post(f"/api/devices/{device['id']}/vulnerability-scans", headers=headers)
    assert response.status_code == 201
    body = response.json()
    assert body["status"] == "COMPLETED"
    assert any(item["severity"] == "HIGH" and item["port"] == 445 for item in body["findings"])
    assert sum(item["category"] == "HTTP_HEADER" for item in body["findings"]) == 3
    assert client.get(f"/api/devices/{device['id']}/vulnerability-scans", headers=headers).json()[0]["id"] == body["id"]


def test_scan_with_no_common_ports_records_positive_information(client, monkeypatch):
    headers = admin_headers(client)
    device = client.post("/api/devices", json=DEVICE, headers=headers).json()
    monkeypatch.setattr("app.services.vulnerability_service.scan_common_tcp_ports", lambda _ip: [])
    body = client.post(f"/api/devices/{device['id']}/vulnerability-scans", headers=headers).json()
    assert body["findings"][0]["severity"] == "INFO"


def test_scan_allows_registered_target_on_authorized_public_lan(client, monkeypatch):
    headers = admin_headers(client)
    device = client.post("/api/devices", json={**DEVICE, "ip_address": "198.19.4.14"}, headers=headers).json()
    monkeypatch.setattr(
        "app.services.scan_policy.get_settings",
        lambda: SimpleNamespace(allow_public_lan_discovery=True, authorized_lab_mode=False),
    )
    monkeypatch.setattr(
        "app.services.scan_policy.get_primary_private_network",
        lambda: LocalNetwork("Wi-Fi", "198.19.4.125", "198.19.4.0/24", "198.19.4.1"),
    )
    monkeypatch.setattr("app.services.vulnerability_service.scan_common_tcp_ports", lambda _ip: [])

    response = client.post(f"/api/devices/{device['id']}/vulnerability-scans", headers=headers)

    assert response.status_code == 201
    assert response.json()["status"] == "COMPLETED"


def test_scan_rejects_public_target_outside_authorized_lan(client, monkeypatch):
    headers = admin_headers(client)
    device = client.post("/api/devices", json={**DEVICE, "ip_address": "8.8.8.8"}, headers=headers).json()
    monkeypatch.setattr(
        "app.services.scan_policy.get_settings",
        lambda: SimpleNamespace(allow_public_lan_discovery=True, authorized_lab_mode=False),
    )
    monkeypatch.setattr(
        "app.services.scan_policy.get_primary_private_network",
        lambda: LocalNetwork("Wi-Fi", "198.19.4.125", "198.19.4.0/24", "198.19.4.1"),
    )

    response = client.post(f"/api/devices/{device['id']}/vulnerability-scans", headers=headers)

    assert response.status_code == 400
    assert response.json()["detail"] == "Vulnerability scanning is restricted to the connected authorized LAN"


def test_authorized_lab_mode_allows_registered_target_outside_connected_lan(client, monkeypatch):
    headers = admin_headers(client)
    device = client.post("/api/devices", json={**DEVICE, "ip_address": "203.0.113.25"}, headers=headers).json()
    monkeypatch.setattr(
        "app.services.scan_policy.get_settings",
        lambda: SimpleNamespace(allow_public_lan_discovery=True, authorized_lab_mode=True),
    )
    monkeypatch.setattr("app.services.vulnerability_service.scan_common_tcp_ports", lambda _ip: [])

    response = client.post(f"/api/devices/{device['id']}/vulnerability-scans", headers=headers)

    assert response.status_code == 201


def test_attack_surface_scan_records_banner_version_and_tls_posture(client, monkeypatch):
    headers = admin_headers(client)
    device = client.post("/api/devices", json=DEVICE, headers=headers).json()
    monkeypatch.setattr(
        "app.services.vulnerability_service.scan_common_tcp_ports",
        lambda _ip: [OpenPort(22, "SSH", 1.0), OpenPort(443, "HTTPS", 1.2)],
    )
    monkeypatch.setattr(
        "app.services.vulnerability_service._service_banner",
        lambda *_args: "SSH-2.0-OpenSSH_9.3",
    )
    monkeypatch.setattr(
        "app.services.vulnerability_service._http_headers",
        lambda *_args: {
            "server": "nginx/1.24.0",
            "x-content-type-options": "nosniff",
            "x-frame-options": "DENY",
            "content-security-policy": "default-src 'none'",
        },
    )
    monkeypatch.setattr(
        "app.services.vulnerability_service._tls_posture",
        lambda *_args: TlsPosture(
            protocol="TLSv1",
            cipher="AES256-SHA",
            certificate_sha256="a" * 64,
            certificate_verified=False,
            verification_error="self-signed certificate",
        ),
    )

    response = client.post(
        f"/api/devices/{device['id']}/vulnerability-scans", headers=headers
    )

    assert response.status_code == 201
    categories = {finding["category"] for finding in response.json()["findings"]}
    assert {
        "SERVICE_BANNER",
        "VERSION_DISCLOSURE",
        "TLS_POSTURE",
        "TLS_PROTOCOL",
        "TLS_CERTIFICATE",
    } <= categories


def test_attack_surface_scan_is_admin_only(client):
    headers = admin_headers(client)
    device = client.post("/api/devices", json=DEVICE, headers=headers).json()
    created = client.post(
        "/api/auth/users",
        headers=headers,
        json={
            "username": "scan-operator",
            "password": "operator-password-is-long",
            "role": "OPERATOR",
        },
    )
    assert created.status_code == 201
    login = client.post(
        "/api/auth/login",
        json={"username": "scan-operator", "password": "operator-password-is-long"},
    )

    response = client.post(
        f"/api/devices/{device['id']}/vulnerability-scans",
        headers={"Authorization": f"Bearer {login.json()['token']}"},
    )

    assert response.status_code == 403
    history = client.get(
        f"/api/devices/{device['id']}/vulnerability-scans",
        headers={"Authorization": f"Bearer {login.json()['token']}"},
    )
    assert history.status_code == 200


def test_attack_surface_comparison_tracks_new_and_resolved_findings(client, monkeypatch):
    headers = admin_headers(client)
    device = client.post("/api/devices", json=DEVICE, headers=headers).json()
    results = iter([[OpenPort(23, "Telnet", 1.0)], []])
    monkeypatch.setattr(
        "app.services.vulnerability_service.scan_common_tcp_ports",
        lambda _ip: next(results),
    )
    monkeypatch.setattr(
        "app.services.vulnerability_service._service_banner",
        lambda *_args: None,
    )

    first = client.post(
        f"/api/devices/{device['id']}/vulnerability-scans", headers=headers
    ).json()
    baseline = client.get(
        f"/api/devices/{device['id']}/vulnerability-scans/comparison", headers=headers
    ).json()
    assert baseline["current_scan_id"] == first["id"]
    assert baseline["previous_scan_id"] is None
    assert baseline["risk_score"] == 40
    assert [item["title"] for item in baseline["new_findings"]] == ["Telnet service exposed"]

    second = client.post(
        f"/api/devices/{device['id']}/vulnerability-scans", headers=headers
    ).json()
    comparison = client.get(
        f"/api/devices/{device['id']}/vulnerability-scans/comparison", headers=headers
    ).json()
    assert comparison["current_scan_id"] == second["id"]
    assert comparison["previous_scan_id"] == first["id"]
    assert comparison["risk_score"] == 0
    assert comparison["new_findings"] == []
    assert [item["title"] for item in comparison["resolved_findings"]] == [
        "Telnet service exposed"
    ]
