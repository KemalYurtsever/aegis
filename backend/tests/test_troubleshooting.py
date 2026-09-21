from types import SimpleNamespace

from app.services.ping_service import PingResult
from app.services.service_check_service import ServiceProbeResult


def test_troubleshooting_records_ordered_evidence_without_claiming_a_root_cause(client, admin_headers, monkeypatch):
    device = client.post("/api/devices", headers=admin_headers, json={
        "name": "Lab web server", "ip_address": "198.18.60.20",
        "prefix_length": 26, "gateway_ip": "198.18.60.1", "vlan": "LAB-60",
    }).json()
    check = client.post(f"/api/devices/{device['id']}/service-checks", headers=admin_headers, json={
        "name": "Web", "check_type": "HTTP", "port": 8080,
    }).json()
    monkeypatch.setattr("app.routers.troubleshooting.check_ip", lambda address, **_kwargs:
        PingResult("ONLINE" if address.endswith(".1") else "OFFLINE", None, "timeout"))
    monkeypatch.setattr("app.routers.troubleshooting.query_dns", lambda _name:
        SimpleNamespace(addresses=["198.18.60.20"]))

    class Connection:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

    monkeypatch.setattr("app.routers.troubleshooting.socket.create_connection", lambda *_args, **_kwargs: Connection())
    monkeypatch.setattr("app.routers.troubleshooting.probe_service", lambda *_args, **_kwargs:
        ServiceProbeResult("UP", 3.0, http_status_code=200))

    response = client.post(f"/api/devices/{device['id']}/troubleshooting-runs", headers=admin_headers, json={
        "dns_name": "web.lab.example", "service_check_id": check["id"],
    })
    assert response.status_code == 201
    body = response.json()
    assert body["source"] == "AEGIS_HOST"
    assert body["target_ip"] == device["ip_address"]
    assert [(step["key"], step["status"]) for step in body["steps"]] == [
        ("CONFIG", "PASS"), ("GATEWAY", "PASS"), ("DNS", "PASS"),
        ("ROUTE", "SKIP"), ("TARGET", "FAIL"), ("PORT", "PASS"),
        ("SERVICE", "PASS"),
    ]
    assert "ICMP filtering" in body["steps"][4]["observation"]
    history = client.get(f"/api/devices/{device['id']}/troubleshooting-runs", headers=admin_headers)
    assert history.status_code == 200
    assert history.json()[0]["id"] == body["id"]


def test_troubleshooting_rejects_another_devices_service_before_probing(client, admin_headers, monkeypatch):
    source = client.post("/api/devices", headers=admin_headers, json={
        "name": "Source", "ip_address": "198.18.61.10",
    }).json()
    other = client.post("/api/devices", headers=admin_headers, json={
        "name": "Other", "ip_address": "198.18.61.11",
    }).json()
    check = client.post(f"/api/devices/{other['id']}/service-checks", headers=admin_headers, json={
        "name": "Web", "check_type": "TCP", "port": 443,
    }).json()
    monkeypatch.setattr("app.routers.troubleshooting.check_ip", lambda *_args, **_kwargs:
        (_ for _ in ()).throw(AssertionError("probe must not run")))
    response = client.post(f"/api/devices/{source['id']}/troubleshooting-runs", headers=admin_headers, json={
        "service_check_id": check["id"],
    })
    assert response.status_code == 404
    assert client.post(f"/api/devices/{source['id']}/troubleshooting-runs", headers=admin_headers, json={
        "dns_name": "bad name",
    }).status_code == 422


def test_troubleshooting_requires_administrator(client, admin_headers):
    device = client.post("/api/devices", headers=admin_headers, json={
        "name": "Lab target", "ip_address": "198.18.62.10",
    }).json()
    client.post("/api/auth/users", headers=admin_headers, json={
        "username": "operator-trouble", "password": "operator-correct-horse-battery-staple", "role": "OPERATOR",
    })
    token = client.post("/api/auth/login", json={
        "username": "operator-trouble", "password": "operator-correct-horse-battery-staple",
    }).json()["token"]
    headers = {"Authorization": f"Bearer {token}"}
    assert client.post(f"/api/devices/{device['id']}/troubleshooting-runs", headers=headers, json={}).status_code == 403
    assert client.get(f"/api/devices/{device['id']}/troubleshooting-runs", headers=headers).status_code == 403
