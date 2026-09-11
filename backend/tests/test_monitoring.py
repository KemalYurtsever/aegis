import threading
from types import SimpleNamespace

from app.models import Device
from app.services.monitoring_service import apply_neighbor_evidence
from app.services.ping_service import PingResult


DEVICE = {
    "name": "Lab Server",
    "ip_address": "198.18.56.20",
    "device_type": "Server",
    "description": "Controlled target",
    "is_active": True,
}


def test_manual_online_check_is_persisted(client, monkeypatch):
    created = client.post("/api/devices", json=DEVICE).json()
    monkeypatch.setattr(
        "app.services.monitoring_service.check_ip",
        lambda *_args, **_kwargs: PingResult(status="ONLINE", latency_ms=2.14),
    )

    response = client.post(f"/api/devices/{created['id']}/check")

    assert response.status_code == 201
    assert response.json()["device_id"] == created["id"]
    assert response.json()["status"] == "ONLINE"
    assert response.json()["latency_ms"] == 2.14


def test_manual_offline_check_stores_null_latency(client, monkeypatch):
    created = client.post("/api/devices", json=DEVICE).json()
    monkeypatch.setattr(
        "app.services.monitoring_service.check_ip",
        lambda *_args, **_kwargs: PingResult("OFFLINE", None, "no_reply"),
    )

    response = client.post(f"/api/devices/{created['id']}/check")

    assert response.status_code == 201
    assert response.json()["status"] == "OFFLINE"
    assert response.json()["latency_ms"] is None


def test_manual_check_unknown_device_returns_404(client):
    assert client.post("/api/devices/999/check").status_code == 404


def test_monitoring_does_not_probe_legacy_broadcast_inventory_target(client, monkeypatch):
    with client.app.state.session_factory() as db:
        device = Device(
            name="Legacy broadcast entry",
            ip_address="198.19.7.255",
            mac_address="FF:FF:FF:FF:FF:FF",
            inventory_source="DISCOVERY",
        )
        db.add(device)
        db.commit()
        device_id = device.id

    monkeypatch.setattr(
        "app.services.monitoring_service.check_ip",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("invalid target was probed")),
    )

    response = client.post(f"/api/devices/{device_id}/check")

    assert response.status_code == 201
    assert response.json()["status"] == "OFFLINE"


def test_check_all_checks_only_active_devices(client, monkeypatch):
    first = client.post("/api/devices", json=DEVICE).json()
    second_payload = {**DEVICE, "name": "Offline host", "ip_address": "198.18.56.21"}
    second = client.post("/api/devices", json=second_payload).json()
    inactive_payload = {**DEVICE, "name": "Inactive host", "ip_address": "198.18.56.22", "is_active": False}
    inactive = client.post("/api/devices", json=inactive_payload).json()
    monkeypatch.setattr(
        "app.services.monitoring_service.check_ip",
        lambda ip, *_args: PingResult("ONLINE", 1.5) if ip == first["ip_address"] else PingResult("OFFLINE", None, "no_reply"),
    )

    response = client.post("/api/devices/check-all")

    assert response.status_code == 201
    assert response.json()["checked_devices"] == 2
    assert response.json()["online_devices"] == 1
    assert response.json()["offline_devices"] == 1
    assert {result["device_id"] for result in response.json()["results"]} == {first["id"], second["id"]}
    assert client.get(f"/api/devices/{inactive['id']}/history").json() == []


def test_check_all_with_no_active_devices_returns_empty_summary(client):
    response = client.post("/api/devices/check-all")

    assert response.status_code == 201
    assert response.json() == {
        "checked_devices": 0,
        "online_devices": 0,
        "offline_devices": 0,
        "results": [],
    }


def test_check_all_probes_devices_concurrently(client, monkeypatch):
    devices = []
    for index in range(3):
        response = client.post("/api/devices", json={
            **DEVICE,
            "name": f"Concurrent host {index}",
            "ip_address": f"192.168.56.{30 + index}",
        })
        devices.append(response.json())

    started = threading.Barrier(len(devices))

    def concurrent_probe(_address, *_args, **_kwargs):
        started.wait(timeout=1.0)
        return PingResult("ONLINE", 1.0)

    monkeypatch.setattr("app.services.monitoring_service.check_ip", concurrent_probe)
    response = client.post("/api/devices/check-all")

    assert response.status_code == 201
    assert response.json()["checked_devices"] == len(devices)


def test_matching_neighbor_evidence_marks_ping_blocking_device_online(monkeypatch):
    monkeypatch.setattr(
        "app.services.discovery_service.read_windows_arp_table",
        lambda: {"198.18.56.44": "AA:BB:CC:DD:EE:44"},
    )

    results = apply_neighbor_evidence(
        [SimpleNamespace(ip_address="198.18.56.44", mac_address="AA:BB:CC:DD:EE:44")],
        [PingResult("OFFLINE", None, "no_reply")],
    )

    assert results == [PingResult("ONLINE", None, "neighbor_cache")]
