from datetime import datetime, timezone
import threading

from sqlalchemy.orm import Session

from app.services import fingerprint_service
from app.services.fingerprint_service import FINGERPRINT_PORTS, FingerprintEvidence, classify_from_evidence


DEVICE = {
    "name": "Unknown device", "ip_address": "198.18.56.70", "device_type": "Other",
    "description": None, "is_active": True,
}


def test_classification_requires_strong_service_evidence():
    assert classify_from_evidence([631], None, None)[0] == "Printer"
    assert classify_from_evidence([554], None, None)[0] == "Camera"
    assert classify_from_evidence([445], None, None)[0] == "Workstation"
    assert classify_from_evidence([22], None, None)[0] == "Server"
    assert classify_from_evidence([80], None, None)[0] is None


def test_device_fingerprint_is_stored_and_classifies_other_device(client, monkeypatch):
    device = client.post("/api/devices", json=DEVICE).json()
    timestamp = datetime.now(timezone.utc)
    monkeypatch.setattr(
        "app.routers.services.fingerprint_target",
        lambda *_args: FingerprintEvidence([631, 9100], "Printer", "printing service; open TCP: 631, 9100", timestamp),
    )

    response = client.post(f"/api/devices/{device['id']}/fingerprint")

    assert response.status_code == 200
    assert response.json()["classification"] == "Printer"
    stored = client.get(f"/api/devices/{device['id']}").json()
    assert stored["device_type"] == "Printer"
    assert stored["fingerprint_ports"] == "631,9100"
    assert stored["fingerprint_summary"].startswith("printing service")


def test_fingerprint_ports_are_probed_in_one_bounded_wave(monkeypatch):
    lock = threading.Lock()
    all_started = threading.Event()
    started = 0

    def fake_connection(_target, timeout):
        nonlocal started
        assert timeout == 0.4
        with lock:
            started += 1
            if started == len(FINGERPRINT_PORTS):
                all_started.set()
        assert all_started.wait(1.0)
        raise OSError

    monkeypatch.setattr(fingerprint_service.socket, "create_connection", fake_connection)

    evidence = fingerprint_service.fingerprint_target("198.18.56.70")

    assert started == len(FINGERPRINT_PORTS)
    assert evidence.open_ports == []


def test_fingerprint_all_commits_results_once(client, monkeypatch):
    for index in range(3):
        client.post("/api/devices", json={**DEVICE, "name": f"Device {index}", "ip_address": f"192.168.56.{70 + index}"})

    timestamp = datetime.now(timezone.utc)
    monkeypatch.setattr(
        "app.routers.services.fingerprint_target",
        lambda *_args: FingerprintEvidence([], None, "No identifying service responded", timestamp),
    )
    original_commit = Session.commit
    commits = 0

    def counted_commit(session):
        nonlocal commits
        commits += 1
        return original_commit(session)

    monkeypatch.setattr(Session, "commit", counted_commit)

    response = client.post("/api/devices/fingerprint-all")

    assert response.status_code == 200
    assert response.json()["fingerprinted_devices"] == 3
    assert commits == 1
