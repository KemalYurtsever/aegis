from datetime import datetime, timezone

from app.services.anomaly_service import _score


def admin_headers(client):
    response = client.post("/api/auth/setup", json={"username": "admin", "password": "correct-horse-battery-staple"})
    client.app.state.auth_required = True
    return {"Authorization": f"Bearer {response.json()['token']}"}


def test_packet_capture_stores_metadata_only(client, monkeypatch):
    headers = admin_headers(client)
    monkeypatch.setattr("app.services.packet_capture_service.capture_metadata", lambda *_args: [{
        "timestamp": datetime.now(timezone.utc), "source_ip": "192.168.1.10", "destination_ip": "192.168.1.1",
        "protocol": "TCP", "source_port": 51000, "destination_port": 443, "length_bytes": 120,
    }])
    response = client.post("/api/packet-captures", headers=headers, json={"duration_seconds": 1, "max_packets": 10})
    assert response.status_code == 201
    assert response.json()["status"] == "COMPLETED"
    packet = response.json()["packets"][0]
    assert packet["destination_port"] == 443
    assert "payload" not in packet


def test_packet_capture_limits_are_validated(client):
    headers = admin_headers(client)
    assert client.post("/api/packet-captures", headers=headers, json={"duration_seconds": 31, "max_packets": 10}).status_code == 422


def test_local_robust_anomaly_score_detects_spike():
    score, center = _score(100, [10] * 20)
    assert score >= 5
    assert center == 10
