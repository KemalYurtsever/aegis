from app.services.ping_service import PingResult


DEVICE = {
    "name": "Statistics Target",
    "ip_address": "198.18.56.30",
    "device_type": "Server",
    "description": None,
    "is_active": True,
}


def create_device(client):
    return client.post("/api/devices", json=DEVICE).json()


def install_ping_sequence(monkeypatch, values):
    sequence = iter(values)
    monkeypatch.setattr(
        "app.services.monitoring_service.check_ip",
        lambda *_args, **_kwargs: next(sequence),
    )


def test_no_history_statistics_are_unknown(client):
    device = create_device(client)

    response = client.get(f"/api/devices/{device['id']}/statistics")

    assert response.status_code == 200
    assert response.json() == {
        "device_id": device["id"],
        "total_checks": 0,
        "online_checks": 0,
        "offline_checks": 0,
        "availability_percent": None,
        "average_latency_ms": None,
        "current_status": "UNKNOWN",
        "last_checked_at": None,
    }


def test_history_statistics_and_status_events(client, monkeypatch):
    device = create_device(client)
    install_ping_sequence(
        monkeypatch,
        [
            PingResult("ONLINE", 1.0),
            PingResult("ONLINE", 3.0),
            PingResult("OFFLINE", None, "no_reply"),
            PingResult("OFFLINE", None, "no_reply"),
            PingResult("ONLINE", 2.0),
        ],
    )
    for _ in range(5):
        assert client.post(f"/api/devices/{device['id']}/check").status_code == 201

    history = client.get(f"/api/devices/{device['id']}/history?limit=3")
    assert history.status_code == 200
    assert len(history.json()) == 3
    assert [item["status"] for item in history.json()] == ["ONLINE", "OFFLINE", "OFFLINE"]

    statistics = client.get(f"/api/devices/{device['id']}/statistics")
    assert statistics.status_code == 200
    body = statistics.json()
    assert body["total_checks"] == 5
    assert body["online_checks"] == 3
    assert body["offline_checks"] == 2
    assert body["availability_percent"] == 60.0
    assert body["average_latency_ms"] == 2.0
    assert body["current_status"] == "ONLINE"
    assert body["last_checked_at"] is not None

    events = client.get(f"/api/devices/{device['id']}/status-events")
    assert events.status_code == 200
    assert [event["event_type"] for event in events.json()] == [
        "OFFLINE_TO_ONLINE",
        "ONLINE_TO_OFFLINE",
    ]


def test_all_offline_has_zero_availability_and_no_average(client, monkeypatch):
    device = create_device(client)
    install_ping_sequence(monkeypatch, [PingResult("OFFLINE", None, "no_reply")])
    client.post(f"/api/devices/{device['id']}/check")

    body = client.get(f"/api/devices/{device['id']}/statistics").json()
    assert body["availability_percent"] == 0.0
    assert body["average_latency_ms"] is None
    assert body["current_status"] == "OFFLINE"


def test_history_limit_is_validated(client):
    device = create_device(client)
    assert client.get(f"/api/devices/{device['id']}/history?limit=0").status_code == 422
    assert client.get(f"/api/devices/{device['id']}/history?limit=1001").status_code == 422


def test_statistics_unknown_device_returns_404(client):
    assert client.get("/api/devices/999/statistics").status_code == 404
