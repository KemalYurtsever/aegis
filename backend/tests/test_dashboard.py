from app.services.ping_service import PingResult


def create_device(client, name, ip_address, is_active=True):
    return client.post(
        "/api/devices",
        json={
            "name": name,
            "ip_address": ip_address,
            "device_type": "Server",
            "description": None,
            "is_active": is_active,
        },
    ).json()


def test_empty_dashboard(client):
    response = client.get("/api/dashboard")

    assert response.status_code == 200
    assert response.json() == {
        "total_devices": 0,
        "active_devices": 0,
        "online_devices": 0,
        "offline_devices": 0,
        "unknown_devices": 0,
        "average_latest_latency_ms": None,
        "devices": [],
        "recent_events": [],
        "active_alert_count": 0,
        "active_alerts": [],
        "snmp_configured": False,
        "notification_configured": False,
        "notification_tested": False,
    }


def test_dashboard_aggregates_devices_and_events(client, monkeypatch):
    first = create_device(client, "Alpha", "198.18.56.10")
    create_device(client, "Beta", "198.18.56.11", is_active=False)
    sequence = iter([PingResult("ONLINE", 2.0), PingResult("OFFLINE", None, "no_reply")])
    monkeypatch.setattr(
        "app.services.monitoring_service.check_ip",
        lambda *_args, **_kwargs: next(sequence),
    )
    client.post(f"/api/devices/{first['id']}/check")
    client.post(f"/api/devices/{first['id']}/check")

    response = client.get("/api/dashboard")

    assert response.status_code == 200
    body = response.json()
    assert body["total_devices"] == 2
    assert body["active_devices"] == 1
    assert body["online_devices"] == 0
    assert body["offline_devices"] == 1
    assert body["unknown_devices"] == 1
    assert body["average_latest_latency_ms"] is None
    assert [device["name"] for device in body["devices"]] == ["Alpha", "Beta"]
    assert body["devices"][0]["availability_percent"] == 50.0
    assert body["recent_events"][0]["event_type"] == "ONLINE_TO_OFFLINE"
    assert body["recent_events"][0]["device_name"] == "Alpha"
    assert body["active_alert_count"] == 0
