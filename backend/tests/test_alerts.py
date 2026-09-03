from datetime import datetime, timedelta, timezone

from app.services.ping_service import PingResult


DEVICE = {
    "name": "Alert Target",
    "ip_address": "192.168.56.40",
    "device_type": "Server",
    "description": None,
    "is_active": True,
}


def setup_device_and_rule(client):
    device = client.post("/api/devices", json=DEVICE).json()
    rule = client.put(
        f"/api/devices/{device['id']}/alert-rule",
        json={"enabled": True, "consecutive_failures": 2, "latency_threshold_ms": 10.0},
    )
    assert rule.status_code == 200
    return device


def install_sequence(monkeypatch, sequence):
    values = iter(sequence)
    monkeypatch.setattr(
        "app.services.monitoring_service.check_ip",
        lambda *_args, **_kwargs: next(values),
    )


def test_offline_alert_triggers_once_and_resolves_on_recovery(client, monkeypatch):
    device = setup_device_and_rule(client)
    install_sequence(
        monkeypatch,
        [
            PingResult("OFFLINE", None, "no_reply"),
            PingResult("OFFLINE", None, "no_reply"),
            PingResult("OFFLINE", None, "no_reply"),
            PingResult("ONLINE", 2.0),
        ],
    )

    client.post(f"/api/devices/{device['id']}/check")
    assert client.get("/api/alerts").json() == []
    client.post(f"/api/devices/{device['id']}/check")
    alerts = client.get("/api/alerts").json()
    assert len(alerts) == 1
    assert alerts[0]["alert_type"] == "DEVICE_OFFLINE"
    assert alerts[0]["severity"] == "CRITICAL"

    client.post(f"/api/devices/{device['id']}/check")
    assert len(client.get("/api/alerts").json()) == 1

    client.post(f"/api/devices/{device['id']}/check")
    assert client.get("/api/alerts").json() == []
    historical = client.get("/api/alerts?active_only=false").json()
    assert len(historical) == 1
    assert historical[0]["resolved_at"] is not None


def test_high_latency_alert_acknowledgement_and_resolution(client, monkeypatch):
    device = setup_device_and_rule(client)
    install_sequence(monkeypatch, [PingResult("ONLINE", 25.0), PingResult("ONLINE", 2.0)])

    client.post(f"/api/devices/{device['id']}/check")
    alert = client.get("/api/alerts").json()[0]
    assert alert["alert_type"] == "HIGH_LATENCY"
    assert alert["severity"] == "WARNING"

    acknowledged = client.post(f"/api/alerts/{alert['id']}/acknowledge")
    assert acknowledged.status_code == 200
    assert acknowledged.json()["acknowledged_at"] is not None
    dashboard = client.get("/api/dashboard").json()
    assert dashboard["active_alert_count"] == 0
    assert dashboard["active_alerts"] == []

    client.post(f"/api/devices/{device['id']}/check")
    assert client.get("/api/alerts").json() == []


def test_acknowledge_all_active_alerts_is_idempotent(client, monkeypatch):
    first = setup_device_and_rule(client)
    second = client.post(
        "/api/devices",
        json={**DEVICE, "name": "Second Alert Target", "ip_address": "192.168.56.42"},
    ).json()
    rule = client.put(
        f"/api/devices/{second['id']}/alert-rule",
        json={"enabled": True, "consecutive_failures": 2, "latency_threshold_ms": 10.0},
    )
    assert rule.status_code == 200
    install_sequence(monkeypatch, [PingResult("ONLINE", 25.0), PingResult("ONLINE", 30.0)])

    client.post(f"/api/devices/{first['id']}/check")
    client.post(f"/api/devices/{second['id']}/check")
    assert client.get("/api/dashboard").json()["active_alert_count"] == 2

    acknowledged = client.post("/api/alerts/acknowledge-all")
    assert acknowledged.status_code == 200
    assert acknowledged.json() == {"acknowledged_count": 2}
    dashboard = client.get("/api/dashboard").json()
    assert dashboard["active_alert_count"] == 0
    assert dashboard["active_alerts"] == []

    repeated = client.post("/api/alerts/acknowledge-all")
    assert repeated.status_code == 200
    assert repeated.json() == {"acknowledged_count": 0}
    historical = client.get("/api/alerts?active_only=false").json()
    assert len(historical) == 2
    assert all(alert["acknowledged_at"] is not None for alert in historical)


def test_alert_rule_validation(client):
    device = client.post("/api/devices", json=DEVICE).json()
    response = client.put(
        f"/api/devices/{device['id']}/alert-rule",
        json={"enabled": True, "consecutive_failures": 0, "latency_threshold_ms": 100},
    )
    assert response.status_code == 422


def test_maintenance_window_keeps_results_but_suppresses_new_alerts(client, monkeypatch):
    device = setup_device_and_rule(client)
    maintenance_payload = DEVICE | {
        "maintenance_until": (datetime.now(timezone.utc) + timedelta(hours=2)).isoformat(),
        "maintenance_reason": "Switch replacement",
    }
    updated = client.put(f"/api/devices/{device['id']}", json=maintenance_payload)
    assert updated.status_code == 200

    install_sequence(monkeypatch, [PingResult("OFFLINE", None, "no_reply"), PingResult("OFFLINE", None, "no_reply")])
    client.post(f"/api/devices/{device['id']}/check")
    client.post(f"/api/devices/{device['id']}/check")

    assert client.get("/api/alerts").json() == []
    history = client.get(f"/api/devices/{device['id']}/history").json()
    assert len(history) == 2
    assert all(result["status"] == "OFFLINE" for result in history)


def test_agent_resource_threshold_alerts_trigger_and_resolve(client):
    device = client.post("/api/devices", json={**DEVICE, "ip_address": "192.168.56.41"}).json()
    client.put(f"/api/devices/{device['id']}/alert-rule", json={
        "enabled": True,
        "consecutive_failures": 2,
        "latency_threshold_ms": 100,
        "cpu_threshold_percent": 80,
        "memory_threshold_percent": 85,
        "disk_threshold_percent": 90,
    })
    token = client.post(f"/api/devices/{device['id']}/agent/enroll").json()["token"]
    payload = {
        "hostname": "resource-host", "platform": "Windows", "agent_version": "0.1.0",
        "report_interval_seconds": 60,
        "cpu_percent": 95, "memory_percent": 50, "disk_percent": 40,
        "memory_used_bytes": 500, "memory_total_bytes": 1000,
        "disk_used_bytes": 400, "disk_total_bytes": 1000,
    }
    assert client.post("/api/agent/metrics", json=payload, headers={"X-Agent-Token": token}).status_code == 201
    alerts = client.get("/api/alerts").json()
    assert len(alerts) == 1
    assert alerts[0]["alert_type"] == "HIGH_CPU"

    payload["cpu_percent"] = 20
    assert client.post("/api/agent/metrics", json=payload, headers={"X-Agent-Token": token}).status_code == 201
    assert client.get("/api/alerts").json() == []
