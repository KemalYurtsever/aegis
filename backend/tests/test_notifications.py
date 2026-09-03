from app.services import notification_service


def setup_admin(client):
    response = client.post("/api/auth/setup", json={"username": "admin", "password": "correct-horse-battery-staple"})
    client.app.state.auth_required = True
    return {"Authorization": f"Bearer {response.json()['token']}"}


def test_admin_can_persist_channels_and_delivery_history(client, monkeypatch):
    headers = setup_admin(client)
    channels = client.get("/api/notifications/channels", headers=headers)
    assert channels.status_code == 200
    assert {item["channel_type"] for item in channels.json()} == {"EMAIL", "TEAMS", "SMS"}
    saved = client.put("/api/notifications/channels/EMAIL", headers=headers, json={
        "enabled": True, "smtp_host": "smtp.example.test", "smtp_port": 587,
        "smtp_username": "liims", "email_from": "liims@example.test",
        "email_to": "admin@example.test", "use_tls": True,
    })
    assert saved.status_code == 200
    monkeypatch.setattr(notification_service, "_send_email", lambda channel, delivery: None)
    delivery = client.post("/api/notifications/channels/EMAIL/test", headers=headers)
    assert delivery.json()["status"] == "SENT"
    assert client.get("/api/notifications/deliveries", headers=headers).json()[0]["attempt_count"] == 1


def test_failed_delivery_retry_is_bounded(client, monkeypatch):
    headers = setup_admin(client)
    def fail(_delivery): raise RuntimeError("offline")
    monkeypatch.setattr(notification_service, "_send_teams", fail)
    failed = client.post("/api/notifications/channels/TEAMS/test", headers=headers).json()
    for _ in range(4):
        failed = client.post(f"/api/notifications/deliveries/{failed['id']}/retry", headers=headers).json()
    assert failed["status"] == "FAILED"
    assert failed["attempt_count"] == 3
    assert failed["last_error"] == "offline"


def test_sms_delivery_uses_same_safe_history(client, monkeypatch):
    headers = setup_admin(client)
    client.put("/api/notifications/channels/SMS", headers=headers, json={"enabled": True, "sms_from": "+15550000001", "sms_to": "+15550000002"})
    monkeypatch.setattr(notification_service, "_send_sms", lambda channel, delivery: None)
    result = client.post("/api/notifications/channels/SMS/test", headers=headers)
    assert result.status_code == 200
    assert result.json()["status"] == "SENT"
