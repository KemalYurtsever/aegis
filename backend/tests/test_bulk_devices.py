from app.services.ping_service import PingResult


def create_devices(client):
    devices = []
    for index in range(3):
        response = client.post("/api/devices", json={
            "name": f"Bulk device {index + 1}",
            "ip_address": f"192.168.110.{index + 10}",
            "device_type": "Workstation",
        })
        assert response.status_code == 201
        devices.append(response.json())
    return devices


def test_bulk_group_and_monitoring_updates(client):
    devices = create_devices(client)
    selected = [devices[0]["id"], devices[2]["id"]]
    grouped = client.put(
        "/api/devices/bulk/group",
        json={"device_ids": selected, "device_group": "  Finance Lab  "},
    )
    assert grouped.status_code == 200
    assert grouped.json()["updated_devices"] == 2
    assert {device["device_group"] for device in grouped.json()["devices"]} == {"Finance Lab"}

    paused = client.put(
        "/api/devices/bulk/monitoring",
        json={"device_ids": selected, "action": "DISABLE"},
    )
    assert paused.status_code == 200
    assert all(device["is_active"] is False for device in paused.json()["devices"])
    untouched = client.get(f"/api/devices/{devices[1]['id']}").json()
    assert untouched["device_group"] is None
    assert untouched["is_active"] is True

    cleared = client.put(
        "/api/devices/bulk/group",
        json={"device_ids": selected, "device_group": "   "},
    )
    assert cleared.status_code == 200
    assert all(device["device_group"] is None for device in cleared.json()["devices"])


def test_bulk_updates_are_atomic_and_validate_unique_ids(client):
    devices = create_devices(client)
    target_id = devices[0]["id"]
    missing = client.put(
        "/api/devices/bulk/group",
        json={"device_ids": [target_id, 99999], "device_group": "Should not apply"},
    )
    assert missing.status_code == 404
    assert client.get(f"/api/devices/{target_id}").json()["device_group"] is None

    duplicate = client.put(
        "/api/devices/bulk/monitoring",
        json={"device_ids": [target_id, target_id], "action": "DISABLE"},
    )
    assert duplicate.status_code == 422
    assert client.get(f"/api/devices/{target_id}").json()["is_active"] is True


def test_bulk_check_records_results_for_selected_devices(client, monkeypatch):
    devices = create_devices(client)
    selected = [devices[0]["id"], devices[1]["id"]]
    results = iter([PingResult("ONLINE", 4.0), PingResult("OFFLINE", None, "no_reply")])
    monkeypatch.setattr("app.services.monitoring_service.check_ip", lambda *_args, **_kwargs: next(results))

    response = client.post("/api/devices/bulk/check", json={"device_ids": selected})
    assert response.status_code == 201
    assert response.json()["checked_devices"] == 2
    assert response.json()["online_devices"] == 1
    assert response.json()["offline_devices"] == 1
    assert client.get(f"/api/devices/{devices[2]['id']}/history").json() == []
