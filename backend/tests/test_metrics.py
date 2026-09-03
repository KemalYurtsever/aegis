from types import SimpleNamespace


DEVICE = {"name": "Local", "ip_address": "127.0.0.1", "device_type": "Workstation", "description": None, "is_active": True}


def test_collect_and_read_local_metrics(client, monkeypatch):
    device = client.post("/api/devices", json=DEVICE).json()
    monkeypatch.setattr("app.services.host_metrics_service.psutil.cpu_percent", lambda interval: 12.5)
    monkeypatch.setattr("app.services.host_metrics_service.psutil.virtual_memory", lambda: SimpleNamespace(percent=50.0, used=8, total=16))
    monkeypatch.setattr("app.services.host_metrics_service.psutil.disk_usage", lambda path: SimpleNamespace(percent=25.0, used=25, total=100))

    response = client.post(f"/api/devices/{device['id']}/metrics/collect")
    assert response.status_code == 201
    assert response.json()["cpu_percent"] == 12.5
    assert response.json()["memory_percent"] == 50.0
    assert response.json()["disk_percent"] == 25.0
    assert len(client.get(f"/api/devices/{device['id']}/metrics").json()) == 1


def test_builtin_metrics_reject_remote_device(client):
    payload = DEVICE | {"ip_address": "192.168.56.80"}
    device = client.post("/api/devices", json=payload).json()
    response = client.post(f"/api/devices/{device['id']}/metrics/collect")
    assert response.status_code == 400
