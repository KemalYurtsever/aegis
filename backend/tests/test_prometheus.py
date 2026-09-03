def test_metrics_requires_dedicated_token(client, monkeypatch):
    monkeypatch.setenv("AEGIS_PROMETHEUS_TOKEN", "scrape-secret")
    assert client.get("/metrics").status_code == 401
    assert client.get("/metrics", headers={"Authorization": "Bearer wrong"}).status_code == 401
    response = client.get("/metrics", headers={"Authorization": "Bearer scrape-secret"})
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("application/openmetrics-text")
    assert "aegis_devices_total 0" in response.text
    assert response.text.endswith("# EOF\n")


def test_metrics_exports_latest_device_values(client, monkeypatch):
    monkeypatch.setenv("AEGIS_PROMETHEUS_TOKEN", "scrape-secret")
    device = client.post("/api/devices", json={"name": "Router A", "ip_address": "192.168.1.1", "device_type": "Router", "is_active": True}).json()
    response = client.get("/metrics", headers={"Authorization": "Bearer scrape-secret"})
    assert f'device_id="{device["id"]}",device_name="Router A"' in response.text
    assert "aegis_device_status" in response.text
