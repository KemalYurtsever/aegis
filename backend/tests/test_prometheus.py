from sqlalchemy import event

from app.models import Device, HostMetric, MonitorResult, ServiceCheck, ServiceResult


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
    device = client.post("/api/devices", json={"name": "Router A", "ip_address": "198.18.1.1", "device_type": "Router", "is_active": True}).json()
    response = client.get("/metrics", headers={"Authorization": "Bearer scrape-secret"})
    assert f'device_id="{device["id"]}",device_name="Router A"' in response.text
    assert "aegis_device_status" in response.text


def test_metrics_query_count_is_constant_for_multiple_devices(client, monkeypatch):
    monkeypatch.setenv("AEGIS_PROMETHEUS_TOKEN", "scrape-secret")
    with client.app.state.session_factory() as db:
        for index in range(20):
            device = Device(
                name=f"Node {index}",
                ip_address=f"192.168.50.{index + 1}",
                device_type="Server",
                is_active=True,
            )
            db.add(device)
            db.flush()
            db.add(MonitorResult(device_id=device.id, status="ONLINE", latency_ms=index + 0.5))
            check = ServiceCheck(
                device_id=device.id,
                name="HTTPS",
                check_type="HTTPS",
                port=443,
                path="/",
            )
            db.add(check)
            db.flush()
            db.add(ServiceResult(service_check_id=check.id, status="UP", response_time_ms=10))
            db.add(HostMetric(
                device_id=device.id,
                cpu_percent=10,
                memory_percent=20,
                disk_percent=30,
                memory_used_bytes=200,
                memory_total_bytes=1000,
                disk_used_bytes=300,
                disk_total_bytes=1000,
            ))
        db.commit()

    engine = client.app.state.session_factory.kw["bind"]
    select_statements = []

    def count_selects(_connection, _cursor, statement, _parameters, _context, _many):
        if statement.lstrip().upper().startswith("SELECT"):
            select_statements.append(statement)

    event.listen(engine, "before_cursor_execute", count_selects)
    try:
        response = client.get("/metrics", headers={"Authorization": "Bearer scrape-secret"})
    finally:
        event.remove(engine, "before_cursor_execute", count_selects)

    assert response.status_code == 200
    assert "aegis_devices_total 20" in response.text
    assert len(select_statements) <= 5
