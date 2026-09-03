from datetime import datetime, timedelta, timezone

from app.models import Device, MonitorResult


def test_availability_report_calculates_uptime_incidents_and_streaks(client):
    now = datetime.now(timezone.utc)
    with client.app.state.session_factory() as db:
        primary = Device(
            name="Critical server", ip_address="198.18.100.10", device_type="Server", criticality="CRITICAL"
        )
        empty = Device(name="Unchecked switch", ip_address="198.18.100.20", device_type="Switch")
        db.add_all([primary, empty]); db.flush()
        db.add_all([
            MonitorResult(device_id=primary.id, timestamp=now - timedelta(days=40), status="OFFLINE"),
            MonitorResult(device_id=primary.id, timestamp=now - timedelta(days=4), status="ONLINE", latency_ms=10),
            MonitorResult(device_id=primary.id, timestamp=now - timedelta(days=3), status="ONLINE", latency_ms=20),
            MonitorResult(device_id=primary.id, timestamp=now - timedelta(days=2), status="OFFLINE"),
            MonitorResult(device_id=primary.id, timestamp=now - timedelta(days=1), status="OFFLINE"),
        ])
        db.commit()

    response = client.get("/api/reports/availability?days=30")
    assert response.status_code == 200
    report = response.json()
    assert report["days"] == 30
    assert len(report["devices"]) == 2
    primary_row = next(row for row in report["devices"] if row["device_name"] == "Critical server")
    assert primary_row["total_checks"] == 4
    assert primary_row["online_checks"] == 2
    assert primary_row["offline_checks"] == 2
    assert primary_row["availability_percent"] == 50.0
    assert primary_row["average_latency_ms"] == 15.0
    assert primary_row["offline_incidents"] == 1
    assert primary_row["longest_offline_streak"] == 2
    assert primary_row["current_status"] == "OFFLINE"
    empty_row = next(row for row in report["devices"] if row["device_name"] == "Unchecked switch")
    assert empty_row["total_checks"] == 0
    assert empty_row["availability_percent"] is None
    assert empty_row["current_status"] == "UNKNOWN"


def test_availability_report_validates_date_range(client):
    assert client.get("/api/reports/availability?days=6").status_code == 422
    assert client.get("/api/reports/availability?days=366").status_code == 422
