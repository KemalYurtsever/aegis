from datetime import datetime, timedelta, timezone
from pathlib import Path
import sqlite3
import subprocess
import sys

from sqlalchemy import func, select

from app.models import (
    AnomalyEvent,
    CveMirrorState,
    Device,
    HostMetric,
    LocalCveCpeMatch,
    LocalCveRecord,
    MonitorResult,
)


def admin_headers(client):
    response = client.post(
        "/api/auth/setup",
        json={"username": "reliability-admin", "password": "a-secure-test-password"},
    )
    assert response.status_code == 201
    client.app.state.auth_required = True
    return {"Authorization": f"Bearer {response.json()['token']}"}


def test_backup_create_verify_list_and_download(client):
    headers = admin_headers(client)
    device = client.post(
        "/api/devices",
        headers=headers,
        json={"name": "Backup target", "ip_address": "198.18.90.10", "device_type": "Server"},
    )
    assert device.status_code == 201

    created = client.post("/api/backups", headers=headers)
    assert created.status_code == 201
    backup = created.json()
    assert backup["valid"] is True
    assert backup["integrity_result"] == "ok"
    assert backup["device_count"] == 1

    listed = client.get("/api/backups", headers=headers)
    assert listed.status_code == 200
    assert [item["filename"] for item in listed.json()] == [backup["filename"]]

    verified = client.post(f"/api/backups/{backup['filename']}/verify", headers=headers)
    assert verified.status_code == 200
    assert verified.json()["valid"] is True
    backup_path = client.app.state.backup_service.download_path(backup["filename"])
    assert not Path(f"{backup_path}-wal").exists()
    assert not Path(f"{backup_path}-shm").exists()
    assert client.app.state.backup_service.seconds_until_due(24) > 23 * 3600

    downloaded = client.get(f"/api/backups/{backup['filename']}/download", headers=headers)
    assert downloaded.status_code == 200
    assert downloaded.content.startswith(b"SQLite format 3")

    for _ in range(3):
        assert client.post("/api/backups", headers=headers).status_code == 201
    retained = client.get("/api/backups", headers=headers).json()
    assert len(retained) == 3


def test_core_backup_excludes_rebuildable_cve_rows(client):
    headers = admin_headers(client)
    with client.app.state.session_factory() as db:
        db.add(LocalCveRecord(cve_id="CVE-2026-99999", description="Rebuildable"))
        db.flush()
        db.add(LocalCveCpeMatch(
            cve_id="CVE-2026-99999",
            criteria="cpe:2.3:a:example:server:*:*:*:*:*:*:*:*",
            vulnerable=True,
            part="a",
            vendor="example",
            product="server",
            criteria_version="*",
        ))
        state = db.get(CveMirrorState, 1)
        assert state is not None
        state.status = "READY"
        state.baseline_complete = True
        db.commit()

    created = client.post("/api/backups", headers=headers)
    assert created.status_code == 201
    backup_path = client.app.state.backup_service.download_path(created.json()["filename"])
    with sqlite3.connect(backup_path) as backup:
        assert backup.execute("SELECT COUNT(*) FROM local_cve_records").fetchone()[0] == 0
        assert backup.execute("SELECT COUNT(*) FROM local_cve_cpe_matches").fetchone()[0] == 0
        assert backup.execute("SELECT COUNT(*) FROM cve_mirror_state").fetchone()[0] == 0


def test_backup_routes_require_admin_and_reject_unknown_names(client):
    assert client.get("/api/backups").status_code == 403
    headers = admin_headers(client)
    assert client.post("/api/backups/not-a-backup.db/verify", headers=headers).status_code == 404


def test_offline_restore_verifier_accepts_backup_and_rejects_other_files(client, tmp_path):
    headers = admin_headers(client)
    created = client.post("/api/backups", headers=headers).json()
    backup_path = client.app.state.backup_service.download_path(created["filename"])
    verifier = Path(__file__).parents[1] / "tools" / "verify_sqlite_backup.py"
    valid = subprocess.run([sys.executable, str(verifier), str(backup_path)], capture_output=True, text=True)
    assert valid.returncode == 0
    assert '"valid": true' in valid.stdout

    invalid_path = tmp_path / "not-a-backup.db"
    invalid_path.write_text("not sqlite", encoding="utf-8")
    invalid = subprocess.run([sys.executable, str(verifier), str(invalid_path)], capture_output=True, text=True)
    assert invalid.returncode == 1
    assert '"valid": false' in invalid.stdout


def test_retention_preview_and_confirmed_cleanup(client):
    headers = admin_headers(client)
    now = datetime.now(timezone.utc)
    with client.app.state.session_factory() as db:
        device = Device(name="Retention target", ip_address="198.18.90.20", device_type="Server")
        db.add(device); db.flush()
        db.add_all([
            MonitorResult(device_id=device.id, timestamp=now - timedelta(days=100), status="ONLINE", latency_ms=1),
            MonitorResult(device_id=device.id, timestamp=now - timedelta(days=2), status="ONLINE", latency_ms=1),
            HostMetric(
                device_id=device.id, timestamp=now - timedelta(days=100), cpu_percent=1, memory_percent=2,
                disk_percent=3, memory_used_bytes=1, memory_total_bytes=2, disk_used_bytes=1, disk_total_bytes=2,
            ),
            AnomalyEvent(
                device_id=device.id, metric="latency_ms", severity="WARNING", score=3,
                observed_value=100, baseline_value=10, message="Old anomaly", detected_at=now - timedelta(days=100),
            ),
        ])
        db.commit()

    preview = client.get("/api/retention/preview?days=90", headers=headers)
    assert preview.status_code == 200
    assert preview.json()["total_records"] == 3
    assert preview.json()["monitor_results"] == 1
    assert preview.json()["host_metrics"] == 1
    assert preview.json()["anomaly_events"] == 1

    unconfirmed = client.post(
        "/api/retention/apply",
        headers=headers,
        json={"retention_days": 90, "confirmation": "yes"},
    )
    assert unconfirmed.status_code == 422

    applied = client.post(
        "/api/retention/apply",
        headers=headers,
        json={"retention_days": 90, "confirmation": "DELETE HISTORY"},
    )
    assert applied.status_code == 200
    assert applied.json()["total_records"] == 3
    with client.app.state.session_factory() as db:
        assert db.scalar(select(func.count(MonitorResult.id))) == 1
        assert db.scalar(select(func.count(HostMetric.id))) == 0
        assert db.scalar(select(func.count(AnomalyEvent.id))) == 0
