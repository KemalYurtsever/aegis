import asyncio

from sqlalchemy import func, select
from sqlalchemy.orm import sessionmaker

from app.database import Base, create_database_engine
from datetime import datetime, timedelta, timezone

from app.models import AgentEnrollment, AlertEvent, Device, MonitorResult
from app.scheduler import PeriodicMonitor
from app.services.ping_service import PingResult


def make_session_factory(tmp_path):
    engine = create_database_engine(f"sqlite:///{tmp_path / 'scheduler.db'}")
    Base.metadata.create_all(engine)
    return engine, sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)


def test_scheduler_checks_only_active_devices(tmp_path, monkeypatch):
    engine, sessions = make_session_factory(tmp_path)
    with sessions() as db:
        db.add_all(
            [
                Device(name="Active", ip_address="192.168.56.10", device_type="Server", is_active=True),
                Device(name="Inactive", ip_address="192.168.56.11", device_type="Server", is_active=False),
            ]
        )
        db.commit()

    monkeypatch.setattr(
        "app.services.monitoring_service.check_ip",
        lambda *_args, **_kwargs: PingResult("ONLINE", 1.25),
    )
    scheduler = PeriodicMonitor(sessions, interval_seconds=60)

    assert scheduler.run_cycle() == 1
    with sessions() as db:
        results = list(db.scalars(select(MonitorResult)))
        assert len(results) == 1
        assert results[0].latency_ms == 1.25
        active_device = db.scalar(select(Device).where(Device.name == "Active"))
        assert results[0].device_id == active_device.id
    engine.dispose()


def test_scheduler_is_single_instance_and_stops_cleanly(tmp_path):
    engine, sessions = make_session_factory(tmp_path)
    scheduler = PeriodicMonitor(sessions, interval_seconds=60)

    async def exercise_scheduler():
        scheduler.start()
        first_task = scheduler._task
        scheduler.start()
        assert scheduler._task is first_task
        assert scheduler.is_running is True
        await scheduler.stop()
        assert scheduler.is_running is False

    asyncio.run(exercise_scheduler())
    engine.dispose()


def test_disabled_scheduler_does_not_start(tmp_path):
    engine, sessions = make_session_factory(tmp_path)
    scheduler = PeriodicMonitor(sessions, interval_seconds=60, enabled=False)

    async def exercise_scheduler():
        scheduler.start()
        assert scheduler.is_running is False

    asyncio.run(exercise_scheduler())
    engine.dispose()


def test_scheduler_status_endpoint_is_disabled_during_tests(client):
    response = client.get("/api/scheduler/status")

    assert response.status_code == 200
    assert response.json() == {
        "enabled": False,
        "running": False,
        "interval_seconds": 60.0,
    }


def test_pause_scheduler_is_idempotent(client):
    first = client.post("/api/scheduler/pause")
    second = client.post("/api/scheduler/pause")

    assert first.status_code == 200
    assert second.status_code == 200
    assert first.json()["running"] is False
    assert second.json()["running"] is False


def test_disabled_scheduler_cannot_be_resumed(client):
    response = client.post("/api/scheduler/resume")

    assert response.status_code == 409
    assert response.json()["detail"] == "Automatic monitoring is disabled by server configuration"


def test_enabled_scheduler_can_resume_and_pause(client):
    scheduler = client.app.state.monitor_scheduler
    scheduler.enabled = True

    resumed = client.post("/api/scheduler/resume")
    paused = client.post("/api/scheduler/pause")

    assert resumed.status_code == 200
    assert resumed.json()["running"] is True
    assert paused.status_code == 200
    assert paused.json()["running"] is False


def test_scheduler_creates_and_resolves_offline_agent_alert(tmp_path, monkeypatch):
    engine, sessions = make_session_factory(tmp_path)
    with sessions() as db:
        device = Device(name="Agent host", ip_address="192.168.56.30", device_type="Server", is_active=True)
        db.add(device); db.flush()
        db.add(AgentEnrollment(
            device_id=device.id,
            token_hash="b" * 64,
            last_seen_at=datetime.now(timezone.utc) - timedelta(minutes=10),
            report_interval_seconds=60,
        ))
        db.commit()
    monkeypatch.setattr(
        "app.services.monitoring_service.check_ip",
        lambda *_args, **_kwargs: PingResult("ONLINE", 1.0),
    )
    scheduler = PeriodicMonitor(sessions, interval_seconds=60)
    scheduler.run_cycle()
    with sessions() as db:
        alert = db.scalar(select(AlertEvent).where(AlertEvent.alert_type == "AGENT_OFFLINE"))
        assert alert is not None
        enrollment = db.scalar(select(AgentEnrollment))
        enrollment.last_seen_at = datetime.now(timezone.utc)
        db.commit()
    scheduler.run_cycle()
    with sessions() as db:
        alert = db.scalar(select(AlertEvent).where(AlertEvent.alert_type == "AGENT_OFFLINE"))
        assert alert.resolved_at is not None
    engine.dispose()
