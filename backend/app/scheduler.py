import asyncio
import logging
from collections.abc import Callable

from sqlalchemy import select
from sqlalchemy.orm import Session, selectinload, sessionmaker

from app.models import Device, ServiceCheck, SnmpConfig
from app.services.host_metrics_service import collect_and_store_host_metrics, is_local_device
from app.services.monitoring_service import check_and_store_devices
from app.services.service_check_service import run_and_store_service_checks
from app.services.notification_service import dispatch_pending
from app.services.snmp_service import poll_device
from app.services.anomaly_service import detect_device_anomalies
from app.services.alert_service import evaluate_agent_health_alerts
from app.services.automation_service import run_automation_cycle

logger = logging.getLogger(__name__)


class PeriodicMonitor:
    def __init__(
        self,
        session_factory: sessionmaker[Session],
        interval_seconds: float,
        enabled: bool = True,
    ) -> None:
        if interval_seconds <= 0:
            raise ValueError("Monitoring interval must be greater than zero")
        self._session_factory = session_factory
        self.interval_seconds = interval_seconds
        self.enabled = enabled
        self._task: asyncio.Task | None = None

    @property
    def is_running(self) -> bool:
        return self._task is not None and not self._task.done()

    def start(self) -> None:
        if not self.enabled or self.is_running:
            return
        self._task = asyncio.create_task(self._run_loop(), name="aegis-periodic-monitor")
        logger.info("Periodic monitoring started interval_seconds=%s", self.interval_seconds)

    async def stop(self) -> None:
        if self._task is None:
            return
        self._task.cancel()
        try:
            await self._task
        except asyncio.CancelledError:
            pass
        finally:
            self._task = None
        logger.info("Periodic monitoring stopped")

    async def _run_loop(self) -> None:
        while True:
            await asyncio.sleep(self.interval_seconds)
            await asyncio.to_thread(self.run_cycle)

    def run_cycle(self) -> int:
        with self._session_factory() as db:
            devices = list(
                db.scalars(select(Device).where(Device.is_active.is_(True)).order_by(Device.id))
            )
            results = check_and_store_devices(devices, db)
            checked = len(results)
            for device in devices:
                try:
                    if is_local_device(device):
                        collect_and_store_host_metrics(device, db)
                    detect_device_anomalies(device, db)
                except Exception:
                    db.rollback()
                    logger.exception("Scheduled device analysis failed id=%s", device.id)

        with self._session_factory() as db:
            checks = list(db.scalars(
                select(ServiceCheck)
                .join(ServiceCheck.device)
                .options(selectinload(ServiceCheck.device))
                .where(ServiceCheck.is_active.is_(True), Device.is_active.is_(True))
                .order_by(ServiceCheck.id)
            ))
            run_and_store_service_checks(checks, db)

        with self._session_factory() as db:
            evaluate_agent_health_alerts(db)
            db.commit()
            dispatch_pending(db)

        with self._session_factory() as db:
            snmp_ids = list(db.scalars(select(SnmpConfig.device_id).where(SnmpConfig.enabled.is_(True))))
        self._run_items(snmp_ids, "SNMP device", self._poll_snmp)

        with self._session_factory() as db:
            run_automation_cycle(db)
        logger.info("Periodic monitoring cycle completed checked_devices=%s", checked)
        return checked

    def _run_items(self, item_ids: list[int], label: str, operation: Callable[[int, Session], bool]) -> int:
        """Run isolated jobs so one failed device cannot roll back another."""
        completed = 0
        for item_id in item_ids:
            with self._session_factory() as db:
                try:
                    completed += bool(operation(item_id, db))
                except Exception:
                    db.rollback()
                    logger.exception("Scheduled %s failed id=%s", label, item_id)
        return completed

    @staticmethod
    def _poll_snmp(device_id: int, db: Session) -> bool:
        device = db.get(Device, device_id)
        config = db.scalar(select(SnmpConfig).where(SnmpConfig.device_id == device_id))
        if device is None or config is None or not device.is_active:
            return False
        poll_device(device, config, db)
        return True
