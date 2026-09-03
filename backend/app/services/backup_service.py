import asyncio
import logging
import os
import re
import sqlite3
import threading
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path
from secrets import token_hex

from sqlalchemy.engine import make_url

from app.schemas import BackupRead, BackupVerification


logger = logging.getLogger(__name__)
BACKUP_NAME = re.compile(r"^aegis-\d{8}-\d{6}-[0-9a-f]{6}\.db$")


class BackupService:
    def __init__(self, database_url: str, backup_directory: str | Path, keep_count: int = 14) -> None:
        url = make_url(database_url)
        if url.drivername != "sqlite" or not url.database or url.database == ":memory:":
            raise ValueError("Local backups currently require a file-based SQLite database")
        self.database_path = Path(url.database).resolve()
        self.backup_directory = Path(backup_directory).resolve()
        self.keep_count = keep_count
        self._create_lock = threading.Lock()

    def _backup_path(self, filename: str) -> Path:
        if not BACKUP_NAME.fullmatch(filename):
            raise ValueError("Invalid backup filename")
        path = (self.backup_directory / filename).resolve()
        if path.parent != self.backup_directory:
            raise ValueError("Invalid backup path")
        return path

    def create_backup(self) -> BackupVerification:
        with self._create_lock:
            return self._create_backup()

    def _create_backup(self) -> BackupVerification:
        if not self.database_path.is_file():
            raise FileNotFoundError("SQLite database file was not found")
        self.backup_directory.mkdir(parents=True, exist_ok=True)
        filename = f"aegis-{datetime.now(timezone.utc):%Y%m%d-%H%M%S}-{token_hex(3)}.db"
        destination = self._backup_path(filename)
        temporary = destination.with_suffix(".tmp")
        try:
            with closing(sqlite3.connect(self.database_path)) as source, closing(sqlite3.connect(temporary)) as target:
                source.backup(target)
            os.replace(temporary, destination)
            verification = self.verify_backup(filename)
            if not verification.valid:
                destination.unlink(missing_ok=True)
                raise RuntimeError(f"Backup integrity check failed: {verification.integrity_result}")
            self.prune()
            return verification
        finally:
            temporary.unlink(missing_ok=True)

    def list_backups(self) -> list[BackupRead]:
        if not self.backup_directory.exists():
            return []
        backups = []
        for path in self.backup_directory.glob("aegis-*.db"):
            if not BACKUP_NAME.fullmatch(path.name) or not path.is_file():
                continue
            stat = path.stat()
            backups.append(BackupRead(
                filename=path.name,
                size_bytes=stat.st_size,
                created_at=datetime.fromtimestamp(stat.st_mtime, timezone.utc),
            ))
        return sorted(backups, key=lambda item: item.created_at, reverse=True)

    def verify_backup(self, filename: str) -> BackupVerification:
        path = self._backup_path(filename)
        if not path.is_file():
            raise FileNotFoundError("Backup not found")
        stat = path.stat()
        try:
            with closing(sqlite3.connect(f"file:{path.as_posix()}?mode=ro", uri=True)) as database:
                result = str(database.execute("PRAGMA integrity_check").fetchone()[0])
                tables = {row[0] for row in database.execute("SELECT name FROM sqlite_master WHERE type='table'")}
                device_count = int(database.execute("SELECT COUNT(*) FROM devices").fetchone()[0]) if "devices" in tables else None
                valid = result.lower() == "ok" and "devices" in tables
        except sqlite3.DatabaseError as exc:
            result = str(exc)
            device_count = None
            valid = False
        return BackupVerification(
            filename=filename,
            size_bytes=stat.st_size,
            created_at=datetime.fromtimestamp(stat.st_mtime, timezone.utc),
            valid=valid,
            integrity_result=result,
            device_count=device_count,
        )

    def download_path(self, filename: str) -> Path:
        path = self._backup_path(filename)
        if not path.is_file():
            raise FileNotFoundError("Backup not found")
        return path

    def prune(self) -> None:
        for backup in self.list_backups()[self.keep_count:]:
            self._backup_path(backup.filename).unlink(missing_ok=True)


class PeriodicBackup:
    def __init__(self, service: BackupService, interval_hours: int, enabled: bool = True) -> None:
        self.service = service
        self.interval_hours = interval_hours
        self.enabled = enabled
        self._task: asyncio.Task | None = None

    @property
    def is_running(self) -> bool:
        return self._task is not None and not self._task.done()

    def start(self) -> None:
        if not self.enabled or self.is_running:
            return
        self._task = asyncio.create_task(self._run_loop(), name="aegis-periodic-backup")

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

    async def _run_loop(self) -> None:
        while True:
            try:
                await asyncio.to_thread(self.service.create_backup)
            except Exception:
                logger.exception("Scheduled AEGIS backup failed")
            await asyncio.sleep(self.interval_hours * 3600)
