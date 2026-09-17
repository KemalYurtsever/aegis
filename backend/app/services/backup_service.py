import asyncio
import logging
import os
import re
import sqlite3
import threading
from contextlib import closing
from datetime import datetime, timedelta, timezone
from pathlib import Path
from secrets import token_hex

from sqlalchemy.engine import make_url

from app.schemas import BackupRead, BackupVerification


logger = logging.getLogger(__name__)
BACKUP_NAME = re.compile(r"^aegis-\d{8}-\d{6}-[0-9a-f]{6}\.db$")
REBUILDABLE_CVE_TABLES = frozenset({
    "cve_mirror_state",
    "local_cve_records",
    "local_cve_cpe_matches",
})


class BackupService:
    def __init__(
        self,
        database_url: str,
        backup_directory: str | Path,
        keep_count: int = 14,
        *,
        include_cve_mirror: bool = False,
    ) -> None:
        url = make_url(database_url)
        if url.drivername != "sqlite" or not url.database or url.database == ":memory:":
            raise ValueError("Local backups currently require a file-based SQLite database")
        self.database_path = Path(url.database).resolve()
        self.backup_directory = Path(backup_directory).resolve()
        self.keep_count = keep_count
        self.include_cve_mirror = include_cve_mirror
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
                if self.include_cve_mirror:
                    source.backup(target)
                else:
                    self._copy_without_rebuildable_cve_data(source, target)
            os.replace(temporary, destination)
            verification = self.verify_backup(filename)
            if not verification.valid:
                destination.unlink(missing_ok=True)
                raise RuntimeError(f"Backup integrity check failed: {verification.integrity_result}")
            self.prune()
            return verification
        finally:
            temporary.unlink(missing_ok=True)

    @staticmethod
    def _quote_identifier(value: str) -> str:
        return '"' + value.replace('"', '""') + '"'

    def _copy_without_rebuildable_cve_data(
        self,
        source: sqlite3.Connection,
        target: sqlite3.Connection,
    ) -> None:
        """Create a consistent core backup while retaining empty mirror schemas."""
        source.execute("BEGIN")
        target.execute("PRAGMA foreign_keys=OFF")
        schema_rows = source.execute(
            "SELECT type, name, tbl_name, sql FROM sqlite_master "
            "WHERE sql IS NOT NULL AND name NOT LIKE 'sqlite_%' "
            "ORDER BY CASE type WHEN 'table' THEN 0 WHEN 'index' THEN 1 "
            "WHEN 'trigger' THEN 2 ELSE 3 END, rowid"
        ).fetchall()
        tables = [row for row in schema_rows if row[0] == "table"]
        for _kind, _name, _table_name, sql in tables:
            target.execute(sql)

        for _kind, name, _table_name, _sql in tables:
            if name in REBUILDABLE_CVE_TABLES:
                continue
            identifier = self._quote_identifier(name)
            cursor = source.execute(f"SELECT * FROM {identifier}")
            column_count = len(cursor.description or ())
            if column_count == 0:
                continue
            placeholders = ",".join("?" for _ in range(column_count))
            insert_sql = f"INSERT INTO {identifier} VALUES ({placeholders})"
            while rows := cursor.fetchmany(1000):
                target.executemany(insert_sql, rows)

        for kind, _name, table_name, sql in schema_rows:
            if kind == "table" or table_name in REBUILDABLE_CVE_TABLES and kind != "index":
                continue
            target.execute(sql)
        user_version = int(source.execute("PRAGMA user_version").fetchone()[0])
        target.execute(f"PRAGMA user_version={user_version}")
        target.commit()
        source.rollback()

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
            with closing(sqlite3.connect(
                f"file:{path.as_posix()}?mode=ro&immutable=1", uri=True
            )) as database:
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
            path = self._backup_path(backup.filename)
            path.unlink(missing_ok=True)
            Path(f"{path}-wal").unlink(missing_ok=True)
            Path(f"{path}-shm").unlink(missing_ok=True)

    def seconds_until_due(self, interval_hours: int) -> float:
        backups = self.list_backups()
        if not backups:
            return 0
        due_at = backups[0].created_at + timedelta(hours=interval_hours)
        return max(0, (due_at - datetime.now(timezone.utc)).total_seconds())


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
            delay = self.service.seconds_until_due(self.interval_hours)
            if delay:
                await asyncio.sleep(delay)
            try:
                await asyncio.to_thread(self.service.create_backup)
            except Exception:
                logger.exception("Scheduled AEGIS backup failed")
                await asyncio.sleep(min(300, self.interval_hours * 3600))
