import json
import sqlite3
import sys
from contextlib import closing
from pathlib import Path


REQUIRED_TABLES = {"devices", "monitor_results", "users"}


def verify(path: Path) -> dict:
    if not path.is_file():
        return {"valid": False, "error": "Backup file does not exist"}
    with path.open("rb") as stream:
        header = stream.read(16)
    if path.stat().st_size < 100 or header != b"SQLite format 3\x00":
        return {"valid": False, "error": "File is not a SQLite 3 database"}
    try:
        with closing(sqlite3.connect(f"file:{path.resolve().as_posix()}?mode=ro", uri=True)) as database:
            integrity = str(database.execute("PRAGMA integrity_check").fetchone()[0])
            tables = {row[0] for row in database.execute("SELECT name FROM sqlite_master WHERE type='table'")}
            missing = sorted(REQUIRED_TABLES - tables)
            device_count = int(database.execute("SELECT COUNT(*) FROM devices").fetchone()[0]) if "devices" in tables else None
    except sqlite3.DatabaseError as exc:
        return {"valid": False, "error": str(exc)}
    valid = integrity.lower() == "ok" and not missing
    return {
        "valid": valid,
        "integrity": integrity,
        "missing_tables": missing,
        "device_count": device_count,
        "size_bytes": path.stat().st_size,
    }


def main() -> int:
    if len(sys.argv) != 2:
        print(json.dumps({"valid": False, "error": "Usage: verify_sqlite_backup.py BACKUP_FILE"}))
        return 2
    result = verify(Path(sys.argv[1]))
    print(json.dumps(result))
    return 0 if result["valid"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
