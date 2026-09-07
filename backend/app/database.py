from collections.abc import Generator

from sqlalchemy import create_engine, event, inspect, text
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

from app.config import get_settings


class Base(DeclarativeBase):
    pass


def create_database_engine(database_url: str):
    connect_args = {"check_same_thread": False} if database_url.startswith("sqlite") else {}
    engine = create_engine(database_url, connect_args=connect_args)

    if database_url.startswith("sqlite"):
        @event.listens_for(engine, "connect")
        def enable_sqlite_foreign_keys(dbapi_connection, _connection_record):
            cursor = dbapi_connection.cursor()
            cursor.execute("PRAGMA foreign_keys=ON")
            cursor.close()

    return engine


engine = create_database_engine(get_settings().database_url)
SessionLocal = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)


def get_db() -> Generator[Session, None, None]:
    with SessionLocal() as session:
        yield session


def migrate_device_inventory_columns(engine) -> None:
    if engine.dialect.name != "sqlite":
        return
    with engine.begin() as connection:
        inspector = inspect(connection)
        if "devices" not in inspector.get_table_names():
            return
        columns = {column["name"] for column in inspector.get_columns("devices")}
        if "mac_address" not in columns:
            connection.execute(text("ALTER TABLE devices ADD COLUMN mac_address VARCHAR(17)"))
        if "manufacturer" not in columns:
            connection.execute(text("ALTER TABLE devices ADD COLUMN manufacturer VARCHAR(255)"))
        if "discovered_services" not in columns:
            connection.execute(text("ALTER TABLE devices ADD COLUMN discovered_services VARCHAR(500)"))
        if "fingerprint_ports" not in columns:
            connection.execute(text("ALTER TABLE devices ADD COLUMN fingerprint_ports VARCHAR(200)"))
        if "fingerprint_summary" not in columns:
            connection.execute(text("ALTER TABLE devices ADD COLUMN fingerprint_summary VARCHAR(500)"))
        if "fingerprinted_at" not in columns:
            connection.execute(text("ALTER TABLE devices ADD COLUMN fingerprinted_at DATETIME"))
        if "inventory_source" not in columns:
            connection.execute(text("ALTER TABLE devices ADD COLUMN inventory_source VARCHAR(30)"))
        if "vlan" not in columns:
            connection.execute(text("ALTER TABLE devices ADD COLUMN vlan VARCHAR(64)"))
        if "lease_expires_at" not in columns:
            connection.execute(text("ALTER TABLE devices ADD COLUMN lease_expires_at DATETIME"))
        if "asset_tag" not in columns:
            connection.execute(text("ALTER TABLE devices ADD COLUMN asset_tag VARCHAR(80)"))
        if "owner" not in columns:
            connection.execute(text("ALTER TABLE devices ADD COLUMN owner VARCHAR(120)"))
        if "location" not in columns:
            connection.execute(text("ALTER TABLE devices ADD COLUMN location VARCHAR(120)"))
        if "operating_system" not in columns:
            connection.execute(text("ALTER TABLE devices ADD COLUMN operating_system VARCHAR(120)"))
        if "criticality" not in columns:
            connection.execute(text("ALTER TABLE devices ADD COLUMN criticality VARCHAR(10) NOT NULL DEFAULT 'MEDIUM'"))
        if "maintenance_until" not in columns:
            connection.execute(text("ALTER TABLE devices ADD COLUMN maintenance_until DATETIME"))
        if "maintenance_reason" not in columns:
            connection.execute(text("ALTER TABLE devices ADD COLUMN maintenance_reason VARCHAR(300)"))
        if "device_group" not in columns:
            connection.execute(text("ALTER TABLE devices ADD COLUMN device_group VARCHAR(80)"))
        if "tags_json" not in columns:
            connection.execute(text("ALTER TABLE devices ADD COLUMN tags_json TEXT NOT NULL DEFAULT '[]'"))


def migrate_notification_tables(engine) -> None:
    """Upgrade the pre-SMS SQLite notification tables without losing delivery history."""
    if engine.dialect.name != "sqlite":
        return
    with engine.connect() as connection:
        tables = inspect(connection).get_table_names()
        if "notification_channels" not in tables:
            return
        definition = connection.execute(text("SELECT sql FROM sqlite_master WHERE type='table' AND name='notification_channels'")) .scalar() or ""
        if "'SMS'" in definition:
            # Clean up an empty legacy table left by an interrupted older
            # migration. Never remove it if it still contains recoverable data.
            if "notification_channels_legacy" in tables:
                legacy_count = connection.execute(text("SELECT COUNT(*) FROM notification_channels_legacy")).scalar() or 0
                if legacy_count == 0:
                    connection.execute(text("DROP TABLE notification_channels_legacy"))
                    connection.commit()
            return
        connection.exec_driver_sql("PRAGMA foreign_keys=OFF")
        connection.execute(text("ALTER TABLE notification_channels RENAME TO notification_channels_legacy"))
        if "notification_deliveries" in tables:
            connection.execute(text("ALTER TABLE notification_deliveries RENAME TO notification_deliveries_legacy"))
        connection.commit()
    Base.metadata.create_all(bind=engine)
    with engine.begin() as connection:
        connection.execute(text("INSERT INTO notification_channels (id, channel_type, enabled, smtp_host, smtp_port, smtp_username, email_from, email_to, use_tls, updated_at) SELECT id, channel_type, enabled, smtp_host, smtp_port, smtp_username, email_from, email_to, use_tls, updated_at FROM notification_channels_legacy"))
        if "notification_deliveries" in tables:
            connection.execute(text("INSERT INTO notification_deliveries (id, alert_event_id, channel_type, status, subject, message, attempt_count, last_error, created_at, last_attempt_at, sent_at) SELECT id, alert_event_id, channel_type, status, subject, message, attempt_count, last_error, created_at, last_attempt_at, sent_at FROM notification_deliveries_legacy"))
            connection.execute(text("DROP TABLE notification_deliveries_legacy"))
        connection.execute(text("DROP TABLE notification_channels_legacy"))
        connection.exec_driver_sql("PRAGMA foreign_keys=ON")


def migrate_agent_monitoring_columns(engine) -> None:
    if engine.dialect.name != "sqlite":
        return
    with engine.begin() as connection:
        inspector = inspect(connection)
        tables = inspector.get_table_names()
        if "agent_enrollments" in tables:
            columns = {column["name"] for column in inspector.get_columns("agent_enrollments")}
            if "report_interval_seconds" not in columns:
                connection.execute(text(
                    "ALTER TABLE agent_enrollments ADD COLUMN report_interval_seconds INTEGER NOT NULL DEFAULT 60"
                ))
            if "diagnostics_enabled" not in columns:
                connection.execute(text(
                    "ALTER TABLE agent_enrollments ADD COLUMN diagnostics_enabled BOOLEAN NOT NULL DEFAULT 0"
                ))
        if "alert_rules" in tables:
            columns = {column["name"] for column in inspector.get_columns("alert_rules")}
            additions = {
                "cpu_threshold_percent": "FLOAT DEFAULT 90.0",
                "memory_threshold_percent": "FLOAT DEFAULT 90.0",
                "disk_threshold_percent": "FLOAT DEFAULT 90.0",
            }
            for name, definition in additions.items():
                if name not in columns:
                    connection.execute(text(f"ALTER TABLE alert_rules ADD COLUMN {name} {definition}"))

    with engine.connect() as connection:
        tables = inspect(connection).get_table_names()
        if "alert_events" not in tables and "alert_events_legacy" not in tables:
            return
        definition = ""
        if "alert_events" in tables:
            definition = connection.execute(text(
                "SELECT sql FROM sqlite_master WHERE type='table' AND name='alert_events'"
            )).scalar() or ""
        migration_started = "alert_events_legacy" in tables
        if "HIGH_CPU" in definition and "AGENT_OFFLINE" in definition and not migration_started:
            return

        connection.exec_driver_sql("PRAGMA foreign_keys=OFF")
        if not migration_started:
            if "notification_deliveries" in tables:
                connection.execute(text(
                    "ALTER TABLE notification_deliveries RENAME TO notification_deliveries_alert_legacy"
                ))
            connection.execute(text("ALTER TABLE alert_events RENAME TO alert_events_legacy"))
        # SQLite retains explicit index names after a table rename. Remove the
        # legacy indexes so SQLAlchemy can create them for the replacement.
        for index_name in (
            "ix_alert_events_device_id",
            "ix_notification_deliveries_alert_event_id",
            "ix_notification_deliveries_channel_type",
            "ix_notification_deliveries_status",
        ):
            connection.execute(text(f"DROP INDEX IF EXISTS {index_name}"))
        connection.commit()

    Base.metadata.create_all(bind=engine)

    with engine.connect() as connection:
        connection.exec_driver_sql("PRAGMA foreign_keys=OFF")
        tables = inspect(connection).get_table_names()
        if "alert_events_legacy" in tables:
            connection.execute(text(
                "INSERT OR IGNORE INTO alert_events (id, device_id, alert_type, severity, message, triggered_at, resolved_at, acknowledged_at) "
                "SELECT id, device_id, alert_type, severity, message, triggered_at, resolved_at, acknowledged_at FROM alert_events_legacy"
            ))
        for legacy in ("notification_deliveries_alert_legacy", "notification_deliveries_legacy"):
            if legacy in tables:
                connection.execute(text(
                    "INSERT OR IGNORE INTO notification_deliveries (id, alert_event_id, channel_type, status, subject, message, attempt_count, last_error, created_at, last_attempt_at, sent_at) "
                    f"SELECT id, alert_event_id, channel_type, status, subject, message, attempt_count, last_error, created_at, last_attempt_at, sent_at FROM {legacy}"
                ))
        for legacy in ("notification_deliveries_alert_legacy", "notification_deliveries_legacy", "alert_events_legacy"):
            if legacy in tables:
                connection.execute(text(f"DROP TABLE {legacy}"))
        connection.commit()
        connection.exec_driver_sql("PRAGMA foreign_keys=ON")


def migrate_automation_columns(engine) -> None:
    """Keep the small single-row automation table compatible during local upgrades."""
    if engine.dialect.name != "sqlite":
        return
    with engine.begin() as connection:
        inspector = inspect(connection)
        if "automation_settings" not in inspector.get_table_names():
            return
        columns = {column["name"] for column in inspector.get_columns("automation_settings")}
        additions = {
            "discovery_enabled": "BOOLEAN NOT NULL DEFAULT 0",
            "vulnerability_scans_enabled": "BOOLEAN NOT NULL DEFAULT 0",
            "service_discovery_enabled": "BOOLEAN NOT NULL DEFAULT 0",
            "discovery_interval_hours": "INTEGER NOT NULL DEFAULT 6",
            "vulnerability_interval_hours": "INTEGER NOT NULL DEFAULT 168",
            "alert_escalation_minutes": "INTEGER NOT NULL DEFAULT 30",
            "notification_window_enabled": "BOOLEAN NOT NULL DEFAULT 0",
            "notification_start_hour": "INTEGER NOT NULL DEFAULT 8",
            "notification_end_hour": "INTEGER NOT NULL DEFAULT 18",
            "last_discovery_at": "DATETIME",
            "last_discovery_network": "VARCHAR(80)",
            "last_vulnerability_at": "DATETIME",
        }
        for name, definition in additions.items():
            if name not in columns:
                connection.execute(text(f"ALTER TABLE automation_settings ADD COLUMN {name} {definition}"))
