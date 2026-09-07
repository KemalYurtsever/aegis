from datetime import datetime, timezone

import json

from sqlalchemy import Boolean, CheckConstraint, DateTime, Float, ForeignKey, Index, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class Device(Base):
    __tablename__ = "devices"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(80), nullable=False)
    ip_address: Mapped[str] = mapped_column(String(45), unique=True, index=True, nullable=False)
    mac_address: Mapped[str | None] = mapped_column(String(17), nullable=True)
    manufacturer: Mapped[str | None] = mapped_column(String(255), nullable=True)
    discovered_services: Mapped[str | None] = mapped_column(String(500), nullable=True)
    fingerprint_ports: Mapped[str | None] = mapped_column(String(200), nullable=True)
    fingerprint_summary: Mapped[str | None] = mapped_column(String(500), nullable=True)
    fingerprinted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    inventory_source: Mapped[str | None] = mapped_column(String(30), nullable=True)
    vlan: Mapped[str | None] = mapped_column(String(64), nullable=True)
    lease_expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    asset_tag: Mapped[str | None] = mapped_column(String(80), nullable=True)
    owner: Mapped[str | None] = mapped_column(String(120), nullable=True)
    location: Mapped[str | None] = mapped_column(String(120), nullable=True)
    operating_system: Mapped[str | None] = mapped_column(String(120), nullable=True)
    criticality: Mapped[str] = mapped_column(String(10), nullable=False, default="MEDIUM")
    maintenance_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    maintenance_reason: Mapped[str | None] = mapped_column(String(300), nullable=True)
    device_group: Mapped[str | None] = mapped_column(String(80), nullable=True)
    tags_json: Mapped[str] = mapped_column(Text, nullable=False, default="[]")
    device_type: Mapped[str] = mapped_column(String(20), nullable=False, default="Other")
    description: Mapped[str | None] = mapped_column(String(500), nullable=True)
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now)
    monitor_results: Mapped[list["MonitorResult"]] = relationship(
        back_populates="device",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )
    alert_rule: Mapped["AlertRule | None"] = relationship(
        back_populates="device", cascade="all, delete-orphan", passive_deletes=True
    )
    alert_events: Mapped[list["AlertEvent"]] = relationship(
        back_populates="device", cascade="all, delete-orphan", passive_deletes=True
    )
    service_checks: Mapped[list["ServiceCheck"]] = relationship(
        back_populates="device", cascade="all, delete-orphan", passive_deletes=True
    )
    host_metrics: Mapped[list["HostMetric"]] = relationship(
        back_populates="device", cascade="all, delete-orphan", passive_deletes=True
    )
    agent_enrollment: Mapped["AgentEnrollment | None"] = relationship(
        back_populates="device", cascade="all, delete-orphan", passive_deletes=True
    )
    diagnostic_jobs: Mapped[list["DiagnosticJob"]] = relationship(
        back_populates="device", cascade="all, delete-orphan", passive_deletes=True
    )
    notes: Mapped[list["DeviceNote"]] = relationship(
        back_populates="device", cascade="all, delete-orphan", passive_deletes=True
    )
    attachments: Mapped[list["DeviceAttachment"]] = relationship(
        back_populates="device", cascade="all, delete-orphan", passive_deletes=True
    )

    @property
    def tags(self) -> list[str]:
        try:
            tags = json.loads(self.tags_json or "[]")
        except (TypeError, json.JSONDecodeError):
            return []
        return tags if isinstance(tags, list) and all(isinstance(tag, str) for tag in tags) else []

    @tags.setter
    def tags(self, values: list[str]) -> None:
        self.tags_json = json.dumps(values)


class DeviceNote(Base):
    __tablename__ = "device_notes"

    id: Mapped[int] = mapped_column(primary_key=True)
    device_id: Mapped[int] = mapped_column(
        ForeignKey("devices.id", ondelete="CASCADE"), index=True, nullable=False
    )
    author: Mapped[str] = mapped_column(String(80), nullable=False, default="local-user")
    body: Mapped[str] = mapped_column(String(1000), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), index=True, nullable=False, default=utc_now
    )

    device: Mapped[Device] = relationship(back_populates="notes")


class DeviceAttachment(Base):
    __tablename__ = "device_attachments"

    id: Mapped[int] = mapped_column(primary_key=True)
    device_id: Mapped[int] = mapped_column(ForeignKey("devices.id", ondelete="CASCADE"), index=True, nullable=False)
    original_name: Mapped[str] = mapped_column(String(120), nullable=False)
    media_type: Mapped[str] = mapped_column(String(40), nullable=False)
    size_bytes: Mapped[int] = mapped_column(Integer, nullable=False)
    storage_name: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    uploaded_by: Mapped[str] = mapped_column(String(80), nullable=False, default="local-user")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True, nullable=False, default=utc_now)

    device: Mapped[Device] = relationship(back_populates="attachments")


class TopologyLink(Base):
    __tablename__ = "topology_links"
    __table_args__ = (
        CheckConstraint("relationship_type IN ('UPLINK', 'CONNECTS_TO', 'ROUTES_TO', 'MANAGES')", name="ck_topology_link_type"),
        UniqueConstraint("source_device_id", "target_device_id", "relationship_type", name="uq_topology_link"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    source_device_id: Mapped[int] = mapped_column(ForeignKey("devices.id", ondelete="CASCADE"), index=True, nullable=False)
    target_device_id: Mapped[int] = mapped_column(ForeignKey("devices.id", ondelete="CASCADE"), index=True, nullable=False)
    relationship_type: Mapped[str] = mapped_column(String(20), nullable=False, default="CONNECTS_TO")
    description: Mapped[str | None] = mapped_column(String(200), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now)


class MonitorResult(Base):
    __tablename__ = "monitor_results"
    __table_args__ = (
        CheckConstraint("status IN ('ONLINE', 'OFFLINE')", name="ck_monitor_result_status"),
        Index("ix_monitor_results_device_timestamp_id", "device_id", "timestamp", "id"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    device_id: Mapped[int] = mapped_column(
        ForeignKey("devices.id", ondelete="CASCADE"), index=True, nullable=False
    )
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True, nullable=False, default=utc_now)
    status: Mapped[str] = mapped_column(String(7), nullable=False)
    latency_ms: Mapped[float | None] = mapped_column(Float, nullable=True)

    device: Mapped[Device] = relationship(back_populates="monitor_results")


class AlertRule(Base):
    __tablename__ = "alert_rules"

    id: Mapped[int] = mapped_column(primary_key=True)
    device_id: Mapped[int] = mapped_column(
        ForeignKey("devices.id", ondelete="CASCADE"), unique=True, index=True, nullable=False
    )
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    consecutive_failures: Mapped[int] = mapped_column(Integer, nullable=False, default=2)
    latency_threshold_ms: Mapped[float | None] = mapped_column(Float, nullable=True, default=100.0)
    cpu_threshold_percent: Mapped[float | None] = mapped_column(Float, nullable=True, default=90.0)
    memory_threshold_percent: Mapped[float | None] = mapped_column(Float, nullable=True, default=90.0)
    disk_threshold_percent: Mapped[float | None] = mapped_column(Float, nullable=True, default=90.0)

    device: Mapped[Device] = relationship(back_populates="alert_rule")


class AlertEvent(Base):
    __tablename__ = "alert_events"
    __table_args__ = (
        CheckConstraint(
            "alert_type IN ('DEVICE_OFFLINE', 'HIGH_LATENCY', 'HIGH_CPU', 'HIGH_MEMORY', 'HIGH_DISK', 'AGENT_OFFLINE')",
            name="ck_alert_type",
        ),
        CheckConstraint("severity IN ('WARNING', 'CRITICAL')", name="ck_alert_severity"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    device_id: Mapped[int] = mapped_column(
        ForeignKey("devices.id", ondelete="CASCADE"), index=True, nullable=False
    )
    alert_type: Mapped[str] = mapped_column(String(30), nullable=False)
    severity: Mapped[str] = mapped_column(String(10), nullable=False)
    message: Mapped[str] = mapped_column(String(300), nullable=False)
    triggered_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now)
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    acknowledged_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    device: Mapped[Device] = relationship(back_populates="alert_events")
    notification_deliveries: Mapped[list["NotificationDelivery"]] = relationship(
        back_populates="alert_event", cascade="all, delete-orphan", passive_deletes=True
    )


class NotificationChannel(Base):
    __tablename__ = "notification_channels"
    __table_args__ = (CheckConstraint("channel_type IN ('EMAIL', 'TEAMS', 'SMS')", name="ck_notification_channel_type"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    channel_type: Mapped[str] = mapped_column(String(10), unique=True, index=True, nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    smtp_host: Mapped[str | None] = mapped_column(String(255), nullable=True)
    smtp_port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    smtp_username: Mapped[str | None] = mapped_column(String(255), nullable=True)
    email_from: Mapped[str | None] = mapped_column(String(320), nullable=True)
    email_to: Mapped[str | None] = mapped_column(String(1000), nullable=True)
    sms_from: Mapped[str | None] = mapped_column(String(30), nullable=True)
    sms_to: Mapped[str | None] = mapped_column(String(500), nullable=True)
    use_tls: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now, onupdate=utc_now)


class NotificationDelivery(Base):
    __tablename__ = "notification_deliveries"
    __table_args__ = (
        CheckConstraint("channel_type IN ('EMAIL', 'TEAMS', 'SMS')", name="ck_notification_delivery_channel"),
        CheckConstraint("status IN ('PENDING', 'SENT', 'FAILED')", name="ck_notification_delivery_status"),
        UniqueConstraint("alert_event_id", "channel_type", name="uq_notification_alert_channel"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    alert_event_id: Mapped[int | None] = mapped_column(ForeignKey("alert_events.id", ondelete="CASCADE"), index=True, nullable=True)
    channel_type: Mapped[str] = mapped_column(String(10), index=True, nullable=False)
    status: Mapped[str] = mapped_column(String(10), index=True, nullable=False, default="PENDING")
    subject: Mapped[str] = mapped_column(String(200), nullable=False)
    message: Mapped[str] = mapped_column(Text, nullable=False)
    attempt_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    last_error: Mapped[str | None] = mapped_column(String(500), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now)
    last_attempt_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    sent_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    alert_event: Mapped[AlertEvent | None] = relationship(back_populates="notification_deliveries")


class SnmpConfig(Base):
    __tablename__ = "snmp_configs"
    id: Mapped[int] = mapped_column(primary_key=True)
    device_id: Mapped[int] = mapped_column(ForeignKey("devices.id", ondelete="CASCADE"), unique=True, index=True, nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    port: Mapped[int] = mapped_column(Integer, nullable=False, default=161)
    community_env: Mapped[str] = mapped_column(String(100), nullable=False, default="AEGIS_SNMP_COMMUNITY")
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now, onupdate=utc_now)


class SnmpResult(Base):
    __tablename__ = "snmp_results"
    id: Mapped[int] = mapped_column(primary_key=True)
    device_id: Mapped[int] = mapped_column(ForeignKey("devices.id", ondelete="CASCADE"), index=True, nullable=False)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True, nullable=False, default=utc_now)
    status: Mapped[str] = mapped_column(String(10), nullable=False)
    system_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    description: Mapped[str | None] = mapped_column(String(1000), nullable=True)
    location: Mapped[str | None] = mapped_column(String(255), nullable=True)
    uptime_ticks: Mapped[int | None] = mapped_column(Integer, nullable=True)
    interface_count: Mapped[int | None] = mapped_column(Integer, nullable=True)
    error: Mapped[str | None] = mapped_column(String(500), nullable=True)


class VulnerabilityScan(Base):
    __tablename__ = "vulnerability_scans"
    id: Mapped[int] = mapped_column(primary_key=True)
    device_id: Mapped[int] = mapped_column(ForeignKey("devices.id", ondelete="CASCADE"), index=True, nullable=False)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    status: Mapped[str] = mapped_column(String(10), nullable=False, default="RUNNING")
    findings: Mapped[list["VulnerabilityFinding"]] = relationship(cascade="all, delete-orphan", passive_deletes=True)


class VulnerabilityFinding(Base):
    __tablename__ = "vulnerability_findings"
    id: Mapped[int] = mapped_column(primary_key=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("vulnerability_scans.id", ondelete="CASCADE"), index=True, nullable=False)
    severity: Mapped[str] = mapped_column(String(10), index=True, nullable=False)
    category: Mapped[str] = mapped_column(String(40), nullable=False)
    title: Mapped[str] = mapped_column(String(200), nullable=False)
    description: Mapped[str] = mapped_column(String(1000), nullable=False)
    recommendation: Mapped[str] = mapped_column(String(1000), nullable=False)
    port: Mapped[int | None] = mapped_column(Integer, nullable=True)


class PacketCapture(Base):
    __tablename__ = "packet_captures"
    id: Mapped[int] = mapped_column(primary_key=True)
    interface_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    duration_seconds: Mapped[int] = mapped_column(Integer, nullable=False)
    max_packets: Mapped[int] = mapped_column(Integer, nullable=False)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    status: Mapped[str] = mapped_column(String(10), nullable=False, default="RUNNING")
    error: Mapped[str | None] = mapped_column(String(500), nullable=True)
    packets: Mapped[list["PacketMetadata"]] = relationship(cascade="all, delete-orphan", passive_deletes=True)


class PacketMetadata(Base):
    __tablename__ = "packet_metadata"
    id: Mapped[int] = mapped_column(primary_key=True)
    capture_id: Mapped[int] = mapped_column(ForeignKey("packet_captures.id", ondelete="CASCADE"), index=True, nullable=False)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    source_ip: Mapped[str | None] = mapped_column(String(45), nullable=True)
    destination_ip: Mapped[str | None] = mapped_column(String(45), nullable=True)
    protocol: Mapped[str] = mapped_column(String(20), nullable=False)
    source_port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    destination_port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    length_bytes: Mapped[int] = mapped_column(Integer, nullable=False)


class AnomalyEvent(Base):
    __tablename__ = "anomaly_events"
    id: Mapped[int] = mapped_column(primary_key=True)
    device_id: Mapped[int] = mapped_column(ForeignKey("devices.id", ondelete="CASCADE"), index=True, nullable=False)
    metric: Mapped[str] = mapped_column(String(30), nullable=False)
    severity: Mapped[str] = mapped_column(String(10), nullable=False)
    score: Mapped[float] = mapped_column(Float, nullable=False)
    observed_value: Mapped[float] = mapped_column(Float, nullable=False)
    baseline_value: Mapped[float] = mapped_column(Float, nullable=False)
    message: Mapped[str] = mapped_column(String(500), nullable=False)
    detected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now)


class ServiceCheck(Base):
    __tablename__ = "service_checks"
    __table_args__ = (
        CheckConstraint("check_type IN ('TCP', 'HTTP', 'HTTPS')", name="ck_service_check_type"),
        CheckConstraint("port >= 1 AND port <= 65535", name="ck_service_check_port"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    device_id: Mapped[int] = mapped_column(
        ForeignKey("devices.id", ondelete="CASCADE"), index=True, nullable=False
    )
    name: Mapped[str] = mapped_column(String(80), nullable=False)
    check_type: Mapped[str] = mapped_column(String(5), nullable=False)
    port: Mapped[int] = mapped_column(Integer, nullable=False)
    path: Mapped[str] = mapped_column(String(300), nullable=False, default="/")
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now)

    device: Mapped[Device] = relationship(back_populates="service_checks")
    results: Mapped[list["ServiceResult"]] = relationship(
        back_populates="service_check", cascade="all, delete-orphan", passive_deletes=True
    )


class ServiceResult(Base):
    __tablename__ = "service_results"
    __table_args__ = (
        CheckConstraint("status IN ('UP', 'DOWN')", name="ck_service_result_status"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    service_check_id: Mapped[int] = mapped_column(
        ForeignKey("service_checks.id", ondelete="CASCADE"), index=True, nullable=False
    )
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now)
    status: Mapped[str] = mapped_column(String(4), nullable=False)
    response_time_ms: Mapped[float | None] = mapped_column(Float, nullable=True)
    http_status_code: Mapped[int | None] = mapped_column(Integer, nullable=True)
    diagnostic_reason: Mapped[str | None] = mapped_column(String(100), nullable=True)

    service_check: Mapped[ServiceCheck] = relationship(back_populates="results")


class HostMetric(Base):
    __tablename__ = "host_metrics"

    id: Mapped[int] = mapped_column(primary_key=True)
    device_id: Mapped[int] = mapped_column(
        ForeignKey("devices.id", ondelete="CASCADE"), index=True, nullable=False
    )
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now)
    cpu_percent: Mapped[float] = mapped_column(Float, nullable=False)
    memory_percent: Mapped[float] = mapped_column(Float, nullable=False)
    disk_percent: Mapped[float] = mapped_column(Float, nullable=False)
    memory_used_bytes: Mapped[int] = mapped_column(Integer, nullable=False)
    memory_total_bytes: Mapped[int] = mapped_column(Integer, nullable=False)
    disk_used_bytes: Mapped[int] = mapped_column(Integer, nullable=False)
    disk_total_bytes: Mapped[int] = mapped_column(Integer, nullable=False)

    device: Mapped[Device] = relationship(back_populates="host_metrics")


class AgentEnrollment(Base):
    __tablename__ = "agent_enrollments"

    id: Mapped[int] = mapped_column(primary_key=True)
    device_id: Mapped[int] = mapped_column(
        ForeignKey("devices.id", ondelete="CASCADE"), unique=True, index=True, nullable=False
    )
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True, nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now)
    last_seen_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    hostname: Mapped[str | None] = mapped_column(String(255), nullable=True)
    platform: Mapped[str | None] = mapped_column(String(255), nullable=True)
    agent_version: Mapped[str | None] = mapped_column(String(30), nullable=True)
    report_interval_seconds: Mapped[int] = mapped_column(Integer, nullable=False, default=60)
    diagnostics_enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)

    device: Mapped[Device] = relationship(back_populates="agent_enrollment")


class DiagnosticJob(Base):
    __tablename__ = "diagnostic_jobs"
    __table_args__ = (
        CheckConstraint(
            "job_type IN ('SERVICE_SCAN', 'PACKET_CAPTURE', 'SECURITY_LOG_SUMMARY', "
            "'NETWORK_CONNECTIONS', 'TOP_PROCESSES', 'SUID_AUDIT', 'LOGIN_HISTORY', "
            "'LOCAL_ACCOUNTS', 'FIREWALL_RULES')",
            name="ck_diagnostic_job_type",
        ),
        CheckConstraint(
            "status IN ('PENDING', 'RUNNING', 'COMPLETED', 'FAILED', 'CANCELLED', 'EXPIRED')",
            name="ck_diagnostic_job_status",
        ),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    device_id: Mapped[int] = mapped_column(
        ForeignKey("devices.id", ondelete="CASCADE"), index=True, nullable=False
    )
    job_type: Mapped[str] = mapped_column(String(40), index=True, nullable=False)
    status: Mapped[str] = mapped_column(String(12), index=True, nullable=False, default="PENDING")
    requested_by: Mapped[str] = mapped_column(String(80), nullable=False)
    parameters_json: Mapped[str] = mapped_column(Text, nullable=False, default="{}")
    result_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    error: Mapped[str | None] = mapped_column(String(1000), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now)
    claimed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    device: Mapped[Device] = relationship(back_populates="diagnostic_jobs")


class User(Base):
    __tablename__ = "users"
    __table_args__ = (
        CheckConstraint("role IN ('ADMIN', 'OPERATOR', 'VIEWER')", name="ck_user_role"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    username: Mapped[str] = mapped_column(String(80), unique=True, index=True, nullable=False)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    role: Mapped[str] = mapped_column(String(10), nullable=False, default="VIEWER")
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now)
    sessions: Mapped[list["UserSession"]] = relationship(
        back_populates="user", cascade="all, delete-orphan", passive_deletes=True
    )


class UserSession(Base):
    __tablename__ = "user_sessions"

    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True, nullable=False)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True, nullable=False)
    user: Mapped[User] = relationship(back_populates="sessions")


class AuditEvent(Base):
    __tablename__ = "audit_events"

    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), index=True, nullable=True)
    username: Mapped[str] = mapped_column(String(80), index=True, nullable=False)
    role: Mapped[str] = mapped_column(String(10), nullable=False)
    method: Mapped[str] = mapped_column(String(10), nullable=False)
    path: Mapped[str] = mapped_column(String(300), index=True, nullable=False)
    status_code: Mapped[int] = mapped_column(Integer, nullable=False)
    client_ip: Mapped[str | None] = mapped_column(String(45), nullable=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True, nullable=False, default=utc_now)


class AutomationSettings(Base):
    """Single-row configuration for optional AEGIS automations."""

    __tablename__ = "automation_settings"

    id: Mapped[int] = mapped_column(primary_key=True, default=1)
    incidents_enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    diagnostics_enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    reports_enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    drift_enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    discovery_enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    vulnerability_scans_enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    service_discovery_enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    report_interval_hours: Mapped[int] = mapped_column(Integer, nullable=False, default=24)
    report_days: Mapped[int] = mapped_column(Integer, nullable=False, default=30)
    discovery_interval_hours: Mapped[int] = mapped_column(Integer, nullable=False, default=6)
    vulnerability_interval_hours: Mapped[int] = mapped_column(Integer, nullable=False, default=168)
    alert_escalation_minutes: Mapped[int] = mapped_column(Integer, nullable=False, default=30)
    notification_window_enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    notification_start_hour: Mapped[int] = mapped_column(Integer, nullable=False, default=8)
    notification_end_hour: Mapped[int] = mapped_column(Integer, nullable=False, default=18)
    desired_agent_version: Mapped[str] = mapped_column(String(30), nullable=False, default="0.3.0")
    last_report_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_discovery_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_discovery_network: Mapped[str | None] = mapped_column(String(80), nullable=True)
    last_vulnerability_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utc_now, onupdate=utc_now
    )


class MaintenanceWindow(Base):
    __tablename__ = "maintenance_windows"
    __table_args__ = (
        CheckConstraint("repeat IN ('NONE', 'DAILY', 'WEEKLY')", name="ck_maintenance_repeat"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(100), nullable=False)
    device_group: Mapped[str | None] = mapped_column(String(80), index=True, nullable=True)
    starts_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True, nullable=False)
    ends_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True, nullable=False)
    repeat: Mapped[str] = mapped_column(String(10), nullable=False, default="NONE")
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    reason: Mapped[str | None] = mapped_column(String(300), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now)


class Incident(Base):
    __tablename__ = "incidents"
    __table_args__ = (
        CheckConstraint("status IN ('OPEN', 'RESOLVED')", name="ck_incident_status"),
        CheckConstraint("severity IN ('WARNING', 'CRITICAL')", name="ck_incident_severity"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    correlation_key: Mapped[str] = mapped_column(String(120), index=True, nullable=False)
    title: Mapped[str] = mapped_column(String(200), nullable=False)
    summary: Mapped[str] = mapped_column(String(1000), nullable=False)
    severity: Mapped[str] = mapped_column(String(10), nullable=False)
    status: Mapped[str] = mapped_column(String(10), index=True, nullable=False, default="OPEN")
    alert_ids_json: Mapped[str] = mapped_column(Text, nullable=False, default="[]")
    assigned_to: Mapped[str | None] = mapped_column(String(80), nullable=True)
    operator_note: Mapped[str | None] = mapped_column(String(500), nullable=True)
    opened_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True, nullable=False, default=utc_now)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now)
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class GeneratedReport(Base):
    __tablename__ = "generated_reports"

    id: Mapped[int] = mapped_column(primary_key=True)
    report_type: Mapped[str] = mapped_column(String(30), nullable=False, default="AVAILABILITY")
    period_days: Mapped[int] = mapped_column(Integer, nullable=False)
    filename: Mapped[str] = mapped_column(String(255), unique=True, nullable=False)
    device_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    generated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True, nullable=False, default=utc_now)


class AssetBaseline(Base):
    __tablename__ = "asset_baselines"

    id: Mapped[int] = mapped_column(primary_key=True)
    device_id: Mapped[int] = mapped_column(
        ForeignKey("devices.id", ondelete="CASCADE"), unique=True, index=True, nullable=False
    )
    signature: Mapped[str] = mapped_column(String(64), nullable=False)
    snapshot_json: Mapped[str] = mapped_column(Text, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now)


class AutomationEvent(Base):
    __tablename__ = "automation_events"
    __table_args__ = (
        CheckConstraint("severity IN ('INFO', 'WARNING', 'CRITICAL')", name="ck_automation_event_severity"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    device_id: Mapped[int | None] = mapped_column(
        ForeignKey("devices.id", ondelete="CASCADE"), index=True, nullable=True
    )
    event_type: Mapped[str] = mapped_column(String(40), index=True, nullable=False)
    severity: Mapped[str] = mapped_column(String(10), nullable=False, default="INFO")
    message: Mapped[str] = mapped_column(String(500), nullable=False)
    details_json: Mapped[str] = mapped_column(Text, nullable=False, default="{}")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True, nullable=False, default=utc_now)
