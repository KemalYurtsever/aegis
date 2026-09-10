from datetime import datetime
from enum import Enum
from ipaddress import ip_address
import re
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator


class DeviceType(str, Enum):
    server = "Server"
    workstation = "Workstation"
    router = "Router"
    switch = "Switch"
    printer = "Printer"
    camera = "Camera"
    access_point = "Access Point"
    other = "Other"


class DeviceFields(BaseModel):
    name: str = Field(min_length=1, max_length=80)
    ip_address: str
    device_type: DeviceType = DeviceType.other
    description: str | None = Field(default=None, max_length=500)
    asset_tag: str | None = Field(default=None, max_length=80)
    owner: str | None = Field(default=None, max_length=120)
    location: str | None = Field(default=None, max_length=120)
    operating_system: str | None = Field(default=None, max_length=120)
    criticality: Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"] = "MEDIUM"
    maintenance_until: datetime | None = None
    maintenance_reason: str | None = Field(default=None, max_length=300)
    device_group: str | None = Field(default=None, max_length=80)
    tags: list[str] = Field(default_factory=list, max_length=12)
    is_active: bool = True

    @field_validator("name")
    @classmethod
    def normalize_name(cls, value: str) -> str:
        normalized = value.strip()
        if not normalized:
            raise ValueError("Name must not be blank")
        return normalized

    @field_validator("ip_address")
    @classmethod
    def normalize_ip_address(cls, value: str) -> str:
        try:
            return str(ip_address(value.strip()))
        except ValueError as exc:
            raise ValueError("A valid IPv4 or IPv6 address is required") from exc

    @field_validator("description", "asset_tag", "owner", "location", "operating_system", "maintenance_reason", "device_group")
    @classmethod
    def normalize_description(cls, value: str | None) -> str | None:
        if value is None:
            return None
        normalized = value.strip()
        return normalized or None

    @field_validator("tags")
    @classmethod
    def normalize_tags(cls, values: list[str]) -> list[str]:
        normalized: list[str] = []
        for value in values:
            tag = " ".join(value.split()).lower()
            if not tag:
                continue
            if len(tag) > 32 or not re.fullmatch(r"[a-z0-9][a-z0-9 ._/-]*", tag):
                raise ValueError("Tags must use letters, numbers, spaces, dots, underscores, slashes, or hyphens")
            if tag not in normalized:
                normalized.append(tag)
        return normalized


class DeviceCreate(DeviceFields):
    pass


class DeviceUpdate(DeviceFields):
    pass


class ClearDevicesRequest(BaseModel):
    confirmation: str


class ClearDevicesResponse(BaseModel):
    deleted_devices: int
    deleted_attachments: int


class DeviceRead(DeviceFields):
    id: int
    mac_address: str | None = None
    manufacturer: str | None = None
    discovered_services: str | None = None
    fingerprint_ports: str | None = None
    fingerprint_summary: str | None = None
    fingerprinted_at: datetime | None = None
    inventory_source: str | None = None
    vlan: str | None = None
    lease_expires_at: datetime | None = None
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class DeviceNoteCreate(BaseModel):
    body: str = Field(min_length=1, max_length=1000)

    @field_validator("body")
    @classmethod
    def normalize_body(cls, value: str) -> str:
        normalized = value.strip()
        if not normalized:
            raise ValueError("Note must not be blank")
        return normalized


class DeviceNoteRead(BaseModel):
    id: int
    device_id: int
    author: str
    body: str
    created_at: datetime
    model_config = ConfigDict(from_attributes=True)


class DeviceAttachmentCreate(BaseModel):
    original_name: str = Field(min_length=1, max_length=120)
    media_type: Literal["text/plain", "application/pdf", "image/png", "image/jpeg"]
    content_base64: str = Field(min_length=1, max_length=7_100_000)

    @field_validator("original_name")
    @classmethod
    def clean_attachment_name(cls, value: str) -> str:
        cleaned = re.sub(r"[\\/\x00-\x1f]", "_", value).strip(" .")
        if not cleaned:
            raise ValueError("Attachment filename is invalid")
        return cleaned[:120]


class DeviceAttachmentRead(BaseModel):
    id: int
    device_id: int
    original_name: str
    media_type: str
    size_bytes: int
    uploaded_by: str
    created_at: datetime
    model_config = ConfigDict(from_attributes=True)


class DeviceActivityItem(BaseModel):
    id: str
    category: Literal["NOTE", "ATTACHMENT", "STATUS", "CHECK", "ALERT", "CHANGE", "DIAGNOSTIC", "MAINTENANCE"]
    title: str
    description: str | None = None
    timestamp: datetime
    actor: str | None = None
    severity: Literal["INFO", "WARNING", "CRITICAL"] = "INFO"


class HealthResponse(BaseModel):
    status: str
    application: str


class SchedulerStatus(BaseModel):
    enabled: bool
    running: bool
    interval_seconds: float


class MonitorResultRead(BaseModel):
    id: int
    device_id: int
    timestamp: datetime
    status: Literal["ONLINE", "OFFLINE"]
    latency_ms: float | None

    model_config = ConfigDict(from_attributes=True)


class BatchCheckResponse(BaseModel):
    checked_devices: int
    online_devices: int
    offline_devices: int
    results: list[MonitorResultRead]


class BulkDeviceIds(BaseModel):
    device_ids: list[int] = Field(min_length=1, max_length=200)

    @field_validator("device_ids")
    @classmethod
    def unique_device_ids(cls, value: list[int]) -> list[int]:
        if any(device_id < 1 for device_id in value):
            raise ValueError("Device IDs must be positive")
        if len(set(value)) != len(value):
            raise ValueError("Device IDs must be unique")
        return value


class BulkMonitoringRequest(BulkDeviceIds):
    action: Literal["ENABLE", "DISABLE"]


class BulkGroupRequest(BulkDeviceIds):
    device_group: str | None = Field(default=None, max_length=80)

    @field_validator("device_group")
    @classmethod
    def normalize_device_group(cls, value: str | None) -> str | None:
        if value is None:
            return None
        normalized = value.strip()
        return normalized or None


class BulkDeviceUpdateResponse(BaseModel):
    updated_devices: int
    devices: list[DeviceRead]


class DeviceStatistics(BaseModel):
    device_id: int
    total_checks: int
    online_checks: int
    offline_checks: int
    availability_percent: float | None
    average_latency_ms: float | None
    current_status: Literal["ONLINE", "OFFLINE", "UNKNOWN"]
    last_checked_at: datetime | None


class StatusEvent(BaseModel):
    device_id: int
    timestamp: datetime
    previous_status: Literal["ONLINE", "OFFLINE"]
    current_status: Literal["ONLINE", "OFFLINE"]
    event_type: Literal["ONLINE_TO_OFFLINE", "OFFLINE_TO_ONLINE"]


class DashboardDevice(BaseModel):
    id: int
    name: str
    ip_address: str
    mac_address: str | None
    manufacturer: str | None
    discovered_services: str | None
    inventory_source: str | None
    vlan: str | None
    lease_expires_at: datetime | None
    asset_tag: str | None
    owner: str | None
    location: str | None
    operating_system: str | None
    criticality: Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    maintenance_until: datetime | None
    maintenance_reason: str | None
    device_group: str | None
    tags: list[str] = Field(default_factory=list)
    device_type: DeviceType
    is_active: bool
    current_status: Literal["ONLINE", "OFFLINE", "UNKNOWN"]
    latest_latency_ms: float | None
    last_checked_at: datetime | None
    availability_percent: float | None
    created_at: datetime


class DashboardEvent(StatusEvent):
    device_name: str


class DashboardResponse(BaseModel):
    total_devices: int
    active_devices: int
    online_devices: int
    offline_devices: int
    unknown_devices: int
    average_latest_latency_ms: float | None
    devices: list[DashboardDevice]
    recent_events: list[DashboardEvent]
    active_alert_count: int
    active_alerts: list["AlertEventRead"]
    snmp_configured: bool = False
    notification_configured: bool = False
    notification_tested: bool = False


class AlertRuleUpdate(BaseModel):
    enabled: bool = True
    consecutive_failures: int = Field(default=2, ge=1, le=10)
    latency_threshold_ms: float | None = Field(default=100.0, gt=0, le=60000)
    cpu_threshold_percent: float | None = Field(default=90.0, gt=0, le=100)
    memory_threshold_percent: float | None = Field(default=90.0, gt=0, le=100)
    disk_threshold_percent: float | None = Field(default=90.0, gt=0, le=100)


class AlertRuleRead(AlertRuleUpdate):
    id: int
    device_id: int
    model_config = ConfigDict(from_attributes=True)


class AlertEventRead(BaseModel):
    id: int
    device_id: int
    device_name: str
    alert_type: Literal["DEVICE_OFFLINE", "HIGH_LATENCY", "HIGH_CPU", "HIGH_MEMORY", "HIGH_DISK", "AGENT_OFFLINE"]
    severity: Literal["WARNING", "CRITICAL"]
    message: str
    triggered_at: datetime
    resolved_at: datetime | None
    acknowledged_at: datetime | None


class AlertAcknowledgementSummary(BaseModel):
    acknowledged_count: int


DashboardResponse.model_rebuild()


class DiscoveryNetwork(BaseModel):
    interface_name: str
    local_ip: str
    network: str
    gateway: str | None


class DiscoveryResult(BaseModel):
    network: DiscoveryNetwork
    addresses_scanned: int
    responsive_devices: int
    devices_added: int
    devices_skipped: int
    added_devices: list[DeviceRead]


class TopologyDevice(BaseModel):
    device_id: int
    name: str
    ip_address: str
    device_type: DeviceType
    status: Literal["ONLINE", "OFFLINE", "UNKNOWN"]
    role: Literal["GATEWAY", "INFRASTRUCTURE", "ENDPOINT"]


class TopologyNetwork(BaseModel):
    key: str
    label: str
    subnet: str
    vlan: str | None
    gateway_ip: str | None
    gateway_device_id: int | None
    device_count: int
    online_devices: int
    offline_devices: int
    unknown_devices: int
    devices: list[TopologyDevice]


class TopologyLinkCreate(BaseModel):
    source_device_id: int = Field(gt=0)
    target_device_id: int = Field(gt=0)
    relationship_type: Literal["UPLINK", "CONNECTS_TO", "ROUTES_TO", "MANAGES"] = "CONNECTS_TO"
    description: str | None = Field(default=None, max_length=200)

    @field_validator("description")
    @classmethod
    def clean_topology_description(cls, value: str | None) -> str | None:
        cleaned = " ".join(value.split()) if value else ""
        return cleaned or None


class TopologyLinkRead(TopologyLinkCreate):
    id: int
    source_name: str
    target_name: str
    created_at: datetime


class TopologyResponse(BaseModel):
    interface_name: str | None
    local_ip: str | None
    groups: list[TopologyNetwork]
    links: list[TopologyLinkRead] = Field(default_factory=list)


class DhcpLeaseRow(BaseModel):
    hostname: str | None = Field(default=None, max_length=80)
    ip_address: str
    mac_address: str | None = None
    lease_expires_at: datetime | None = None
    vlan: str | None = Field(default=None, max_length=64)

    @field_validator("hostname", "vlan")
    @classmethod
    def normalize_optional_text(cls, value: str | None) -> str | None:
        if value is None:
            return None
        normalized = value.strip()
        return normalized or None

    @field_validator("ip_address")
    @classmethod
    def normalize_ipv4_address(cls, value: str) -> str:
        try:
            parsed = ip_address(value.strip())
        except ValueError as exc:
            raise ValueError("A valid IPv4 address is required") from exc
        if parsed.version != 4:
            raise ValueError("DHCP lease imports support IPv4 addresses only")
        return str(parsed)

    @field_validator("mac_address")
    @classmethod
    def normalize_mac_address(cls, value: str | None) -> str | None:
        if value is None or not value.strip():
            return None
        compact = re.sub(r"[:.\-]", "", value.strip())
        if not re.fullmatch(r"[0-9A-Fa-f]{12}", compact):
            raise ValueError("A valid 48-bit MAC address is required")
        return ":".join(compact[index:index + 2] for index in range(0, 12, 2)).upper()


class DhcpLeaseImport(BaseModel):
    rows: list[DhcpLeaseRow] = Field(min_length=1, max_length=1000)


class DhcpLeaseImportResult(BaseModel):
    rows_received: int
    devices_added: int
    devices_updated: int
    rows_skipped: int
    conflicts: list[str]


class InventoryHealthIssue(BaseModel):
    device_id: int
    device_name: str
    ip_address: str
    issue_type: Literal["LEASE_EXPIRED", "LEASE_EXPIRING", "NEVER_CHECKED", "STALE_CHECK", "DUPLICATE_MAC"]
    detail: str


class InventoryHealthResponse(BaseModel):
    total_issues: int
    expired_leases: int
    expiring_leases: int
    never_checked: int
    stale_checks: int
    duplicate_mac_records: int
    issues: list[InventoryHealthIssue]


class BackupRead(BaseModel):
    filename: str
    size_bytes: int
    created_at: datetime


class BackupVerification(BackupRead):
    valid: bool
    integrity_result: str
    device_count: int | None = None


class BackupStatus(BaseModel):
    enabled: bool
    running: bool
    interval_hours: int
    keep_count: int
    history_retention_days: int


class RetentionPreview(BaseModel):
    retention_days: int
    cutoff: datetime
    monitor_results: int
    service_results: int
    host_metrics: int
    snmp_results: int
    anomaly_events: int
    total_records: int


class RetentionApplyRequest(BaseModel):
    retention_days: int = Field(ge=7, le=3650)
    confirmation: Literal["DELETE HISTORY"]


class AvailabilityReportDevice(BaseModel):
    device_id: int
    device_name: str
    ip_address: str
    criticality: Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    total_checks: int
    online_checks: int
    offline_checks: int
    availability_percent: float | None
    average_latency_ms: float | None
    offline_incidents: int
    longest_offline_streak: int
    current_status: Literal["ONLINE", "OFFLINE", "UNKNOWN"]


class AvailabilityReport(BaseModel):
    days: int
    starts_at: datetime
    ends_at: datetime
    generated_at: datetime
    devices: list[AvailabilityReportDevice]


class ServiceCheckFields(BaseModel):
    name: str = Field(min_length=1, max_length=80)
    check_type: Literal["TCP", "HTTP", "HTTPS"]
    port: int = Field(ge=1, le=65535)
    path: str = Field(default="/", max_length=300)
    is_active: bool = True

    @field_validator("name")
    @classmethod
    def normalize_service_name(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("Service name must not be blank")
        return value

    @field_validator("path")
    @classmethod
    def validate_service_path(cls, value: str) -> str:
        value = value.strip() or "/"
        if not value.startswith("/") or value.startswith("//"):
            raise ValueError("HTTP path must begin with one slash")
        return value


class ServiceCheckCreate(ServiceCheckFields):
    pass


class ServiceCheckRead(ServiceCheckFields):
    id: int
    device_id: int
    created_at: datetime
    current_status: Literal["UP", "DOWN", "UNKNOWN"] = "UNKNOWN"
    last_response_time_ms: float | None = None
    last_checked_at: datetime | None = None
    model_config = ConfigDict(from_attributes=True)


class ServiceResultRead(BaseModel):
    id: int
    service_check_id: int
    timestamp: datetime
    status: Literal["UP", "DOWN"]
    response_time_ms: float | None
    http_status_code: int | None
    diagnostic_reason: str | None
    model_config = ConfigDict(from_attributes=True)


class ServiceStatistics(BaseModel):
    service_check_id: int
    total_checks: int
    up_checks: int
    down_checks: int
    availability_percent: float | None
    average_response_time_ms: float | None
    current_status: Literal["UP", "DOWN", "UNKNOWN"]
    last_checked_at: datetime | None


class ServiceOverviewItem(BaseModel):
    id: int
    device_id: int
    device_name: str
    ip_address: str
    name: str
    check_type: Literal["TCP", "HTTP", "HTTPS"]
    port: int
    path: str
    is_active: bool
    current_status: Literal["UP", "DOWN", "UNKNOWN"]
    last_response_time_ms: float | None
    last_checked_at: datetime | None
    diagnostic_reason: str | None


class ServiceOverview(BaseModel):
    total_services: int
    active_services: int
    up_services: int
    down_services: int
    unknown_services: int
    services: list[ServiceOverviewItem]


class OpenPortRead(BaseModel):
    port: int
    service: str
    response_time_ms: float | None


class PortScanResponse(BaseModel):
    device_id: int
    target_ip: str
    scanned_ports: list[int]
    scanned_port_count: int
    scanner: str
    duration_ms: float
    open_ports: list[OpenPortRead]


class DeviceFingerprintRead(BaseModel):
    device_id: int
    classification: DeviceType | None
    open_ports: list[int]
    summary: str
    fingerprinted_at: datetime


class FingerprintBatchResponse(BaseModel):
    fingerprinted_devices: int
    classified_devices: int
    results: list[DeviceFingerprintRead]


class HostMetricRead(BaseModel):
    id: int
    device_id: int
    timestamp: datetime
    cpu_percent: float
    memory_percent: float
    disk_percent: float
    memory_used_bytes: int
    memory_total_bytes: int
    disk_used_bytes: int
    disk_total_bytes: int
    model_config = ConfigDict(from_attributes=True)


class AgentEnrollmentRead(BaseModel):
    device_id: int
    enabled: bool
    created_at: datetime
    last_seen_at: datetime | None
    hostname: str | None
    platform: str | None
    agent_version: str | None
    report_interval_seconds: int
    diagnostics_enabled: bool
    health_status: Literal["WAITING", "REPORTING", "DELAYED", "OFFLINE"]
    seconds_since_last_report: int | None
    model_config = ConfigDict(from_attributes=True)


class AgentEnrollmentCreated(AgentEnrollmentRead):
    token: str


class AgentFleetItem(AgentEnrollmentRead):
    device_name: str
    ip_address: str


class AgentFleetOverview(BaseModel):
    total_agents: int
    reporting_agents: int
    delayed_agents: int
    offline_agents: int
    waiting_agents: int
    agents: list[AgentFleetItem]


class AgentMetricSubmission(BaseModel):
    hostname: str = Field(min_length=1, max_length=255)
    platform: str = Field(min_length=1, max_length=255)
    agent_version: str = Field(min_length=1, max_length=30)
    report_interval_seconds: int = Field(default=60, ge=10, le=3600)
    diagnostics_enabled: bool = False
    cpu_percent: float = Field(ge=0, le=100)
    memory_percent: float = Field(ge=0, le=100)
    disk_percent: float = Field(ge=0, le=100)
    memory_used_bytes: int = Field(ge=0)
    memory_total_bytes: int = Field(gt=0)
    disk_used_bytes: int = Field(ge=0)
    disk_total_bytes: int = Field(gt=0)


DiagnosticJobType = Literal[
    "SERVICE_SCAN",
    "PACKET_CAPTURE",
    "SECURITY_LOG_SUMMARY",
    "NETWORK_CONNECTIONS",
    "TOP_PROCESSES",
    "SUID_AUDIT",
    "LOGIN_HISTORY",
    "LOCAL_ACCOUNTS",
    "FIREWALL_RULES",
]


class DiagnosticJobCreate(BaseModel):
    job_type: DiagnosticJobType
    max_records: int = Field(default=100, ge=10, le=500)
    duration_seconds: int = Field(default=10, ge=1, le=30)


class DiagnosticJobRead(BaseModel):
    id: int
    device_id: int
    job_type: DiagnosticJobType
    status: Literal["PENDING", "RUNNING", "COMPLETED", "FAILED", "CANCELLED", "EXPIRED"]
    requested_by: str
    parameters: dict[str, int]
    result: Any | None
    error: str | None
    created_at: datetime
    claimed_at: datetime | None
    completed_at: datetime | None
    expires_at: datetime


class DiagnosticJobAgentRead(BaseModel):
    id: int
    job_type: DiagnosticJobType
    parameters: dict[str, int]


class DiagnosticJobResultSubmission(BaseModel):
    status: Literal["COMPLETED", "FAILED"]
    result: Any | None = None
    error: str | None = Field(default=None, max_length=1000)


class UserRead(BaseModel):
    id: int
    username: str
    role: Literal["ADMIN", "OPERATOR", "VIEWER"]
    is_active: bool
    created_at: datetime
    model_config = ConfigDict(from_attributes=True)


class AuthStatus(BaseModel):
    setup_required: bool
    authenticated: bool
    user: UserRead | None = None


class SetupRequest(BaseModel):
    username: str = Field(min_length=3, max_length=80, pattern=r"^[A-Za-z0-9_.-]+$")
    password: str = Field(min_length=12, max_length=200)


class LoginRequest(BaseModel):
    username: str = Field(min_length=1, max_length=80)
    password: str = Field(min_length=1, max_length=200)


class AuthSessionCreated(BaseModel):
    token: str
    expires_at: datetime
    user: UserRead


class UserCreate(SetupRequest):
    role: Literal["ADMIN", "OPERATOR", "VIEWER"] = "VIEWER"


class UserUpdate(BaseModel):
    role: Literal["ADMIN", "OPERATOR", "VIEWER"]
    is_active: bool
    password: str | None = Field(default=None, min_length=12, max_length=200)


class AuditEventRead(BaseModel):
    id: int
    user_id: int | None
    username: str
    role: Literal["ADMIN", "OPERATOR", "VIEWER"]
    method: str
    path: str
    status_code: int
    client_ip: str | None
    timestamp: datetime
    model_config = ConfigDict(from_attributes=True)


class NotificationChannelUpdate(BaseModel):
    enabled: bool = False
    smtp_host: str | None = Field(default=None, max_length=255)
    smtp_port: int | None = Field(default=None, ge=1, le=65535)
    smtp_username: str | None = Field(default=None, max_length=255)
    email_from: str | None = Field(default=None, max_length=320)
    email_to: str | None = Field(default=None, max_length=1000)
    sms_from: str | None = Field(default=None, max_length=30)
    sms_to: str | None = Field(default=None, max_length=500)
    use_tls: bool = True


class NotificationChannelRead(NotificationChannelUpdate):
    id: int
    channel_type: Literal["EMAIL", "TEAMS", "SMS"]
    secret_configured: bool
    updated_at: datetime


class NotificationDeliveryRead(BaseModel):
    id: int
    alert_event_id: int | None
    channel_type: Literal["EMAIL", "TEAMS", "SMS"]
    status: Literal["PENDING", "SENT", "FAILED"]
    subject: str
    message: str
    attempt_count: int
    last_error: str | None
    created_at: datetime
    last_attempt_at: datetime | None
    sent_at: datetime | None
    model_config = ConfigDict(from_attributes=True)


class SnmpConfigUpdate(BaseModel):
    enabled: bool = False
    port: int = Field(default=161, ge=1, le=65535)
    community_env: Literal["AEGIS_SNMP_COMMUNITY"] = "AEGIS_SNMP_COMMUNITY"


class SnmpConfigRead(SnmpConfigUpdate):
    id: int
    device_id: int
    secret_configured: bool
    updated_at: datetime


class SnmpResultRead(BaseModel):
    id: int
    device_id: int
    timestamp: datetime
    status: Literal["SUCCESS", "FAILED"]
    system_name: str | None
    description: str | None
    location: str | None
    uptime_ticks: int | None
    interface_count: int | None
    error: str | None
    model_config = ConfigDict(from_attributes=True)


class VulnerabilityFindingRead(BaseModel):
    id: int
    scan_id: int
    severity: Literal["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
    category: str
    title: str
    description: str
    recommendation: str
    port: int | None
    cve_id: str | None
    cvss_score: float | None
    cve_url: str | None
    match_confidence: Literal["HIGH", "MEDIUM"] | None
    service_product: str | None
    service_version: str | None
    service_cpe: str | None
    model_config = ConfigDict(from_attributes=True)


class VulnerabilityScanRead(BaseModel):
    id: int
    device_id: int
    started_at: datetime
    completed_at: datetime | None
    status: Literal["RUNNING", "COMPLETED", "FAILED"]
    profile: Literal["FAST", "DETAILED", "AGGRESSIVE"]
    findings: list[VulnerabilityFindingRead]
    model_config = ConfigDict(from_attributes=True)


class AttackSurfaceFinding(BaseModel):
    severity: Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    category: str
    title: str
    port: int | None


class AttackSurfaceComparison(BaseModel):
    device_id: int
    current_scan_id: int | None
    previous_scan_id: int | None
    risk_score: int = Field(ge=0, le=100)
    new_findings: list[AttackSurfaceFinding]
    persistent_findings: list[AttackSurfaceFinding]
    resolved_findings: list[AttackSurfaceFinding]


class AttackPathRead(BaseModel):
    entry_device_id: int
    entry_device_name: str
    entry_ip_address: str
    entry_port: int
    entry_finding: str
    target_device_id: int
    target_device_name: str
    target_ip_address: str
    severity: Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    rationale: str


class AttackPathOverview(BaseModel):
    generated_at: datetime
    assessed_devices: int
    candidate_paths: int
    paths: list[AttackPathRead]


class TraceRouteRequest(BaseModel):
    device_id: int = Field(gt=0)


class TraceRouteHop(BaseModel):
    hop: int
    address: str | None
    latency_ms: float | None
    timed_out: bool


class TraceRouteRead(BaseModel):
    device_id: int
    device_name: str
    target: str
    completed: bool
    hops: list[TraceRouteHop]


class DnsQueryRequest(BaseModel):
    query: str = Field(min_length=1, max_length=253)

    @field_validator("query")
    @classmethod
    def clean_dns_query(cls, value: str) -> str:
        cleaned = value.strip().rstrip(".")
        if not cleaned or any(character.isspace() for character in cleaned):
            raise ValueError("Enter one hostname or IP address")
        return cleaned


class DnsQueryRead(BaseModel):
    query: str
    canonical_name: str | None
    addresses: list[str]
    reverse_name: str | None


class LabCommandRead(BaseModel):
    tool: Literal["nmap", "arp-scan", "ip-neigh", "curl", "dig", "test-connection"]
    target: str | None = None
    exit_code: int
    output: str
    duration_ms: float
    truncated: bool = False
    scanned_port_count: int | None = None


class LabCommandFilter(BaseModel):
    grep: str | None = Field(default=None, max_length=120)


class NmapTcpScanRequest(LabCommandFilter):
    device_id: int = Field(gt=0)
    ports: list[int] = Field(default_factory=lambda: [22, 80, 443, 445, 3389], min_length=1, max_length=1024)
    scan_mode: Literal["CUSTOM", "TOP_1000"] = "CUSTOM"
    profile: Literal["FAST", "FAST_VERSION", "DETAILED", "AGGRESSIVE"] = "FAST"
    service_detection: bool = False
    show_reason: bool = False

    @field_validator("ports")
    @classmethod
    def normalize_ports(cls, values: list[int]) -> list[int]:
        if any(port < 1 or port > 65535 for port in values):
            raise ValueError("Ports must be between 1 and 65535")
        return list(dict.fromkeys(values))


class TestConnectionPortRequest(LabCommandFilter):
    device_id: int = Field(gt=0)
    ports: list[int] = Field(default_factory=lambda: [22, 80, 443, 445, 3389], min_length=1, max_length=128)
    timeout_seconds: int = Field(default=2, ge=1, le=10)

    @field_validator("ports")
    @classmethod
    def normalize_ports(cls, values: list[int]) -> list[int]:
        if any(port < 1 or port > 65535 for port in values):
            raise ValueError("Ports must be between 1 and 65535")
        return list(dict.fromkeys(values))


class SecurityPlaybookRunCreate(BaseModel):
    device_id: int = Field(gt=0)
    profile: Literal["FAST", "DETAILED", "AGGRESSIVE"] = "FAST"


class SecurityPlaybookStepRead(BaseModel):
    id: int
    run_id: int
    position: int
    step_key: str
    name: str
    status: Literal["PENDING", "RUNNING", "COMPLETED", "FAILED", "CANCELLED"]
    started_at: datetime | None
    completed_at: datetime | None
    duration_ms: float | None
    output: str | None
    error: str | None
    model_config = ConfigDict(from_attributes=True)


class SecurityPlaybookRunRead(BaseModel):
    id: int
    device_id: int
    target_name: str
    target_ip: str
    requested_by: str
    profile: Literal["FAST", "DETAILED", "AGGRESSIVE"]
    status: Literal["QUEUED", "RUNNING", "COMPLETED", "PARTIAL", "FAILED", "CANCELLED"]
    current_step: str | None
    cancel_requested: bool
    created_at: datetime
    started_at: datetime | None
    completed_at: datetime | None
    summary: dict[str, object]
    error: str | None
    steps: list[SecurityPlaybookStepRead]
    model_config = ConfigDict(from_attributes=True)


class SecurityPlaybookRunIndexRead(BaseModel):
    id: int
    device_id: int
    target_name: str
    target_ip: str
    profile: Literal["FAST", "DETAILED", "AGGRESSIVE"]
    status: Literal["QUEUED", "RUNNING", "COMPLETED", "PARTIAL", "FAILED", "CANCELLED"]
    created_at: datetime
    model_config = ConfigDict(from_attributes=True)


class ArpScanRequest(LabCommandFilter):
    interface_name: str | None = Field(default=None, max_length=64, pattern=r"^[A-Za-z0-9][A-Za-z0-9_.: -]{0,63}$")


class NeighborTableRequest(LabCommandFilter):
    pass


class CurlRequest(LabCommandFilter):
    url: str = Field(min_length=8, max_length=2048)
    method: Literal["GET", "HEAD"] = "GET"
    insecure: bool = False

    @field_validator("url")
    @classmethod
    def validate_url(cls, value: str) -> str:
        from urllib.parse import urlsplit

        cleaned = value.strip()
        parsed = urlsplit(cleaned)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username or parsed.password:
            raise ValueError("Enter an HTTP or HTTPS URL without embedded credentials")
        return cleaned


class DigRequest(LabCommandFilter):
    query: str = Field(min_length=1, max_length=253, pattern=r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,252}$")
    record_type: Literal["A", "AAAA", "CNAME", "MX", "NS", "PTR", "SOA", "TXT", "ANY"] = "A"


class WirelessAdapterRead(BaseModel):
    name: str
    status: Literal["UP", "DOWN"]
    addresses: list[str]
    link_speed_mbps: int | None
    active_for_discovery: bool = False


class FirewallProfileRead(BaseModel):
    name: str
    enabled: bool
    default_inbound_action: str
    default_outbound_action: str


class FirewallRuleSummary(BaseModel):
    name: str
    direction: str
    action: str
    profile: str


class RouteEntryRead(BaseModel):
    destination: str
    prefix_length: int = Field(ge=0, le=128)
    next_hop: str | None
    interface: str
    metric: int | None = Field(default=None, ge=0)
    is_default: bool = False


class HostNetworkPolicyRead(BaseModel):
    platform: str
    firewall_source: str
    firewall_profiles: list[FirewallProfileRead]
    enabled_firewall_rule_count: int = Field(ge=0)
    firewall_rules: list[FirewallRuleSummary]
    routes: list[RouteEntryRead]
    notes: list[str] = Field(default_factory=list)


class PacketCaptureRequest(BaseModel):
    interface_name: str | None = Field(default=None, max_length=255)
    duration_seconds: int = Field(default=10, ge=1, le=30)
    max_packets: int = Field(default=200, ge=1, le=1000)


class PacketCaptureInterface(BaseModel):
    value: str
    label: str
    ip_address: str | None = None
    recommended: bool = False


class PacketMetadataRead(BaseModel):
    id: int
    capture_id: int
    timestamp: datetime
    source_ip: str | None
    destination_ip: str | None
    protocol: str
    source_port: int | None
    destination_port: int | None
    length_bytes: int
    model_config = ConfigDict(from_attributes=True)


class PacketCaptureRead(BaseModel):
    id: int
    interface_name: str | None
    duration_seconds: int
    max_packets: int
    started_at: datetime
    completed_at: datetime | None
    status: Literal["RUNNING", "COMPLETED", "FAILED"]
    error: str | None
    packets: list[PacketMetadataRead]
    model_config = ConfigDict(from_attributes=True)


class AnomalyEventRead(BaseModel):
    id: int
    device_id: int
    metric: str
    severity: Literal["WARNING", "CRITICAL"]
    score: float
    observed_value: float
    baseline_value: float
    message: str
    detected_at: datetime
    model_config = ConfigDict(from_attributes=True)


class AutomationSettingsUpdate(BaseModel):
    incidents_enabled: bool = True
    diagnostics_enabled: bool = False
    reports_enabled: bool = True
    drift_enabled: bool = True
    discovery_enabled: bool = False
    vulnerability_scans_enabled: bool = False
    service_discovery_enabled: bool = False
    report_interval_hours: int = Field(default=24, ge=1, le=720)
    report_days: int = Field(default=30, ge=7, le=365)
    discovery_interval_hours: int = Field(default=6, ge=1, le=720)
    vulnerability_interval_hours: int = Field(default=168, ge=24, le=2160)
    alert_escalation_minutes: int = Field(default=30, ge=5, le=1440)
    notification_window_enabled: bool = False
    notification_start_hour: int = Field(default=8, ge=0, le=23)
    notification_end_hour: int = Field(default=18, ge=0, le=23)
    desired_agent_version: str = Field(default="0.3.0", min_length=1, max_length=30)


class AutomationSettingsRead(AutomationSettingsUpdate):
    id: int
    last_report_at: datetime | None
    last_discovery_at: datetime | None
    last_discovery_network: str | None
    last_vulnerability_at: datetime | None
    updated_at: datetime
    model_config = ConfigDict(from_attributes=True)


class MaintenanceWindowCreate(BaseModel):
    name: str = Field(min_length=1, max_length=100)
    device_group: str | None = Field(default=None, max_length=80)
    starts_at: datetime
    ends_at: datetime
    repeat: Literal["NONE", "DAILY", "WEEKLY"] = "NONE"
    enabled: bool = True
    reason: str | None = Field(default=None, max_length=300)

    @field_validator("name", "device_group", "reason")
    @classmethod
    def clean_maintenance_text(cls, value: str | None) -> str | None:
        if value is None:
            return None
        cleaned = " ".join(value.split())
        return cleaned or None


class MaintenanceWindowRead(MaintenanceWindowCreate):
    id: int
    created_at: datetime
    active_now: bool = False
    model_config = ConfigDict(from_attributes=True)


class MaintenanceWindowUpdate(BaseModel):
    name: str = Field(default=None, min_length=1, max_length=100)
    device_group: str | None = Field(default=None, max_length=80)
    starts_at: datetime = None
    ends_at: datetime = None
    repeat: Literal["NONE", "DAILY", "WEEKLY"] = None
    enabled: bool = None
    reason: str | None = Field(default=None, max_length=300)

    @field_validator("name", "device_group", "reason")
    @classmethod
    def clean_maintenance_text(cls, value: str | None) -> str | None:
        if value is None:
            return None
        cleaned = " ".join(value.split())
        return cleaned or None


class IncidentRead(BaseModel):
    id: int
    correlation_key: str
    title: str
    summary: str
    severity: Literal["WARNING", "CRITICAL"]
    status: Literal["OPEN", "RESOLVED"]
    alert_ids: list[int]
    assigned_to: str | None
    operator_note: str | None
    opened_at: datetime
    updated_at: datetime
    resolved_at: datetime | None


class IncidentUpdate(BaseModel):
    assigned_to: str | None = Field(default=None, max_length=80)
    operator_note: str | None = Field(default=None, max_length=500)

    @field_validator("assigned_to", "operator_note")
    @classmethod
    def normalize_incident_text(cls, value: str | None) -> str | None:
        if value is None:
            return None
        normalized = " ".join(value.split())
        return normalized or None


class GeneratedReportRead(BaseModel):
    id: int
    report_type: str
    period_days: int
    filename: str
    device_count: int
    generated_at: datetime
    model_config = ConfigDict(from_attributes=True)


class AssetBaselineRead(BaseModel):
    id: int
    device_id: int
    signature: str
    snapshot: dict[str, Any]
    updated_at: datetime


class AutomationEventRead(BaseModel):
    id: int
    device_id: int | None
    event_type: str
    severity: Literal["INFO", "WARNING", "CRITICAL"]
    message: str
    details: dict[str, Any]
    created_at: datetime


class AutomationOverview(BaseModel):
    settings: AutomationSettingsRead
    active_maintenance_windows: int
    open_incidents: int
    outdated_agents: int
    drift_events: int
    generated_reports: int
    foundry_local_configured: bool


class AutomationSummary(BaseModel):
    source: Literal["LOCAL_MODEL", "BUILT_IN"]
    text: str
    generated_at: datetime


class SystemComponentRead(BaseModel):
    name: str
    status: Literal["HEALTHY", "WARNING", "DISABLED"]
    message: str


class SystemReadiness(BaseModel):
    status: Literal["HEALTHY", "WARNING"]
    checked_at: datetime
    components: list[SystemComponentRead]
