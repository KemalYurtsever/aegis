import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import RemoteDiagnosticsPanel from "./RemoteDiagnosticsPanel.jsx";
import AutomationModal from "./AutomationModal.jsx";
import SystemStatusModal from "./SystemStatusModal.jsx";
import AttackPathsModal from "./AttackPathsModal.jsx";
import SecurityWorkbenchModal from "./SecurityWorkbenchModal.jsx";
import aegisShield from "./assets/aegis-shield.png";
import aegisShieldDark from "./assets/aegis-shield-dark.png";
import { formatDate, formatMetric, toDateTimeLocal } from "./format.js";
import {
  checkDevice,
  checkAllDevices,
  checkSelectedDevices,
  updateSelectedMonitoring,
  updateSelectedGroup,
  collectHostMetrics,
  acknowledgeAlert,
  acknowledgeAllAlerts,
  createDevice,
  createServiceCheck,
  clearAllDevices,
  deleteDevice,
  getDeviceNotes,
  getDeviceActivity,
  getDeviceAttachments,
  createDeviceAttachment,
  deleteDeviceAttachment,
  downloadDeviceAttachment,
  createDeviceNote,
  deleteDeviceNote,
  deleteServiceCheck,
  discoverDevices,
  enrollAgent,
  getDashboard,
  listAlerts,
  getServiceOverview,
  getAgentOverview,
  getTopology,
  createTopologyLink,
  deleteTopologyLink,
  getSchedulerStatus,
  getServiceHistory,
  getServiceStatistics,
  getAuthStatus,
  setupAdmin,
  loginUser,
  logoutUser,
  setAuthToken,
  listUsers,
  createUser,
  updateUser,
  listAuditEvents,
  listNotificationChannels,
  updateNotificationChannel,
  testNotificationChannel,
  listNotificationDeliveries,
  retryNotificationDelivery,
  updateSnmpConfig,
  pollSnmp,
  runVulnerabilityScan,
  detectAnomalies,
  getPacketInterfaces,
  listPacketCaptures,
  startPacketCapture,
  getDiscoveryNetwork,
  getDeviceDetails,
  getDeviceChangeEvents,
  updateDevice,
  updateAlertRule,
  updateServiceCheck,
  runServiceCheck,
  scanCommonPorts,
  fingerprintDevice,
  fingerprintAllDevices,
  getDashboardRefresh,
  importDhcpLeases,
  getInventoryHealth,
  getAvailabilityReport,
  listBackups,
  getBackupStatus,
  createBackup,
  verifyBackup,
  downloadBackup,
  previewRetention,
  applyRetention,
  revokeAgent,
  pauseScheduler,
  resumeScheduler,
  refreshAssetBaselines,
} from "./api.js";

const EMPTY_DASHBOARD = {
  total_devices: 0,
  active_devices: 0,
  online_devices: 0,
  offline_devices: 0,
  unknown_devices: 0,
  average_latest_latency_ms: null,
  devices: [],
  recent_events: [],
  active_alert_count: 0,
  active_alerts: [],
  snmp_configured: false,
  notification_configured: false,
  notification_tested: false,
};
const EMPTY_INVENTORY_HEALTH = {
  total_issues: 0,
  expired_leases: 0,
  expiring_leases: 0,
  never_checked: 0,
  stale_checks: 0,
  duplicate_mac_records: 0,
  issues: [],
};
const LAST_DISCOVERY_NETWORK_KEY = "aegis_last_discovery_network";
const CLEAR_DEVICES_CONFIRMATION = "CLEAR ALL DEVICES";

function ipv4AddressInCidr(address, cidr) {
  const [networkAddress, prefixText] = String(cidr || "").split("/");
  const prefix = Number(prefixText);
  const toNumber = (value) => {
    const parts = String(value).split(".").map(Number);
    if (
      parts.length !== 4 ||
      parts.some((part) => !Number.isInteger(part) || part < 0 || part > 255)
    )
      return null;
    return parts.reduce((total, part) => ((total << 8) | part) >>> 0, 0);
  };
  const ip = toNumber(address);
  const network = toNumber(networkAddress);
  if (ip === null || network === null || !Number.isInteger(prefix) || prefix < 0 || prefix > 32)
    return false;
  const mask = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
  return (ip & mask) === (network & mask);
}

const EMPTY_TOPOLOGY = { interface_name: null, local_ip: null, groups: [], links: [] };
const EMPTY_AGENT_OVERVIEW = {
  total_agents: 0,
  reporting_agents: 0,
  delayed_agents: 0,
  offline_agents: 0,
  waiting_agents: 0,
  agents: [],
};
const EMPTY_SERVICE_OVERVIEW = {
  total_services: 0,
  active_services: 0,
  up_services: 0,
  down_services: 0,
  unknown_services: 0,
  services: [],
};
const EMPTY_FORM = {
  name: "",
  ip_address: "",
  device_type: "Other",
  description: "",
  asset_tag: "",
  owner: "",
  location: "",
  operating_system: "",
  criticality: "MEDIUM",
  device_group: "",
  tags: "",
  maintenance_until: "",
  maintenance_reason: "",
  is_active: true,
};
const DEFAULT_DEVICE_FILTERS = {
  query: "",
  status: "ALL",
  type: "ALL",
  group: "ALL",
  tag: "ALL",
};
const DASHBOARD_SECTION_DEFAULTS = {
  alerts: true,
  services: true,
  agents: true,
  topology: true,
  inventoryHealth: true,
};
const DEVICE_TYPES = [
  "Server",
  "Workstation",
  "Router",
  "Switch",
  "Printer",
  "Camera",
  "Access Point",
  "Other",
];
const GRAFANA_URL = import.meta.env.VITE_GRAFANA_URL || "http://127.0.0.1:3000";
const GRAFANA_DASHBOARD_URL =
  import.meta.env.VITE_GRAFANA_DASHBOARD_URL ||
  `${GRAFANA_URL}/d/aegis-overview/aegis-infrastructure-overview?orgId=1&kiosk&theme=dark&refresh=15s`;
const DEVICE_PAGE_SIZES = [10, 20];

function normalizedDevicePageSize(value) {
  return DEVICE_PAGE_SIZES.includes(Number(value)) ? Number(value) : 10;
}

function StatusBadge({ status }) {
  return (
    <span className={`status status--${status.toLowerCase()}`}>{status}</span>
  );
}

const PROFILE_FIELDS = [
  ["asset_tag", "asset tag"],
  ["device_group", "device group"],
  ["owner", "owner or team"],
  ["location", "location"],
  ["operating_system", "operating system"],
  ["mac_address", "MAC address"],
  ["criticality", "criticality"],
  ["description", "description"],
];

function deviceProfile(device) {
  const missing = PROFILE_FIELDS.filter(([field]) => !device[field]).map(
    ([, label]) => label,
  );
  return {
    percent: Math.round(
      ((PROFILE_FIELDS.length - missing.length) / PROFILE_FIELDS.length) * 100,
    ),
    missing,
  };
}

function ProfileCompleteness({ device }) {
  const profile = deviceProfile(device);
  const tone =
    profile.percent === 100
      ? "complete"
      : profile.percent >= 60
        ? "partial"
        : "incomplete";
  return (
    <span
      className={`profile-completeness profile-completeness--${tone}`}
      title={
        profile.missing.length
          ? `Missing: ${profile.missing.join(", ")}`
          : "All core asset fields are complete"
      }
    >
      Profile {profile.percent}%
    </span>
  );
}

function MetricCard({ label, value, tone }) {
  return (
    <article className={`metric-card metric-card--${tone}`}>
      <span>{label}</span>
      <strong>{value}</strong>
    </article>
  );
}

function OperationalInsights({ devices, onSelectDevice }) {
  const attention = devices
    .filter((device) => device.current_status !== "ONLINE" || (device.availability_percent ?? 100) < 90)
    .sort((a, b) => (a.availability_percent ?? -1) - (b.availability_percent ?? -1))
    .slice(0, 5);
  const slowest = devices
    .filter((device) => device.latest_latency_ms != null)
    .sort((a, b) => b.latest_latency_ms - a.latest_latency_ms)
    .slice(0, 5);
  const unstable = devices
    .filter((device) => device.availability_percent != null && device.availability_percent < 100)
    .sort((a, b) => a.availability_percent - b.availability_percent)
    .slice(0, 5);
  const recent = [...devices]
    .filter((device) => device.created_at)
    .sort((a, b) => new Date(b.created_at) - new Date(a.created_at))
    .slice(0, 5);
  const groups = [
    ["Needs attention", attention, (item) => item.current_status],
    ["Slowest", slowest, (item) => `${formatMetric(item.latest_latency_ms, " ms")}`],
    ["Most unstable", unstable, (item) => `${formatMetric(item.availability_percent, "%")}`],
    ["Recently discovered", recent, (item) => formatDate(item.created_at)],
  ];
  if (!devices.length) return null;
  return (
    <section className="panel operational-insights">
      <div className="panel-heading">
        <div><p className="eyebrow">Daily operations</p><h2>Operational focus</h2></div>
        <span>Prioritized automatically</span>
      </div>
      <div className="operational-insights__grid">
        {groups.map(([title, items, value]) => (
          <article key={title}>
            <h3>{title}</h3>
            {items.length ? (
              <ol>{items.map((item) => (
                <li key={item.id}>
                  <button onClick={() => onSelectDevice(item.id)}>{item.name}</button>
                  <span>{value(item)}</span>
                </li>
              ))}</ol>
            ) : <p>No matching devices.</p>}
          </article>
        ))}
      </div>
    </section>
  );
}

function CommandPalette({ commands, onClose }) {
  const [query, setQuery] = useState("");
  const [activeIndex, setActiveIndex] = useState(0);
  const inputRef = useRef(null);
  const resultRefs = useRef([]);
  const matches = useMemo(() => {
    const normalized = query.trim().toLocaleLowerCase();
    if (!normalized) return commands.slice(0, 12);
    return commands
      .filter((command) =>
        `${command.label} ${command.description || ""}`
          .toLocaleLowerCase()
          .includes(normalized),
      )
      .slice(0, 12);
  }, [commands, query]);

  useEffect(() => {
    setActiveIndex(0);
  }, [query]);

  useEffect(() => {
    resultRefs.current[activeIndex]?.scrollIntoView({ block: "nearest" });
  }, [activeIndex, matches]);

  useEffect(() => {
    inputRef.current?.focus();
    function handleKeyDown(event) {
      if (event.key === "Escape") onClose();
      if (event.key === "ArrowDown" && matches.length > 0) {
        event.preventDefault();
        setActiveIndex((index) => (index + 1) % matches.length);
      }
      if (event.key === "ArrowUp" && matches.length > 0) {
        event.preventDefault();
        setActiveIndex((index) => (index - 1 + matches.length) % matches.length);
      }
      if (event.key === "Home" && matches.length > 0) {
        event.preventDefault();
        setActiveIndex(0);
      }
      if (event.key === "End" && matches.length > 0) {
        event.preventDefault();
        setActiveIndex(matches.length - 1);
      }
      if (event.key === "Enter" && matches[activeIndex]) {
        event.preventDefault();
        onClose();
        matches[activeIndex].action();
      }
    }
    document.addEventListener("keydown", handleKeyDown);
    return () => document.removeEventListener("keydown", handleKeyDown);
  }, [activeIndex, matches, onClose]);

  function run(command) {
    onClose();
    command.action();
  }

  return (
    <div
      className="modal-backdrop command-palette-backdrop"
      onPointerDown={(event) => {
        if (event.target === event.currentTarget) onClose();
      }}
    >
      <section
        className="command-palette"
        role="dialog"
        aria-modal="true"
        aria-labelledby="command-palette-title"
      >
        <h2 id="command-palette-title" className="sr-only">
          Command palette
        </h2>
        <div className="command-palette__search">
          <span aria-hidden="true">⌕</span>
          <input
            ref={inputRef}
            type="search"
            value={query}
            onChange={(event) => setQuery(event.target.value)}
            placeholder="Search actions and devices…"
            aria-label="Search commands"
            role="combobox"
            aria-autocomplete="list"
            aria-expanded="true"
            aria-controls="command-palette-results"
            aria-activedescendant={
              matches[activeIndex]
                ? `command-${matches[activeIndex].id}`
                : undefined
            }
          />
          <kbd>Esc</kbd>
        </div>
        <div
          className="command-palette__results"
          id="command-palette-results"
          role="listbox"
          aria-label="Matching commands"
        >
          {matches.map((command, index) => (
            <button
              ref={(element) => {
                resultRefs.current[index] = element;
              }}
              id={`command-${command.id}`}
              key={command.id}
              type="button"
              role="option"
              aria-selected={index === activeIndex}
              onMouseMove={() => setActiveIndex(index)}
              onClick={() => run(command)}
            >
              <span className="command-palette__icon" aria-hidden="true">
                {command.icon || "→"}
              </span>
              <span>
                <strong>{command.label}</strong>
                {command.description && <small>{command.description}</small>}
              </span>
              {index === activeIndex && <kbd>Enter</kbd>}
            </button>
          ))}
          {matches.length === 0 && (
            <div className="command-palette__empty">
              No matching actions or devices.
            </div>
          )}
        </div>
        <footer>
          <span>Type to filter</span>
          <span>
            <kbd>↑↓</kbd> choose · <kbd>Enter</kbd> open · <kbd>Esc</kbd> close
          </span>
        </footer>
      </section>
    </div>
  );
}

function ObservabilityModal({ onClose }) {
  const [frameKey, setFrameKey] = useState(0);
  const [loading, setLoading] = useState(true);

  function reload() {
    setLoading(true);
    setFrameKey((current) => current + 1);
  }

  return (
    <div className="modal-backdrop observability-backdrop">
      <section
        className="modal observability-modal"
        role="dialog"
        aria-modal="true"
        aria-labelledby="observability-title"
      >
        <div className="modal-heading observability-heading">
          <div>
            <p className="eyebrow">Metrics and trends</p>
            <h2 id="observability-title">Observability dashboard</h2>
            <span>Read-only Grafana panels refresh every 15 seconds.</span>
          </div>
          <div className="row-actions">
            <button className="button button--secondary" onClick={reload}>
              Reload panels
            </button>
            <button
              className="icon-button"
              onClick={onClose}
              aria-label="Close observability dashboard"
            >
              ×
            </button>
          </div>
        </div>
        <div className="observability-frame">
          {loading && (
            <div className="observability-loading">Loading Grafana panels…</div>
          )}
          <iframe
            key={frameKey}
            src={GRAFANA_DASHBOARD_URL}
            title="Aegis Grafana dashboard"
            onLoad={() => setLoading(false)}
          />
        </div>
        <p className="observability-note">
          Grafana is displayed inside Aegis in local, read-only viewer mode. If
          panels remain unavailable, restart the observability containers.
        </p>
      </section>
    </div>
  );
}

function SetupGuidePanel({ items, onDismiss }) {
  const completed = items.filter((item) => item.complete).length;
  const percent = Math.round((completed / items.length) * 100);
  return (
    <section className="panel setup-guide" aria-labelledby="setup-guide-title">
      <div className="setup-guide__heading">
        <div>
          <p className="eyebrow">Getting started</p>
          <h2 id="setup-guide-title">Finish setting up Aegis</h2>
          <span>
            {completed} of {items.length} essentials complete
          </span>
        </div>
        <div
          className="setup-guide__progress"
          aria-label={`${percent}% complete`}
        >
          <strong>{percent}%</strong>
          <span>
            <i style={{ width: `${percent}%` }} />
          </span>
        </div>
        <button className="text-button" type="button" onClick={onDismiss}>
          Hide guide
        </button>
      </div>
      <div className="setup-guide__items">
        {items.map((item) => (
          <article
            key={item.id}
            className={
              item.complete ? "setup-guide__item complete" : "setup-guide__item"
            }
          >
            <span aria-hidden="true">{item.complete ? "✓" : item.number}</span>
            <div>
              <strong>{item.label}</strong>
              <small>{item.description}</small>
            </div>
            {!item.complete && item.action && (
              <button
                className="button button--secondary"
                onClick={item.action}
              >
                {item.actionLabel}
              </button>
            )}
          </article>
        ))}
      </div>
    </section>
  );
}

function SavedViewsControl({ views, onApply, onSave, onDelete }) {
  const [selectedId, setSelectedId] = useState("");
  const [naming, setNaming] = useState(false);
  const [name, setName] = useState("");

  function select(event) {
    const id = event.target.value;
    setSelectedId(id);
    const view = views.find((item) => item.id === id);
    if (view) onApply(view);
  }

  function save() {
    const normalized = name.trim();
    if (!normalized) return;
    onSave(normalized);
    setName("");
    setNaming(false);
  }

  return (
    <div className="saved-views">
      <select
        value={selectedId}
        onChange={select}
        aria-label="Saved device views"
      >
        <option value="">Saved views</option>
        {views.map((view) => (
          <option key={view.id} value={view.id}>
            {view.name}
          </option>
        ))}
      </select>
      {naming ? (
        <div className="saved-views__name">
          <input
            value={name}
            onChange={(event) => setName(event.target.value)}
            onKeyDown={(event) => {
              if (event.key === "Enter") save();
              if (event.key === "Escape") setNaming(false);
            }}
            maxLength="50"
            placeholder="View name"
            aria-label="Saved view name"
            autoFocus
          />
          <button
            className="button button--secondary"
            onClick={save}
            disabled={!name.trim()}
          >
            Save
          </button>
          <button className="text-button" onClick={() => setNaming(false)}>
            Cancel
          </button>
        </div>
      ) : (
        <button
          className="button button--secondary"
          onClick={() => setNaming(true)}
        >
          Save current view
        </button>
      )}
      {selectedId && (
        <button
          className="text-button text-button--danger"
          onClick={() => {
            onDelete(selectedId);
            setSelectedId("");
          }}
        >
          Delete view
        </button>
      )}
    </div>
  );
}

function DashboardDisplayControl({ sections, onChange, onReset }) {
  const [open, setOpen] = useState(false);
  const controlRef = useRef(null);

  useEffect(() => {
    if (!open) return undefined;
    function dismiss(event) {
      if (event.type === "keydown" && event.key !== "Escape") return;
      if (
        event.type === "pointerdown" &&
        controlRef.current?.contains(event.target)
      )
        return;
      setOpen(false);
    }
    document.addEventListener("keydown", dismiss);
    document.addEventListener("pointerdown", dismiss);
    return () => {
      document.removeEventListener("keydown", dismiss);
      document.removeEventListener("pointerdown", dismiss);
    };
  }, [open]);

  return (
    <div className="dashboard-display-control" ref={controlRef}>
      <button
        className="button button--secondary"
        type="button"
        aria-expanded={open}
        aria-controls="dashboard-display-options"
        onClick={() => setOpen((value) => !value)}
      >
        Customize
      </button>
      {open && (
        <div
          id="dashboard-display-options"
          className="dashboard-display-options"
          role="dialog"
          aria-label="Customize dashboard"
        >
          <strong>Dashboard sections</strong>
          <p>Choose the operational context you want to see.</p>
          {[
            ["alerts", "Active alerts"],
            ["services", "Service health"],
            ["agents", "Agent fleet"],
            ["topology", "Network topology"],
            ["inventoryHealth", "Inventory health"],
          ].map(([key, label]) => (
            <label key={key}>
              <input
                type="checkbox"
                checked={sections[key]}
                onChange={(event) => onChange(key, event.target.checked)}
              />
              {label}
            </label>
          ))}
          <button className="text-button" type="button" onClick={onReset}>
            Restore defaults
          </button>
        </div>
      )}
    </div>
  );
}

function LogicalNetworkPanel({ topology, onSelectDevice, canWrite, onChanged }) {
  const [expanded, setExpanded] = useState(true);
  const [linkForm, setLinkForm] = useState({ source_device_id: "", target_device_id: "", relationship_type: "CONNECTS_TO" });
  const [linkBusy, setLinkBusy] = useState(false);
  const [linkError, setLinkError] = useState("");

  if (topology.groups.length === 0) return null;
  const topologyDevices = topology.groups.flatMap((group) => group.devices);
  async function addLink() {
    setLinkBusy(true);
    setLinkError("");
    try {
      await createTopologyLink({
        source_device_id: Number(linkForm.source_device_id),
        target_device_id: Number(linkForm.target_device_id),
        relationship_type: linkForm.relationship_type,
      });
      setLinkForm({ source_device_id: "", target_device_id: "", relationship_type: "CONNECTS_TO" });
      await onChanged();
    } catch (error) {
      setLinkError(error.message);
    } finally {
      setLinkBusy(false);
    }
  }
  async function removeLink(linkId) {
    setLinkBusy(true);
    try {
      await deleteTopologyLink(linkId);
      await onChanged();
    } catch (error) {
      setLinkError(error.message);
    } finally {
      setLinkBusy(false);
    }
  }
  function DeviceNode({ device, label }) {
    return (
      <button
        className={`topology-device topology-device--${device.status.toLowerCase()}`}
        onClick={() => onSelectDevice(device.device_id)}
        title={`${device.ip_address} · ${device.status}`}
      >
        <span className="topology-device__dot" />
        <span>
          <strong>{device.name}</strong>
          <small>
            {label || device.device_type} · {device.ip_address}
          </small>
        </span>
      </button>
    );
  }
  return (
    <section className="panel topology-panel">
      <div className="panel-heading">
        <div>
          <p className="eyebrow">Logical topology</p>
          <h2>Networks, gateways and infrastructure</h2>
        </div>
        <div className="row-actions">
          <span>
            {topology.interface_name
              ? `${topology.interface_name} · ${topology.local_ip}`
              : `${topology.groups.length} networks`}
          </span>
          <button
            className="button button--secondary"
            onClick={() => setExpanded((value) => !value)}
          >
            {expanded ? "Collapse" : "Expand"}
          </button>
        </div>
      </div>
      {expanded && (
        <>
          <p className="topology-note">
            Relationships are inferred from VLAN, subnet and device type. They
            do not claim physical switch-port or cable discovery. Confirmed
            relationships are displayed separately from inferences.
          </p>
          <div className="topology-links">
            <div className="topology-links__heading">
              <strong>Confirmed relationships</strong>
              <span>{topology.links?.length || 0} recorded</span>
            </div>
            {canWrite && topologyDevices.length > 1 && (
              <div className="topology-link-form">
                <select aria-label="Relationship source" value={linkForm.source_device_id} onChange={(event) => setLinkForm({ ...linkForm, source_device_id: event.target.value })}>
                  <option value="">Source device</option>
                  {topologyDevices.map((device) => <option key={device.device_id} value={device.device_id}>{device.name}</option>)}
                </select>
                <select aria-label="Relationship type" value={linkForm.relationship_type} onChange={(event) => setLinkForm({ ...linkForm, relationship_type: event.target.value })}>
                  <option value="UPLINK">Uplink to</option>
                  <option value="CONNECTS_TO">Connects to</option>
                  <option value="ROUTES_TO">Routes to</option>
                  <option value="MANAGES">Manages</option>
                </select>
                <select aria-label="Relationship target" value={linkForm.target_device_id} onChange={(event) => setLinkForm({ ...linkForm, target_device_id: event.target.value })}>
                  <option value="">Target device</option>
                  {topologyDevices.filter((device) => String(device.device_id) !== String(linkForm.source_device_id)).map((device) => <option key={device.device_id} value={device.device_id}>{device.name}</option>)}
                </select>
                <button className="button button--secondary" onClick={addLink} disabled={linkBusy || !linkForm.source_device_id || !linkForm.target_device_id}>Add relationship</button>
              </div>
            )}
            {linkError && <div className="form-error">{linkError}</div>}
            {topology.links?.length > 0 && (
              <ol className="topology-link-list">
                {topology.links.map((link) => (
                  <li key={link.id}>
                    <button onClick={() => onSelectDevice(link.source_device_id)}>{link.source_name}</button>
                    <span>{link.relationship_type.replaceAll("_", " ")} →</span>
                    <button onClick={() => onSelectDevice(link.target_device_id)}>{link.target_name}</button>
                    {canWrite && <button className="text-button text-button--danger" onClick={() => removeLink(link.id)} disabled={linkBusy}>Remove</button>}
                  </li>
                ))}
              </ol>
            )}
          </div>
          <div className="topology-groups">
            {topology.groups.map((group) => {
              const gateway = group.devices.find(
                (device) => device.role === "GATEWAY",
              );
              const infrastructure = group.devices.filter(
                (device) => device.role === "INFRASTRUCTURE",
              );
              const endpoints = group.devices.filter(
                (device) => device.role === "ENDPOINT",
              );
              return (
                <article
                  className="topology-group topology-group--flow"
                  key={group.key}
                >
                  <header>
                    <div>
                      <strong>{group.label}</strong>
                      <span>
                        {group.device_count} devices · gateway{" "}
                        {group.gateway_ip || "unknown"}
                      </span>
                    </div>
                    <div className="topology-counts">
                      <span className="topology-count topology-count--online">
                        {group.online_devices}
                      </span>
                      <span className="topology-count topology-count--offline">
                        {group.offline_devices}
                      </span>
                      <span className="topology-count topology-count--unknown">
                        {group.unknown_devices}
                      </span>
                    </div>
                  </header>
                  <div className="topology-flow">
                    <div className="topology-tier">
                      <span className="topology-tier__label">Gateway</span>
                      {gateway ? (
                        <DeviceNode device={gateway} label="Gateway" />
                      ) : (
                        <div className="topology-placeholder">
                          <strong>
                            {group.gateway_ip || "Not identified"}
                          </strong>
                          <small>Gateway address</small>
                        </div>
                      )}
                    </div>
                    <span className="topology-connector" aria-hidden="true">
                      ↓
                    </span>
                    <div className="topology-tier">
                      <span className="topology-tier__label">
                        Infrastructure
                      </span>
                      <div className="topology-devices">
                        {infrastructure.length ? (
                          infrastructure.map((device) => (
                            <DeviceNode
                              key={device.device_id}
                              device={device}
                            />
                          ))
                        ) : (
                          <div className="topology-placeholder">
                            <strong>No switch or AP classified</strong>
                            <small>Edit device types to improve the map</small>
                          </div>
                        )}
                      </div>
                    </div>
                    <span className="topology-connector" aria-hidden="true">
                      ↓
                    </span>
                    <div className="topology-tier">
                      <span className="topology-tier__label">Endpoints</span>
                      <div className="topology-devices">
                        {endpoints.map((device) => (
                          <DeviceNode key={device.device_id} device={device} />
                        ))}
                      </div>
                    </div>
                  </div>
                </article>
              );
            })}
          </div>
        </>
      )}
    </section>
  );
}

function ServiceOverviewPanel({ overview, onSelectDevice }) {
  const [expanded, setExpanded] = useState(false);
  if (overview.total_services === 0) return null;
  const statusTone = (status) =>
    status === "UP" ? "up" : status === "DOWN" ? "down" : "unknown";
  return (
    <section className="panel service-overview-panel">
      <div className="panel-heading">
        <div>
          <p className="eyebrow">Application health</p>
          <h2>Service overview</h2>
        </div>
        <div className="row-actions service-overview-summary">
          <span><strong>{overview.up_services}</strong> up</span>
          <span><strong>{overview.down_services}</strong> down</span>
          <span><strong>{overview.unknown_services}</strong> unchecked</span>
          <button
            className="button button--secondary"
            type="button"
            onClick={() => setExpanded((value) => !value)}
          >
            {expanded ? "Hide services" : "View services"}
          </button>
        </div>
      </div>
      {expanded && (
        <div className="service-overview-list">
          {overview.services.map((service) => (
            <button
              key={service.id}
              className={`service-overview-row${service.is_active ? "" : " service-overview-row--inactive"}`}
              type="button"
              onClick={() => onSelectDevice(service.device_id)}
            >
              <span className={`service-status service-status--${statusTone(service.current_status)}`}>
                {service.is_active ? service.current_status : "PAUSED"}
              </span>
              <span>
                <strong>{service.name}</strong>
                <small>{service.check_type} · port {service.port}{service.check_type !== "TCP" ? service.path : ""}</small>
              </span>
              <span>
                <strong>{service.device_name}</strong>
                <small>{service.ip_address}</small>
              </span>
              <span>
                <strong>{formatMetric(service.last_response_time_ms, " ms")}</strong>
                <small>{service.last_checked_at ? formatDate(service.last_checked_at) : "Never checked"}</small>
              </span>
              <small>{service.diagnostic_reason || "Open device service details"}</small>
            </button>
          ))}
        </div>
      )}
    </section>
  );
}

function AgentFleetPanel({ overview, onSelectDevice }) {
  const [expanded, setExpanded] = useState(false);
  const [statusFilter, setStatusFilter] = useState("ALL");
  const statusPriority = { OFFLINE: 0, DELAYED: 1, WAITING: 2, REPORTING: 3 };
  const visibleAgents = useMemo(
    () =>
      overview.agents
        .filter(
          (agent) =>
            statusFilter === "ALL" || agent.health_status === statusFilter,
        )
        .sort((left, right) => {
          const priority =
            statusPriority[left.health_status] -
            statusPriority[right.health_status];
          if (priority !== 0) return priority;
          const leftSeen = left.last_seen_at
            ? new Date(left.last_seen_at).getTime()
            : 0;
          const rightSeen = right.last_seen_at
            ? new Date(right.last_seen_at).getTime()
            : 0;
          return (
            leftSeen - rightSeen ||
            left.device_name.localeCompare(right.device_name)
          );
        }),
    [overview.agents, statusFilter],
  );
  if (overview.total_agents === 0) return null;
  const statusTone = (status) =>
    status === "REPORTING" ? "up" : status === "OFFLINE" ? "down" : "unknown";
  return (
    <section className="panel agent-fleet-panel">
      <div className="panel-heading">
        <div>
          <p className="eyebrow">Authenticated collectors</p>
          <h2>Remote agent fleet</h2>
        </div>
        <div className="row-actions agent-fleet-summary">
          <span>
            <strong>{overview.reporting_agents}</strong> reporting
          </span>
          <span>
            <strong>{overview.delayed_agents}</strong> delayed
          </span>
          <span>
            <strong>{overview.offline_agents}</strong> offline
          </span>
          <span>
            <strong>{overview.waiting_agents}</strong> waiting
          </span>
          <button
            className="button button--secondary"
            onClick={() => setExpanded((value) => !value)}
          >
            {expanded ? "Hide agents" : "View agents"}
          </button>
        </div>
      </div>
      {expanded && (
        <>
          <div className="agent-fleet-tools">
            <span>
              {visibleAgents.length} of {overview.total_agents} agents
            </span>
            <label>
              <span>Health state</span>
              <select
                value={statusFilter}
                onChange={(event) => setStatusFilter(event.target.value)}
              >
                <option value="ALL">All states</option>
                <option value="OFFLINE">Offline</option>
                <option value="DELAYED">Delayed</option>
                <option value="WAITING">Waiting</option>
                <option value="REPORTING">Reporting</option>
              </select>
            </label>
            <small>Attention states and oldest reports are listed first.</small>
          </div>
          <div className="agent-fleet-list">
            {visibleAgents.length === 0 ? (
              <div className="empty-state empty-state--compact">
                No agents match this health state.
              </div>
            ) : (
              visibleAgents.map((agent) => (
                <button
                  key={agent.device_id}
                  className="agent-fleet-row"
                  onClick={() => onSelectDevice(agent.device_id)}
                >
                  <span
                    className={`service-status service-status--${statusTone(agent.health_status)}`}
                  >
                    {agent.health_status}
                  </span>
                  <span>
                    <strong>{agent.device_name}</strong>
                    <small>{agent.ip_address}</small>
                  </span>
                  <span>
                    <strong>{agent.hostname || "Not connected"}</strong>
                    <small>{agent.platform || "Platform pending"}</small>
                  </span>
                  <span>
                    <strong>
                      {agent.last_seen_at
                        ? formatDate(agent.last_seen_at)
                        : "No reports"}
                    </strong>
                    <small>
                      {agent.seconds_since_last_report === null
                        ? `Expected every ${agent.report_interval_seconds}s`
                        : `${agent.seconds_since_last_report}s since last report`}
                    </small>
                  </span>
                </button>
              ))
            )}
          </div>
        </>
      )}
    </section>
  );
}

const INVENTORY_ISSUE_LABELS = {
  LEASE_EXPIRED: "Lease expired",
  LEASE_EXPIRING: "Lease expiring",
  NEVER_CHECKED: "Never checked",
  STALE_CHECK: "Monitoring stale",
  DUPLICATE_MAC: "Duplicate MAC",
};

function InventoryHealthPanel({ health, onSelectDevice }) {
  const [expanded, setExpanded] = useState(false);
  const healthy = health.total_issues === 0;
  return (
    <section
      className={`panel inventory-health inventory-health--${healthy ? "healthy" : "attention"}`}
    >
      <div className="panel-heading">
        <div>
          <p className="eyebrow">Inventory quality</p>
          <h2>
            {healthy
              ? "Inventory health is clear"
              : `${health.total_issues} inventory issues`}
          </h2>
        </div>
        <div className="row-actions">
          <span>
            {healthy ? "No stale or conflicting records" : "Review recommended"}
          </span>
          {!healthy && (
            <button
              className="button button--secondary"
              onClick={() => setExpanded((value) => !value)}
            >
              {expanded ? "Hide issues" : "Review issues"}
            </button>
          )}
        </div>
      </div>
      {!healthy && (
        <div className="inventory-health-counts">
          <span>
            <strong>{health.expired_leases}</strong> expired
          </span>
          <span>
            <strong>{health.expiring_leases}</strong> expiring
          </span>
          <span>
            <strong>{health.never_checked}</strong> never checked
          </span>
          <span>
            <strong>{health.stale_checks}</strong> stale
          </span>
          <span>
            <strong>{health.duplicate_mac_records}</strong> duplicate MAC
          </span>
        </div>
      )}
      {expanded && (
        <div className="inventory-issues">
          {health.issues.map((issue, index) => (
            <button
              key={`${issue.device_id}-${issue.issue_type}-${index}`}
              onClick={() => onSelectDevice(issue.device_id)}
            >
              <span
                className={`inventory-issue-type inventory-issue-type--${issue.issue_type.toLowerCase()}`}
              >
                {INVENTORY_ISSUE_LABELS[issue.issue_type]}
              </span>
              <span>
                <strong>{issue.device_name}</strong>
                <small>
                  {issue.ip_address} · {issue.detail}
                </small>
              </span>
            </button>
          ))}
        </div>
      )}
    </section>
  );
}

function LatencyChart({ history }) {
  const samples = history
    .filter((item) => item.latency_ms !== null)
    .slice(0, 30)
    .reverse();
  if (samples.length < 2) {
    return (
      <div className="chart-empty">
        At least two successful checks are needed to draw the latency chart.
      </div>
    );
  }

  const width = 900;
  const height = 260;
  const padding = { top: 24, right: 24, bottom: 42, left: 56 };
  const values = samples.map((item) => item.latency_ms);
  const maximum = Math.max(...values, 1);
  const minimum = Math.min(...values, 0);
  const range = Math.max(maximum - minimum, 1);
  const x = (index) =>
    padding.left +
    (index / (samples.length - 1)) * (width - padding.left - padding.right);
  const y = (value) =>
    padding.top +
    ((maximum - value) / range) * (height - padding.top - padding.bottom);
  const points = samples
    .map((item, index) => `${x(index)},${y(item.latency_ms)}`)
    .join(" ");
  const areaPoints = `${padding.left},${height - padding.bottom} ${points} ${width - padding.right},${height - padding.bottom}`;
  const gridValues = [maximum, maximum - range / 2, minimum];

  return (
    <div className="chart-wrap">
      <svg
        className="latency-chart"
        viewBox={`0 0 ${width} ${height}`}
        role="img"
        aria-label={`Latency chart showing ${samples.length} successful checks`}
      >
        <defs>
          <linearGradient id="latencyFill" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stopColor="#4f7cff" stopOpacity="0.28" />
            <stop offset="100%" stopColor="#4f7cff" stopOpacity="0.02" />
          </linearGradient>
        </defs>
        {gridValues.map((value, index) => {
          const lineY = y(value);
          return (
            <g key={index}>
              <line
                x1={padding.left}
                y1={lineY}
                x2={width - padding.right}
                y2={lineY}
                className="chart-grid"
              />
              <text
                x={padding.left - 10}
                y={lineY + 4}
                className="chart-label"
                textAnchor="end"
              >
                {value.toFixed(1)} ms
              </text>
            </g>
          );
        })}
        <polygon points={areaPoints} fill="url(#latencyFill)" />
        <polyline points={points} className="chart-line" />
        {samples.map((item, index) => (
          <circle
            key={item.id}
            cx={x(index)}
            cy={y(item.latency_ms)}
            r="4"
            className="chart-point"
          >
            <title>{`${item.latency_ms} ms — ${formatDate(item.timestamp)}`}</title>
          </circle>
        ))}
        <text x={padding.left} y={height - 14} className="chart-label">
          {formatDate(samples[0].timestamp)}
        </text>
        <text
          x={width - padding.right}
          y={height - 14}
          className="chart-label"
          textAnchor="end"
        >
          {formatDate(samples.at(-1).timestamp)}
        </text>
      </svg>
    </div>
  );
}

function ServiceResponseChart({ history }) {
  const samples = history
    .filter((item) => item.response_time_ms !== null)
    .slice()
    .reverse();
  if (samples.length < 2)
    return (
      <div className="service-chart-empty">
        Two successful results are needed for a response-time chart.
      </div>
    );
  const width = 700;
  const height = 150;
  const padding = { top: 15, right: 18, bottom: 30, left: 48 };
  const values = samples.map((item) => item.response_time_ms);
  const maximum = Math.max(...values, 1);
  const minimum = Math.min(...values, 0);
  const range = Math.max(maximum - minimum, 1);
  const x = (index) =>
    padding.left +
    (index / (samples.length - 1)) * (width - padding.left - padding.right);
  const y = (value) =>
    padding.top +
    ((maximum - value) / range) * (height - padding.top - padding.bottom);
  const points = samples
    .map((item, index) => `${x(index)},${y(item.response_time_ms)}`)
    .join(" ");
  return (
    <div className="service-chart-wrap">
      <svg
        viewBox={`0 0 ${width} ${height}`}
        role="img"
        aria-label={`Service response-time chart with ${samples.length} successful results`}
      >
        <line
          x1={padding.left}
          y1={y(maximum)}
          x2={width - padding.right}
          y2={y(maximum)}
          className="chart-grid"
        />
        <line
          x1={padding.left}
          y1={y(minimum)}
          x2={width - padding.right}
          y2={y(minimum)}
          className="chart-grid"
        />
        <text
          x={padding.left - 8}
          y={y(maximum) + 4}
          textAnchor="end"
          className="chart-label"
        >
          {maximum.toFixed(1)} ms
        </text>
        <text
          x={padding.left - 8}
          y={y(minimum) + 4}
          textAnchor="end"
          className="chart-label"
        >
          {minimum.toFixed(1)} ms
        </text>
        <polyline points={points} className="service-chart-line" />
        {samples.map((item, index) => (
          <circle
            key={item.id}
            cx={x(index)}
            cy={y(item.response_time_ms)}
            r="3.5"
            className="service-chart-point"
          >
            <title>
              {item.response_time_ms} ms · {formatDate(item.timestamp)}
            </title>
          </circle>
        ))}
      </svg>
    </div>
  );
}

function deviceIdFromPath() {
  const match = window.location.pathname.match(/^\/devices\/(\d+)\/?$/);
  return match ? Number(match[1]) : null;
}

function DeviceForm({ device, onClose, onSaved }) {
  const [form, setForm] = useState(
    device
      ? {
          name: device.name,
          ip_address: device.ip_address,
          device_type: device.device_type,
          description: device.description || "",
          asset_tag: device.asset_tag || "",
          owner: device.owner || "",
          location: device.location || "",
          operating_system: device.operating_system || "",
          criticality: device.criticality || "MEDIUM",
          device_group: device.device_group || "",
          tags: (device.tags || []).join(", "),
          maintenance_until: toDateTimeLocal(device.maintenance_until),
          maintenance_reason: device.maintenance_reason || "",
          is_active: device.is_active,
        }
      : EMPTY_FORM,
  );
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState("");

  function updateField(event) {
    const { name, value, type, checked } = event.target;
    setForm((current) => ({
      ...current,
      [name]: type === "checkbox" ? checked : value,
    }));
  }

  async function handleSubmit(event) {
    event.preventDefault();
    setSaving(true);
    setError("");
    try {
      const payload = {
        ...form,
        description: form.description.trim() || null,
        asset_tag: form.asset_tag.trim() || null,
        owner: form.owner.trim() || null,
        location: form.location.trim() || null,
        operating_system: form.operating_system.trim() || null,
        device_group: form.device_group.trim() || null,
        tags: form.tags
          .split(",")
          .map((tag) => tag.trim())
          .filter(Boolean),
        maintenance_until: form.maintenance_until
          ? new Date(form.maintenance_until).toISOString()
          : null,
        maintenance_reason: form.maintenance_reason.trim() || null,
      };
      const saved = device
        ? await updateDevice(device.id, payload)
        : await createDevice(payload);
      await onSaved(saved);
    } catch (requestError) {
      setError(requestError.message);
    } finally {
      setSaving(false);
    }
  }

  return (
    <div
      className="modal-backdrop"
      role="presentation"
      onMouseDown={(event) => event.target === event.currentTarget && onClose()}
    >
      <section
        className="modal device-modal"
        role="dialog"
        aria-modal="true"
        aria-labelledby="device-form-title"
      >
        <div className="modal-heading">
          <div>
            <p className="eyebrow">Device inventory</p>
            <h2 id="device-form-title">
              {device ? "Edit device" : "Add device"}
            </h2>
          </div>
          <button className="icon-button" onClick={onClose} aria-label="Close">
            ×
          </button>
        </div>
        <form onSubmit={handleSubmit}>
          {error && (
            <div className="form-error" role="alert">
              {error}
            </div>
          )}
          <label>
            Name
            <input
              name="name"
              value={form.name}
              onChange={updateField}
              maxLength="80"
              required
              autoFocus
            />
          </label>
          <label>
            IP address
            <input
              name="ip_address"
              value={form.ip_address}
              onChange={updateField}
              placeholder="192.168.56.20"
              required
            />
          </label>
          <label>
            Device type
            <select
              name="device_type"
              value={form.device_type}
              onChange={updateField}
            >
              {DEVICE_TYPES.map((type) => (
                <option key={type}>{type}</option>
              ))}
            </select>
          </label>
          <div className="device-field-grid">
            <label>
              Asset tag
              <input
                name="asset_tag"
                value={form.asset_tag}
                onChange={updateField}
                maxLength="80"
                placeholder="LAB-0042"
              />
            </label>
            <label>
              Device group
              <input
                name="device_group"
                value={form.device_group}
                onChange={updateField}
                maxLength="80"
                placeholder="Finance Lab"
              />
            </label>
            <label>
              Tags
              <input
                name="tags"
                value={form.tags}
                onChange={updateField}
                maxLength="395"
                placeholder="production, edge"
              />
            </label>
            <label>
              Criticality
              <select
                name="criticality"
                value={form.criticality}
                onChange={updateField}
              >
                <option>LOW</option>
                <option>MEDIUM</option>
                <option>HIGH</option>
                <option>CRITICAL</option>
              </select>
            </label>
            <label>
              Owner or team
              <input
                name="owner"
                value={form.owner}
                onChange={updateField}
                maxLength="120"
              />
            </label>
            <label>
              Physical location
              <input
                name="location"
                value={form.location}
                onChange={updateField}
                maxLength="120"
              />
            </label>
            <label>
              Operating system
              <input
                name="operating_system"
                value={form.operating_system}
                onChange={updateField}
                maxLength="120"
                placeholder="Windows 11, Ubuntu 24.04…"
              />
            </label>
            <label>
              Maintenance until
              <input
                type="datetime-local"
                name="maintenance_until"
                value={form.maintenance_until}
                onChange={updateField}
              />
            </label>
          </div>
          <label>
            Maintenance reason
            <input
              name="maintenance_reason"
              value={form.maintenance_reason}
              onChange={updateField}
              maxLength="300"
              placeholder="Leave empty when no maintenance is planned"
            />
          </label>
          <label>
            Description
            <textarea
              name="description"
              value={form.description}
              onChange={updateField}
              maxLength="500"
              rows="3"
            />
          </label>
          <label className="check-field">
            <input
              type="checkbox"
              name="is_active"
              checked={form.is_active}
              onChange={updateField}
            />
            <span>Enable automatic monitoring</span>
          </label>
          <div className="modal-actions">
            <button
              type="button"
              className="button button--secondary"
              onClick={onClose}
            >
              Cancel
            </button>
            <button
              type="submit"
              className="button button--primary"
              disabled={saving}
            >
              {saving ? "Saving…" : device ? "Save changes" : "Add device"}
            </button>
          </div>
        </form>
      </section>
    </div>
  );
}

function AlertRuleEditor({ deviceId, rule, onSaved }) {
  const [form, setForm] = useState(rule);
  const [saving, setSaving] = useState(false);
  const [message, setMessage] = useState("");

  async function save(event) {
    event.preventDefault();
    setSaving(true);
    try {
      const saved = await updateAlertRule(deviceId, {
        enabled: form.enabled,
        consecutive_failures: Number(form.consecutive_failures),
        latency_threshold_ms:
          form.latency_threshold_ms === ""
            ? null
            : Number(form.latency_threshold_ms),
        cpu_threshold_percent:
          form.cpu_threshold_percent === ""
            ? null
            : Number(form.cpu_threshold_percent),
        memory_threshold_percent:
          form.memory_threshold_percent === ""
            ? null
            : Number(form.memory_threshold_percent),
        disk_threshold_percent:
          form.disk_threshold_percent === ""
            ? null
            : Number(form.disk_threshold_percent),
      });
      setForm(saved);
      setMessage("Alert rule saved.");
      onSaved(saved);
    } catch (error) {
      setMessage(error.message);
    } finally {
      setSaving(false);
    }
  }

  return (
    <form className="alert-rule-form" onSubmit={save}>
      <label className="check-field">
        <input
          type="checkbox"
          checked={form.enabled}
          onChange={(event) =>
            setForm({ ...form, enabled: event.target.checked })
          }
        />
        <span>Enable alerts</span>
      </label>
      <label>
        Offline after
        <input
          type="number"
          min="1"
          max="10"
          value={form.consecutive_failures}
          onChange={(event) =>
            setForm({ ...form, consecutive_failures: event.target.value })
          }
        />
        <span>consecutive failed checks</span>
      </label>
      <label>
        Latency warning
        <input
          type="number"
          min="0.01"
          max="60000"
          step="0.01"
          value={form.latency_threshold_ms ?? ""}
          onChange={(event) =>
            setForm({ ...form, latency_threshold_ms: event.target.value })
          }
        />
        <span>milliseconds; blank disables it</span>
      </label>
      <label>
        CPU warning
        <input
          type="number"
          min="0.01"
          max="100"
          step="0.01"
          value={form.cpu_threshold_percent ?? ""}
          onChange={(event) =>
            setForm({ ...form, cpu_threshold_percent: event.target.value })
          }
        />
        <span>percent; blank disables it</span>
      </label>
      <label>
        Memory warning
        <input
          type="number"
          min="0.01"
          max="100"
          step="0.01"
          value={form.memory_threshold_percent ?? ""}
          onChange={(event) =>
            setForm({ ...form, memory_threshold_percent: event.target.value })
          }
        />
        <span>percent; blank disables it</span>
      </label>
      <label>
        Disk warning
        <input
          type="number"
          min="0.01"
          max="100"
          step="0.01"
          value={form.disk_threshold_percent ?? ""}
          onChange={(event) =>
            setForm({ ...form, disk_threshold_percent: event.target.value })
          }
        />
        <span>percent; blank disables it</span>
      </label>
      {message && <p className="form-message">{message}</p>}
      <button className="button button--secondary" disabled={saving}>
        {saving ? "Saving…" : "Save alert rule"}
      </button>
    </form>
  );
}

function ServiceChecksPanel({ deviceId, checks, onChanged }) {
  const [showForm, setShowForm] = useState(false);
  const [editingCheck, setEditingCheck] = useState(null);
  const [runningId, setRunningId] = useState(null);
  const [error, setError] = useState("");
  const [scanning, setScanning] = useState(false);
  const [scanResult, setScanResult] = useState(null);
  const [addingPort, setAddingPort] = useState(null);
  const [historyCheckId, setHistoryCheckId] = useState(null);
  const [serviceHistory, setServiceHistory] = useState([]);
  const [serviceStatistics, setServiceStatistics] = useState(null);
  const [historyLoading, setHistoryLoading] = useState(false);
  const [form, setForm] = useState({
    name: "",
    check_type: "TCP",
    port: 80,
    path: "/",
    is_active: true,
  });

  async function addCheck(event) {
    event.preventDefault();
    try {
      const payload = { ...form, port: Number(form.port) };
      if (editingCheck) await updateServiceCheck(editingCheck.id, payload);
      else await createServiceCheck(deviceId, payload);
      setShowForm(false);
      setEditingCheck(null);
      setError("");
      await onChanged();
    } catch (requestError) {
      setError(requestError.message);
    }
  }

  function openNewCheck() {
    setEditingCheck(null);
    setForm({
      name: "",
      check_type: "TCP",
      port: 80,
      path: "/",
      is_active: true,
    });
    setShowForm(true);
  }

  function openEditCheck(check) {
    setEditingCheck(check);
    setForm({
      name: check.name,
      check_type: check.check_type,
      port: check.port,
      path: check.path,
      is_active: check.is_active,
    });
    setShowForm(true);
  }

  function closeCheckForm() {
    setShowForm(false);
    setEditingCheck(null);
  }

  async function run(checkId) {
    setRunningId(checkId);
    try {
      await runServiceCheck(checkId);
      setError("");
      await onChanged();
    } catch (requestError) {
      setError(requestError.message);
    } finally {
      setRunningId(null);
    }
  }

  async function remove(check) {
    if (!window.confirm(`Delete service check ${check.name} and its history?`))
      return;
    try {
      await deleteServiceCheck(check.id);
      await onChanged();
    } catch (requestError) {
      setError(requestError.message);
    }
  }

  async function scanPorts() {
    if (
      !window.confirm(
        "Run an Nmap scan of the 1,000 most common TCP ports on this registered device? Only continue for a device you own or are authorized to test.",
      )
    )
      return;
    setScanning(true);
    setError("");
    setScanResult(null);
    try {
      setScanResult(await scanCommonPorts(deviceId));
    } catch (requestError) {
      setError(requestError.message);
    } finally {
      setScanning(false);
    }
  }

  async function monitorOpenPort(port) {
    const checkType =
      port.port === 443
        ? "HTTPS"
        : port.port === 80 || port.port === 8080
          ? "HTTP"
          : "TCP";
    setAddingPort(port.port);
    setError("");
    try {
      await createServiceCheck(deviceId, {
        name: `${port.service} on port ${port.port}`,
        check_type: checkType,
        port: port.port,
        path: "/",
        is_active: true,
      });
      await onChanged();
    } catch (requestError) {
      setError(requestError.message);
    } finally {
      setAddingPort(null);
    }
  }

  async function toggleServiceHistory(checkId) {
    if (historyCheckId === checkId) {
      setHistoryCheckId(null);
      setServiceHistory([]);
      setServiceStatistics(null);
      return;
    }
    setHistoryCheckId(checkId);
    setHistoryLoading(true);
    setError("");
    try {
      const [history, statistics] = await Promise.all([
        getServiceHistory(checkId),
        getServiceStatistics(checkId),
      ]);
      setServiceHistory(history);
      setServiceStatistics(statistics);
    } catch (requestError) {
      setError(requestError.message);
      setServiceHistory([]);
      setServiceStatistics(null);
    } finally {
      setHistoryLoading(false);
    }
  }

  return (
    <section className="panel service-panel">
      <div className="panel-heading">
        <div>
          <p className="eyebrow">Application health</p>
          <h2>Service checks</h2>
        </div>
        <div className="row-actions">
          <button
            className="button button--secondary"
            onClick={scanPorts}
            disabled={scanning}
          >
            {scanning ? "Scanning 1,000 ports…" : "Scan top 1,000 TCP ports"}
          </button>
          <button
            className="button button--secondary"
            onClick={showForm ? closeCheckForm : openNewCheck}
          >
            {showForm ? "Cancel" : "+ Add check"}
          </button>
        </div>
      </div>
      {error && <div className="form-error service-error">{error}</div>}
      {scanResult && (
        <div className="port-scan-result">
          <div>
            <strong>
              {scanResult.open_ports.length} open of{" "}
              {scanResult.scanned_port_count} scanned
            </strong>
            <span>
              {scanResult.target_ip} · {scanResult.scanner} ·{" "}
              {(scanResult.duration_ms / 1000).toFixed(1)} seconds
            </span>
          </div>
          {scanResult.open_ports.length === 0 ? (
            <p>No open TCP ports were found in this scan.</p>
          ) : (
            <ul>
              {scanResult.open_ports.map((port) => {
                const monitored = checks.some(
                  (check) => check.port === port.port,
                );
                return (
                  <li key={port.port}>
                    <strong>{port.port}</strong>
                    <span>{port.service}</span>
                    <small>
                      {port.response_time_ms == null
                        ? "Nmap detected"
                        : `${port.response_time_ms} ms`}
                    </small>
                    <button
                      className="button button--check"
                      disabled={monitored || addingPort !== null}
                      onClick={() => monitorOpenPort(port)}
                    >
                      {monitored
                        ? "Monitored"
                        : addingPort === port.port
                          ? "Adding…"
                          : "Monitor"}
                    </button>
                  </li>
                );
              })}
            </ul>
          )}
        </div>
      )}
      {historyCheckId && serviceStatistics && (
        <section
          className="service-analysis"
          aria-label="Service performance summary"
        >
          <div className="service-summary-grid">
            <article>
              <span>Availability</span>
              <strong>
                {formatMetric(serviceStatistics.availability_percent, "%")}
              </strong>
            </article>
            <article>
              <span>Average response</span>
              <strong>
                {formatMetric(
                  serviceStatistics.average_response_time_ms,
                  " ms",
                )}
              </strong>
            </article>
            <article>
              <span>Successful checks</span>
              <strong>{serviceStatistics.up_checks}</strong>
            </article>
            <article>
              <span>Failed checks</span>
              <strong>{serviceStatistics.down_checks}</strong>
            </article>
          </div>
          <ServiceResponseChart history={serviceHistory} />
        </section>
      )}
      {showForm && (
        <form className="service-form" onSubmit={addCheck}>
          <label>
            Name
            <input
              required
              maxLength="80"
              value={form.name}
              onChange={(event) =>
                setForm({ ...form, name: event.target.value })
              }
              placeholder="Web server"
            />
          </label>
          <label>
            Type
            <select
              value={form.check_type}
              onChange={(event) =>
                setForm({
                  ...form,
                  check_type: event.target.value,
                  port:
                    event.target.value === "HTTPS"
                      ? 443
                      : event.target.value === "HTTP"
                        ? 80
                        : form.port,
                })
              }
            >
              <option>TCP</option>
              <option>HTTP</option>
              <option>HTTPS</option>
            </select>
          </label>
          <label>
            Port
            <input
              type="number"
              min="1"
              max="65535"
              required
              value={form.port}
              onChange={(event) =>
                setForm({ ...form, port: event.target.value })
              }
            />
          </label>
          {form.check_type !== "TCP" && (
            <label>
              Path
              <input
                required
                value={form.path}
                onChange={(event) =>
                  setForm({ ...form, path: event.target.value })
                }
                placeholder="/health"
              />
            </label>
          )}
          <label className="check-field">
            <input
              type="checkbox"
              checked={form.is_active}
              onChange={(event) =>
                setForm({ ...form, is_active: event.target.checked })
              }
            />
            <span>Automatic checks</span>
          </label>
          <button className="button button--primary">
            {editingCheck ? "Save service check" : "Create service check"}
          </button>
        </form>
      )}
      {checks.length === 0 ? (
        <div className="empty-state empty-state--compact">
          No TCP or web service checks configured.
        </div>
      ) : (
        <div className="service-list">
          {checks.map((check) => (
            <article key={check.id} className="service-item-wrap">
              <div className="service-item">
                <div>
                  <span
                    className={`service-status service-status--${check.current_status.toLowerCase()}`}
                  >
                    {check.current_status}
                  </span>
                  <strong>{check.name}</strong>
                  <p>
                    {check.check_type} · port {check.port}
                    {check.check_type !== "TCP"
                      ? ` · ${check.path}`
                      : ""} · {check.is_active ? "automatic" : "paused"}
                  </p>
                  <small>
                    {check.last_checked_at
                      ? `${formatMetric(check.last_response_time_ms, " ms")} · ${formatDate(check.last_checked_at)}`
                      : "Never checked"}
                  </small>
                </div>
                <div className="row-actions">
                  <button
                    className="button button--secondary"
                    onClick={() => toggleServiceHistory(check.id)}
                  >
                    {historyCheckId === check.id ? "Hide history" : "History"}
                  </button>
                  <button
                    className="button button--check"
                    disabled={runningId !== null}
                    onClick={() => run(check.id)}
                  >
                    {runningId === check.id ? "Running…" : "Run"}
                  </button>
                  <button
                    className="icon-button"
                    onClick={() => openEditCheck(check)}
                    aria-label={`Edit ${check.name}`}
                  >
                    ✎
                  </button>
                  <button
                    className="icon-button"
                    onClick={() => remove(check)}
                    aria-label={`Delete ${check.name}`}
                  >
                    ×
                  </button>
                </div>
              </div>
              {historyCheckId === check.id && (
                <div className="service-history">
                  {historyLoading ? (
                    <p>Loading service history…</p>
                  ) : serviceHistory.length === 0 ? (
                    <p>No service results recorded yet.</p>
                  ) : (
                    <div className="table-wrap">
                      <table>
                        <thead>
                          <tr>
                            <th>Timestamp</th>
                            <th>Status</th>
                            <th>Response</th>
                            <th>HTTP</th>
                            <th>Diagnostic</th>
                          </tr>
                        </thead>
                        <tbody>
                          {serviceHistory.map((result) => (
                            <tr key={result.id}>
                              <td>{formatDate(result.timestamp)}</td>
                              <td>
                                <span
                                  className={`service-status service-status--${result.status.toLowerCase()}`}
                                >
                                  {result.status}
                                </span>
                              </td>
                              <td>
                                {formatMetric(result.response_time_ms, " ms")}
                              </td>
                              <td>{result.http_status_code ?? "—"}</td>
                              <td>
                                {result.diagnostic_reason?.replaceAll(
                                  "_",
                                  " ",
                                ) ?? "—"}
                              </td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  )}
                </div>
              )}
            </article>
          ))}
        </div>
      )}
    </section>
  );
}

function HostMetricsPanel({ device, metrics, onChanged }) {
  const [collecting, setCollecting] = useState(false);
  const latest = metrics[0];
  const isLocal =
    device.ip_address === "127.0.0.1" || device.ip_address === "::1";

  async function collect() {
    setCollecting(true);
    try {
      await collectHostMetrics(device.id);
      await onChanged();
    } finally {
      setCollecting(false);
    }
  }

  if (!isLocal) return null;
  return (
    <section className="panel host-panel">
      <div className="panel-heading">
        <div>
          <p className="eyebrow">Local agent</p>
          <h2>Host resources</h2>
        </div>
        <button
          className="button button--secondary"
          onClick={collect}
          disabled={collecting}
        >
          {collecting ? "Collecting…" : "Collect now"}
        </button>
      </div>
      {!latest ? (
        <div className="empty-state empty-state--compact">
          Waiting for the first resource sample.
        </div>
      ) : (
        <div className="resource-grid">
          {[
            { label: "CPU", value: latest.cpu_percent, tone: "blue" },
            { label: "Memory", value: latest.memory_percent, tone: "purple" },
            { label: "Disk", value: latest.disk_percent, tone: "orange" },
          ].map((metric) => (
            <article key={metric.label} className="resource-card">
              <div>
                <span>{metric.label}</span>
                <strong>{metric.value}%</strong>
              </div>
              <div className="resource-bar">
                <span
                  className={`resource-bar__fill resource-bar__fill--${metric.tone}`}
                  style={{ width: `${Math.min(metric.value, 100)}%` }}
                />
              </div>
            </article>
          ))}
          <p className="resource-time">
            Latest sample: {formatDate(latest.timestamp)} · {metrics.length}{" "}
            stored samples
          </p>
        </div>
      )}
    </section>
  );
}

function RemoteAgentPanel({ device, agent, onChanged }) {
  const [token, setToken] = useState("");
  const [busy, setBusy] = useState(false);
  const isLocal =
    device.ip_address === "127.0.0.1" || device.ip_address === "::1";
  if (isLocal) return null;

  async function enroll() {
    if (
      agent &&
      !window.confirm(
        "Generate a new token? The existing remote agent token will stop working immediately.",
      )
    )
      return;
    setBusy(true);
    try {
      const created = await enrollAgent(device.id);
      setToken(created.token);
      await onChanged();
    } finally {
      setBusy(false);
    }
  }

  async function revoke() {
    if (
      !window.confirm("Revoke this agent token and stop accepting its reports?")
    )
      return;
    setBusy(true);
    try {
      await revokeAgent(device.id);
      setToken("");
      await onChanged();
    } finally {
      setBusy(false);
    }
  }

  return (
    <section className="panel agent-panel">
      <div className="panel-heading">
        <div>
          <p className="eyebrow">Authenticated collector</p>
          <h2>Remote host agent</h2>
        </div>
        <div className="row-actions">
          <button
            className="button button--secondary"
            onClick={enroll}
            disabled={busy}
          >
            {agent ? "Rotate token" : "Enroll agent"}
          </button>
          {agent && (
            <button
              className="button button--danger"
              onClick={revoke}
              disabled={busy}
            >
              Revoke
            </button>
          )}
        </div>
      </div>
      <div className="agent-content">
        {!agent ? (
          <p>No remote agent is enrolled for this device.</p>
        ) : (
          <>
            <div className="agent-status">
              <span
                className={`service-status service-status--${agent.health_status === "REPORTING" ? "up" : agent.health_status === "OFFLINE" ? "down" : "unknown"}`}
              >
                {agent.health_status}
              </span>
              <strong>{agent.hostname || "Agent has not connected yet"}</strong>
              <p>
                {agent.platform ||
                  "Platform information will appear after the first report."}
              </p>
              <small>
                {agent.last_seen_at
                  ? `Last report: ${formatDate(agent.last_seen_at)} · every ${agent.report_interval_seconds}s · agent ${agent.agent_version}`
                  : "No metric reports received"}
              </small>
            </div>
          </>
        )}
        {token && (
          <div className="token-box">
            <strong>Copy this token now—it will not be shown again.</strong>
            <code>{token}</code>
            <p>
              Set it as <code>AEGIS_AGENT_TOKEN</code> on the remote machine.
            </p>
          </div>
        )}
      </div>
    </section>
  );
}

function SnmpPanel({ deviceId, config, history, onChanged }) {
  const [form, setForm] = useState(config);
  const [busy, setBusy] = useState(false);
  const latest = history[0];
  async function save() {
    setBusy(true);
    try {
      await updateSnmpConfig(deviceId, {
        enabled: form.enabled,
        port: Number(form.port),
        community_env: form.community_env,
      });
      await onChanged();
    } finally {
      setBusy(false);
    }
  }
  async function poll() {
    setBusy(true);
    try {
      await pollSnmp(deviceId);
      await onChanged();
    } finally {
      setBusy(false);
    }
  }
  return (
    <section className="panel snmp-panel">
      <div className="panel-heading">
        <div>
          <p className="eyebrow">Network management</p>
          <h2>SNMP monitoring</h2>
        </div>
        <span>
          {config.secret_configured ? "Community configured" : "Secret missing"}
        </span>
      </div>
      <div className="snmp-controls">
        <p className="panel-help">SNMP reads management counters from devices that explicitly expose UDP 161. The community value stays in a server environment variable and is never returned to the browser.</p>
        <label>
          <input
            type="checkbox"
            checked={form.enabled}
            onChange={(e) => setForm({ ...form, enabled: e.target.checked })}
          />{" "}
          Automatic polling
        </label>
        <label>
          UDP port
          <input
            type="number"
            min="1"
            max="65535"
            value={form.port}
            onChange={(e) => setForm({ ...form, port: e.target.value })}
          />
        </label>
        <label>
          Community environment variable
          <input
            value={form.community_env}
            onChange={(e) =>
              setForm({ ...form, community_env: e.target.value.toUpperCase() })
            }
          />
        </label>
        <button
          className="button button--secondary"
          onClick={save}
          disabled={busy}
        >
          Save
        </button>
        <button
          className="button button--primary"
          onClick={poll}
          disabled={busy}
        >
          {busy ? "Working…" : "Poll now"}
        </button>
      </div>
      {latest ? (
        <div className="snmp-result">
          <StatusBadge
            status={latest.status === "SUCCESS" ? "ONLINE" : "OFFLINE"}
          />
          <strong>{latest.system_name || "SNMP poll"}</strong>
          <span>{latest.description || latest.error}</span>
          <dl>
            <div>
              <dt>Uptime</dt>
              <dd>
                {latest.uptime_ticks === null
                  ? "—"
                  : `${Math.round(latest.uptime_ticks / 100)} seconds`}
              </dd>
            </div>
            <div>
              <dt>Interfaces</dt>
              <dd>{latest.interface_count ?? "—"}</dd>
            </div>
            <div>
              <dt>Location</dt>
              <dd>{latest.location || "—"}</dd>
            </div>
            <div>
              <dt>Checked</dt>
              <dd>{formatDate(latest.timestamp)}</dd>
            </div>
          </dl>
        </div>
      ) : (
        <div className="empty-state empty-state--compact">
          No SNMP polls recorded.
        </div>
      )}
    </section>
  );
}

function VulnerabilityPanel({ device, scans, comparison, onChanged, canScan }) {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const latest = scans[0];

  async function scan() {
    const confirmed = window.confirm(
      `Scan the top 1,000 TCP ports on registered device ${device.ip_address}, identify open-service versions, and compare supported fingerprints with NVD? ` +
        "This assessment does not exploit services.",
    );
    if (!confirmed) return;
    setBusy(true);
    setError("");
    try {
      await runVulnerabilityScan(device.id);
      await onChanged();
    } catch (requestError) {
      setError(requestError.message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <section className="panel vulnerability-panel">
      <div className="panel-heading">
        <div>
          <p className="eyebrow">Administrator assessment</p>
          <h2>Attack surface</h2>
        </div>
        {canScan && (
          <button
            className="button button--primary"
            onClick={scan}
            disabled={busy}
          >
            {busy ? "Scanning services & CVEs…" : "Run assessment"}
          </button>
        )}
      </div>
      {error && <div className="form-error">{error}</div>}
      <p className="panel-help">The fast assessment scans the top 1,000 TCP ports first, then gives low-intensity version detection six seconds only when ports are open. It runs signed, bounded Nuclei exposure checks on discovered web endpoints, searches NVD when product and version evidence is available, then adds CISA KEV and FIRST EPSS priority data. Fast detection may miss quiet services; every match still requires review.</p>
      {!latest ? (
        <div className="empty-state empty-state--compact">
          No assessments recorded. The bounded assessment checks registered
          devices without exploiting services.
        </div>
      ) : (
        <div>
          <div className="scan-summary">
            <strong>{latest.findings.length} findings</strong>
            <span>
              {latest.findings.filter((finding) => finding.cve_id).length} CVE candidates
            </span>
            <span>
              {latest.findings.filter((finding) => finding.category === "NUCLEI_VALIDATION").length} template matches
            </span>
            <span>Risk {comparison?.risk_score ?? 0}/100</span>
            <span>
              {comparison?.previous_scan_id
                ? `${comparison.new_findings.length} new · ${comparison.persistent_findings.length} persistent · ${comparison.resolved_findings.length} resolved`
                : "Baseline assessment"}
            </span>
            <span>
              {latest.status} · {formatDate(latest.completed_at)}
            </span>
          </div>
          <div className="finding-list">
            {latest.findings.map((finding) => (
              <article
                key={finding.id}
                className={`finding finding--${finding.severity.toLowerCase()}`}
              >
                <span>{finding.severity}</span>
                <div>
                  <strong>
                    {finding.title}
                    {finding.port ? ` · TCP ${finding.port}` : ""}
                  </strong>
                  <p>{finding.description}</p>
                  {finding.cve_id && (
                    <div className="cve-finding-meta">
                      {finding.cvss_score != null && <span>CVSS {finding.cvss_score}</span>}
                      {finding.known_exploited && (
                        <span className="cve-priority-badge cve-priority-badge--kev">
                          CISA KEV{finding.kev_date_added ? ` · ${finding.kev_date_added}` : ""}
                        </span>
                      )}
                      {finding.epss_score != null && (
                        <span
                          className={finding.epss_score >= 0.1 ? "cve-priority-badge cve-priority-badge--epss-high" : ""}
                          title={finding.epss_percentile != null ? `EPSS percentile ${(finding.epss_percentile * 100).toFixed(1)}%` : undefined}
                        >
                          EPSS {(finding.epss_score * 100).toFixed(1)}%
                        </span>
                      )}
                      {finding.match_confidence && <span>{finding.match_confidence} confidence</span>}
                      {finding.service_product && (
                        <span>
                          {finding.service_product}
                          {finding.service_version ? ` ${finding.service_version}` : ""}
                        </span>
                      )}
                      {finding.cve_url && (
                        <a href={finding.cve_url} target="_blank" rel="noreferrer">
                          Open NVD record
                        </a>
                      )}
                    </div>
                  )}
                  {finding.validation_tool && (
                    <div className="validation-finding-meta">
                      <span>{finding.validation_tool}</span>
                      {finding.validation_check_id && <code>{finding.validation_check_id}</code>}
                      {finding.validation_target && (
                        <a href={finding.validation_target} target="_blank" rel="noreferrer">
                          Matched endpoint
                        </a>
                      )}
                      {finding.validation_reference && (
                        <a href={finding.validation_reference} target="_blank" rel="noreferrer">
                          Template reference
                        </a>
                      )}
                    </div>
                  )}
                  {finding.service_cpe && <code className="cve-finding-cpe">{finding.service_cpe}</code>}
                  {finding.known_exploited && finding.kev_required_action && (
                    <small className="kev-required-action">CISA action: {finding.kev_required_action}</small>
                  )}
                  <small>{finding.recommendation}</small>
                </div>
              </article>
            ))}
          </div>
        </div>
      )}
    </section>
  );
}

function AnomalyPanel({ deviceId, anomalies, onChanged }) {
  const [busy, setBusy] = useState(false);
  async function detect() {
    setBusy(true);
    try {
      await detectAnomalies(deviceId);
      await onChanged();
    } finally {
      setBusy(false);
    }
  }
  return (
    <section className="panel anomaly-panel">
      <div className="panel-heading">
        <div>
          <p className="eyebrow">Local intelligence</p>
          <h2>Anomaly detection</h2>
        </div>
        <button
          className="button button--secondary"
          onClick={detect}
          disabled={busy}
        >
          {busy ? "Analyzing…" : "Analyze now"}
        </button>
      </div>
      {anomalies.length === 0 ? (
        <div className="empty-state empty-state--compact">
          No anomalies detected. At least 21 samples are required for a
          baseline.
        </div>
      ) : (
        <div className="finding-list">
          {anomalies.map((item) => (
            <article
              className={`finding finding--${item.severity.toLowerCase()}`}
              key={item.id}
            >
              <span>{item.severity}</span>
              <div>
                <strong>
                  {item.metric} · score {item.score}
                </strong>
                <p>{item.message}</p>
                <small>{formatDate(item.detected_at)}</small>
              </div>
            </article>
          ))}
        </div>
      )}
    </section>
  );
}

const DHCP_HEADER_ALIASES = {
  hostname: ["hostname", "host_name", "host", "name", "client_name"],
  ip_address: ["ip_address", "ip", "address", "leased_ip"],
  mac_address: ["mac_address", "mac", "hardware_address", "chaddr"],
  lease_expires_at: [
    "lease_expires_at",
    "lease_expires",
    "expires_at",
    "expiration",
    "expiry",
  ],
  vlan: ["vlan", "vlan_id", "network"],
};

function parseCsvRecords(text) {
  const records = [];
  let record = [];
  let field = "";
  let quoted = false;
  for (let index = 0; index < text.length; index += 1) {
    const character = text[index];
    if (quoted) {
      if (character === '"' && text[index + 1] === '"') {
        field += '"';
        index += 1;
      } else if (character === '"') quoted = false;
      else field += character;
    } else if (character === '"' && field.length === 0) quoted = true;
    else if (character === ",") {
      record.push(field);
      field = "";
    } else if (character === "\n") {
      record.push(field);
      records.push(record);
      record = [];
      field = "";
    } else if (character !== "\r") field += character;
  }
  if (quoted) throw new Error("The CSV contains an unterminated quoted field.");
  if (field.length > 0 || record.length > 0) {
    record.push(field);
    records.push(record);
  }
  return records.filter((row) => row.some((value) => value.trim() !== ""));
}

function normalizeHeader(value) {
  return value
    .replace(/^\uFEFF/, "")
    .trim()
    .toLocaleLowerCase()
    .replace(/[\s-]+/g, "_");
}

function rowsFromDhcpCsv(text) {
  if (text.includes("\0"))
    throw new Error("Binary data is not a valid CSV file.");
  const records = parseCsvRecords(text);
  if (records.length < 2)
    throw new Error(
      "The CSV must contain a header and at least one lease row.",
    );
  const headers = records[0].map(normalizeHeader);
  const columnFor = (field) =>
    headers.findIndex((header) => DHCP_HEADER_ALIASES[field].includes(header));
  const columns = Object.fromEntries(
    Object.keys(DHCP_HEADER_ALIASES).map((field) => [field, columnFor(field)]),
  );
  if (columns.ip_address < 0)
    throw new Error(
      "Missing required IP column. Use ip_address, ip, address, or leased_ip.",
    );
  if (records.length - 1 > 1000)
    throw new Error("A single import can contain at most 1,000 lease rows.");

  return records.slice(1).map((record, index) => {
    const value = (field) =>
      columns[field] < 0 ? "" : (record[columns[field]] || "").trim();
    const ip = value("ip_address");
    const octets = ip.split(".");
    if (
      octets.length !== 4 ||
      octets.some((part) => !/^\d{1,3}$/.test(part) || Number(part) > 255)
    ) {
      throw new Error(
        `Row ${index + 2}: ${ip || "empty value"} is not a valid IPv4 address.`,
      );
    }
    const mac = value("mac_address");
    const compactMac = mac.replace(/[:.\-]/g, "");
    if (mac && !/^[0-9a-fA-F]{12}$/.test(compactMac))
      throw new Error(`Row ${index + 2}: invalid MAC address.`);
    const expires = value("lease_expires_at");
    const parsedExpiry = expires ? new Date(expires) : null;
    if (parsedExpiry && Number.isNaN(parsedExpiry.getTime()))
      throw new Error(
        `Row ${index + 2}: lease expiry must be an ISO date/time.`,
      );
    return {
      hostname: value("hostname") || null,
      ip_address: ip,
      mac_address: mac || null,
      lease_expires_at: parsedExpiry ? parsedExpiry.toISOString() : null,
      vlan: value("vlan") || null,
    };
  });
}

function formatBytes(value) {
  if (value < 1024) return `${value} B`;
  if (value < 1024 * 1024) return `${(value / 1024).toFixed(1)} KB`;
  return `${(value / (1024 * 1024)).toFixed(1)} MB`;
}

function ReliabilityModal({ onClose }) {
  const [backups, setBackups] = useState([]);
  const [status, setStatus] = useState(null);
  const [days, setDays] = useState(null);
  const [preview, setPreview] = useState(null);
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState("");
  const [restoreFile, setRestoreFile] = useState("");
  const [restoreConfirmation, setRestoreConfirmation] = useState("");
  const load = useCallback(async () => {
    try {
      const [backupItems, backupStatus, retention] = await Promise.all([
        listBackups(),
        getBackupStatus(),
        previewRetention(days),
      ]);
      setBackups(backupItems);
      setStatus(backupStatus);
      setPreview(retention);
      setDays((current) => current ?? backupStatus.history_retention_days);
    } catch (error) {
      setMessage(error.message);
    }
  }, [days]);
  useEffect(() => {
    load();
  }, [load]);

  async function makeBackup() {
    setBusy(true);
    setMessage("");
    try {
      const result = await createBackup();
      setMessage(
        `Backup verified: ${result.filename} · ${result.device_count ?? "unknown"} devices.`,
      );
      await load();
    } catch (error) {
      setMessage(error.message);
    } finally {
      setBusy(false);
    }
  }

  async function verify(filename) {
    setBusy(true);
    setMessage("");
    try {
      const result = await verifyBackup(filename);
      setMessage(
        result.valid
          ? `${filename} passed integrity verification.`
          : `${filename} failed: ${result.integrity_result}`,
      );
    } catch (error) {
      setMessage(error.message);
    } finally {
      setBusy(false);
    }
  }

  async function download(filename) {
    setBusy(true);
    setMessage("");
    try {
      const blob = await downloadBackup(filename);
      const url = URL.createObjectURL(blob);
      const link = document.createElement("a");
      link.href = url;
      link.download = filename;
      document.body.appendChild(link);
      link.click();
      link.remove();
      window.setTimeout(() => URL.revokeObjectURL(url), 1000);
    } catch (error) {
      setMessage(error.message);
    } finally {
      setBusy(false);
    }
  }

  async function cleanup() {
    if (!preview || preview.total_records === 0) return;
    const confirmation = window.prompt(
      `This will permanently delete ${preview.total_records} monitoring records older than ${days} days. Type DELETE HISTORY to continue.`,
    );
    if (confirmation !== "DELETE HISTORY") {
      setMessage("Cleanup cancelled. No records were deleted.");
      return;
    }
    setBusy(true);
    setMessage("");
    try {
      const result = await applyRetention(Number(days));
      setMessage(`${result.total_records} old monitoring records deleted.`);
      await load();
    } catch (error) {
      setMessage(error.message);
    } finally {
      setBusy(false);
    }
  }

  async function prepareRestore() {
    if (!restoreFile || restoreConfirmation !== "RESTORE BACKUP") return;
    setBusy(true);
    setMessage("");
    try {
      const result = await verifyBackup(restoreFile);
      if (!result.valid) throw new Error(`Backup failed verification: ${result.integrity_result}`);
      const command = [
        ".\\stop-hybrid.ps1",
        `.\\restore-backup.ps1 -BackupFile ".\\backend\\backups\\${restoreFile}"`,
        ".\\start-hybrid.ps1",
      ].join("\r\n");
      await navigator.clipboard.writeText(command);
      setMessage(`Verified restore procedure copied for ${restoreFile}. Run it from the AEGIS project root; the current database will be preserved automatically.`);
      setRestoreConfirmation("");
    } catch (error) {
      setMessage(error.message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="modal-backdrop">
      <section
        className="modal reliability-modal"
        role="dialog"
        aria-modal="true"
        aria-labelledby="reliability-title"
      >
        <div className="modal-heading">
          <div>
            <p className="eyebrow">Data protection</p>
            <h2 id="reliability-title">Backups and retention</h2>
          </div>
          <button className="icon-button" onClick={onClose} aria-label="Close">
            ×
          </button>
        </div>
        {message && (
          <div className="form-message reliability-message">{message}</div>
        )}
        <section className="reliability-section">
          <div className="reliability-title">
            <div>
              <h3>SQLite backups</h3>
              <p>
                {status
                  ? `${status.enabled ? "Automatic" : "Manual only"} · every ${status.interval_hours} hours · keeping ${status.keep_count}`
                  : "Loading backup configuration…"}
              </p>
            </div>
            <button
              className="button button--primary"
              onClick={makeBackup}
              disabled={busy}
            >
              {busy ? "Working…" : "Create backup"}
            </button>
          </div>
          {backups.length === 0 ? (
            <div className="empty-state empty-state--compact">
              No local backups have been created yet.
            </div>
          ) : (
            <div className="table-wrap reliability-table">
              <table>
                <thead>
                  <tr>
                    <th>Created</th>
                    <th>Filename</th>
                    <th>Size</th>
                    <th>Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {backups.map((backup) => (
                    <tr key={backup.filename}>
                      <td>{formatDate(backup.created_at)}</td>
                      <td>
                        <code>{backup.filename}</code>
                      </td>
                      <td>{formatBytes(backup.size_bytes)}</td>
                      <td>
                        <div className="row-actions">
                          <button
                            className="button button--secondary"
                            onClick={() => verify(backup.filename)}
                            disabled={busy}
                          >
                            Verify
                          </button>
                          <button
                            className="button button--secondary"
                            onClick={() => download(backup.filename)}
                            disabled={busy}
                          >
                            Download
                          </button>
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </section>
        <section className="reliability-section">
          <div className="reliability-title">
            <div>
              <h3>Guided restore</h3>
              <p>A restore must stop AEGIS so SQLite cannot be replaced while in use. This verifies the selected backup and prepares the guarded stop, restore, and restart commands.</p>
            </div>
          </div>
          <div className="retention-controls">
            <label>
              Backup
              <select value={restoreFile} onChange={(event) => setRestoreFile(event.target.value)}>
                <option value="">Select a verified backup</option>
                {backups.map((backup) => <option key={backup.filename} value={backup.filename}>{backup.filename}</option>)}
              </select>
            </label>
            <label>
              Type RESTORE BACKUP
              <input value={restoreConfirmation} onChange={(event) => setRestoreConfirmation(event.target.value)} autoComplete="off" />
            </label>
            <button className="button button--danger" onClick={prepareRestore} disabled={busy || !restoreFile || restoreConfirmation !== "RESTORE BACKUP"}>
              Verify and copy restore steps
            </button>
          </div>
        </section>
        <section className="reliability-section">
          <div className="reliability-title">
            <div>
              <h3>Monitoring history retention</h3>
              <p>
                Preview first. A verified safety backup is created before
                cleanup; devices, users, and settings are never removed.
              </p>
            </div>
          </div>
          <div className="retention-controls">
            <label>
              Keep history for
              <input
                type="number"
                min="7"
                max="3650"
                value={days ?? ""}
                onChange={(event) =>
                  setDays(
                    Math.max(
                      7,
                      Math.min(3650, Number(event.target.value) || 7),
                    ),
                  )
                }
              />{" "}
              days
            </label>
            <button
              className="button button--secondary"
              onClick={load}
              disabled={busy || days === null}
            >
              Refresh preview
            </button>
            <button
              className="button button--danger"
              onClick={cleanup}
              disabled={busy || !preview?.total_records}
            >
              Delete previewed records
            </button>
          </div>
          {preview && (
            <div className="retention-preview">
              <strong>
                {preview.total_records} records before{" "}
                {formatDate(preview.cutoff)}
              </strong>
              <span>
                {preview.monitor_results} reachability ·{" "}
                {preview.service_results} service · {preview.host_metrics} host
                metrics · {preview.snmp_results} SNMP · {preview.anomaly_events}{" "}
                anomalies
              </span>
            </div>
          )}
        </section>
      </section>
    </div>
  );
}

function AvailabilityReportModal({ onClose }) {
  const [days, setDays] = useState(30);
  const [report, setReport] = useState(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const load = useCallback(async () => {
    setBusy(true);
    setError("");
    try {
      setReport(await getAvailabilityReport(days));
    } catch (requestError) {
      setError(requestError.message);
    } finally {
      setBusy(false);
    }
  }, [days]);
  useEffect(() => {
    load();
  }, [load]);
  const checked =
    report?.devices.filter((device) => device.total_checks > 0) || [];
  const averageAvailability = checked.length
    ? checked.reduce((sum, device) => sum + device.availability_percent, 0) /
      checked.length
    : null;
  const totalIncidents = checked.reduce(
    (sum, device) => sum + device.offline_incidents,
    0,
  );

  async function exportReport() {
    if (!report) return;
    setBusy(true);
    setError("");
    try {
      const { default: ExcelJS } = await import("exceljs");
      const workbook = new ExcelJS.Workbook();
      workbook.creator = "Aegis";
      workbook.created = new Date();
      const sheet = workbook.addWorksheet("Availability", {
        views: [{ state: "frozen", ySplit: 1 }],
      });
      const headers = [
        "Device",
        "IP address",
        "Criticality",
        "Status",
        "Checks",
        "Online",
        "Offline",
        "Availability",
        "Average latency (ms)",
        "Offline incidents",
        "Longest offline streak",
      ];
      const rows = report.devices.map((device) => [
        device.device_name,
        device.ip_address,
        device.criticality,
        device.current_status,
        device.total_checks,
        device.online_checks,
        device.offline_checks,
        device.availability_percent === null
          ? null
          : device.availability_percent / 100,
        device.average_latency_ms,
        device.offline_incidents,
        device.longest_offline_streak,
      ]);
      sheet.addTable({
        name: "AvailabilityReport",
        ref: "A1",
        headerRow: true,
        style: { theme: "TableStyleMedium2", showRowStripes: true },
        columns: headers.map((name) => ({ name, filterButton: true })),
        rows,
      });
      sheet.columns = [
        { width: 32 },
        { width: 18 },
        { width: 14 },
        { width: 14 },
        { width: 12 },
        { width: 12 },
        { width: 12 },
        { width: 16 },
        { width: 22 },
        { width: 18 },
        { width: 22 },
      ];
      sheet.getColumn(8).numFmt = "0.00%";
      sheet.getColumn(9).numFmt = "0.00";
      const summary = workbook.addWorksheet("Report Summary");
      summary.columns = [{ width: 28 }, { width: 28 }];
      summary.addRows([
        ["Aegis Availability Report", null],
        ["Period", `${report.days} days`],
        ["From", new Date(report.starts_at)],
        ["To", new Date(report.ends_at)],
        ["Devices with checks", checked.length],
        [
          "Average availability",
          averageAvailability === null ? null : averageAvailability / 100,
        ],
        ["Offline incidents", totalIncidents],
      ]);
      summary.getCell("A1").font = { bold: true, size: 16 };
      summary.getCell("B6").numFmt = "0.00%";
      summary.getCell("B3").numFmt = "yyyy-mm-dd hh:mm:ss";
      summary.getCell("B4").numFmt = "yyyy-mm-dd hh:mm:ss";
      const buffer = await workbook.xlsx.writeBuffer();
      const blob = new Blob([buffer], {
        type: "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
      });
      const url = URL.createObjectURL(blob);
      const link = document.createElement("a");
      link.href = url;
      link.download = `aegis-availability-${report.days}d-${new Date().toISOString().slice(0, 10)}.xlsx`;
      document.body.appendChild(link);
      link.click();
      link.remove();
      window.setTimeout(() => URL.revokeObjectURL(url), 1000);
    } catch (exportError) {
      setError(exportError.message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="modal-backdrop">
      <section
        className="modal report-modal"
        role="dialog"
        aria-modal="true"
        aria-labelledby="report-title"
      >
        <div className="modal-heading">
          <div>
            <p className="eyebrow">Operations reporting</p>
            <h2 id="report-title">Availability report</h2>
          </div>
          <button className="icon-button" onClick={onClose} aria-label="Close">
            ×
          </button>
        </div>
        <div className="report-controls">
          <label>
            Reporting period
            <select
              value={days}
              onChange={(event) => setDays(Number(event.target.value))}
            >
              <option value="7">Last 7 days</option>
              <option value="30">Last 30 days</option>
              <option value="90">Last 90 days</option>
              <option value="180">Last 180 days</option>
              <option value="365">Last 365 days</option>
            </select>
          </label>
          <button
            className="button button--secondary"
            onClick={load}
            disabled={busy}
          >
            {busy ? "Loading…" : "Refresh"}
          </button>
          <button
            className="button button--excel"
            onClick={exportReport}
            disabled={busy || !report}
          >
            Export Excel
          </button>
        </div>
        {error && <div className="form-error report-error">{error}</div>}
        {report && (
          <>
            <div className="report-summary">
              <article>
                <span>Devices with checks</span>
                <strong>
                  {checked.length}/{report.devices.length}
                </strong>
              </article>
              <article>
                <span>Average availability</span>
                <strong>
                  {formatMetric(
                    averageAvailability === null
                      ? null
                      : averageAvailability.toFixed(2),
                    "%",
                  )}
                </strong>
              </article>
              <article>
                <span>Offline incidents</span>
                <strong>{totalIncidents}</strong>
              </article>
              <article>
                <span>Generated</span>
                <strong>{formatDate(report.generated_at)}</strong>
              </article>
            </div>
            <div className="table-wrap report-table">
              <table>
                <thead>
                  <tr>
                    <th>Device</th>
                    <th>Criticality</th>
                    <th>Status</th>
                    <th>Checks</th>
                    <th>Availability</th>
                    <th>Avg. latency</th>
                    <th>Incidents</th>
                    <th>Longest offline streak</th>
                  </tr>
                </thead>
                <tbody>
                  {report.devices.map((device) => (
                    <tr key={device.device_id}>
                      <td>
                        <strong>{device.device_name}</strong>
                        <span>{device.ip_address}</span>
                      </td>
                      <td>
                        <span
                          className={`criticality criticality--${device.criticality.toLowerCase()}`}
                        >
                          {device.criticality}
                        </span>
                      </td>
                      <td>
                        <StatusBadge status={device.current_status} />
                      </td>
                      <td>{device.total_checks}</td>
                      <td>{formatMetric(device.availability_percent, "%")}</td>
                      <td>{formatMetric(device.average_latency_ms, " ms")}</td>
                      <td>{device.offline_incidents}</td>
                      <td>{device.longest_offline_streak} checks</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </>
        )}
      </section>
    </div>
  );
}

function AlertHistoryModal({ onClose, onSelectDevice }) {
  const [alerts, setAlerts] = useState([]);
  const [statusFilter, setStatusFilter] = useState("ALL");
  const [typeFilter, setTypeFilter] = useState("ALL");
  const [page, setPage] = useState(1);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const pageSize = 20;

  const load = useCallback(async () => {
    setLoading(true);
    setError("");
    try {
      setAlerts(await listAlerts(false, 500));
    } catch (requestError) {
      setError(requestError.message);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    load();
  }, [load]);

  const alertStatus = (alert) =>
    alert.resolved_at ? "RESOLVED" : alert.acknowledged_at ? "ACKNOWLEDGED" : "ACTIVE";
  const alertTypes = useMemo(
    () => [...new Set(alerts.map((alert) => alert.alert_type))].sort(),
    [alerts],
  );
  const filtered = alerts.filter(
    (alert) =>
      (statusFilter === "ALL" || alertStatus(alert) === statusFilter) &&
      (typeFilter === "ALL" || alert.alert_type === typeFilter),
  );
  const pageCount = Math.max(1, Math.ceil(filtered.length / pageSize));
  const currentPage = Math.min(page, pageCount);
  const visible = filtered.slice((currentPage - 1) * pageSize, currentPage * pageSize);

  useEffect(() => {
    setPage(1);
  }, [statusFilter, typeFilter]);

  function openDevice(deviceId) {
    onClose();
    onSelectDevice(deviceId);
  }

  return (
    <div className="modal-backdrop">
      <section
        className="modal alert-history-modal"
        role="dialog"
        aria-modal="true"
        aria-labelledby="alert-history-title"
      >
        <div className="modal-heading">
          <div>
            <p className="eyebrow">Operations record</p>
            <h2 id="alert-history-title">Alert history</h2>
          </div>
          <button className="icon-button" onClick={onClose} aria-label="Close">×</button>
        </div>
        <div className="alert-history-controls">
          <label>
            State
            <select value={statusFilter} onChange={(event) => setStatusFilter(event.target.value)}>
              <option value="ALL">All states</option>
              <option value="ACTIVE">Active</option>
              <option value="ACKNOWLEDGED">Acknowledged</option>
              <option value="RESOLVED">Resolved</option>
            </select>
          </label>
          <label>
            Alert type
            <select value={typeFilter} onChange={(event) => setTypeFilter(event.target.value)}>
              <option value="ALL">All types</option>
              {alertTypes.map((type) => <option key={type} value={type}>{type.replaceAll("_", " ")}</option>)}
            </select>
          </label>
          <span>{filtered.length} of {alerts.length} alerts</span>
          <button className="button button--secondary" onClick={load} disabled={loading}>
            {loading ? "Refreshing…" : "Refresh"}
          </button>
        </div>
        {error && <div className="form-error">{error}</div>}
        <div className="alert-history-list">
          {visible.map((alert) => {
            const state = alertStatus(alert);
            return (
              <button key={alert.id} type="button" onClick={() => openDevice(alert.device_id)}>
                <span className={`alert-history-state alert-history-state--${state.toLowerCase()}`}>{state}</span>
                <span>
                  <strong>{alert.device_name}</strong>
                  <small>{alert.alert_type.replaceAll("_", " ")} · {alert.severity}</small>
                </span>
                <span>{alert.message}</span>
                <time>{formatDate(alert.triggered_at)}</time>
              </button>
            );
          })}
          {!loading && visible.length === 0 && (
            <div className="empty-state empty-state--compact">No alerts match these filters.</div>
          )}
        </div>
        <nav className="alert-history-pagination" aria-label="Alert history pagination">
          <span>Page {currentPage} of {pageCount}</span>
          <button className="button button--secondary" onClick={() => setPage((value) => Math.max(1, value - 1))} disabled={currentPage === 1}>Previous</button>
          <button className="button button--secondary" onClick={() => setPage((value) => Math.min(pageCount, value + 1))} disabled={currentPage === pageCount}>Next</button>
        </nav>
      </section>
    </div>
  );
}

function DhcpImportModal({ onClose, onImported }) {
  const [rows, setRows] = useState([]);
  const [fileName, setFileName] = useState("");
  const [error, setError] = useState("");
  const [result, setResult] = useState(null);
  const [busy, setBusy] = useState(false);

  async function chooseFile(event) {
    const file = event.target.files?.[0];
    setRows([]);
    setResult(null);
    setError("");
    setFileName(file?.name || "");
    if (!file) return;
    const allowedTypes = [
      "",
      "text/csv",
      "application/csv",
      "application/vnd.ms-excel",
    ];
    if (
      !file.name.toLocaleLowerCase().endsWith(".csv") ||
      !allowedTypes.includes(file.type)
    ) {
      setError("Choose a CSV file. Other file types are not accepted.");
      return;
    }
    if (file.size > 2 * 1024 * 1024) {
      setError("The CSV is larger than the 2 MB limit.");
      return;
    }
    try {
      setRows(rowsFromDhcpCsv(await file.text()));
    } catch (parseError) {
      setError(parseError.message);
    }
  }

  async function submit(event) {
    event.preventDefault();
    if (rows.length === 0 || busy) return;
    setBusy(true);
    setError("");
    try {
      const imported = await importDhcpLeases(rows);
      setResult(imported);
      await onImported(imported);
    } catch (requestError) {
      setError(requestError.message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="modal-backdrop">
      <section
        className="modal dhcp-modal"
        role="dialog"
        aria-modal="true"
        aria-labelledby="dhcp-title"
      >
        <div className="modal-heading">
          <div>
            <p className="eyebrow">Authoritative inventory</p>
            <h2 id="dhcp-title">Import DHCP leases</h2>
          </div>
          <button className="icon-button" onClick={onClose} aria-label="Close">
            ×
          </button>
        </div>
        <form onSubmit={submit}>
          <p className="import-help">
            The CSV is parsed in this browser and sent as validated data; the
            file itself is never uploaded or stored. Required header:{" "}
            <code>ip_address</code>. Optional: <code>hostname</code>,{" "}
            <code>mac_address</code>, <code>vlan</code>,{" "}
            <code>lease_expires_at</code> (ISO date/time).
          </p>
          <label>
            DHCP lease CSV
            <input type="file" accept=".csv,text/csv" onChange={chooseFile} />
          </label>
          {fileName && (
            <p className="form-message">
              {fileName} · {rows.length} valid rows ready
            </p>
          )}
          {error && (
            <div className="form-error" role="alert">
              {error}
            </div>
          )}
          {rows.length > 0 && (
            <div className="import-preview">
              <strong>Preview</strong>
              <div className="table-wrap">
                <table>
                  <thead>
                    <tr>
                      <th>Hostname</th>
                      <th>IP</th>
                      <th>MAC</th>
                      <th>VLAN</th>
                    </tr>
                  </thead>
                  <tbody>
                    {rows.slice(0, 5).map((row, index) => (
                      <tr key={`${row.ip_address}-${index}`}>
                        <td>{row.hostname || "—"}</td>
                        <td>{row.ip_address}</td>
                        <td>{row.mac_address || "—"}</td>
                        <td>{row.vlan || "—"}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
              {rows.length > 5 && (
                <small>Showing 5 of {rows.length} rows.</small>
              )}
            </div>
          )}
          {result && (
            <div className="import-result" role="status">
              <strong>Import complete</strong>
              <span>
                {result.devices_added} added · {result.devices_updated} updated
                · {result.rows_skipped} skipped
              </span>
              {result.conflicts.map((conflict) => (
                <small key={conflict}>{conflict}</small>
              ))}
            </div>
          )}
          <div className="modal-actions">
            <button
              type="button"
              className="button button--secondary"
              onClick={onClose}
            >
              Close
            </button>
            <button
              className="button button--primary"
              disabled={busy || rows.length === 0}
            >
              {busy ? "Importing…" : `Import ${rows.length || ""} leases`}
            </button>
          </div>
        </form>
      </section>
    </div>
  );
}

function PacketCaptureModal({ onClose }) {
  const [interfaces, setInterfaces] = useState([]);
  const [captures, setCaptures] = useState([]);
  const [form, setForm] = useState({
    interface_name: "",
    duration_seconds: 10,
    max_packets: 200,
  });
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const retryTimer = useRef(null);
  const retryCount = useRef(0);
  const load = useCallback(async () => {
    try {
      const [i, c] = await Promise.all([
        getPacketInterfaces(),
        listPacketCaptures(),
      ]);
      setInterfaces(i);
      setCaptures(c);
      setError("");
      setForm((current) => ({
        ...current,
        interface_name:
          current.interface_name ||
          i.find((item) => item.recommended)?.value ||
          "",
      }));
      if (i.length === 0 && retryCount.current < 3) {
        retryCount.current += 1;
        retryTimer.current = window.setTimeout(load, 1500);
      }
    } catch (e) {
      setError(e.message);
    }
  }, []);
  useEffect(() => {
    load();
    return () => window.clearTimeout(retryTimer.current);
  }, [load]);
  async function start() {
    if (
      !window.confirm(
        `Capture metadata for up to ${form.duration_seconds} seconds? Packet payloads will not be stored.`,
      )
    )
      return;
    setBusy(true);
    try {
      await startPacketCapture({
        ...form,
        interface_name: form.interface_name || null,
        duration_seconds: Number(form.duration_seconds),
        max_packets: Number(form.max_packets),
      });
      await load();
    } catch (e) {
      setError(e.message);
    } finally {
      setBusy(false);
    }
  }
  return (
    <div className="modal-backdrop">
      <section
        className="modal capture-modal"
        role="dialog"
        aria-modal="true"
        aria-labelledby="packet-capture-title"
      >
        <div className="modal-heading">
          <div>
            <p className="eyebrow">Administrator tool</p>
            <h2 id="packet-capture-title">Controlled packet capture</h2>
          </div>
          <button
            className="icon-button"
            onClick={onClose}
            aria-label="Close packet capture"
          >
            ×
          </button>
        </div>
        <p className="panel-help">Captures are time- and packet-limited and retain packet metadata only. Selecting an interface determines which traffic this host can actually observe.</p>
        {error && <div className="form-error user-error">{error}</div>}
        {interfaces.length === 0 && (
          <div className="capture-interface-status">
            No interfaces loaded yet.
            <button
              className="text-button"
              onClick={() => {
                retryCount.current = 0;
                load();
              }}
            >
              Refresh interfaces
            </button>
          </div>
        )}
        <div className="capture-form">
          <select
            value={form.interface_name}
            onChange={(e) =>
              setForm({ ...form, interface_name: e.target.value })
            }
          >
            <option value="">
              {interfaces.length === 0
                ? "Loading interfaces…"
                : "Default interface"}
            </option>
            {interfaces.map((item) => (
              <option key={item.value} value={item.value}>
                {item.label}
                {item.recommended ? " (recommended)" : ""}
              </option>
            ))}
          </select>
          <label>
            Seconds
            <input
              type="number"
              min="1"
              max="30"
              value={form.duration_seconds}
              onChange={(e) =>
                setForm({ ...form, duration_seconds: e.target.value })
              }
            />
          </label>
          <label>
            Max packets
            <input
              type="number"
              min="1"
              max="1000"
              value={form.max_packets}
              onChange={(e) =>
                setForm({ ...form, max_packets: e.target.value })
              }
            />
          </label>
          <button
            className="button button--primary"
            onClick={start}
            disabled={busy || interfaces.length === 0}
          >
            {busy ? "Capturing…" : "Start capture"}
          </button>
        </div>
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Started</th>
                <th>Interface</th>
                <th>Status</th>
                <th>Packets</th>
                <th>Error</th>
              </tr>
            </thead>
            <tbody>
              {captures.map((item) => (
                <tr key={item.id}>
                  <td>{formatDate(item.started_at)}</td>
                  <td>
                    {interfaces.find(
                      (option) => option.value === item.interface_name,
                    )?.label ||
                      item.interface_name ||
                      "Default"}
                  </td>
                  <td>{item.status}</td>
                  <td>{item.packets.length}</td>
                  <td>{item.error || "—"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>
    </div>
  );
}

function DeviceChangeHistory({ events, onRefresh }) {
  const [busy, setBusy] = useState(false);
  async function refresh() {
    setBusy(true);
    try {
      await refreshAssetBaselines();
      await onRefresh();
    } finally {
      setBusy(false);
    }
  }
  return (
    <section className="panel change-history-panel">
      <div className="panel-heading">
        <div>
          <p className="eyebrow">Change detection</p>
          <h2>Asset change history</h2>
        </div>
        <button
          className="button button--secondary"
          onClick={refresh}
          disabled={busy}
        >
          {busy ? "Comparing…" : "Compare now"}
        </button>
      </div>
      {events.length === 0 ? (
        <div className="empty-state empty-state--compact">
          No tracked changes yet. “Compare now” stores the first baseline and
          reports future differences.
        </div>
      ) : (
        <ol className="change-history-list">
          {events.map((event) => (
            <li key={event.id}>
              <span
                className={`change-severity change-severity--${event.severity.toLowerCase()}`}
              >
                {event.severity}
              </span>
              <div>
                <strong>{event.message}</strong>
                {event.details?.changed_fields?.length > 0 && (
                  <span>
                    Changed: {event.details.changed_fields.join(", ")}
                  </span>
                )}
                <time>{formatDate(event.created_at)}</time>
              </div>
            </li>
          ))}
        </ol>
      )}
    </section>
  );
}

function DeviceNotesPanel({ deviceId, notes, onChanged, canWrite }) {
  const [body, setBody] = useState("");
  const [busy, setBusy] = useState(false);
  async function addNote() {
    const normalized = body.trim();
    if (!normalized) return;
    setBusy(true);
    try {
      await createDeviceNote(deviceId, normalized);
      setBody("");
      await onChanged();
    } finally {
      setBusy(false);
    }
  }
  async function removeNote(noteId) {
    if (!window.confirm("Delete this technician note?")) return;
    setBusy(true);
    try {
      await deleteDeviceNote(deviceId, noteId);
      await onChanged();
    } finally {
      setBusy(false);
    }
  }
  return (
    <section className="panel device-notes-panel">
      <div className="panel-heading">
        <div>
          <p className="eyebrow">Team context</p>
          <h2>Technician notes</h2>
        </div>
        <span>{notes.length} notes</span>
      </div>
      {canWrite && (
        <div className="device-note-form">
          <textarea
            value={body}
            onChange={(event) => setBody(event.target.value)}
            maxLength="1000"
            rows="3"
            placeholder="Record maintenance, ownership, or troubleshooting context…"
            aria-label="New technician note"
          />
          <div>
            <small>{body.length}/1000</small>
            <button
              className="button button--primary"
              onClick={addNote}
              disabled={busy || !body.trim()}
            >
              {busy ? "Saving…" : "Add note"}
            </button>
          </div>
        </div>
      )}
      {notes.length === 0 ? (
        <div className="empty-state empty-state--compact">
          No technician notes yet.
        </div>
      ) : (
        <ol className="device-note-list">
          {notes.map((note) => (
            <li key={note.id}>
              <div>
                <strong>{note.author}</strong>
                <time>{formatDate(note.created_at)}</time>
              </div>
              <p>{note.body}</p>
              {canWrite && (
                <button
                  className="text-button text-button--danger"
                  onClick={() => removeNote(note.id)}
                  disabled={busy}
                >
                  Delete
                </button>
              )}
            </li>
          ))}
        </ol>
      )}
    </section>
  );
}

function DeviceActivityTimeline({ items }) {
  return (
    <section className="panel activity-timeline-panel">
      <div className="panel-heading">
        <div>
          <p className="eyebrow">Unified history</p>
          <h2>Device activity timeline</h2>
        </div>
        <span>{items.length} events</span>
      </div>
      {items.length === 0 ? (
        <div className="empty-state empty-state--compact">No activity recorded yet.</div>
      ) : (
        <ol className="activity-timeline">
          {items.map((item) => (
            <li key={item.id}>
              <span className={`activity-timeline__marker activity-timeline__marker--${item.severity.toLowerCase()}`} />
              <div>
                <div className="activity-timeline__heading">
                  <span>{item.category}</span>
                  <strong>{item.title}</strong>
                  <time>{formatDate(item.timestamp)}</time>
                </div>
                {item.description && <p>{item.description}</p>}
                {item.actor && <small>By {item.actor}</small>}
              </div>
            </li>
          ))}
        </ol>
      )}
    </section>
  );
}

function DeviceAttachmentsPanel({ deviceId, attachments, onChanged, canWrite }) {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const inputRef = useRef(null);
  const allowedTypes = ["text/plain", "application/pdf", "image/png", "image/jpeg"];

  async function upload(event) {
    const file = event.target.files?.[0];
    event.target.value = "";
    if (!file) return;
    if (!allowedTypes.includes(file.type)) {
      setError("Choose a UTF-8 text, PDF, PNG, or JPEG file.");
      return;
    }
    if (file.size > 5 * 1024 * 1024) {
      setError("Attachments cannot exceed 5 MiB.");
      return;
    }
    setBusy(true);
    setError("");
    try {
      const dataUrl = await new Promise((resolve, reject) => {
        const reader = new FileReader();
        reader.onload = () => resolve(reader.result);
        reader.onerror = () => reject(new Error("The selected file could not be read."));
        reader.readAsDataURL(file);
      });
      await createDeviceAttachment(deviceId, {
        original_name: file.name,
        media_type: file.type,
        content_base64: String(dataUrl).split(",", 2)[1],
      });
      await onChanged();
    } catch (requestError) {
      setError(requestError.message);
    } finally {
      setBusy(false);
    }
  }

  async function download(item) {
    setBusy(true);
    setError("");
    try {
      const blob = await downloadDeviceAttachment(deviceId, item.id);
      const url = URL.createObjectURL(blob);
      const link = document.createElement("a");
      link.href = url;
      link.download = item.original_name;
      link.click();
      window.setTimeout(() => URL.revokeObjectURL(url), 1000);
    } catch (requestError) {
      setError(requestError.message);
    } finally {
      setBusy(false);
    }
  }

  async function remove(item) {
    if (!window.confirm(`Delete attachment ${item.original_name}?`)) return;
    setBusy(true);
    setError("");
    try {
      await deleteDeviceAttachment(deviceId, item.id);
      await onChanged();
    } catch (requestError) {
      setError(requestError.message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <section className="panel device-attachments-panel">
      <div className="panel-heading">
        <div><p className="eyebrow">Supporting evidence</p><h2>Device attachments</h2></div>
        <div className="row-actions">
          <span>{attachments.length} files</span>
          {canWrite && <button className="button button--secondary" onClick={() => inputRef.current?.click()} disabled={busy}>{busy ? "Working…" : "Add file"}</button>}
        </div>
      </div>
      <p className="panel-help">Only UTF-8 text, PDF, PNG and JPEG files up to 5 MiB are accepted. Files are signature-checked, stored with random non-executable names and always downloaded as attachments.</p>
      {canWrite && <input ref={inputRef} className="visually-hidden" type="file" accept="text/plain,application/pdf,image/png,image/jpeg" onChange={upload} />}
      {error && <div className="form-error">{error}</div>}
      {attachments.length === 0 ? <div className="empty-state empty-state--compact">No device attachments yet.</div> : (
        <ol className="device-attachment-list">
          {attachments.map((item) => <li key={item.id}>
            <div><strong>{item.original_name}</strong><span>{formatBytes(item.size_bytes)} · {item.media_type}</span><small>{item.uploaded_by} · {formatDate(item.created_at)}</small></div>
            <button className="button button--secondary" onClick={() => download(item)} disabled={busy}>Download</button>
            {canWrite && <button className="text-button text-button--danger" onClick={() => remove(item)} disabled={busy}>Delete</button>}
          </li>)}
        </ol>
      )}
    </section>
  );
}

function DeviceDetail({
  deviceId,
  onBack,
  backLabel = "Back to dashboard",
  onEdit,
  onDeleted,
  isAdmin,
  canWrite,
}) {
  const [details, setDetails] = useState(null);
  const [loading, setLoading] = useState(true);
  const [checking, setChecking] = useState(false);
  const [fingerprinting, setFingerprinting] = useState(false);
  const [error, setError] = useState("");
  const [historyPage, setHistoryPage] = useState(1);
  const [changeEvents, setChangeEvents] = useState([]);
  const [notes, setNotes] = useState([]);
  const [activity, setActivity] = useState([]);
  const [attachments, setAttachments] = useState([]);

  const load = useCallback(async () => {
    try {
      const [nextDetails, nextChanges, nextNotes, nextActivity, nextAttachments] = await Promise.all([
        getDeviceDetails(deviceId),
        isAdmin ? getDeviceChangeEvents(deviceId) : Promise.resolve([]),
        getDeviceNotes(deviceId),
        getDeviceActivity(deviceId),
        getDeviceAttachments(deviceId),
      ]);
      setDetails(nextDetails);
      setChangeEvents(nextChanges);
      setNotes(nextNotes);
      setActivity(nextActivity);
      setAttachments(nextAttachments);
      setError("");
    } catch (requestError) {
      setError(requestError.message);
    } finally {
      setLoading(false);
    }
  }, [deviceId, isAdmin]);

  useEffect(() => {
    load();
  }, [load]);
  useEffect(() => {
    setHistoryPage(1);
  }, [deviceId]);

  async function runCheck() {
    setChecking(true);
    try {
      await checkDevice(deviceId);
      await load();
    } catch (requestError) {
      setError(requestError.message);
    } finally {
      setChecking(false);
    }
  }

  async function runFingerprint() {
    setFingerprinting(true);
    try {
      await fingerprintDevice(deviceId);
      await load();
    } catch (requestError) {
      setError(requestError.message);
    } finally {
      setFingerprinting(false);
    }
  }

  async function removeDevice() {
    if (
      !window.confirm(
        `Delete ${details.device.name} and all of its monitoring history?`,
      )
    )
      return;
    try {
      await deleteDevice(deviceId);
      onDeleted();
    } catch (requestError) {
      setError(requestError.message);
    }
  }

  if (loading)
    return <div className="panel empty-state">Loading device details…</div>;
  if (!details)
    return (
      <div className="error-banner">
        <strong>Unable to load device.</strong> {error}
        <br />
        <button className="text-button" onClick={onBack}>
          {backLabel}
        </button>
      </div>
    );
  const { device, statistics, history, events, alertRule } = details;
  const historyPageSize = 20;
  const historyPageCount = Math.max(
    1,
    Math.ceil(history.length / historyPageSize),
  );
  const currentHistoryPage = Math.min(historyPage, historyPageCount);
  const visibleHistory = history.slice(
    (currentHistoryPage - 1) * historyPageSize,
    currentHistoryPage * historyPageSize,
  );
  const maintenanceActive =
    device.maintenance_until &&
    new Date(device.maintenance_until).getTime() > Date.now();

  return (
    <>
      <button className="back-button" onClick={onBack}>
        ← {backLabel}
      </button>
      <header className="detail-header">
        <div>
          <p className="eyebrow">Device details</p>
          <h1>{device.name}</h1>
          <p className="subtitle">
            {device.ip_address} · {device.device_type}
          </p>
        </div>
        <div className="detail-actions">
          <button
            className="button button--secondary"
            onClick={runFingerprint}
            disabled={fingerprinting}
          >
            {fingerprinting ? "Fingerprinting…" : "Fingerprint"}
          </button>
          <button
            className="button button--secondary"
            onClick={() => onEdit(device)}
          >
            Edit
          </button>
          <button className="button button--danger" onClick={removeDevice}>
            Delete
          </button>
          <button
            className="button button--primary"
            onClick={runCheck}
            disabled={checking}
          >
            {checking ? "Checking…" : "Check now"}
          </button>
        </div>
      </header>
      {error && (
        <div className="error-banner" role="alert">
          {error}
        </div>
      )}
      {maintenanceActive && (
        <div className="maintenance-banner" role="status">
          <strong>Planned maintenance active</strong>
          <span>
            New alerts are suppressed until{" "}
            {formatDate(device.maintenance_until)}.
          </span>
          {device.maintenance_reason && (
            <small>{device.maintenance_reason}</small>
          )}
        </div>
      )}
      <section className="metrics detail-metrics">
        <MetricCard
          label="Current status"
          value={<StatusBadge status={statistics.current_status} />}
          tone={statistics.current_status.toLowerCase()}
        />
        <MetricCard
          label="Availability"
          value={formatMetric(statistics.availability_percent, "%")}
          tone="online"
        />
        <MetricCard
          label="Average latency"
          value={formatMetric(statistics.average_latency_ms, " ms")}
          tone="latency"
        />
        <MetricCard
          label="Total checks"
          value={statistics.total_checks}
          tone="neutral"
        />
        <MetricCard
          label="Failed checks"
          value={statistics.offline_checks}
          tone="offline"
        />
      </section>
      <section className="panel asset-panel">
        <div className="panel-heading">
          <div>
            <p className="eyebrow">Asset management</p>
            <h2>Asset record</h2>
          </div>
          <div className="row-actions">
            <ProfileCompleteness device={device} />
            <span
              className={`criticality criticality--${device.criticality.toLowerCase()}`}
            >
              {device.criticality}
            </span>
          </div>
        </div>
        <dl className="asset-details">
          <div>
            <dt>Asset tag</dt>
            <dd>{device.asset_tag || "Not assigned"}</dd>
          </div>
          <div>
            <dt>Device group</dt>
            <dd>{device.device_group || "Ungrouped"}</dd>
          </div>
          <div>
            <dt>Tags</dt>
            <dd>
              {device.tags?.length ? (
                <span className="device-tags">
                  {device.tags.map((tag) => (
                    <span key={tag}>{tag}</span>
                  ))}
                </span>
              ) : (
                "None"
              )}
            </dd>
          </div>
          <div>
            <dt>Owner or team</dt>
            <dd>{device.owner || "Not assigned"}</dd>
          </div>
          <div>
            <dt>Location</dt>
            <dd>{device.location || "Not assigned"}</dd>
          </div>
          <div>
            <dt>Operating system</dt>
            <dd>{device.operating_system || "Unknown"}</dd>
          </div>
          <div>
            <dt>Maintenance</dt>
            <dd>
              {maintenanceActive
                ? `Until ${formatDate(device.maintenance_until)}`
                : "Not scheduled"}
            </dd>
          </div>
          <div>
            <dt>Inventory source</dt>
            <dd>
              {device.inventory_source?.replaceAll("_", " ") || "Unknown"}
            </dd>
          </div>
        </dl>
        {device.description && (
          <p className="asset-description">{device.description}</p>
        )}
      </section>
      <DeviceNotesPanel
        deviceId={device.id}
        notes={notes}
        onChanged={load}
        canWrite={canWrite}
      />
      <DeviceAttachmentsPanel
        deviceId={device.id}
        attachments={attachments}
        onChanged={load}
        canWrite={canWrite}
      />
      <DeviceActivityTimeline items={activity} />
      <section className="panel fingerprint-panel">
        <div className="panel-heading">
          <div>
            <p className="eyebrow">Device intelligence</p>
            <h2>Fingerprint and inventory evidence</h2>
          </div>
          <span>
            {device.fingerprinted_at
              ? formatDate(device.fingerprinted_at)
              : "Not fingerprinted"}
          </span>
        </div>
        <div className="fingerprint-details">
          <div>
            <strong>MAC</strong>
            <span>{device.mac_address || "Unknown"}</span>
          </div>
          <div>
            <strong>Manufacturer</strong>
            <span>{device.manufacturer || "Unknown"}</span>
          </div>
          <div>
            <strong>Advertised model</strong>
            <span>{device.discovered_model || "Not advertised"}</span>
          </div>
          <div>
            <strong>Inventory source</strong>
            <span>
              {device.inventory_source?.replaceAll("_", " ") || "Unknown"}
            </span>
          </div>
          <div>
            <strong>VLAN</strong>
            <span>{device.vlan || "Unknown"}</span>
          </div>
          <div>
            <strong>Lease expires</strong>
            <span>
              {device.lease_expires_at
                ? formatDate(device.lease_expires_at)
                : "Unknown"}
            </span>
          </div>
          <div>
            <strong>Open TCP</strong>
            <span>
              {device.fingerprint_ports?.split(",").join(", ") ||
                "None detected"}
            </span>
          </div>
          <div>
            <strong>mDNS services</strong>
            <span>
              {device.discovered_services?.split(",").join(", ") ||
                "None advertised"}
            </span>
          </div>
          <p>
            {device.fingerprint_summary ||
              "Run fingerprinting to collect bounded service evidence."}
          </p>
        </div>
      </section>
      {isAdmin && (
        <DeviceChangeHistory events={changeEvents} onRefresh={load} />
      )}
      <section className="panel chart-panel">
        <div className="panel-heading">
          <div>
            <p className="eyebrow">Performance</p>
            <h2>Recent latency</h2>
          </div>
          <span>Last 30 successful checks</span>
        </div>
        <LatencyChart history={history} />
      </section>
      <ServiceChecksPanel
        deviceId={device.id}
        checks={details.serviceChecks}
        onChanged={load}
      />
      <HostMetricsPanel
        device={device}
        metrics={details.hostMetrics}
        onChanged={load}
      />
      <RemoteAgentPanel
        device={device}
        agent={details.agent}
        onChanged={load}
      />
      {isAdmin && (
        <RemoteDiagnosticsPanel deviceId={device.id} agent={details.agent} />
      )}
      <SnmpPanel
        deviceId={device.id}
        config={details.snmpConfig}
        history={details.snmpHistory}
        onChanged={load}
      />
      <VulnerabilityPanel
        device={device}
        scans={details.vulnerabilityScans}
        comparison={details.attackSurfaceComparison}
        onChanged={load}
        canScan={isAdmin}
      />
      <AnomalyPanel
        deviceId={device.id}
        anomalies={details.anomalies}
        onChanged={load}
      />
      <div className="detail-grid">
        <section className="panel">
          <div className="panel-heading monitoring-history-heading">
            <div>
              <p className="eyebrow">Measurements</p>
              <h2>Monitoring history</h2>
            </div>
            {history.length > 0 && (
              <nav
                className="history-pagination"
                aria-label="Monitoring history pagination"
              >
                <span>
                  Showing {(currentHistoryPage - 1) * historyPageSize + 1}–
                  {Math.min(
                    currentHistoryPage * historyPageSize,
                    history.length,
                  )}{" "}
                  of {history.length}
                </span>
                <button
                  className="button button--secondary"
                  onClick={() =>
                    setHistoryPage((page) => Math.max(1, page - 1))
                  }
                  disabled={currentHistoryPage === 1}
                >
                  Previous
                </button>
                <span>
                  Page {currentHistoryPage} of {historyPageCount}
                </span>
                <button
                  className="button button--secondary"
                  onClick={() =>
                    setHistoryPage((page) =>
                      Math.min(historyPageCount, page + 1),
                    )
                  }
                  disabled={currentHistoryPage === historyPageCount}
                >
                  Next
                </button>
              </nav>
            )}
          </div>
          {history.length === 0 ? (
            <div className="empty-state">No checks recorded yet.</div>
          ) : (
            <div className="table-wrap">
              <table>
                <thead>
                  <tr>
                    <th>Timestamp</th>
                    <th>Status</th>
                    <th>Latency</th>
                  </tr>
                </thead>
                <tbody>
                  {visibleHistory.map((result) => (
                    <tr key={result.id}>
                      <td>{formatDate(result.timestamp)}</td>
                      <td>
                        <StatusBadge status={result.status} />
                      </td>
                      <td>{formatMetric(result.latency_ms, " ms")}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </section>
        <section className="panel">
          <div className="panel-heading">
            <div>
              <p className="eyebrow">Changes</p>
              <h2>Status events</h2>
            </div>
          </div>
          {events.length === 0 ? (
            <div className="empty-state empty-state--compact">
              No transitions recorded.
            </div>
          ) : (
            <ol className="events-list">
              {events.map((event, index) => (
                <li key={`${event.timestamp}-${index}`}>
                  <span
                    className={`event-dot event-dot--${event.current_status.toLowerCase()}`}
                  />
                  <div>
                    <strong>
                      {event.previous_status} → {event.current_status}
                    </strong>
                    <time>{formatDate(event.timestamp)}</time>
                  </div>
                </li>
              ))}
            </ol>
          )}
        </section>
        <section className="panel">
          <div className="panel-heading">
            <div>
              <p className="eyebrow">Thresholds</p>
              <h2>Alert rule</h2>
            </div>
          </div>
          <AlertRuleEditor
            deviceId={device.id}
            rule={alertRule}
            onSaved={(saved) =>
              setDetails((current) => ({ ...current, alertRule: saved }))
            }
          />
        </section>
      </div>
    </>
  );
}

function NetworkActionDialog({
  action,
  confirmation,
  busy,
  onConfirmationChange,
  onCancel,
  onConfirm,
}) {
  const clearsInventory = action.kind === "reset" || action.requiresReset;
  const title =
    action.kind === "reset"
      ? "Clear device inventory"
      : action.requiresReset
        ? "Switch network and discover"
        : "Review network discovery";
  const submitLabel =
    action.kind === "reset"
      ? "Clear all devices"
      : action.requiresReset
        ? "Clear old devices and scan"
        : "Start discovery";
  const confirmationMatches =
    !clearsInventory || confirmation.trim() === CLEAR_DEVICES_CONFIRMATION;

  return (
    <div className="modal-backdrop">
      <section
        className="modal network-action-modal"
        role="dialog"
        aria-modal="true"
        aria-labelledby="network-action-title"
        aria-describedby="network-action-description"
      >
        <div className="modal-heading">
          <div>
            <p className="eyebrow">Network inventory</p>
            <h2 id="network-action-title">{title}</h2>
          </div>
          <button
            className="icon-button"
            type="button"
            onClick={onCancel}
            disabled={busy}
            aria-label="Close network action"
          >
            ×
          </button>
        </div>
        <p id="network-action-description" className="panel-help">
          {action.kind === "reset"
            ? "Use this when you want to discard the current lab inventory and start again."
            : action.requiresReset
              ? action.resetReason
              : "Confirm the active adapter and subnet before AEGIS searches for devices."}
        </p>
        {action.network && (
          <dl className="network-action-summary">
            <div><dt>Subnet</dt><dd>{action.network.network}</dd></div>
            <div><dt>Adapter</dt><dd>{action.network.interface_name}</dd></div>
            <div><dt>Local address</dt><dd>{action.network.local_ip}</dd></div>
            <div><dt>Gateway</dt><dd>{action.network.gateway || "Unknown"}</dd></div>
          </dl>
        )}
        {clearsInventory && (
          <div className="network-reset-warning">
            <strong>{action.deviceCount} registered devices will be removed.</strong>
            <p>
              This also deletes their monitoring history, alerts, scans, notes,
              topology links, agent enrollments, and attachments.
            </p>
          </div>
        )}
        {action.error && (
          <div className="form-error" role="alert">{action.error}</div>
        )}
        <form className="network-action-form" onSubmit={onConfirm}>
          {clearsInventory && (
            <label>
              Type <strong>{CLEAR_DEVICES_CONFIRMATION}</strong> to confirm
              <input
                value={confirmation}
                onChange={(event) => onConfirmationChange(event.target.value)}
                autoComplete="off"
                spellCheck="false"
                autoFocus
              />
            </label>
          )}
          <div className="network-action-buttons">
            <button
              className="button button--secondary"
              type="button"
              onClick={onCancel}
              disabled={busy}
              autoFocus={!clearsInventory}
            >
              Cancel
            </button>
            <button
              className={clearsInventory ? "button button--danger" : "button button--primary"}
              disabled={busy || !confirmationMatches}
            >
              {busy ? "Working…" : submitLabel}
            </button>
          </div>
        </form>
      </section>
    </div>
  );
}

function AuthScreen({ setupRequired, onAuthenticated, visualTheme }) {
  const [form, setForm] = useState({
    username: "",
    password: "",
    confirmPassword: "",
  });
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  async function submit(event) {
    event.preventDefault();
    setError("");
    if (setupRequired && form.password !== form.confirmPassword) {
      setError("Passwords do not match.");
      return;
    }
    setBusy(true);
    try {
      const session = setupRequired
        ? await setupAdmin({ username: form.username, password: form.password })
        : await loginUser({ username: form.username, password: form.password });
      setAuthToken(session.token);
      onAuthenticated(session.user);
    } catch (requestError) {
      setError(requestError.message);
    } finally {
      setBusy(false);
    }
  }
  return (
    <main className="auth-page">
      <section className="auth-card">
        <div className="auth-brand">
          <span className="brand-mark">
            <img
              src={visualTheme === "goth" ? aegisShieldDark : aegisShield}
              alt=""
            />
          </span>
          <div>
            <strong>Aegis</strong>
            <small>Infrastructure monitor</small>
          </div>
        </div>
        <p className="eyebrow">
          {setupRequired ? "First-run security" : "Protected dashboard"}
        </p>
        <h1>{setupRequired ? "Create administrator" : "Sign in"}</h1>
        <p className="subtitle">
          {setupRequired
            ? "Create the first local administrator account. Use a unique password with at least 12 characters."
            : "Enter your local Aegis account credentials."}
        </p>
        <form onSubmit={submit}>
          {error && (
            <div className="form-error" role="alert">
              {error}
            </div>
          )}
          <label>
            Username
            <input
              value={form.username}
              onChange={(event) =>
                setForm({ ...form, username: event.target.value })
              }
              autoComplete="username"
              minLength="3"
              required
              autoFocus
            />
          </label>
          <label>
            Password
            <span className="password-field">
              <input
                type={showPassword ? "text" : "password"}
                value={form.password}
                onChange={(event) =>
                  setForm({ ...form, password: event.target.value })
                }
                autoComplete={setupRequired ? "new-password" : "current-password"}
                minLength={setupRequired ? 12 : 1}
                required
              />
              <button
                type="button"
                onClick={() => setShowPassword((visible) => !visible)}
                aria-pressed={showPassword}
              >
                {showPassword ? "Hide" : "Show"}
              </button>
            </span>
          </label>
          {setupRequired && (
            <label>
              Confirm password
              <input
                type={showPassword ? "text" : "password"}
                value={form.confirmPassword}
                onChange={(event) =>
                  setForm({ ...form, confirmPassword: event.target.value })
                }
                autoComplete="new-password"
                minLength="12"
                required
              />
            </label>
          )}
          <button className="button button--primary" disabled={busy}>
            {busy
              ? "Please wait…"
              : setupRequired
                ? "Create administrator"
                : "Sign in"}
          </button>
        </form>
      </section>
    </main>
  );
}

function UserManagement({ currentUser, onClose }) {
  const [users, setUsers] = useState([]);
  const [error, setError] = useState("");
  const [form, setForm] = useState({
    username: "",
    password: "",
    role: "VIEWER",
  });
  const load = useCallback(async () => {
    try {
      setUsers(await listUsers());
      setError("");
    } catch (requestError) {
      setError(requestError.message);
    }
  }, []);
  useEffect(() => {
    load();
  }, [load]);
  async function add(event) {
    event.preventDefault();
    try {
      await createUser(form);
      setForm({ username: "", password: "", role: "VIEWER" });
      await load();
    } catch (requestError) {
      setError(requestError.message);
    }
  }
  async function change(user, changes) {
    try {
      await updateUser(user.id, {
        role: changes.role ?? user.role,
        is_active: changes.is_active ?? user.is_active,
        password: null,
      });
      await load();
    } catch (requestError) {
      setError(requestError.message);
    }
  }
  return (
    <div className="modal-backdrop">
      <section
        className="modal user-modal"
        role="dialog"
        aria-modal="true"
        aria-labelledby="users-title"
      >
        <div className="modal-heading">
          <div>
            <p className="eyebrow">Access control</p>
            <h2 id="users-title">Local users</h2>
          </div>
          <button className="icon-button" onClick={onClose} aria-label="Close">
            ×
          </button>
        </div>
        {error && <div className="form-error user-error">{error}</div>}
        <form className="user-create-form" onSubmit={add}>
          <label>
            Username
            <input
              value={form.username}
              onChange={(event) =>
                setForm({ ...form, username: event.target.value })
              }
              minLength="3"
              required
            />
          </label>
          <label>
            Temporary password
            <input
              type="password"
              value={form.password}
              onChange={(event) =>
                setForm({ ...form, password: event.target.value })
              }
              minLength="12"
              required
            />
          </label>
          <label>
            Role
            <select
              value={form.role}
              onChange={(event) =>
                setForm({ ...form, role: event.target.value })
              }
            >
              <option>VIEWER</option>
              <option>OPERATOR</option>
              <option>ADMIN</option>
            </select>
          </label>
          <button className="button button--primary">Add user</button>
        </form>
        <div className="user-list">
          {users.map((user) => (
            <article key={user.id}>
              <div>
                <strong>{user.username}</strong>
                <span>
                  {user.id === currentUser.id
                    ? "Current account"
                    : user.is_active
                      ? "Active"
                      : "Disabled"}
                </span>
              </div>
              <select
                value={user.role}
                onChange={(event) => change(user, { role: event.target.value })}
                disabled={user.id === currentUser.id}
              >
                {["ADMIN", "OPERATOR", "VIEWER"].map((role) => (
                  <option key={role}>{role}</option>
                ))}
              </select>
              <button
                className="button button--secondary"
                onClick={() => change(user, { is_active: !user.is_active })}
                disabled={user.id === currentUser.id}
              >
                {user.is_active ? "Disable" : "Enable"}
              </button>
            </article>
          ))}
        </div>
      </section>
    </div>
  );
}

function AuditLog({ onClose }) {
  const [events, setEvents] = useState([]);
  const [error, setError] = useState("");
  const [query, setQuery] = useState("");
  const [method, setMethod] = useState("ALL");
  useEffect(() => {
    listAuditEvents()
      .then(setEvents)
      .catch((requestError) => setError(requestError.message));
  }, []);
  const filtered = useMemo(() => {
    const term = query.trim().toLocaleLowerCase();
    return events.filter(
      (event) =>
        (method === "ALL" || event.method === method) &&
        (!term ||
          `${event.username} ${event.role} ${event.path} ${event.client_ip || ""} ${event.status_code}`
            .toLocaleLowerCase()
            .includes(term)),
    );
  }, [events, query, method]);
  return (
    <div className="modal-backdrop">
      <section
        className="modal audit-modal"
        role="dialog"
        aria-modal="true"
        aria-labelledby="audit-title"
      >
        <div className="modal-heading">
          <div>
            <p className="eyebrow">Accountability</p>
            <h2 id="audit-title">Audit log</h2>
          </div>
          <button className="icon-button" onClick={onClose} aria-label="Close">
            ×
          </button>
        </div>
        {error && <div className="form-error user-error">{error}</div>}
        <div className="audit-filters">
          <label>
            <span className="sr-only">Search audit events</span>
            <input
              type="search"
              value={query}
              onChange={(event) => setQuery(event.target.value)}
              placeholder="Search actor, route, status, or address"
            />
          </label>
          <label>
            <span className="sr-only">Filter audit method</span>
            <select
              value={method}
              onChange={(event) => setMethod(event.target.value)}
            >
              <option>ALL</option>
              <option>POST</option>
              <option>PUT</option>
              <option>DELETE</option>
            </select>
          </label>
          <span>
            {filtered.length} of {events.length} events
          </span>
        </div>
        {filtered.length === 0 ? (
          <div className="empty-state empty-state--compact">
            No audit events match this view.
          </div>
        ) : (
          <div className="table-wrap audit-table">
            <table>
              <thead>
                <tr>
                  <th>Timestamp</th>
                  <th>Actor</th>
                  <th>Action</th>
                  <th>Route</th>
                  <th>Result</th>
                  <th>Source</th>
                </tr>
              </thead>
              <tbody>
                {filtered.map((event) => (
                  <tr key={event.id}>
                    <td>{formatDate(event.timestamp)}</td>
                    <td>
                      <strong>{event.username}</strong>
                      <span>{event.role}</span>
                    </td>
                    <td>{event.method}</td>
                    <td>
                      <code>{event.path}</code>
                    </td>
                    <td>
                      <span
                        className={`audit-status audit-status--${event.status_code < 400 ? "success" : "failure"}`}
                      >
                        {event.status_code}
                      </span>
                    </td>
                    <td>{event.client_ip || "—"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>
    </div>
  );
}

function NotificationSettings({ onClose }) {
  const [channels, setChannels] = useState([]);
  const [deliveries, setDeliveries] = useState([]);
  const [message, setMessage] = useState("");
  const [busy, setBusy] = useState(false);
  const load = useCallback(async () => {
    try {
      const [c, d] = await Promise.all([
        listNotificationChannels(),
        listNotificationDeliveries(),
      ]);
      setChannels(c);
      setDeliveries(d);
    } catch (error) {
      setMessage(error.message);
    }
  }, []);
  useEffect(() => {
    load();
  }, [load]);
  const change = (type, field, value) =>
    setChannels((items) =>
      items.map((item) =>
        item.channel_type === type ? { ...item, [field]: value } : item,
      ),
    );
  async function save(channel) {
    setBusy(true);
    try {
      await updateNotificationChannel(channel.channel_type, {
        enabled: channel.enabled,
        smtp_host: channel.smtp_host,
        smtp_port: channel.smtp_port ? Number(channel.smtp_port) : null,
        smtp_username: channel.smtp_username,
        email_from: channel.email_from,
        email_to: channel.email_to,
        sms_from: channel.sms_from,
        sms_to: channel.sms_to,
        use_tls: channel.use_tls,
      });
      setMessage(`${channel.channel_type} settings saved.`);
      await load();
    } catch (error) {
      setMessage(error.message);
    } finally {
      setBusy(false);
    }
  }
  async function test(type) {
    setBusy(true);
    try {
      const result = await testNotificationChannel(type);
      setMessage(
        result.status === "SENT"
          ? `${type} test sent.`
          : `${type} test failed: ${result.last_error}`,
      );
      await load();
    } catch (error) {
      setMessage(error.message);
    } finally {
      setBusy(false);
    }
  }
  async function retry(id) {
    setBusy(true);
    try {
      await retryNotificationDelivery(id);
      await load();
    } catch (error) {
      setMessage(error.message);
    } finally {
      setBusy(false);
    }
  }
  return (
    <div className="modal-backdrop">
      <section
        className="modal notification-modal"
        role="dialog"
        aria-modal="true"
        aria-labelledby="notifications-title"
      >
        <div className="modal-heading">
          <div>
            <p className="eyebrow">Alert delivery</p>
            <h2 id="notifications-title">Notifications</h2>
          </div>
          <button
            className="icon-button"
            onClick={onClose}
            aria-label="Close notifications"
          >
            ×
          </button>
        </div>
        {message && <div className="form-message">{message}</div>}
        <div className="notification-channels">
          {channels.map((channel) => (
            <section
              key={channel.channel_type}
              className="notification-channel"
            >
              <div className="notification-title">
                <div>
                  <h3>
                    {channel.channel_type === "EMAIL"
                      ? "Email"
                      : channel.channel_type === "TEAMS"
                        ? "Microsoft Teams"
                        : "SMS"}
                  </h3>
                  <small>
                    Secret:{" "}
                    {channel.secret_configured
                      ? "configured in environment"
                      : "not configured"}
                  </small>
                </div>
                <label className="toggle-label">
                  <input
                    type="checkbox"
                    checked={channel.enabled}
                    onChange={(e) =>
                      change(channel.channel_type, "enabled", e.target.checked)
                    }
                  />{" "}
                  Enabled
                </label>
              </div>
              {channel.channel_type === "EMAIL" && (
                <div className="notification-fields">
                  <input
                    placeholder="SMTP host"
                    value={channel.smtp_host || ""}
                    onChange={(e) =>
                      change("EMAIL", "smtp_host", e.target.value)
                    }
                  />
                  <input
                    type="number"
                    placeholder="Port"
                    value={channel.smtp_port || ""}
                    onChange={(e) =>
                      change("EMAIL", "smtp_port", e.target.value)
                    }
                  />
                  <input
                    placeholder="SMTP username"
                    value={channel.smtp_username || ""}
                    onChange={(e) =>
                      change("EMAIL", "smtp_username", e.target.value)
                    }
                  />
                  <input
                    placeholder="From address"
                    value={channel.email_from || ""}
                    onChange={(e) =>
                      change("EMAIL", "email_from", e.target.value)
                    }
                  />
                  <input
                    placeholder="Recipients (comma-separated)"
                    value={channel.email_to || ""}
                    onChange={(e) =>
                      change("EMAIL", "email_to", e.target.value)
                    }
                  />
                  <label>
                    <input
                      type="checkbox"
                      checked={channel.use_tls}
                      onChange={(e) =>
                        change("EMAIL", "use_tls", e.target.checked)
                      }
                    />{" "}
                    Use TLS
                  </label>
                </div>
              )}
              {channel.channel_type === "SMS" && (
                <div className="notification-fields">
                  <input
                    placeholder="Twilio sender number"
                    value={channel.sms_from || ""}
                    onChange={(e) => change("SMS", "sms_from", e.target.value)}
                  />
                  <input
                    placeholder="Recipients, comma-separated"
                    value={channel.sms_to || ""}
                    onChange={(e) => change("SMS", "sms_to", e.target.value)}
                  />
                </div>
              )}
              <div className="notification-actions">
                <button
                  className="button button--primary"
                  onClick={() => save(channel)}
                  disabled={busy}
                >
                  Save
                </button>
                <button
                  className="button button--secondary"
                  onClick={() => test(channel.channel_type)}
                  disabled={busy}
                >
                  Send test
                </button>
              </div>
            </section>
          ))}
        </div>
        <div className="panel-heading">
          <div>
            <p className="eyebrow">Recent attempts</p>
            <h3>Delivery history</h3>
          </div>
        </div>
        <div className="table-wrap notification-history">
          <table>
            <thead>
              <tr>
                <th>Time</th>
                <th>Channel</th>
                <th>Status</th>
                <th>Attempts</th>
                <th>Details</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {deliveries.map((item) => (
                <tr key={item.id}>
                  <td>{formatDate(item.created_at)}</td>
                  <td>{item.channel_type}</td>
                  <td>
                    <strong>{item.status}</strong>
                  </td>
                  <td>{item.attempt_count}/3</td>
                  <td>{item.last_error || item.subject}</td>
                  <td>
                    {item.status === "FAILED" && item.attempt_count < 3 && (
                      <button
                        className="button button--secondary"
                        onClick={() => retry(item.id)}
                        disabled={busy}
                      >
                        Retry
                      </button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          {deliveries.length === 0 && (
            <div className="empty-state empty-state--compact">
              No notification attempts yet.
            </div>
          )}
        </div>
      </section>
    </div>
  );
}

export default function App() {
  const [visualTheme, setVisualTheme] = useState(() => {
    try {
      const storedTheme = window.localStorage.getItem("aegis_visual_theme");
      // Retire the former decorative default in favour of the neutral console.
      return storedTheme === "goth" ? "classic" : storedTheme || "classic";
    } catch {
      return "classic";
    }
  });
  const [auth, setAuth] = useState(null);
  const [authError, setAuthError] = useState("");
  const [showUsers, setShowUsers] = useState(false);
  const [showAudit, setShowAudit] = useState(false);
  const [showAlertHistory, setShowAlertHistory] = useState(false);
  const [showNotifications, setShowNotifications] = useState(false);
  const [showPacketCapture, setShowPacketCapture] = useState(false);
  const [showDhcpImport, setShowDhcpImport] = useState(false);
  const [showReliability, setShowReliability] = useState(false);
  const [showAutomation, setShowAutomation] = useState(false);
  const [showSystemStatus, setShowSystemStatus] = useState(false);
  const [showAttackPaths, setShowAttackPaths] = useState(false);
  const [showSecurityWorkbench, setShowSecurityWorkbench] = useState(false);
  const [workbenchTab, setWorkbenchTab] = useState("overview");
  const [showReports, setShowReports] = useState(false);
  const [showObservability, setShowObservability] = useState(false);
  const [setupGuideVisible, setSetupGuideVisible] = useState(() => {
    try {
      return window.localStorage.getItem("aegis_setup_guide_hidden") !== "true";
    } catch {
      return true;
    }
  });
  const [observabilitySeen, setObservabilitySeen] = useState(() => {
    try {
      return window.localStorage.getItem("aegis_observability_seen") === "true";
    } catch {
      return false;
    }
  });
  const [headerMenuOpen, setHeaderMenuOpen] = useState(false);
  const [mobileNavigationOpen, setMobileNavigationOpen] = useState(false);
  const [expandedSidebarSections, setExpandedSidebarSections] = useState({
    reports: true,
    security: false,
    administration: false,
  });
  const [commandPaletteOpen, setCommandPaletteOpen] = useState(false);
  const [data, setData] = useState(EMPTY_DASHBOARD);
  const [inventoryHealth, setInventoryHealth] = useState(
    EMPTY_INVENTORY_HEALTH,
  );
  const [topology, setTopology] = useState(EMPTY_TOPOLOGY);
  const [agentOverview, setAgentOverview] = useState(EMPTY_AGENT_OVERVIEW);
  const [serviceOverview, setServiceOverview] = useState(
    EMPTY_SERVICE_OVERVIEW,
  );
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [checkingId, setCheckingId] = useState(null);
  const [checkingAll, setCheckingAll] = useState(false);
  const [fingerprintingAll, setFingerprintingAll] = useState(false);
  const [acknowledgingId, setAcknowledgingId] = useState(null);
  const [acknowledgingAll, setAcknowledgingAll] = useState(false);
  const acknowledgementInFlight = useRef(new Set());
  const headerMenuRef = useRef(null);
  const [scheduler, setScheduler] = useState(null);
  const [schedulerBusy, setSchedulerBusy] = useState(false);
  const [lastUpdated, setLastUpdated] = useState(null);
  const [selectedId, setSelectedId] = useState(deviceIdFromPath);
  const [detailOrigin, setDetailOrigin] = useState(
    () => window.history.state?.aegisOrigin || null,
  );
  const [formDevice, setFormDevice] = useState(undefined);
  const [discovering, setDiscovering] = useState(false);
  const [clearingDevices, setClearingDevices] = useState(false);
  const [networkAction, setNetworkAction] = useState(null);
  const [networkActionConfirmation, setNetworkActionConfirmation] = useState("");
  const [lastDiscoveryNetwork, setLastDiscoveryNetwork] = useState(() => {
    try {
      return window.localStorage.getItem(LAST_DISCOVERY_NETWORK_KEY);
    } catch {
      return null;
    }
  });
  const [discoveryMessage, setDiscoveryMessage] = useState("");
  const [sort, setSort] = useState({ key: "name", direction: "asc" });
  const [filters, setFilters] = useState(DEFAULT_DEVICE_FILTERS);
  const [savedViews, setSavedViews] = useState(() => {
    try {
      const stored = JSON.parse(
        window.localStorage.getItem("aegis_saved_device_views") || "[]",
      );
      return Array.isArray(stored) ? stored : [];
    } catch {
      return [];
    }
  });
  const [dashboardSections, setDashboardSections] = useState(() => {
    try {
      const stored = JSON.parse(
        window.localStorage.getItem("aegis_dashboard_sections") || "{}",
      );
      return stored && typeof stored === "object"
        ? { ...DASHBOARD_SECTION_DEFAULTS, ...stored }
        : DASHBOARD_SECTION_DEFAULTS;
    } catch {
      return DASHBOARD_SECTION_DEFAULTS;
    }
  });
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(10);
  const [selectedDeviceIds, setSelectedDeviceIds] = useState([]);

  const closeTopSidebarWindow = useCallback(() => {
    if (showObservability) setShowObservability(false);
    else if (showReports) setShowReports(false);
    else if (showSecurityWorkbench) setShowSecurityWorkbench(false);
    else if (showAttackPaths) setShowAttackPaths(false);
    else if (showSystemStatus) setShowSystemStatus(false);
    else if (showAutomation) setShowAutomation(false);
    else if (showReliability) setShowReliability(false);
    else if (showDhcpImport) setShowDhcpImport(false);
    else if (showPacketCapture) setShowPacketCapture(false);
    else if (showNotifications) setShowNotifications(false);
    else if (showAlertHistory) setShowAlertHistory(false);
    else if (showAudit) setShowAudit(false);
    else if (showUsers) setShowUsers(false);
  }, [
    showAlertHistory,
    showAttackPaths,
    showAudit,
    showAutomation,
    showDhcpImport,
    showNotifications,
    showObservability,
    showPacketCapture,
    showReliability,
    showReports,
    showSecurityWorkbench,
    showSystemStatus,
    showUsers,
  ]);

  const sidebarWindowOpen =
    showUsers ||
    showAudit ||
    showAlertHistory ||
    showNotifications ||
    showPacketCapture ||
    showDhcpImport ||
    showReliability ||
    showAutomation ||
    showSystemStatus ||
    showAttackPaths ||
    showSecurityWorkbench ||
    showReports ||
    showObservability;

  useEffect(() => {
    document.documentElement.dataset.aegisTheme = visualTheme;
    try {
      window.localStorage.setItem("aegis_visual_theme", visualTheme);
    } catch {
      /* Theme persistence is optional when storage is unavailable. */
    }
  }, [visualTheme]);

  useEffect(() => {
    if (!sidebarWindowOpen) return undefined;
    function dismissSidebarWindow(event) {
      if (
        event.key !== "Escape" ||
        commandPaletteOpen ||
        formDevice !== undefined
      )
        return;
      event.preventDefault();
      closeTopSidebarWindow();
    }
    document.addEventListener("keydown", dismissSidebarWindow);
    return () => document.removeEventListener("keydown", dismissSidebarWindow);
  }, [
    closeTopSidebarWindow,
    commandPaletteOpen,
    formDevice,
    sidebarWindowOpen,
  ]);

  useEffect(() => {
    if (!headerMenuOpen) return undefined;
    function closeHeaderMenu(event) {
      if (event.type === "keydown" && event.key !== "Escape") return;
      if (
        event.type === "pointerdown" &&
        headerMenuRef.current?.contains(event.target)
      )
        return;
      setHeaderMenuOpen(false);
    }
    document.addEventListener("keydown", closeHeaderMenu);
    document.addEventListener("pointerdown", closeHeaderMenu);
    return () => {
      document.removeEventListener("keydown", closeHeaderMenu);
      document.removeEventListener("pointerdown", closeHeaderMenu);
    };
  }, [headerMenuOpen]);

  useEffect(() => {
    if (!networkAction || clearingDevices || discovering) return undefined;
    setHeaderMenuOpen(false);
    setCommandPaletteOpen(false);
    function closeNetworkActionOnEscape(event) {
      if (event.key !== "Escape") return;
      event.preventDefault();
      setNetworkAction(null);
      setNetworkActionConfirmation("");
    }
    document.addEventListener("keydown", closeNetworkActionOnEscape);
    return () => document.removeEventListener("keydown", closeNetworkActionOnEscape);
  }, [networkAction, clearingDevices, discovering]);

  const [bulkGroup, setBulkGroup] = useState("");
  const [bulkBusy, setBulkBusy] = useState(false);
  const canWrite =
    auth?.user?.role === "ADMIN" || auth?.user?.role === "OPERATOR";

  const refreshAuthStatus = useCallback(async () => {
    setAuthError("");
    setAuth(null);
    try {
      setAuth(await getAuthStatus());
    } catch (requestError) {
      setAuthError(requestError.message);
    }
  }, []);

  useEffect(() => {
    refreshAuthStatus();
  }, [refreshAuthStatus]);

  const deviceTypes = useMemo(
    () =>
      [...new Set(data.devices.map((device) => device.device_type))].sort(
        (left, right) => left.localeCompare(right),
      ),
    [data.devices],
  );
  const deviceGroups = useMemo(
    () =>
      [
        ...new Set(
          data.devices.map((device) => device.device_group).filter(Boolean),
        ),
      ].sort((left, right) => left.localeCompare(right)),
    [data.devices],
  );
  const deviceTags = useMemo(
    () =>
      [...new Set(data.devices.flatMap((device) => device.tags || []))].sort(
        (left, right) => left.localeCompare(right),
      ),
    [data.devices],
  );

  const filteredDevices = useMemo(() => {
    const query = filters.query.trim().toLocaleLowerCase();
    return data.devices.filter((device) => {
      const searchable =
        `${device.name} ${device.ip_address} ${device.device_type} ${device.asset_tag || ""} ${device.device_group || ""} ${(device.tags || []).join(" ")} ${device.owner || ""} ${device.location || ""} ${device.operating_system || ""} ${device.criticality || ""} ${device.mac_address || ""} ${device.manufacturer || ""} ${device.discovered_model || ""} ${device.vlan || ""}`.toLocaleLowerCase();
      return (
        (!query || searchable.includes(query)) &&
        (filters.status === "ALL" ||
          device.current_status === filters.status) &&
        (filters.type === "ALL" || device.device_type === filters.type) &&
        (filters.group === "ALL" ||
          (filters.group === "__UNGROUPED__"
            ? !device.device_group
            : device.device_group === filters.group)) &&
        (filters.tag === "ALL" ||
          (filters.tag === "__UNTAGGED__"
            ? !device.tags?.length
            : device.tags?.includes(filters.tag)))
      );
    });
  }, [data.devices, filters]);

  const sortedAllDevices = useMemo(() => {
    const statusOrder = { ONLINE: 0, OFFLINE: 1, UNKNOWN: 2 };
    const valueFor = (device) => {
      if (sort.key === "status") return statusOrder[device.current_status] ?? 3;
      if (sort.key === "latency") return device.latest_latency_ms;
      if (sort.key === "availability") return device.availability_percent;
      if (sort.key === "last_checked")
        return device.last_checked_at
          ? new Date(device.last_checked_at).getTime()
          : null;
      return device.name.toLocaleLowerCase();
    };
    return [...filteredDevices].sort((left, right) => {
      const leftValue = valueFor(left);
      const rightValue = valueFor(right);
      if (leftValue === null || leftValue === undefined)
        return rightValue === null || rightValue === undefined ? 0 : 1;
      if (rightValue === null || rightValue === undefined) return -1;
      const comparison =
        typeof leftValue === "string"
          ? leftValue.localeCompare(rightValue)
          : leftValue - rightValue;
      return sort.direction === "asc" ? comparison : -comparison;
    });
  }, [filteredDevices, sort]);

  const filtersActive =
    filters.query !== "" ||
    filters.status !== "ALL" ||
    filters.type !== "ALL" ||
    filters.group !== "ALL" ||
    filters.tag !== "ALL";
  const pageCount = Math.max(1, Math.ceil(sortedAllDevices.length / pageSize));
  const currentPage = Math.min(page, pageCount);
  const paginatedDevices = useMemo(
    () =>
      sortedAllDevices.slice(
        (currentPage - 1) * pageSize,
        currentPage * pageSize,
      ),
    [sortedAllDevices, currentPage, pageSize],
  );
  const sortedDevices = paginatedDevices;
  const allPageSelected =
    paginatedDevices.length > 0 &&
    paginatedDevices.every((device) => selectedDeviceIds.includes(device.id));

  useEffect(() => {
    setPage(1);
  }, [filters, pageSize]);
  useEffect(() => {
    const validIds = new Set(data.devices.map((device) => device.id));
    setSelectedDeviceIds((current) =>
      current.filter((deviceId) => validIds.has(deviceId)),
    );
  }, [data.devices]);

  function changeSort(key) {
    setSort((current) =>
      current.key === key
        ? { key, direction: current.direction === "asc" ? "desc" : "asc" }
        : { key, direction: "asc" },
    );
  }

  function sortIndicator(key) {
    if (sort.key !== key) return "↕";
    return sort.direction === "asc" ? "↑" : "↓";
  }

  function ariaSort(key) {
    if (sort.key !== key) return "none";
    return sort.direction === "asc" ? "ascending" : "descending";
  }

  function toggleDeviceSelection(deviceId) {
    setSelectedDeviceIds((current) =>
      current.includes(deviceId)
        ? current.filter((value) => value !== deviceId)
        : [...current, deviceId],
    );
  }

  function togglePageSelection() {
    const pageIds = paginatedDevices.map((device) => device.id);
    const allSelected =
      pageIds.length > 0 &&
      pageIds.every((deviceId) => selectedDeviceIds.includes(deviceId));
    setSelectedDeviceIds((current) =>
      allSelected
        ? current.filter((deviceId) => !pageIds.includes(deviceId))
        : [...new Set([...current, ...pageIds])],
    );
  }

  async function handleBulkCheck() {
    setBulkBusy(true);
    setDiscoveryMessage("");
    try {
      const result = await checkSelectedDevices(selectedDeviceIds);
      setDiscoveryMessage(
        `Selected check complete: ${result.checked_devices} checked, ${result.online_devices} online, ${result.offline_devices} offline.`,
      );
      await loadDashboard({ quiet: true });
    } catch (requestError) {
      setError(requestError.message);
    } finally {
      setBulkBusy(false);
    }
  }

  async function handleBulkMonitoring(action) {
    setBulkBusy(true);
    setDiscoveryMessage("");
    try {
      const result = await updateSelectedMonitoring(selectedDeviceIds, action);
      setDiscoveryMessage(
        `${result.updated_devices} devices ${action === "ENABLE" ? "enabled" : "paused"} for automatic monitoring.`,
      );
      await loadDashboard({ quiet: true });
    } catch (requestError) {
      setError(requestError.message);
    } finally {
      setBulkBusy(false);
    }
  }

  async function handleBulkGroup(clear = false) {
    if (!clear && !bulkGroup.trim()) {
      setError("Enter a group name or use Clear group.");
      return;
    }
    setBulkBusy(true);
    setDiscoveryMessage("");
    try {
      const result = await updateSelectedGroup(
        selectedDeviceIds,
        clear ? null : bulkGroup.trim(),
      );
      setDiscoveryMessage(
        clear
          ? `${result.updated_devices} devices removed from their group.`
          : `${result.updated_devices} devices assigned to ${bulkGroup.trim()}.`,
      );
      if (!clear) setBulkGroup("");
      await loadDashboard({ quiet: true });
    } catch (requestError) {
      setError(requestError.message);
    } finally {
      setBulkBusy(false);
    }
  }

  function downloadBlob(blob, filename) {
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = filename;
    document.body.appendChild(link);
    link.click();
    link.remove();
    URL.revokeObjectURL(url);
  }

  async function exportExcel() {
    try {
      const { default: ExcelJS } = await import("exceljs");
      const workbook = new ExcelJS.Workbook();
      workbook.creator = "Aegis";
      workbook.created = new Date();
      const inventory = workbook.addWorksheet("Device Inventory", {
        views: [{ state: "frozen", ySplit: 1 }],
      });
      const headers = [
        "Name",
        "Asset tag",
        "Device group",
        "Owner",
        "Location",
        "Operating system",
        "Criticality",
        "IP address",
        "MAC address",
        "Manufacturer",
        "Advertised model",
        "Device type",
        "VLAN",
        "Inventory source",
        "Lease expires",
        "Maintenance until",
        "Maintenance reason",
        "Status",
        "Latency (ms)",
        "Availability",
        "Last checked",
      ];
      const rows = sortedAllDevices.map((device) => [
        device.name,
        device.asset_tag,
        device.device_group,
        device.owner,
        device.location,
        device.operating_system,
        device.criticality,
        device.ip_address,
        device.mac_address,
        device.manufacturer,
        device.discovered_model,
        device.device_type,
        device.vlan,
        device.inventory_source,
        device.lease_expires_at ? new Date(device.lease_expires_at) : null,
        device.maintenance_until ? new Date(device.maintenance_until) : null,
        device.maintenance_reason,
        device.current_status,
        device.latest_latency_ms,
        device.availability_percent === null ||
        device.availability_percent === undefined
          ? null
          : device.availability_percent / 100,
        device.last_checked_at ? new Date(device.last_checked_at) : null,
      ]);
      inventory.addTable({
        name: "DeviceInventory",
        ref: "A1",
        headerRow: true,
        style: { theme: "TableStyleMedium2", showRowStripes: true },
        columns: headers.map((name) => ({ name, filterButton: true })),
        rows,
      });
      inventory.columns = [
        { width: 34 },
        { width: 16 },
        { width: 20 },
        { width: 24 },
        { width: 22 },
        { width: 24 },
        { width: 13 },
        { width: 18 },
        { width: 20 },
        { width: 28 },
        { width: 17 },
        { width: 12 },
        { width: 18 },
        { width: 23 },
        { width: 23 },
        { width: 30 },
        { width: 14 },
        { width: 16 },
        { width: 16 },
        { width: 23 },
      ];
      inventory.getColumn(14).numFmt = "yyyy-mm-dd hh:mm:ss";
      inventory.getColumn(15).numFmt = "yyyy-mm-dd hh:mm:ss";
      inventory.getColumn(18).numFmt = "0.00";
      inventory.getColumn(19).numFmt = "0.00%";
      inventory.getColumn(20).numFmt = "yyyy-mm-dd hh:mm:ss";
      inventory.autoFilter = { from: "A1", to: `T${rows.length + 1}` };
      inventory.eachRow((row, rowNumber) => {
        row.height = rowNumber === 1 ? 24 : 20;
        row.alignment = { vertical: "middle" };
        if (rowNumber > 1) {
          const statusCell = row.getCell(17);
          const status = statusCell.value;
          const color =
            status === "ONLINE"
              ? "FFE6F5EC"
              : status === "OFFLINE"
                ? "FFFCE8E8"
                : "FFFFF3D6";
          statusCell.fill = {
            type: "pattern",
            pattern: "solid",
            fgColor: { argb: color },
          };
          statusCell.font = { bold: true };
        }
      });

      const summary = workbook.addWorksheet("Summary", {
        views: [{ state: "frozen", ySplit: 3 }],
      });
      summary.mergeCells("A1:D1");
      summary.getCell("A1").value = "Aegis Infrastructure Summary";
      summary.getCell("A1").font = {
        size: 18,
        bold: true,
        color: { argb: "FFFFFFFF" },
      };
      summary.getCell("A1").fill = {
        type: "pattern",
        pattern: "solid",
        fgColor: { argb: "FF183153" },
      };
      summary.getCell("A2").value = "Exported";
      summary.getCell("B2").value = new Date();
      summary.getCell("B2").numFmt = "yyyy-mm-dd hh:mm:ss";
      summary.addRows([
        ["Metric", "Value"],
        [
          "Matching devices",
          { formula: "ROWS(DeviceInventory[Name])", result: rows.length },
        ],
        [
          "Online",
          {
            formula: 'COUNTIF(DeviceInventory[Status],"ONLINE")',
            result: rows.filter((row) => row[16] === "ONLINE").length,
          },
        ],
        [
          "Offline",
          {
            formula: 'COUNTIF(DeviceInventory[Status],"OFFLINE")',
            result: rows.filter((row) => row[16] === "OFFLINE").length,
          },
        ],
        [
          "Not checked",
          {
            formula: 'COUNTIF(DeviceInventory[Status],"UNKNOWN")',
            result: rows.filter((row) => row[16] === "UNKNOWN").length,
          },
        ],
      ]);
      summary.getRow(3).font = { bold: true, color: { argb: "FFFFFFFF" } };
      summary.getRow(3).fill = {
        type: "pattern",
        pattern: "solid",
        fgColor: { argb: "FF315FDA" },
      };
      summary.columns = [
        { width: 24 },
        { width: 24 },
        { width: 14 },
        { width: 14 },
      ];

      const buffer = await workbook.xlsx.writeBuffer();
      downloadBlob(
        new Blob([buffer], {
          type: "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        }),
        `aegis-devices-${new Date().toISOString().slice(0, 10)}.xlsx`,
      );
    } catch (exportError) {
      setError(`Excel export failed: ${exportError.message}`);
    }
  }

  const loadDashboard = useCallback(async ({ quiet = false } = {}) => {
    if (!quiet) setLoading(true);
    try {
      const refresh = await getDashboardRefresh();
      const {
        dashboard,
        scheduler: schedulerStatus,
        inventory_health: health,
        topology: topologyResult,
        agent_overview: agentResult,
        service_overview: serviceResult,
      } = refresh;
      const actionableAlerts = dashboard.active_alerts.filter(
        (alert) => !alert.acknowledged_at,
      );
      setData({
        ...dashboard,
        active_alerts: actionableAlerts,
        active_alert_count: actionableAlerts.length,
      });
      setInventoryHealth(health);
      setTopology(topologyResult);
      setAgentOverview(agentResult);
      setServiceOverview(serviceResult);
      setScheduler(schedulerStatus);
      setError("");
      setLastUpdated(new Date());
    } catch (requestError) {
      setError(requestError.message);
    } finally {
      if (!quiet) setLoading(false);
    }
  }, []);

  async function handleSchedulerToggle() {
    if (!scheduler?.enabled) return;
    setSchedulerBusy(true);
    try {
      setScheduler(
        scheduler.running ? await pauseScheduler() : await resumeScheduler(),
      );
      setError("");
    } catch (requestError) {
      setError(requestError.message);
    } finally {
      setSchedulerBusy(false);
    }
  }

  useEffect(() => {
    if (!auth?.authenticated) return undefined;
    loadDashboard();
    const timer = window.setInterval(
      () => !selectedId && loadDashboard({ quiet: true }),
      15000,
    );
    return () => window.clearInterval(timer);
  }, [loadDashboard, selectedId, auth?.authenticated]);

  useEffect(() => {
    function handlePopState(event) {
      setSelectedId(deviceIdFromPath());
      setDetailOrigin(event.state?.aegisOrigin || null);
    }
    window.addEventListener("popstate", handlePopState);
    return () => window.removeEventListener("popstate", handlePopState);
  }, []);

  function navigateToDevice(deviceId, origin = null) {
    window.history.pushState(
      origin ? { aegisOrigin: origin } : {},
      "",
      `/devices/${deviceId}`,
    );
    setSelectedId(deviceId);
    setDetailOrigin(origin);
  }

  function navigateToDashboard() {
    window.history.pushState({}, "", "/");
    setSelectedId(null);
    setDetailOrigin(null);
    loadDashboard({ quiet: true });
  }

  function navigateBackFromDevice() {
    const returnToWorkbench = detailOrigin === "security-workbench";
    navigateToDashboard();
    if (returnToWorkbench) setShowSecurityWorkbench(true);
  }

  function navigateFromSecurityWorkbench(deviceId) {
    navigateToDevice(deviceId, "security-workbench");
  }

  function openObservability() {
    setObservabilitySeen(true);
    setShowObservability(true);
    try {
      window.localStorage.setItem("aegis_observability_seen", "true");
    } catch {
      /* Local progress persistence is optional. */
    }
  }

  function showSetupGuide() {
    setSetupGuideVisible(true);
    try {
      window.localStorage.removeItem("aegis_setup_guide_hidden");
    } catch {
      /* Local progress persistence is optional. */
    }
  }

  function dismissSetupGuide() {
    setSetupGuideVisible(false);
    try {
      window.localStorage.setItem("aegis_setup_guide_hidden", "true");
    } catch {
      /* Local progress persistence is optional. */
    }
  }

  function persistSavedViews(nextViews) {
    setSavedViews(nextViews);
    try {
      window.localStorage.setItem(
        "aegis_saved_device_views",
        JSON.stringify(nextViews),
      );
    } catch {
      /* Saved views remain available for the current session. */
    }
  }

  function updateDashboardSection(section, enabled) {
    setDashboardSections((current) => {
      const next = { ...current, [section]: enabled };
      try {
        window.localStorage.setItem(
          "aegis_dashboard_sections",
          JSON.stringify(next),
        );
      } catch {
        /* Dashboard preferences remain available for this session. */
      }
      return next;
    });
  }

  function resetDashboardSections() {
    setDashboardSections(DASHBOARD_SECTION_DEFAULTS);
    try {
      window.localStorage.removeItem("aegis_dashboard_sections");
    } catch {
      /* Storage can be unavailable in private browsing modes. */
    }
  }

  function saveCurrentView(name) {
    const view = {
      id: `${Date.now()}`,
      name,
      filters: { ...filters },
      sort: { ...sort },
      pageSize,
    };
    persistSavedViews([...savedViews, view]);
  }

  function applySavedView(view) {
    setFilters({ ...DEFAULT_DEVICE_FILTERS, ...view.filters });
    setSort({ ...view.sort });
    setPageSize(normalizedDevicePageSize(view.pageSize));
    setPage(1);
  }

  function deleteSavedView(id) {
    persistSavedViews(savedViews.filter((view) => view.id !== id));
  }

  const setupGuideItems = [
    {
      id: "inventory",
      number: "1",
      label: "Build the inventory",
      description: "Add or discover at least one monitored device.",
      complete: data.total_devices > 0,
      actionLabel: "Add device",
      action: () => setFormDevice(null),
    },
    {
      id: "scheduler",
      number: "2",
      label: "Enable automatic monitoring",
      description: "Keep reachability checks running in the background.",
      complete: Boolean(scheduler?.enabled && scheduler?.running),
      actionLabel: scheduler?.enabled ? "Start monitoring" : "System status",
      action: scheduler?.enabled
        ? handleSchedulerToggle
        : () => setShowSystemStatus(true),
    },
    {
      id: "agents",
      number: "3",
      label: "Connect a host agent",
      description: "Collect authenticated operating-system and resource data.",
      complete: agentOverview.total_agents > 0,
      actionLabel: "View agents",
      action: () =>
        document
          .querySelector(".agent-fleet-panel")
          ?.scrollIntoView({ behavior: "smooth", block: "start" }),
    },
    {
      id: "snmp",
      number: "4",
      label: "Configure SNMP",
      description: "Enable SNMP on a device and provide its server-side secret.",
      complete: data.snmp_configured,
      actionLabel: data.total_devices ? "Open first device" : "Add device",
      action: () => data.devices[0]
        ? navigateToDevice(data.devices[0].id)
        : setFormDevice(null),
    },
    {
      id: "notifications",
      number: "5",
      label: "Test notifications",
      description: data.notification_configured
        ? "Send a successful test through an enabled channel."
        : "Configure and enable an email, Teams, or SMS channel.",
      complete: data.notification_tested,
      actionLabel: "Open notifications",
      action: () => setShowNotifications(true),
    },
    {
      id: "observability",
      number: "6",
      label: "Review observability",
      description: "Open the embedded Grafana dashboard at least once.",
      complete: observabilitySeen,
      actionLabel: "Open dashboard",
      action: openObservability,
    },
  ];

  const commandPaletteCommands = useMemo(() => {
    const commands = [
      {
        id: "refresh-dashboard",
        label: "Refresh dashboard",
        description: "Reload device, alert, and scheduler data",
        icon: "↻",
        action: () => loadDashboard(),
      },
      {
        id: "availability-reports",
        label: "Open availability reports",
        description: "Review and export availability history",
        icon: "▥",
        action: () => setShowReports(true),
      },
      {
        id: "alert-history",
        label: "Open alert history",
        description: "Review active, acknowledged, and resolved alerts",
        icon: "!",
        action: () => setShowAlertHistory(true),
      },
      {
        id: "observability-dashboard",
        label: "Open observability dashboard",
        description: "View embedded Grafana metrics and trends",
        icon: "▦",
        action: openObservability,
      },
      {
        id: "setup-guide",
        label: "Show setup guide",
        description: "Review the essential Aegis setup checklist",
        icon: "✓",
        action: showSetupGuide,
      },
    ];
    if (canWrite) {
      commands.push(
        {
          id: "add-device",
          label: "Add a device",
          description: "Register a device manually",
          icon: "+",
          action: () => setFormDevice(null),
        },
      );
    }
    if (auth?.user?.role === "ADMIN") {
      commands.push(
        {
          id: "discover-devices",
          label: "Discover network devices",
          description: "Search the connected network for devices",
          icon: "⌁",
          action: handleDiscovery,
        },
        {
          id: "clear-device-inventory",
          label: "Clear all devices",
          description: "Reset device inventory before changing lab networks",
          icon: "×",
          action: handleClearAllDevices,
        },
        {
          id: "security-workbench",
          label: "Open Security Workbench",
          description: "Defensive analysis and investigation tools",
          icon: "◇",
          action: () => setShowSecurityWorkbench(true),
        },
        {
          id: "attack-paths",
          label: "Open attack paths",
          description: "Review candidate exposure paths",
          icon: "⇢",
          action: () => setShowAttackPaths(true),
        },
        {
          id: "system-status",
          label: "Open system status",
          description: "Check Aegis component readiness",
          icon: "●",
          action: () => setShowSystemStatus(true),
        },
        {
          id: "automation-center",
          label: "Open automation center",
          description: "Manage scheduled operational workflows",
          icon: "⚙",
          action: () => setShowAutomation(true),
        },
        {
          id: "notifications",
          label: "Open notifications",
          description: "Configure alert delivery channels",
          icon: "✦",
          action: () => setShowNotifications(true),
        },
        {
          id: "packet-capture",
          label: "Open packet capture",
          description: "Start a controlled local capture",
          icon: "◉",
          action: () => setShowPacketCapture(true),
        },
      );
    }
    data.devices.forEach((device) => {
      commands.push({
        id: `device-${device.id}`,
        label: `Open ${device.name}`,
        description: `${device.ip_address} · ${device.device_type}`,
        icon: "▣",
        action: () => navigateToDevice(device.id),
      });
    });
    return commands;
  }, [
    auth?.user?.role,
    canWrite,
    data.devices,
    lastDiscoveryNetwork,
    loadDashboard,
  ]);

  useEffect(() => {
    function handleCommandShortcut(event) {
      if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === "k") {
        event.preventDefault();
        if (auth?.authenticated) setCommandPaletteOpen((open) => !open);
      }
    }
    document.addEventListener("keydown", handleCommandShortcut);
    return () => document.removeEventListener("keydown", handleCommandShortcut);
  }, [auth?.authenticated]);

  async function handleCheck(deviceId) {
    setCheckingId(deviceId);
    try {
      await checkDevice(deviceId);
      await loadDashboard({ quiet: true });
    } catch (requestError) {
      setError(requestError.message);
    } finally {
      setCheckingId(null);
    }
  }

  async function handleCheckAll() {
    setCheckingAll(true);
    setDiscoveryMessage("");
    try {
      const result = await checkAllDevices();
      setDiscoveryMessage(
        `Check complete: ${result.checked_devices} devices checked, ${result.online_devices} online, ${result.offline_devices} offline.`,
      );
      await loadDashboard({ quiet: true });
    } catch (requestError) {
      setError(requestError.message);
    } finally {
      setCheckingAll(false);
    }
  }

  async function handleFingerprintAll() {
    setFingerprintingAll(true);
    setDiscoveryMessage("");
    try {
      const result = await fingerprintAllDevices();
      setDiscoveryMessage(
        `Fingerprint complete: ${result.fingerprinted_devices} devices checked, ${result.classified_devices} produced classification evidence.`,
      );
      await loadDashboard({ quiet: true });
    } catch (requestError) {
      setError(requestError.message);
    } finally {
      setFingerprintingAll(false);
    }
  }

  async function handleAcknowledge(alertId) {
    if (acknowledgementInFlight.current.has(alertId)) return;
    acknowledgementInFlight.current.add(alertId);
    setAcknowledgingId(alertId);
    setData((current) => ({
      ...current,
      active_alerts: current.active_alerts.filter(
        (alert) => alert.id !== alertId,
      ),
      active_alert_count: Math.max(0, current.active_alert_count - 1),
    }));
    try {
      await acknowledgeAlert(alertId);
      await loadDashboard({ quiet: true });
    } catch (requestError) {
      setError(requestError.message);
    } finally {
      acknowledgementInFlight.current.delete(alertId);
      setAcknowledgingId(null);
    }
  }

  async function handleAcknowledgeAll() {
    if (acknowledgingAll || data.active_alert_count === 0) return;
    if (
      !window.confirm(
        `Acknowledge all ${data.active_alert_count} active alerts?`,
      )
    )
      return;
    setAcknowledgingAll(true);
    setError("");
    try {
      await acknowledgeAllAlerts();
      setData((current) => ({
        ...current,
        active_alerts: [],
        active_alert_count: 0,
      }));
      await loadDashboard({ quiet: true });
    } catch (requestError) {
      setError(requestError.message);
    } finally {
      setAcknowledgingAll(false);
    }
  }

  async function handleDiscovery() {
    setDiscovering(true);
    setDiscoveryMessage("");
    setError("");
    try {
      const network = await getDiscoveryNetwork();
      const containsOtherDiscoveredNetworks = data.devices.some(
        (device) =>
          device.inventory_source === "DISCOVERY" &&
          !ipv4AddressInCidr(device.ip_address, network.network),
      );
      const networkChanged = Boolean(
        lastDiscoveryNetwork && lastDiscoveryNetwork !== network.network,
      );
      setNetworkActionConfirmation("");
      setNetworkAction({
        kind: "discover",
        network,
        previousNetwork: lastDiscoveryNetwork,
        requiresReset: data.total_devices > 0 &&
          (networkChanged || containsOtherDiscoveredNetworks),
        resetReason: networkChanged
          ? `The last scan used ${lastDiscoveryNetwork}. AEGIS detected ${network.network} and can clear the old inventory before scanning it.`
          : `The inventory contains discovered devices outside ${network.network}. Clear the saved networks before scanning so old devices do not inflate the dashboard totals.`,
        deviceCount: data.total_devices,
        error: "",
      });
    } catch (requestError) {
      setError(
        `Discovery unavailable: ${requestError.message}. Add devices manually or connect to an RFC 1918 private network.`,
      );
    } finally {
      setDiscovering(false);
    }
  }

  async function confirmNetworkAction(event) {
    event.preventDefault();
    if (!networkAction) return;
    const clearsInventory =
      networkAction.kind === "reset" || networkAction.requiresReset;
    if (
      clearsInventory &&
      networkActionConfirmation.trim() !== CLEAR_DEVICES_CONFIRMATION
    )
      return;

    setClearingDevices(clearsInventory);
    setDiscovering(networkAction.kind === "discover");
    setError("");
    try {
      let cleared = null;
      if (clearsInventory) {
        cleared = await clearAllDevices(CLEAR_DEVICES_CONFIRMATION);
        setSelectedDeviceIds([]);
        setPage(1);
        try {
          window.localStorage.removeItem(LAST_DISCOVERY_NETWORK_KEY);
        } catch {
          /* Reset succeeds even when storage is unavailable. */
        }
        setLastDiscoveryNetwork(null);
      }

      let discovered = null;
      if (networkAction.kind === "discover") {
        discovered = await discoverDevices();
        try {
          window.localStorage.setItem(
            LAST_DISCOVERY_NETWORK_KEY,
            discovered.network.network,
          );
        } catch {
          /* Discovery works even when storage is unavailable. */
        }
        setLastDiscoveryNetwork(discovered.network.network);
      }

      await loadDashboard({ quiet: true });
      if (discovered) {
        const resetSummary = cleared
          ? `${cleared.deleted_devices} old devices cleared. `
          : "";
        setDiscoveryMessage(
          `${resetSummary}Discovery finished on ${discovered.network.network}: ${discovered.responsive_devices} responsive, ${discovered.devices_added} added, ${discovered.devices_skipped} already registered.`,
        );
      } else if (cleared) {
        setDiscoveryMessage(
          `Device inventory cleared: ${cleared.deleted_devices} devices and ${cleared.deleted_attachments} attachments removed.`,
        );
      }
      setNetworkAction(null);
      setNetworkActionConfirmation("");
    } catch (requestError) {
      setNetworkAction((current) =>
        current ? { ...current, error: requestError.message } : current,
      );
    } finally {
      setClearingDevices(false);
      setDiscovering(false);
    }
  }

  function handleClearAllDevices() {
    setNetworkActionConfirmation("");
    setNetworkAction({
      kind: "reset",
      requiresReset: true,
      deviceCount: data.total_devices,
      error: "",
    });
  }

  function closeNetworkAction() {
    if (clearingDevices || discovering) return;
    setNetworkAction(null);
    setNetworkActionConfirmation("");
  }

  async function handleSaved(saved) {
    setFormDevice(undefined);
    await loadDashboard({ quiet: true });
    if (selectedId) navigateToDevice(saved.id, detailOrigin);
  }

  function handleDeleted() {
    navigateBackFromDevice();
  }

  async function handleLogout() {
    try {
      await logoutUser();
    } catch {
      /* Clear the local token even if the session already expired. */
    }
    setAuthToken(null);
    setShowUsers(false);
    setShowAudit(false);
    setAuth({ setup_required: false, authenticated: false, user: null });
  }

  function openSidebarPanel(openPanel) {
    setMobileNavigationOpen(false);
    openPanel();
  }

  function toggleSidebarSection(section) {
    setExpandedSidebarSections((current) => ({
      ...current,
      [section]: !current[section],
    }));
  }

  if (authError)
    return (
      <main className="auth-page">
        <section className="auth-card auth-recovery" role="alert">
          <p className="eyebrow">Connection unavailable</p>
          <h1>Unable to reach Aegis</h1>
          <p>{authError}</p>
          <button className="button button--primary" onClick={refreshAuthStatus}>
            Try again
          </button>
        </section>
      </main>
    );
  if (auth === null)
    return (
      <main className="auth-page">
        <div className="auth-loading">Loading secure session…</div>
      </main>
    );
  if (!auth.authenticated)
    return (
      <AuthScreen
        setupRequired={auth.setup_required}
        visualTheme={visualTheme}
        onAuthenticated={(user) =>
          setAuth({ setup_required: false, authenticated: true, user })
        }
      />
    );

  return (
    <div
      className={`app-shell app-shell--${auth.user.role.toLowerCase()} app-shell--${visualTheme}`}
      onMouseDown={(event) => {
        if (
          event.target instanceof Element &&
          event.target.classList.contains("modal-backdrop") &&
          !commandPaletteOpen &&
          formDevice === undefined
        )
          closeTopSidebarWindow();
      }}
    >
      {networkAction && (
        <NetworkActionDialog
          action={networkAction}
          confirmation={networkActionConfirmation}
          busy={clearingDevices || discovering}
          onConfirmationChange={setNetworkActionConfirmation}
          onCancel={closeNetworkAction}
          onConfirm={confirmNetworkAction}
        />
      )}
      <a
        className="skip-link"
        href="#main-content"
        tabIndex={networkAction ? -1 : undefined}
        aria-hidden={networkAction ? "true" : undefined}
      >
        Skip to main content
      </a>
      <aside
        className={`sidebar${mobileNavigationOpen ? " sidebar--menu-open" : ""}`}
        inert={networkAction ? true : undefined}
        aria-hidden={networkAction ? "true" : undefined}
      >
        <button
          className="sidebar-brand"
          type="button"
          aria-label="Go to the Aegis dashboard"
          onClick={() => {
            setMobileNavigationOpen(false);
            navigateToDashboard();
          }}
        >
          <div className="brand-mark">
            <img
              src={visualTheme === "goth" ? aegisShieldDark : aegisShield}
              alt=""
            />
          </div>
          <div>
            <strong>Aegis</strong>
            <span>Infrastructure monitor</span>
          </div>
        </button>
        <button
          className="sidebar-menu-toggle"
          type="button"
          aria-expanded={mobileNavigationOpen}
          aria-controls="sidebar-mobile-content"
          onClick={() => setMobileNavigationOpen((open) => !open)}
        >
          <span aria-hidden="true">{mobileNavigationOpen ? "×" : "☰"}</span>
          {mobileNavigationOpen ? "Close" : "Menu"}
        </button>
        <div className="sidebar-divider" aria-hidden="true">
          <span>◇</span>
          <i />
        </div>
        <nav
          id="sidebar-mobile-content"
          className="sidebar-tools"
          aria-label="Monitoring tools"
        >
          <button
            className="observability-launch"
            type="button"
            onClick={() => openSidebarPanel(openObservability)}
          >
            <span aria-hidden="true">▦</span>
            Observability
          </button>
        </nav>
        <nav className="sidebar-navigation" aria-label="Application navigation">
          <section className="sidebar-section">
            <button
              className="sidebar-section-toggle"
              type="button"
              aria-expanded={expandedSidebarSections.reports}
              aria-controls="sidebar-reports"
              onClick={() => toggleSidebarSection("reports")}
            >
              <span>Reports</span>
              <span className="sidebar-section-chevron" aria-hidden="true">⌄</span>
            </button>
            <div
              id="sidebar-reports"
              className="sidebar-section-items"
              hidden={!expandedSidebarSections.reports}
            >
              <button onClick={() => openSidebarPanel(showSetupGuide)}>
                Setup guide
              </button>
              <button onClick={() => openSidebarPanel(() => setShowAlertHistory(true))}>
                Alert history
              </button>
              <button onClick={() => openSidebarPanel(() => setShowReports(true))}>
                Availability reports
              </button>
            </div>
          </section>
          {auth.user.role === "ADMIN" && (
            <>
              <section className="sidebar-section">
                <button
                  className="sidebar-section-toggle"
                  type="button"
                  aria-expanded={expandedSidebarSections.security}
                  aria-controls="sidebar-security"
                  onClick={() => toggleSidebarSection("security")}
                >
                  <span>Security</span>
                  <span className="sidebar-section-chevron" aria-hidden="true">⌄</span>
                </button>
                <div
                  id="sidebar-security"
                  className="sidebar-section-items"
                  hidden={!expandedSidebarSections.security}
                >
                  <button onClick={() => openSidebarPanel(() => setShowSecurityWorkbench(true))}>
                    Security workbench
                  </button>
                  <button onClick={() => openSidebarPanel(() => setShowAttackPaths(true))}>
                    Attack paths
                  </button>
                  <button onClick={() => openSidebarPanel(() => setShowPacketCapture(true))}>
                    Packet capture
                  </button>
                </div>
              </section>
              <section className="sidebar-section">
                <button
                  className="sidebar-section-toggle"
                  type="button"
                  aria-expanded={expandedSidebarSections.administration}
                  aria-controls="sidebar-administration"
                  onClick={() => toggleSidebarSection("administration")}
                >
                  <span>Administration</span>
                  <span className="sidebar-section-chevron" aria-hidden="true">⌄</span>
                </button>
                <div
                  id="sidebar-administration"
                  className="sidebar-section-items"
                  hidden={!expandedSidebarSections.administration}
                >
                  <button onClick={() => openSidebarPanel(() => setShowSystemStatus(true))}>
                    System status
                  </button>
                  <button onClick={() => openSidebarPanel(() => setShowAutomation(true))}>
                    Automation center
                  </button>
                  <button onClick={() => openSidebarPanel(() => setShowUsers(true))}>
                    Manage users
                  </button>
                  <button onClick={() => openSidebarPanel(() => setShowAudit(true))}>
                    Audit log
                  </button>
                  <button onClick={() => openSidebarPanel(() => setShowNotifications(true))}>
                    Notifications
                  </button>
                  <button onClick={() => openSidebarPanel(() => setShowReliability(true))}>
                    Backups & retention
                  </button>
                  <button onClick={() => openSidebarPanel(() => setShowDhcpImport(true))}>
                    Import DHCP leases
                  </button>
                </div>
              </section>
            </>
          )}
        </nav>
        <div className="sidebar-footer">
          <div className="sidebar-user">
            <span>{auth.user.role}</span>
            <strong>{auth.user.username}</strong>
            <button onClick={() => openSidebarPanel(handleLogout)}>Sign out</button>
          </div>
          <button
            className="theme-switch"
            type="button"
            aria-pressed={visualTheme === "goth"}
            onClick={() =>
              setVisualTheme((current) =>
                current === "goth" ? "classic" : "goth",
              )
            }
          >
            <span aria-hidden="true">{visualTheme === "goth" ? "☾" : "◐"}</span>
            {visualTheme === "goth" ? "Dark theme" : "Light theme"}
          </button>
        </div>
      </aside>
      <main
        id="main-content"
        tabIndex="-1"
        inert={networkAction ? true : undefined}
        aria-hidden={networkAction ? "true" : undefined}
      >
        {selectedId ? (
          <DeviceDetail
            deviceId={selectedId}
            onBack={navigateBackFromDevice}
            backLabel={
              detailOrigin === "security-workbench"
                ? "Back to Security Workbench"
                : "Back to dashboard"
            }
            onEdit={setFormDevice}
            onDeleted={handleDeleted}
            isAdmin={auth.user.role === "ADMIN"}
            canWrite={canWrite}
          />
        ) : (
          <>
            <header className="page-header">
              <div>
                <p className="eyebrow">Operations overview</p>
                <h1>Infrastructure dashboard</h1>
                <p className="subtitle">
                  Live reachability and availability across your isolated lab.
                </p>
              </div>
              <div className="header-actions">
                <button
                  className="command-trigger"
                  type="button"
                  onClick={() => setCommandPaletteOpen(true)}
                  aria-label="Open command palette"
                >
                  <span aria-hidden="true">⌕</span>
                  Search
                  <kbd>Ctrl K</kbd>
                </button>
                <span>
                  Updated {lastUpdated ? lastUpdated.toLocaleTimeString() : "—"}
                </span>
                {lastDiscoveryNetwork && (
                  <span
                    className="network-context"
                    title="Subnet represented by the most recent device discovery"
                  >
                    Network <strong>{lastDiscoveryNetwork}</strong>
                  </span>
                )}
                {scheduler && canWrite && (
                  <button
                    className={`scheduler-control scheduler-control--${scheduler.running ? "running" : "paused"}`}
                    onClick={handleSchedulerToggle}
                    disabled={!scheduler.enabled || schedulerBusy}
                    title={`Automatic checks every ${scheduler.interval_seconds} seconds`}
                  >
                    <span />
                    {schedulerBusy
                      ? "Updating…"
                      : !scheduler.enabled
                        ? "Auto disabled"
                        : scheduler.running
                          ? "Auto running"
                          : "Auto paused"}
                  </button>
                )}
                <button
                  className="button button--secondary"
                  onClick={() => loadDashboard()}
                  disabled={loading || checkingAll}
                >
                  {loading ? "Refreshing…" : "Refresh"}
                </button>
                <DashboardDisplayControl
                  sections={dashboardSections}
                  onChange={updateDashboardSection}
                  onReset={resetDashboardSections}
                />
                {canWrite && (
                  <>
                    <div className="header-menu" ref={headerMenuRef}>
                      <button
                        className="button button--secondary"
                        type="button"
                        aria-haspopup="menu"
                        aria-expanded={headerMenuOpen}
                        onClick={() => setHeaderMenuOpen((open) => !open)}
                      >
                        More actions <span aria-hidden="true">⌄</span>
                      </button>
                      {headerMenuOpen && (
                        <div className="header-menu__popover" role="menu">
                          <button
                            role="menuitem"
                            onClick={() => {
                              setHeaderMenuOpen(false);
                              handleCheckAll();
                            }}
                            disabled={checkingAll || data.active_devices === 0}
                          >
                            {checkingAll
                              ? "Checking all…"
                              : "Check all devices"}
                            <small>
                              Run a reachability check for every device
                            </small>
                          </button>
                          {auth.user.role === "ADMIN" && (
                            <>
                              <button
                                role="menuitem"
                                onClick={() => {
                                  setHeaderMenuOpen(false);
                                  handleFingerprintAll();
                                }}
                                disabled={
                                  fingerprintingAll ||
                                  checkingAll ||
                                  data.active_devices === 0
                                }
                              >
                                {fingerprintingAll
                                  ? "Fingerprinting…"
                                  : "Fingerprint all devices"}
                                <small>Refresh discovered platform details</small>
                              </button>
                              <button
                                role="menuitem"
                                onClick={() => {
                                  setHeaderMenuOpen(false);
                                  handleDiscovery();
                                }}
                                disabled={discovering || checkingAll || clearingDevices}
                              >
                                {discovering
                                  ? "Discovering…"
                                  : "Discover network devices"}
                                <small>Find devices on the connected network</small>
                              </button>
                              <button
                                className="header-menu__danger"
                                role="menuitem"
                                onClick={() => {
                                  setHeaderMenuOpen(false);
                                  handleClearAllDevices();
                                }}
                                disabled={clearingDevices || data.total_devices === 0}
                              >
                                {clearingDevices
                                  ? "Clearing devices…"
                                  : "Clear all devices"}
                                <small>Reset inventory before switching networks</small>
                              </button>
                            </>
                          )}
                        </div>
                      )}
                    </div>
                    <button
                      className="button button--primary"
                      onClick={() => setFormDevice(null)}
                      disabled={checkingAll}
                    >
                      + Add device
                    </button>
                  </>
                )}
              </div>
            </header>
            {error && (
              <div className="error-banner" role="alert">
                <strong>Dashboard unavailable.</strong> {error}
              </div>
            )}
            {discoveryMessage && (
              <div className="success-banner" role="status">
                {discoveryMessage}
              </div>
            )}
            {setupGuideVisible && (
              <SetupGuidePanel
                items={setupGuideItems}
                onDismiss={dismissSetupGuide}
              />
            )}
            <section className="metrics" aria-label="Infrastructure summary">
              <MetricCard
                label="Total devices"
                value={data.total_devices}
                tone="neutral"
              />
              <MetricCard
                label="Online"
                value={data.online_devices}
                tone="online"
              />
              <MetricCard
                label="Offline"
                value={data.offline_devices}
                tone="offline"
              />
              <MetricCard
                label="Not checked"
                value={data.unknown_devices}
                tone="unknown"
              />
              <MetricCard
                label="Active alerts"
                value={data.active_alert_count}
                tone={data.active_alert_count ? "offline" : "online"}
              />
              <MetricCard
                label="Latest avg. latency"
                value={formatMetric(data.average_latest_latency_ms, " ms")}
                tone="latency"
              />
            </section>
            <OperationalInsights
              devices={data.devices}
              onSelectDevice={navigateToDevice}
            />
            {dashboardSections.alerts && data.active_alerts.length > 0 && (
              <section className="panel alerts-panel">
                <div className="panel-heading">
                  <div>
                    <p className="eyebrow">Attention required</p>
                    <h2>Active alerts</h2>
                  </div>
                  <div className="row-actions">
                    <span>{data.active_alert_count} open</span>
                    {canWrite && (
                      <button
                        className="button button--secondary"
                        onClick={handleAcknowledgeAll}
                        disabled={acknowledgingAll || acknowledgingId !== null}
                      >
                        {acknowledgingAll
                          ? "Acknowledging…"
                          : "Acknowledge all"}
                      </button>
                    )}
                  </div>
                </div>
                <div className="alert-list">
                  {data.active_alerts.map((alert) => (
                    <article
                      key={alert.id}
                      className={`alert-item alert-item--${alert.severity.toLowerCase()}`}
                    >
                      <div>
                        <StatusBadge
                          status={
                            alert.severity === "CRITICAL"
                              ? "OFFLINE"
                              : "UNKNOWN"
                          }
                        />
                        <strong>{alert.device_name}</strong>
                        <p>{alert.message}</p>
                        <time>{formatDate(alert.triggered_at)}</time>
                      </div>
                      <button
                        className="button button--secondary"
                        onClick={() => handleAcknowledge(alert.id)}
                        disabled={acknowledgingAll || acknowledgingId !== null}
                      >
                        {acknowledgingId === alert.id
                          ? "Acknowledging…"
                          : "Acknowledge"}
                      </button>
                    </article>
                  ))}
                </div>
              </section>
            )}
            {dashboardSections.services && (
              <ServiceOverviewPanel
                overview={serviceOverview}
                onSelectDevice={navigateToDevice}
              />
            )}
            {dashboardSections.agents && (
              <AgentFleetPanel
                overview={agentOverview}
                onSelectDevice={navigateToDevice}
              />
            )}
            {dashboardSections.topology && (
              <LogicalNetworkPanel
                topology={topology}
                onSelectDevice={navigateToDevice}
                canWrite={canWrite}
                onChanged={loadDashboard}
              />
            )}
            {dashboardSections.inventoryHealth && (
              <InventoryHealthPanel
                health={inventoryHealth}
                onSelectDevice={navigateToDevice}
              />
            )}
            <div className="content-grid">
              <section className="panel panel--wide">
                <div className="panel-heading">
                  <div>
                    <p className="eyebrow">Inventory</p>
                    <h2>Monitored devices</h2>
                  </div>
                  <span>
                    {sortedAllDevices.length} of {data.devices.length} match
                  </span>
                </div>
                {data.devices.length > 0 && (
                  <div
                    className="device-filters"
                    role="search"
                    aria-label="Filter monitored devices"
                  >
                    <label className="search-field">
                      <span className="sr-only">Search devices</span>
                      <input
                        type="search"
                        value={filters.query}
                        onChange={(event) =>
                          setFilters((current) => ({
                            ...current,
                            query: event.target.value,
                          }))
                        }
                        placeholder="Search name, IP, or type"
                      />
                    </label>
                    <label>
                      <span className="sr-only">Filter by status</span>
                      <select
                        value={filters.status}
                        onChange={(event) =>
                          setFilters((current) => ({
                            ...current,
                            status: event.target.value,
                          }))
                        }
                      >
                        <option value="ALL">All statuses</option>
                        <option value="ONLINE">Online</option>
                        <option value="OFFLINE">Offline</option>
                        <option value="UNKNOWN">Not checked</option>
                      </select>
                    </label>
                    <label>
                      <span className="sr-only">Filter by device type</span>
                      <select
                        value={filters.type}
                        onChange={(event) =>
                          setFilters((current) => ({
                            ...current,
                            type: event.target.value,
                          }))
                        }
                      >
                        <option value="ALL">All device types</option>
                        {deviceTypes.map((type) => (
                          <option key={type} value={type}>
                            {type}
                          </option>
                        ))}
                      </select>
                    </label>
                    <label>
                      <span className="sr-only">Filter by device group</span>
                      <select
                        value={filters.group}
                        onChange={(event) =>
                          setFilters((current) => ({
                            ...current,
                            group: event.target.value,
                          }))
                        }
                      >
                        <option value="ALL">All groups</option>
                        <option value="__UNGROUPED__">Ungrouped</option>
                        {deviceGroups.map((group) => (
                          <option key={group} value={group}>
                            {group}
                          </option>
                        ))}
                      </select>
                    </label>
                    <label>
                      <span className="sr-only">Filter by tag</span>
                      <select
                        value={filters.tag}
                        onChange={(event) =>
                          setFilters((current) => ({
                            ...current,
                            tag: event.target.value,
                          }))
                        }
                      >
                        <option value="ALL">All tags</option>
                        <option value="__UNTAGGED__">Untagged</option>
                        {deviceTags.map((tag) => (
                          <option key={tag} value={tag}>
                            {tag}
                          </option>
                        ))}
                      </select>
                    </label>
                    {filtersActive && (
                      <button
                        className="button button--secondary"
                        onClick={() =>
                          setFilters(DEFAULT_DEVICE_FILTERS)
                        }
                      >
                        Clear filters
                      </button>
                    )}
                    <SavedViewsControl
                      views={savedViews}
                      onApply={applySavedView}
                      onSave={saveCurrentView}
                      onDelete={deleteSavedView}
                    />
                  </div>
                )}
                {canWrite && selectedDeviceIds.length > 0 && (
                  <div
                    className="bulk-toolbar"
                    role="toolbar"
                    aria-label="Selected device actions"
                  >
                    <strong>{selectedDeviceIds.length} selected</strong>
                    <input
                      value={bulkGroup}
                      onChange={(event) => setBulkGroup(event.target.value)}
                      maxLength="80"
                      placeholder="Group name"
                      aria-label="Group name"
                    />
                    <button
                      className="button button--secondary"
                      onClick={() => handleBulkGroup(false)}
                      disabled={bulkBusy}
                    >
                      Assign group
                    </button>
                    <button
                      className="button button--secondary"
                      onClick={() => handleBulkGroup(true)}
                      disabled={bulkBusy}
                    >
                      Clear group
                    </button>
                    <button
                      className="button button--secondary"
                      onClick={handleBulkCheck}
                      disabled={bulkBusy}
                    >
                      {bulkBusy ? "Working…" : "Check selected"}
                    </button>
                    <button
                      className="button button--secondary"
                      onClick={() => handleBulkMonitoring("ENABLE")}
                      disabled={bulkBusy}
                    >
                      Enable monitoring
                    </button>
                    <button
                      className="button button--secondary"
                      onClick={() => handleBulkMonitoring("DISABLE")}
                      disabled={bulkBusy}
                    >
                      Pause monitoring
                    </button>
                    <button
                      className="text-button"
                      onClick={() => setSelectedDeviceIds([])}
                      disabled={bulkBusy}
                    >
                      Clear selection
                    </button>
                  </div>
                )}
                {sortedAllDevices.length > 0 && (
                  <nav
                    className="device-pagination"
                    aria-label="Device table pagination"
                  >
                    <span>
                      Showing {(currentPage - 1) * pageSize + 1}–
                      {Math.min(
                        currentPage * pageSize,
                        sortedAllDevices.length,
                      )}{" "}
                      of {sortedAllDevices.length}
                    </span>
                    <button
                      className="button button--excel"
                      onClick={exportExcel}
                    >
                      Export Excel
                    </button>
                    <label>
                      Rows{" "}
                      <select
                        value={pageSize}
                        onChange={(event) =>
                          setPageSize(Number(event.target.value))
                        }
                      >
                        {DEVICE_PAGE_SIZES.map((size) => (
                          <option key={size} value={size}>
                            {size}
                          </option>
                        ))}
                      </select>
                    </label>
                    <button
                      className="button button--secondary"
                      onClick={() => setPage((value) => Math.max(1, value - 1))}
                      disabled={currentPage === 1}
                    >
                      Previous
                    </button>
                    <span>
                      Page {currentPage} of {pageCount}
                    </span>
                    <button
                      className="button button--secondary"
                      onClick={() =>
                        setPage((value) => Math.min(pageCount, value + 1))
                      }
                      disabled={currentPage === pageCount}
                    >
                      Next
                    </button>
                  </nav>
                )}
                {loading && data.devices.length === 0 ? (
                  <div className="empty-state">Loading devices…</div>
                ) : data.devices.length === 0 ? (
                  <div className="empty-state">
                    No devices yet. Add one to begin monitoring.
                  </div>
                ) : (
                  <div className="table-wrap">
                    <table>
                      <thead>
                        <tr>
                          <th aria-sort={ariaSort("name")}>
                            <div className="inventory-header-device">
                              {canWrite && (
                                <input
                                  type="checkbox"
                                  checked={allPageSelected}
                                  onChange={togglePageSelection}
                                  aria-label="Select all devices on this page"
                                />
                              )}
                              <button
                                className="sort-button"
                                onClick={() => changeSort("name")}
                              >
                                Device <span>{sortIndicator("name")}</span>
                              </button>
                            </div>
                          </th>
                          <th aria-sort={ariaSort("status")}>
                            <button
                              className="sort-button"
                              onClick={() => changeSort("status")}
                            >
                              Status <span>{sortIndicator("status")}</span>
                            </button>
                          </th>
                          <th aria-sort={ariaSort("latency")}>
                            <button
                              className="sort-button"
                              onClick={() => changeSort("latency")}
                            >
                              Latency <span>{sortIndicator("latency")}</span>
                            </button>
                          </th>
                          <th aria-sort={ariaSort("availability")}>
                            <button
                              className="sort-button"
                              onClick={() => changeSort("availability")}
                            >
                              Availability{" "}
                              <span>{sortIndicator("availability")}</span>
                            </button>
                          </th>
                          <th aria-sort={ariaSort("last_checked")}>
                            <button
                              className="sort-button"
                              onClick={() => changeSort("last_checked")}
                            >
                              Last checked{" "}
                              <span>{sortIndicator("last_checked")}</span>
                            </button>
                          </th>
                          <th>
                            <span className="sr-only">Actions</span>
                          </th>
                        </tr>
                      </thead>
                      <tbody>
                        {sortedDevices.map((device) => (
                          <tr key={device.id}>
                            <td>
                              <div className="inventory-device-cell">
                                {canWrite && (
                                  <input
                                    type="checkbox"
                                    checked={selectedDeviceIds.includes(
                                      device.id,
                                    )}
                                    onChange={() =>
                                      toggleDeviceSelection(device.id)
                                    }
                                    aria-label={`Select ${device.name}`}
                                  />
                                )}
                                <button
                                  className="device-link"
                                  onClick={() => navigateToDevice(device.id)}
                                >
                                  <strong>{device.name}</strong>
                                  <span>
                                    {device.ip_address} · {device.device_type}
                                    {device.vlan
                                      ? ` · VLAN ${device.vlan}`
                                      : ""}
                                  </span>
                                  <span>
                                    {device.criticality}
                                    {device.device_group
                                      ? ` · ${device.device_group}`
                                      : ""}
                                    {device.asset_tag
                                      ? ` · ${device.asset_tag}`
                                      : ""}
                                    {device.location
                                      ? ` · ${device.location}`
                                      : ""}
                                    {device.maintenance_until &&
                                    new Date(
                                      device.maintenance_until,
                                    ).getTime() > Date.now()
                                      ? " · Maintenance"
                                      : ""}
                                  </span>
                                  {device.tags?.length > 0 && (
                                    <span className="device-tags">
                                      {device.tags.map((tag) => (
                                        <span key={tag}>{tag}</span>
                                      ))}
                                    </span>
                                  )}
                                  {device.mac_address && (
                                    <span>
                                      {device.mac_address}
                                      {device.manufacturer
                                        ? ` · ${device.manufacturer}`
                                        : ""}
                                    </span>
                                  )}
                                  {device.discovered_model && (
                                    <span>Model: {device.discovered_model}</span>
                                  )}
                                  {device.discovered_services && (
                                    <span>
                                      Services:{" "}
                                      {device.discovered_services
                                        .split(",")
                                        .join(", ")}
                                    </span>
                                  )}
                                  <ProfileCompleteness device={device} />
                                </button>
                              </div>
                            </td>
                            <td>
                              <StatusBadge status={device.current_status} />
                            </td>
                            <td>
                              {formatMetric(device.latest_latency_ms, " ms")}
                            </td>
                            <td>
                              {formatMetric(device.availability_percent, "%")}
                            </td>
                            <td>{formatDate(device.last_checked_at)}</td>
                            <td>
                              <div className="row-actions">
                                <button
                                  className="button button--check"
                                  onClick={() => handleCheck(device.id)}
                                  disabled={checkingId !== null}
                                >
                                  {checkingId === device.id
                                    ? "Checking…"
                                    : "Check now"}
                                </button>
                                <button
                                  className="icon-button"
                                  onClick={() => setFormDevice(device)}
                                  aria-label={`Edit ${device.name}`}
                                >
                                  ✎
                                </button>
                              </div>
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                )}
              </section>
              <section className="panel">
                <div className="panel-heading">
                  <div>
                    <p className="eyebrow">Transitions</p>
                    <h2>Recent events</h2>
                  </div>
                </div>
                {data.recent_events.length === 0 ? (
                  <div className="empty-state empty-state--compact">
                    No status changes recorded yet.
                  </div>
                ) : (
                  <ol className="events-list">
                    {data.recent_events.map((event, index) => (
                      <li
                        key={`${event.device_id}-${event.timestamp}-${index}`}
                      >
                        <span
                          className={`event-dot event-dot--${event.current_status.toLowerCase()}`}
                        />
                        <div>
                          <strong>{event.device_name}</strong>
                          <span>
                            {event.previous_status} → {event.current_status}
                          </span>
                          <time>{formatDate(event.timestamp)}</time>
                        </div>
                      </li>
                    ))}
                  </ol>
                )}
              </section>
            </div>
          </>
        )}
      </main>
      {formDevice !== undefined && (
        <DeviceForm
          device={formDevice}
          onClose={() => setFormDevice(undefined)}
          onSaved={handleSaved}
        />
      )}
      {showUsers && (
        <UserManagement
          currentUser={auth.user}
          onClose={() => setShowUsers(false)}
        />
      )}
      {showAudit && <AuditLog onClose={() => setShowAudit(false)} />}
      {showAlertHistory && (
        <AlertHistoryModal
          onClose={() => setShowAlertHistory(false)}
          onSelectDevice={navigateToDevice}
        />
      )}
      {showNotifications && (
        <NotificationSettings onClose={() => setShowNotifications(false)} />
      )}
      {showPacketCapture && (
        <PacketCaptureModal onClose={() => setShowPacketCapture(false)} />
      )}
      {showDhcpImport && (
        <DhcpImportModal
          onClose={() => setShowDhcpImport(false)}
          onImported={async (result) => {
            setDiscoveryMessage(
              `DHCP import: ${result.devices_added} added, ${result.devices_updated} updated, ${result.rows_skipped} skipped.`,
            );
            await loadDashboard({ quiet: true });
          }}
        />
      )}
      {showReliability && (
        <ReliabilityModal onClose={() => setShowReliability(false)} />
      )}
      {showAutomation && (
        <AutomationModal onClose={() => setShowAutomation(false)} />
      )}
      {showSystemStatus && (
        <SystemStatusModal onClose={() => setShowSystemStatus(false)} />
      )}
      {showAttackPaths && (
        <AttackPathsModal
          onClose={() => setShowAttackPaths(false)}
          onSelectDevice={navigateToDevice}
        />
      )}
      {showSecurityWorkbench && (
        <SecurityWorkbenchModal
          devices={data.devices}
          visualTheme={visualTheme}
          onClose={() => setShowSecurityWorkbench(false)}
          onOpenCapture={() => setShowPacketCapture(true)}
          onSelectDevice={navigateFromSecurityWorkbench}
          initialTab={workbenchTab}
          onTabChange={setWorkbenchTab}
        />
      )}
      {showReports && (
        <AvailabilityReportModal onClose={() => setShowReports(false)} />
      )}
      {showObservability && (
        <ObservabilityModal onClose={() => setShowObservability(false)} />
      )}
      {commandPaletteOpen && (
        <CommandPalette
          commands={commandPaletteCommands}
          onClose={() => setCommandPaletteOpen(false)}
        />
      )}
    </div>
  );
}
