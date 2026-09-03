const API_BASE_URL =
  import.meta.env.VITE_API_BASE_URL || "http://127.0.0.1:8000";
const TOKEN_KEY = "liims_session_token";

export function setAuthToken(token) {
  if (token) sessionStorage.setItem(TOKEN_KEY, token);
  else sessionStorage.removeItem(TOKEN_KEY);
}

async function request(path, options = {}) {
  const token = sessionStorage.getItem(TOKEN_KEY);
  const headers = new Headers(options.headers || {});
  if (token) headers.set("Authorization", `Bearer ${token}`);
  const method = (options.method || "GET").toUpperCase();
  const attempts = method === "GET" || method === "HEAD" ? 2 : 1;
  let response;
  let networkError;
  for (let attempt = 0; attempt < attempts; attempt += 1) {
    try {
      response = await fetch(`${API_BASE_URL}${path}`, { ...options, headers });
      networkError = null;
      break;
    } catch (error) {
      networkError = error;
      if (attempt + 1 < attempts)
        await new Promise((resolve) => window.setTimeout(resolve, 150));
    }
  }
  if (!response)
    throw networkError || new Error("The LIIMS API could not be reached");
  if (!response.ok) {
    const payload = await response.json().catch(() => null);
    throw new Error(
      payload?.detail || `Request failed with status ${response.status}`,
    );
  }
  return response.status === 204 ? null : response.json();
}

function jsonRequest(path, method, payload) {
  return request(path, {
    method,
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
}

export function getAuthStatus() {
  return request("/api/auth/status");
}
export function setupAdmin(payload) {
  return request("/api/auth/setup", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
}
export function loginUser(payload) {
  return request("/api/auth/login", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
}
export function logoutUser() {
  return request("/api/auth/logout", { method: "POST" });
}
export function listUsers() {
  return request("/api/auth/users");
}
export function createUser(payload) {
  return request("/api/auth/users", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
}
export function updateUser(userId, payload) {
  return request(`/api/auth/users/${userId}`, {
    method: "PUT",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
}
export function listAuditEvents(limit = 250) {
  return request(`/api/auth/audit-events?limit=${limit}`);
}
export function listNotificationChannels() {
  return request("/api/notifications/channels");
}
export function updateNotificationChannel(type, payload) {
  return request(`/api/notifications/channels/${type}`, {
    method: "PUT",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
}
export function testNotificationChannel(type) {
  return request(`/api/notifications/channels/${type}/test`, {
    method: "POST",
  });
}
export function listNotificationDeliveries() {
  return request("/api/notifications/deliveries");
}
export function retryNotificationDelivery(id) {
  return request(`/api/notifications/deliveries/${id}/retry`, {
    method: "POST",
  });
}
export function getSnmpConfig(deviceId) {
  return request(`/api/devices/${deviceId}/snmp`);
}
export function updateSnmpConfig(deviceId, payload) {
  return request(`/api/devices/${deviceId}/snmp`, {
    method: "PUT",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
}
export function pollSnmp(deviceId) {
  return request(`/api/devices/${deviceId}/snmp/poll`, { method: "POST" });
}
export function getSnmpHistory(deviceId) {
  return request(`/api/devices/${deviceId}/snmp/history?limit=20`);
}
export function runVulnerabilityScan(deviceId) {
  return request(`/api/devices/${deviceId}/vulnerability-scans`, {
    method: "POST",
  });
}
export function getVulnerabilityScans(deviceId) {
  return request(`/api/devices/${deviceId}/vulnerability-scans?limit=10`);
}
export function getAttackSurfaceComparison(deviceId) {
  return request(`/api/devices/${deviceId}/vulnerability-scans/comparison`);
}
export function getAnomalies(deviceId) {
  return request(`/api/devices/${deviceId}/anomalies?limit=50`);
}
export function detectAnomalies(deviceId) {
  return request(`/api/devices/${deviceId}/anomalies/detect`, {
    method: "POST",
  });
}
export function getPacketInterfaces() {
  return request("/api/packet-captures/interfaces");
}
export function listPacketCaptures() {
  return request("/api/packet-captures");
}
export function startPacketCapture(payload) {
  return request("/api/packet-captures", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
}

export function getDashboard() {
  return request("/api/dashboard");
}

export function getDashboardRefresh() {
  return request("/api/dashboard/refresh");
}

export function listAlerts(activeOnly = false, limit = 500) {
  return request(`/api/alerts?active_only=${activeOnly}&limit=${limit}`);
}

export function getServiceOverview() {
  return request("/api/service-checks/overview");
}

export function getTopology() {
  return request("/api/topology");
}

export function createTopologyLink(payload) {
  return jsonRequest("/api/topology/links", "POST", payload);
}

export function deleteTopologyLink(linkId) {
  return request(`/api/topology/links/${linkId}`, { method: "DELETE" });
}

export function getAgentOverview() {
  return request("/api/agents/overview");
}

export function getSchedulerStatus() {
  return request("/api/scheduler/status");
}

export function getSystemReadiness() {
  return request("/api/system/readiness");
}

export function getAttackPaths(limit = 100) {
  return request(`/api/security/attack-paths?limit=${limit}`);
}

export function runSecurityTraceroute(deviceId) {
  return jsonRequest("/api/security/toolbox/traceroute", "POST", {
    device_id: deviceId,
  });
}

export function runDnsQuery(query) {
  return jsonRequest("/api/security/toolbox/dns-query", "POST", { query });
}

export function getWirelessAdapters() {
  return request("/api/security/toolbox/wireless");
}

export function getHostNetworkPolicy() {
  return request("/api/security/toolbox/host-network-policy");
}

export function pauseScheduler() {
  return request("/api/scheduler/pause", { method: "POST" });
}

export function resumeScheduler() {
  return request("/api/scheduler/resume", { method: "POST" });
}

export function checkDevice(deviceId) {
  return request(`/api/devices/${deviceId}/check`, { method: "POST" });
}

export function checkAllDevices() {
  return request("/api/devices/check-all", { method: "POST" });
}
export function checkSelectedDevices(deviceIds) {
  return request("/api/devices/bulk/check", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ device_ids: deviceIds }),
  });
}
export function updateSelectedMonitoring(deviceIds, action) {
  return request("/api/devices/bulk/monitoring", {
    method: "PUT",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ device_ids: deviceIds, action }),
  });
}
export function updateSelectedGroup(deviceIds, deviceGroup) {
  return request("/api/devices/bulk/group", {
    method: "PUT",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ device_ids: deviceIds, device_group: deviceGroup }),
  });
}

export function createDevice(payload) {
  return request("/api/devices", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
}

export function updateDevice(deviceId, payload) {
  return request(`/api/devices/${deviceId}`, {
    method: "PUT",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
}

export function deleteDevice(deviceId) {
  return request(`/api/devices/${deviceId}`, { method: "DELETE" });
}

export function getDeviceNotes(deviceId) {
  return request(`/api/devices/${deviceId}/notes`);
}

export function createDeviceNote(deviceId, body) {
  return request(`/api/devices/${deviceId}/notes`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ body }),
  });
}

export function deleteDeviceNote(deviceId, noteId) {
  return request(`/api/devices/${deviceId}/notes/${noteId}`, {
    method: "DELETE",
  });
}

export function getDeviceActivity(deviceId, limit = 100) {
  return request(`/api/devices/${deviceId}/activity?limit=${limit}`);
}

export function getDeviceAttachments(deviceId) {
  return request(`/api/devices/${deviceId}/attachments`);
}

export function createDeviceAttachment(deviceId, payload) {
  return jsonRequest(`/api/devices/${deviceId}/attachments`, "POST", payload);
}

export function deleteDeviceAttachment(deviceId, attachmentId) {
  return request(`/api/devices/${deviceId}/attachments/${attachmentId}`, { method: "DELETE" });
}

export async function downloadDeviceAttachment(deviceId, attachmentId) {
  const token = sessionStorage.getItem(TOKEN_KEY);
  const response = await fetch(`${API_BASE_URL}/api/devices/${deviceId}/attachments/${attachmentId}/download`, {
    headers: token ? { Authorization: `Bearer ${token}` } : {},
  });
  if (!response.ok) {
    const payload = await response.json().catch(() => null);
    throw new Error(payload?.detail || `Download failed with status ${response.status}`);
  }
  return response.blob();
}

export async function getDeviceDetails(deviceId) {
  const [
    device,
    statistics,
    history,
    events,
    alertRule,
    serviceChecks,
    hostMetrics,
    agent,
    snmpConfig,
    snmpHistory,
    vulnerabilityScans,
    attackSurfaceComparison,
    anomalies,
  ] = await Promise.all([
    request(`/api/devices/${deviceId}`),
    request(`/api/devices/${deviceId}/statistics`),
    request(`/api/devices/${deviceId}/history?limit=100`),
    request(`/api/devices/${deviceId}/status-events?limit=50`),
    request(`/api/devices/${deviceId}/alert-rule`),
    request(`/api/devices/${deviceId}/service-checks`),
    request(`/api/devices/${deviceId}/metrics?limit=60`),
    request(`/api/devices/${deviceId}/agent`),
    getSnmpConfig(deviceId),
    getSnmpHistory(deviceId),
    getVulnerabilityScans(deviceId),
    getAttackSurfaceComparison(deviceId),
    getAnomalies(deviceId),
  ]);
  return {
    device,
    statistics,
    history,
    events,
    alertRule,
    serviceChecks,
    hostMetrics,
    agent,
    snmpConfig,
    snmpHistory,
    vulnerabilityScans,
    attackSurfaceComparison,
    anomalies,
  };
}

export function updateAlertRule(deviceId, payload) {
  return request(`/api/devices/${deviceId}/alert-rule`, {
    method: "PUT",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
}

export function acknowledgeAlert(alertId) {
  return request(`/api/alerts/${alertId}/acknowledge`, { method: "POST" });
}

export function acknowledgeAllAlerts() {
  return request("/api/alerts/acknowledge-all", { method: "POST" });
}

export function getDiscoveryNetwork() {
  return request("/api/discovery/network");
}

export function discoverDevices() {
  return request("/api/discovery/import", { method: "POST" });
}

export function createServiceCheck(deviceId, payload) {
  return request(`/api/devices/${deviceId}/service-checks`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
}

export function updateServiceCheck(checkId, payload) {
  return request(`/api/service-checks/${checkId}`, {
    method: "PUT",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
}

export function runServiceCheck(checkId) {
  return request(`/api/service-checks/${checkId}/run`, { method: "POST" });
}

export function getServiceHistory(checkId, limit = 20) {
  return request(`/api/service-checks/${checkId}/history?limit=${limit}`);
}

export function getServiceStatistics(checkId) {
  return request(`/api/service-checks/${checkId}/statistics`);
}

export function scanCommonPorts(deviceId) {
  return request(`/api/devices/${deviceId}/scan-ports`, { method: "POST" });
}

export function fingerprintDevice(deviceId) {
  return request(`/api/devices/${deviceId}/fingerprint`, { method: "POST" });
}
export function fingerprintAllDevices() {
  return request("/api/devices/fingerprint-all", { method: "POST" });
}
export function importDhcpLeases(rows) {
  return request("/api/inventory/dhcp-leases/import", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ rows }),
  });
}
export function getInventoryHealth(staleHours = 24) {
  return request(`/api/inventory/health?stale_hours=${staleHours}`);
}
export function getAvailabilityReport(days = 30) {
  return request(`/api/reports/availability?days=${days}`);
}
export function listBackups() {
  return request("/api/backups");
}
export function getBackupStatus() {
  return request("/api/backups/status");
}
export function createBackup() {
  return request("/api/backups", { method: "POST" });
}
export function verifyBackup(filename) {
  return request(`/api/backups/${encodeURIComponent(filename)}/verify`, {
    method: "POST",
  });
}
export function previewRetention(days = null) {
  return request(
    `/api/retention/preview${days === null ? "" : `?days=${days}`}`,
  );
}
export function applyRetention(days) {
  return request("/api/retention/apply", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      retention_days: days,
      confirmation: "DELETE HISTORY",
    }),
  });
}
export async function downloadBackup(filename) {
  const token = sessionStorage.getItem(TOKEN_KEY);
  const response = await fetch(
    `${API_BASE_URL}/api/backups/${encodeURIComponent(filename)}/download`,
    {
      headers: token ? { Authorization: `Bearer ${token}` } : {},
    },
  );
  if (!response.ok) {
    const payload = await response.json().catch(() => null);
    throw new Error(
      payload?.detail || `Download failed with status ${response.status}`,
    );
  }
  return response.blob();
}

export function deleteServiceCheck(checkId) {
  return request(`/api/service-checks/${checkId}`, { method: "DELETE" });
}

export function collectHostMetrics(deviceId) {
  return request(`/api/devices/${deviceId}/metrics/collect`, {
    method: "POST",
  });
}

export function enrollAgent(deviceId) {
  return request(`/api/devices/${deviceId}/agent/enroll`, { method: "POST" });
}

export function revokeAgent(deviceId) {
  return request(`/api/devices/${deviceId}/agent`, { method: "DELETE" });
}

export function listDiagnosticJobs(deviceId) {
  return request(`/api/devices/${deviceId}/diagnostic-jobs`);
}

export function createDiagnosticJob(deviceId, payload) {
  return request(`/api/devices/${deviceId}/diagnostic-jobs`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
}

export function cancelDiagnosticJob(jobId) {
  return request(`/api/diagnostic-jobs/${jobId}/cancel`, { method: "POST" });
}

export function getAutomationOverview() {
  return request("/api/automation/overview");
}
export function updateAutomationSettings(payload) {
  return jsonRequest("/api/automation/settings", "PUT", payload);
}
export function runAutomation() {
  return request("/api/automation/run", { method: "POST" });
}
export function listMaintenanceWindows() {
  return request("/api/automation/maintenance-windows");
}
export function createMaintenanceWindow(payload) {
  return jsonRequest("/api/automation/maintenance-windows", "POST", payload);
}
export function deleteMaintenanceWindow(id) {
  return request(`/api/automation/maintenance-windows/${id}`, {
    method: "DELETE",
  });
}
export function listIncidents() {
  return request("/api/automation/incidents?limit=100");
}
export function resolveIncident(id) {
  return request(`/api/automation/incidents/${id}/resolve`, { method: "POST" });
}
export function listGeneratedReports() {
  return request("/api/automation/reports");
}
export function generateAutomationReport() {
  return request("/api/automation/reports/generate", { method: "POST" });
}
export function refreshAssetBaselines() {
  return request("/api/automation/baselines/refresh", { method: "POST" });
}
export function listAutomationEvents() {
  return request("/api/automation/events?limit=100");
}
export function getDeviceChangeEvents(deviceId, limit = 30) {
  return request(`/api/automation/events?device_id=${deviceId}&limit=${limit}`);
}
export function getAutomationSummary() {
  return request("/api/automation/summary", { method: "POST" });
}
export async function downloadGeneratedReport(filename) {
  const token = sessionStorage.getItem(TOKEN_KEY);
  const response = await fetch(
    `${API_BASE_URL}/api/automation/reports/${encodeURIComponent(filename)}/download`,
    {
      headers: token ? { Authorization: `Bearer ${token}` } : {},
    },
  );
  if (!response.ok) throw new Error("Report download failed");
  return response.blob();
}
