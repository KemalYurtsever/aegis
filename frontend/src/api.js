const API_BASE_URL =
  import.meta.env.VITE_API_BASE_URL || (import.meta.env.DEV ? "http://127.0.0.1:8000" : "");
const TOKEN_KEY = "aegis_session_token";

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
    throw networkError || new Error("The AEGIS API could not be reached");
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
  return jsonRequest("/api/auth/setup", "POST", payload);
}
export function loginUser(payload) {
  return jsonRequest("/api/auth/login", "POST", payload);
}
export function logoutUser() {
  return request("/api/auth/logout", { method: "POST" });
}
export function listUsers() {
  return request("/api/auth/users");
}
export function createUser(payload) {
  return jsonRequest("/api/auth/users", "POST", payload);
}
export function updateUser(userId, payload) {
  return jsonRequest(`/api/auth/users/${userId}`, "PUT", payload);
}
export function listAuditEvents(limit = 250) {
  return request(`/api/auth/audit-events?limit=${limit}`);
}
export function listNotificationChannels() {
  return request("/api/notifications/channels");
}
export function updateNotificationChannel(type, payload) {
  return jsonRequest(`/api/notifications/channels/${type}`, "PUT", payload);
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
  return jsonRequest(`/api/devices/${deviceId}/snmp`, "PUT", payload);
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
  return jsonRequest("/api/packet-captures", "POST", payload);
}

export function getDashboardRefresh() {
  return request("/api/dashboard/refresh");
}

export function listAlerts(activeOnly = false, limit = 500) {
  return request(`/api/alerts?active_only=${activeOnly}&limit=${limit}`);
}

export function createTopologyLink(payload) {
  return jsonRequest("/api/topology/links", "POST", payload);
}

export function deleteTopologyLink(linkId) {
  return request(`/api/topology/links/${linkId}`, { method: "DELETE" });
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

export function runNmapScan(payload) {
  return jsonRequest("/api/security/toolbox/nmap", "POST", payload);
}
export function runNmapUdpScan(payload) {
  return jsonRequest("/api/security/toolbox/nmap-udp", "POST", payload);
}
export function runTestConnectionPorts(payload) {
  return jsonRequest("/api/security/toolbox/test-connection", "POST", payload);
}
export function runArpScan(payload = {}) {
  return jsonRequest("/api/security/toolbox/arp-scan", "POST", payload);
}
export function getNeighborTable(payload = {}) {
  return jsonRequest("/api/security/toolbox/neighbors", "POST", payload);
}
export function runAvahiBrowse(payload = {}) {
  return jsonRequest("/api/security/toolbox/avahi-browse", "POST", payload);
}
export function runCurlRequest(payload) {
  return jsonRequest("/api/security/toolbox/curl", "POST", payload);
}
export function runDigQuery(payload) {
  return jsonRequest("/api/security/toolbox/dig", "POST", payload);
}

export function createSecurityPlaybookRun(payload) {
  return jsonRequest("/api/security/playbooks/runs", "POST", payload);
}

export function listSecurityPlaybookRuns(deviceId, limit = 10) {
  const query = new URLSearchParams({
    device_id: String(deviceId),
    limit: String(limit),
  });
  return request(`/api/security/playbooks/runs?${query.toString()}`);
}

export function listSecurityPlaybookRunIndex(limit = 50) {
  return request(`/api/security/playbooks/run-index?limit=${encodeURIComponent(limit)}`);
}

export function getSecurityPlaybookRun(runId) {
  return request(`/api/security/playbooks/runs/${runId}`);
}

export function cancelSecurityPlaybookRun(runId) {
  return request(`/api/security/playbooks/runs/${runId}/cancel`, { method: "POST" });
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
  return jsonRequest("/api/devices/bulk/check", "POST", { device_ids: deviceIds });
}
export function updateSelectedMonitoring(deviceIds, action) {
  return jsonRequest("/api/devices/bulk/monitoring", "PUT", { device_ids: deviceIds, action });
}
export function updateSelectedGroup(deviceIds, deviceGroup) {
  return jsonRequest("/api/devices/bulk/group", "PUT", {
    device_ids: deviceIds,
    device_group: deviceGroup,
  });
}

export function createDevice(payload) {
  return jsonRequest("/api/devices", "POST", payload);
}

export function updateDevice(deviceId, payload) {
  return jsonRequest(`/api/devices/${deviceId}`, "PUT", payload);
}

export function deleteDevice(deviceId) {
  return request(`/api/devices/${deviceId}`, { method: "DELETE" });
}

export function clearAllDevices(confirmation) {
  return jsonRequest("/api/devices/actions/clear-all", "POST", { confirmation });
}

export function getDeviceNotes(deviceId) {
  return request(`/api/devices/${deviceId}/notes`);
}

export function createDeviceNote(deviceId, body) {
  return jsonRequest(`/api/devices/${deviceId}/notes`, "POST", { body });
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
  return jsonRequest(`/api/devices/${deviceId}/alert-rule`, "PUT", payload);
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
  return jsonRequest(`/api/devices/${deviceId}/service-checks`, "POST", payload);
}

export function updateServiceCheck(checkId, payload) {
  return jsonRequest(`/api/service-checks/${checkId}`, "PUT", payload);
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
  return jsonRequest("/api/inventory/dhcp-leases/import", "POST", { rows });
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
  return jsonRequest("/api/retention/apply", "POST", {
    retention_days: days,
    confirmation: "DELETE HISTORY",
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
  return jsonRequest(`/api/devices/${deviceId}/diagnostic-jobs`, "POST", payload);
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
export function updateMaintenanceWindow(id, payload) {
  return jsonRequest(`/api/automation/maintenance-windows/${id}`, "PATCH", payload);
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
export function updateIncident(id, payload) {
  return jsonRequest(`/api/automation/incidents/${id}`, "PATCH", payload);
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
export function listAutomationEvents(severity = "") {
  const query = new URLSearchParams({ limit: "100" });
  if (severity) query.set("severity", severity);
  return request(`/api/automation/events?${query}`);
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
