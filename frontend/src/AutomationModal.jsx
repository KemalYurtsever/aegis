import { useCallback, useEffect, useState } from "react";
import {
  createMaintenanceWindow,
  deleteMaintenanceWindow,
  downloadGeneratedReport,
  generateAutomationReport,
  getAutomationOverview,
  getAutomationSummary,
  listAutomationEvents,
  listGeneratedReports,
  listIncidents,
  listMaintenanceWindows,
  refreshAssetBaselines,
  resolveIncident,
  runAutomation,
  updateIncident,
  updateMaintenanceWindow,
  updateAutomationSettings,
} from "./api.js";
import { formatDate } from "./format.js";

const EMPTY_WINDOW = {
  name: "",
  device_group: "",
  starts_at: "",
  ends_at: "",
  repeat: "NONE",
  reason: "",
  enabled: true,
};

function localToIso(value) {
  return value ? new Date(value).toISOString() : null;
}

export default function AutomationModal({ onClose }) {
  const [overview, setOverview] = useState(null);
  const [windows, setWindows] = useState([]);
  const [incidents, setIncidents] = useState([]);
  const [reports, setReports] = useState([]);
  const [events, setEvents] = useState([]);
  const [form, setForm] = useState(EMPTY_WINDOW);
  const [summary, setSummary] = useState(null);
  const [incidentDrafts, setIncidentDrafts] = useState({});
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState("");

  const load = useCallback(async () => {
    try {
      const [
        nextOverview,
        nextWindows,
        nextIncidents,
        nextReports,
        nextEvents,
      ] = await Promise.all([
        getAutomationOverview(),
        listMaintenanceWindows(),
        listIncidents(),
        listGeneratedReports(),
        listAutomationEvents(),
      ]);
      setOverview(nextOverview);
      setWindows(nextWindows);
      setIncidents(nextIncidents);
      setReports(nextReports);
      setEvents(nextEvents);
    } catch (error) {
      setMessage(error.message);
    }
  }, []);

  useEffect(() => {
    load();
  }, [load]);

  async function perform(action, success) {
    setBusy(true);
    setMessage("");
    try {
      await action();
      setMessage(success);
      await load();
    } catch (error) {
      setMessage(error.message);
    } finally {
      setBusy(false);
    }
  }

  async function saveSettings(next) {
    setOverview({ ...overview, settings: next });
    await perform(
      () => updateAutomationSettings(next),
      "Automation settings saved.",
    );
  }

  async function addWindow(event) {
    event.preventDefault();
    await perform(
      () =>
        createMaintenanceWindow({
          ...form,
          device_group: form.device_group || null,
          reason: form.reason || null,
          starts_at: localToIso(form.starts_at),
          ends_at: localToIso(form.ends_at),
        }),
      "Maintenance window created.",
    );
    setForm(EMPTY_WINDOW);
  }

  async function download(report) {
    await perform(async () => {
      const blob = await downloadGeneratedReport(report.filename);
      const url = URL.createObjectURL(blob);
      const anchor = document.createElement("a");
      anchor.href = url;
      anchor.download = report.filename;
      anchor.click();
      URL.revokeObjectURL(url);
    }, "Report downloaded.");
  }

  if (!overview)
    return (
      <div className="modal-backdrop">
        <section
          className="modal automation-modal"
          role="dialog"
          aria-modal="true"
          aria-labelledby="automation-loading-title"
        >
          <div className="modal-heading">
            <h2 id="automation-loading-title">Automation center</h2>
            <button
              className="icon-button"
              onClick={onClose}
              aria-label="Close automation center"
            >
              ×
            </button>
          </div>
          <div className="empty-state">Loading automation status…</div>
        </section>
      </div>
    );
  const settings = overview.settings;
  const toggle = (name) =>
    saveSettings({ ...settings, [name]: !settings[name] });

  return (
    <div className="modal-backdrop">
      <section
        className="modal automation-modal"
        role="dialog"
        aria-modal="true"
        aria-labelledby="automation-title"
      >
        <div className="modal-heading">
          <div>
            <p className="eyebrow">Operations automation</p>
            <h2 id="automation-title">Automation center</h2>
          </div>
          <button className="icon-button" onClick={onClose} aria-label="Close">
            ×
          </button>
        </div>
        {message && (
          <div className="form-message automation-message">{message}</div>
        )}
        <div className="automation-actions">
          <button
            className="button button--primary"
            disabled={busy}
            onClick={() =>
              perform(runAutomation, "Automation cycle completed.")
            }
          >
            Run cycle now
          </button>
          <button
            className="button button--secondary"
            disabled={busy}
            onClick={async () => {
              setBusy(true);
              try {
                setSummary(await getAutomationSummary());
              } catch (error) {
                setMessage(error.message);
              } finally {
                setBusy(false);
              }
            }}
          >
            Generate health summary
          </button>
        </div>
        {summary && (
          <section className="automation-summary">
            <strong>
              {summary.source === "LOCAL_MODEL"
                ? "Foundry Local summary"
                : "Built-in summary"}
            </strong>
            <p>{summary.text}</p>
          </section>
        )}
        <div className="automation-metrics">
          <article>
            <span>Open incidents</span>
            <strong>{overview.open_incidents}</strong>
          </article>
          <article>
            <span>Active maintenance</span>
            <strong>{overview.active_maintenance_windows}</strong>
          </article>
          <article>
            <span>Outdated agents</span>
            <strong>{overview.outdated_agents}</strong>
          </article>
          <article>
            <span>Drift events</span>
            <strong>{overview.drift_events}</strong>
          </article>
          <article>
            <span>Reports</span>
            <strong>{overview.generated_reports}</strong>
          </article>
        </div>
        <section className="automation-section">
          <h3>Automation policy</h3>
          <div className="automation-toggles">
            {[
              ["incidents_enabled", "Group related alerts into incidents"],
              [
                "diagnostics_enabled",
                "Queue allowlisted diagnostics for incidents",
              ],
              ["reports_enabled", "Generate scheduled local reports"],
              ["drift_enabled", "Detect inventory configuration drift"],
              ["notification_window_enabled", "Deliver alert notifications only during working hours"],
              ["discovery_enabled", "Discover devices after network changes"],
              [
                "vulnerability_scans_enabled",
                "Run one paced defensive scan per interval",
              ],
              [
                "service_discovery_enabled",
                "Create monitors for detected common services",
              ],
            ].map(([name, label]) => (
              <label key={name}>
                <input
                  type="checkbox"
                  checked={settings[name]}
                  onChange={() => toggle(name)}
                  disabled={busy}
                />{" "}
                {label}
              </label>
            ))}
          </div>
          <div className="automation-settings-row">
            <label>
              Report interval (hours)
              <input
                type="number"
                min="1"
                max="720"
                value={settings.report_interval_hours}
                onChange={(event) =>
                  setOverview({
                    ...overview,
                    settings: {
                      ...settings,
                      report_interval_hours: Number(event.target.value),
                    },
                  })
                }
                onBlur={() => saveSettings(settings)}
              />
            </label>
            <label>
              Report period (days)
              <input
                type="number"
                min="7"
                max="365"
                value={settings.report_days}
                onChange={(event) =>
                  setOverview({
                    ...overview,
                    settings: {
                      ...settings,
                      report_days: Number(event.target.value),
                    },
                  })
                }
                onBlur={() => saveSettings(settings)}
              />
            </label>
            <label>
              Alert escalation (minutes)
              <input
                type="number"
                min="5"
                max="1440"
                value={settings.alert_escalation_minutes}
                onChange={(event) =>
                  setOverview({
                    ...overview,
                    settings: {
                      ...settings,
                      alert_escalation_minutes: Number(event.target.value),
                    },
                  })
                }
                onBlur={() => saveSettings(settings)}
              />
            </label>
            <label>
              Notification start hour
              <input
                type="number"
                min="0"
                max="23"
                value={settings.notification_start_hour}
                disabled={!settings.notification_window_enabled}
                onChange={(event) => setOverview({ ...overview, settings: { ...settings, notification_start_hour: Number(event.target.value) } })}
                onBlur={() => saveSettings(settings)}
              />
            </label>
            <label>
              Notification end hour
              <input
                type="number"
                min="0"
                max="23"
                value={settings.notification_end_hour}
                disabled={!settings.notification_window_enabled}
                onChange={(event) => setOverview({ ...overview, settings: { ...settings, notification_end_hour: Number(event.target.value) } })}
                onBlur={() => saveSettings(settings)}
              />
            </label>
            <label>
              Discovery interval (hours)
              <input
                type="number"
                min="1"
                max="720"
                value={settings.discovery_interval_hours}
                onChange={(event) =>
                  setOverview({
                    ...overview,
                    settings: {
                      ...settings,
                      discovery_interval_hours: Number(event.target.value),
                    },
                  })
                }
                onBlur={() => saveSettings(settings)}
              />
            </label>
            <label>
              Assessment interval (hours)
              <input
                type="number"
                min="24"
                max="2160"
                value={settings.vulnerability_interval_hours}
                onChange={(event) =>
                  setOverview({
                    ...overview,
                    settings: {
                      ...settings,
                      vulnerability_interval_hours: Number(event.target.value),
                    },
                  })
                }
                onBlur={() => saveSettings(settings)}
              />
            </label>
            <label>
              Desired agent version
              <input
                value={settings.desired_agent_version}
                onChange={(event) =>
                  setOverview({
                    ...overview,
                    settings: {
                      ...settings,
                      desired_agent_version: event.target.value,
                    },
                  })
                }
                onBlur={() => saveSettings(settings)}
              />
            </label>
          </div>
        </section>
        <section className="automation-section">
          <div className="automation-section-title">
            <div>
              <h3>Maintenance windows</h3>
              <p>Leave group empty to suppress alerts for all devices.</p>
            </div>
          </div>
          <form className="automation-window-form" onSubmit={addWindow}>
            <input
              placeholder="Window name"
              required
              value={form.name}
              onChange={(event) =>
                setForm({ ...form, name: event.target.value })
              }
            />
            <input
              placeholder="Device group (optional)"
              value={form.device_group}
              onChange={(event) =>
                setForm({ ...form, device_group: event.target.value })
              }
            />
            <input
              type="datetime-local"
              required
              value={form.starts_at}
              onChange={(event) =>
                setForm({ ...form, starts_at: event.target.value })
              }
            />
            <input
              type="datetime-local"
              required
              value={form.ends_at}
              onChange={(event) =>
                setForm({ ...form, ends_at: event.target.value })
              }
            />
            <select
              value={form.repeat}
              onChange={(event) =>
                setForm({ ...form, repeat: event.target.value })
              }
            >
              <option value="NONE">Once</option>
              <option value="DAILY">Daily</option>
              <option value="WEEKLY">Weekly</option>
            </select>
            <button className="button button--primary" disabled={busy}>
              Add window
            </button>
          </form>
          {windows.length === 0 ? (
            <div className="empty-state empty-state--compact">
              No recurring maintenance windows.
            </div>
          ) : (
            <div className="automation-list">
              {windows.map((window) => (
                <article key={window.id}>
                  <span
                    className={`service-status service-status--${window.active_now ? "up" : "unknown"}`}
                  >
                    {window.active_now ? "ACTIVE" : window.enabled ? window.repeat : "PAUSED"}
                  </span>
                  <div>
                    <strong>{window.name}</strong>
                    <small>
                      {window.device_group || "All devices"} ·{" "}
                      {formatDate(window.starts_at)} to{" "}
                      {formatDate(window.ends_at)}
                    </small>
                  </div>
                  <div className="automation-list__actions">
                    <button
                      className="button button--secondary"
                      disabled={busy}
                      onClick={() =>
                        perform(
                          () => updateMaintenanceWindow(window.id, { enabled: !window.enabled }),
                          window.enabled
                            ? "Maintenance window paused."
                            : "Maintenance window resumed.",
                        )
                      }
                    >
                      {window.enabled ? "Pause" : "Resume"}
                    </button>
                    <button
                      className="button button--danger"
                      disabled={busy}
                      onClick={() =>
                        perform(
                          () => deleteMaintenanceWindow(window.id),
                          "Maintenance window removed.",
                        )
                      }
                    >
                      Delete
                    </button>
                  </div>
                </article>
              ))}
            </div>
          )}
        </section>
        <section className="automation-section">
          <h3>Correlated incidents</h3>
          {incidents.length === 0 ? (
            <div className="empty-state empty-state--compact">
              No correlated incidents.
            </div>
          ) : (
            <div className="automation-list">
              {incidents.map((incident) => (
                <article key={incident.id} className="incident-workflow">
                  <span
                    className={`service-status service-status--${incident.status === "OPEN" ? "down" : "up"}`}
                  >
                    {incident.status}
                  </span>
                  <div>
                    <strong>{incident.title}</strong>
                    <small>{incident.summary}</small>
                    <small>
                      {incident.assigned_to
                        ? `Assigned to ${incident.assigned_to}`
                        : "Unassigned"}
                    </small>
                    {incident.operator_note && (
                      <small>Note: {incident.operator_note}</small>
                    )}
                  </div>
                  {incident.status === "OPEN" && (
                    <div className="incident-workflow__controls">
                      <input
                        value={
                          incidentDrafts[incident.id]?.assigned_to ??
                          incident.assigned_to ??
                          ""
                        }
                        onChange={(event) =>
                          setIncidentDrafts((current) => ({
                            ...current,
                            [incident.id]: {
                              ...(current[incident.id] || {
                                operator_note: incident.operator_note || "",
                              }),
                              assigned_to: event.target.value,
                            },
                          }))
                        }
                        maxLength="80"
                        placeholder="Assign owner"
                        aria-label={`Assign owner for ${incident.title}`}
                      />
                      <input
                        value={
                          incidentDrafts[incident.id]?.operator_note ??
                          incident.operator_note ??
                          ""
                        }
                        onChange={(event) =>
                          setIncidentDrafts((current) => ({
                            ...current,
                            [incident.id]: {
                              ...(current[incident.id] || {
                                assigned_to: incident.assigned_to || "",
                              }),
                              operator_note: event.target.value,
                            },
                          }))
                        }
                        maxLength="500"
                        placeholder="Handoff note"
                        aria-label={`Handoff note for ${incident.title}`}
                      />
                      <button
                        className="button button--secondary"
                        disabled={busy}
                        onClick={() =>
                          perform(
                            () =>
                              updateIncident(
                                incident.id,
                                incidentDrafts[incident.id] || {
                                  assigned_to: incident.assigned_to,
                                  operator_note: incident.operator_note,
                                },
                              ),
                            "Incident handoff saved.",
                          )
                        }
                      >
                        Save handoff
                      </button>
                      <button
                        className="button button--secondary"
                        disabled={busy}
                        onClick={() =>
                          perform(
                            () => resolveIncident(incident.id),
                            "Incident resolved.",
                          )
                        }
                      >
                        Resolve
                      </button>
                    </div>
                  )}
                </article>
              ))}
            </div>
          )}
        </section>
        <section className="automation-section">
          <div className="automation-section-title">
            <h3>Scheduled reports</h3>
            <button
              className="button button--secondary"
              disabled={busy}
              onClick={() =>
                perform(generateAutomationReport, "Report generated.")
              }
            >
              Generate now
            </button>
          </div>
          {reports.length === 0 ? (
            <div className="empty-state empty-state--compact">
              No scheduled reports yet.
            </div>
          ) : (
            <div className="automation-list">
              {reports.map((report) => (
                <article key={report.id}>
                  <span className="service-status service-status--up">
                    JSON
                  </span>
                  <div>
                    <strong>{report.filename}</strong>
                    <small>
                      {report.period_days} days · {report.device_count} devices
                      · {formatDate(report.generated_at)}
                    </small>
                  </div>
                  <button
                    className="button button--secondary"
                    disabled={busy}
                    onClick={() => download(report)}
                  >
                    Download
                  </button>
                </article>
              ))}
            </div>
          )}
        </section>
        <section className="automation-section">
          <div className="automation-section-title">
            <div>
              <h3>Configuration drift</h3>
              <p>
                The first run records a baseline; later inventory changes create
                events.
              </p>
            </div>
            <button
              className="button button--secondary"
              disabled={busy}
              onClick={() =>
                perform(refreshAssetBaselines, "Asset baselines refreshed.")
              }
            >
              Refresh baselines
            </button>
          </div>
          {events.length === 0 ? (
            <div className="empty-state empty-state--compact">
              No automation events.
            </div>
          ) : (
            <div className="automation-list">
              {events.slice(0, 20).map((event) => (
                <article key={event.id}>
                  <span className="service-status service-status--unknown">
                    {event.severity}
                  </span>
                  <div>
                    <strong>{event.event_type.replaceAll("_", " ")}</strong>
                    <small>
                      {event.message} · {formatDate(event.created_at)}
                    </small>
                  </div>
                </article>
              ))}
            </div>
          )}
        </section>
      </section>
    </div>
  );
}
