import { useCallback, useEffect, useState } from "react";
import { getAvailabilityReport } from "./api.js";
import { formatDate, formatMetric } from "./format.js";
import StatusBadge from "./StatusBadge.jsx";

export default function AvailabilityReportModal({ onClose }) {
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
