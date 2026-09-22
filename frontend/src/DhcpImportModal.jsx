import { useState } from "react";
import { importDhcpLeases } from "./api.js";
import { rowsFromDhcpCsv } from "./dhcpCsv.js";

export default function DhcpImportModal({ onClose, onImported }) {
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
            <code>prefix_length</code>, <code>gateway_ip</code>,{" "}
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
