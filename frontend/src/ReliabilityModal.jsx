import { useCallback, useEffect, useState } from "react";
import { formatBytes, formatDate } from "./format.js";
import {
  applyRetention,
  createBackup,
  downloadBackup,
  getBackupStatus,
  listBackups,
  previewRetention,
  verifyBackup,
} from "./api.js";

export default function ReliabilityModal({ onClose }) {
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
