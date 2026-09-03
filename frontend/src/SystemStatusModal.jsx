import { useEffect, useState } from "react";
import { getSystemReadiness } from "./api.js";
import { formatDate } from "./format.js";


export default function SystemStatusModal({ onClose }) {
  const [readiness, setReadiness] = useState(null);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  async function load() {
    setLoading(true);
    setError("");
    try {
      setReadiness(await getSystemReadiness());
    } catch (requestError) {
      setError(requestError.message);
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => { load(); }, []);

  return (
    <div className="modal-backdrop">
      <section className="modal system-status-modal" role="dialog" aria-modal="true" aria-labelledby="system-status-title">
        <div className="modal-heading">
          <div><p className="eyebrow">Operational readiness</p><h2 id="system-status-title">System status</h2></div>
          <button className="icon-button" onClick={onClose} aria-label="Close">×</button>
        </div>
        <div className="system-status-toolbar">
          <div>
            <strong>{readiness ? readiness.status : "CHECKING"}</strong>
            <span>{readiness ? `Checked ${formatDate(readiness.checked_at)}` : "Checking local services…"}</span>
          </div>
          <button className="button button--secondary" onClick={load} disabled={loading}>{loading ? "Checking…" : "Refresh"}</button>
        </div>
        {error && <div className="form-error" role="alert">{error}</div>}
        <div className="system-component-list">
          {readiness?.components.map((component) => (
            <article key={component.name} className={`system-component system-component--${component.status.toLowerCase()}`}>
              <span>{component.status}</span>
              <div><strong>{component.name}</strong><p>{component.message}</p></div>
            </article>
          ))}
        </div>
      </section>
    </div>
  );
}
