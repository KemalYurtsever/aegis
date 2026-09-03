import { useEffect, useState } from "react";
import { getAttackPaths } from "./api.js";
import { formatDate } from "./format.js";


export default function AttackPathsModal({ onClose, onSelectDevice }) {
  const [overview, setOverview] = useState(null);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  async function load() {
    setLoading(true);
    setError("");
    try {
      setOverview(await getAttackPaths());
    } catch (requestError) {
      setError(requestError.message);
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => { load(); }, []);

  function selectDevice(deviceId) {
    onClose();
    onSelectDevice(deviceId);
  }

  return (
    <div className="modal-backdrop">
      <section className="modal attack-path-modal" role="dialog" aria-modal="true" aria-labelledby="attack-path-title">
        <div className="modal-heading">
          <div><p className="eyebrow">Passive security analysis</p><h2 id="attack-path-title">Candidate attack paths</h2></div>
          <button className="icon-button" onClick={onClose} aria-label="Close">×</button>
        </div>
        <p className="panel-help">Candidate paths correlate stored service exposure, shared subnets, and asset criticality. They are defensive hypotheses and do not send traffic or demonstrate exploitation.</p>
        <div className="attack-path-toolbar">
          <div><strong>{overview?.candidate_paths ?? 0} candidate paths</strong><span>{overview ? `${overview.assessed_devices} assessed devices · ${formatDate(overview.generated_at)}` : "Analyzing stored evidence…"}</span></div>
          <button className="button button--secondary" onClick={load} disabled={loading}>{loading ? "Analyzing…" : "Refresh"}</button>
        </div>
        {error && <div className="form-error" role="alert">{error}</div>}
        {!loading && overview?.paths.length === 0 && <div className="empty-state">No candidate paths found. Run device attack-surface assessments to create evidence.</div>}
        <div className="attack-path-list">{overview?.paths.map((path, index) => (
          <article className={`attack-path attack-path--${path.severity.toLowerCase()}`} key={`${path.entry_device_id}-${path.target_device_id}-${path.entry_port}-${index}`}>
            <span>{path.severity}</span>
            <button onClick={() => selectDevice(path.entry_device_id)}><strong>{path.entry_device_name}</strong><small>{path.entry_ip_address} · TCP {path.entry_port}</small></button>
            <b aria-hidden="true">→</b>
            <button onClick={() => selectDevice(path.target_device_id)}><strong>{path.target_device_name}</strong><small>{path.target_ip_address}</small></button>
            <p>{path.rationale}</p>
          </article>
        ))}</div>
      </section>
    </div>
  );
}
