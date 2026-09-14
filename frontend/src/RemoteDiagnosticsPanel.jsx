import { useCallback, useEffect, useMemo, useState } from "react";

import { cancelDiagnosticJob, createDiagnosticJob, listDiagnosticJobs } from "./api.js";

const JOB_TYPES = [
  ["NETWORK_CONNECTIONS", "Network and routing state", "Listening ports, active connections, owning processes and the host routing table"],
  ["TOP_PROCESSES", "Top processes", "Processes ranked by CPU and memory consumption"],
  ["SECURITY_LOG_SUMMARY", "Security log summary", "Recent operating-system warnings and errors"],
  ["LOGIN_HISTORY", "Login history", "Recent successful and failed authentication activity"],
  ["LOCAL_ACCOUNTS", "Local accounts", "Sanitized local user-account inventory"],
  ["FIREWALL_RULES", "Firewall rules", "Enabled local firewall rules and policy information"],
  ["SERVICE_SCAN", "Local service scan", "Nmap service and version detection against the agent host only"],
  ["PACKET_CAPTURE", "Packet metadata", "Bounded non-promiscuous packet metadata capture without payloads"],
  ["SUID_AUDIT", "SUID audit", "Privileged-file inventory on Unix-like hosts"],
  ["VALIDATION_SIMULATION", "Safe defensive validation", "Generated temporary artifacts, signed callbacks, policy inspection, or a registered-device segmentation probe"],
];

const SIMULATION_TYPES = [
  ["CALLBACK_CANARY", "Signed callback canary", "Proves that the enrolled agent can make an authenticated, nonce-bound callback to Aegis without opening a shell."],
  ["SYNTHETIC_CREDENTIAL", "Synthetic honey credential", "Creates an explicitly fake credential artifact in an isolated temporary directory, hashes it, and removes it."],
  ["PASSWORD_POLICY_AUDIT", "Password policy audit", "Reads password-policy settings without accessing passwords, hashes, or credential material."],
  ["TEMPORARY_MARKER", "Temporary marker", "Creates, verifies, hashes, and automatically removes one generated marker file."],
  ["SAFE_FILE_ACTIVITY", "Safe file-activity simulation", "Creates and renames generated files only, performs no encryption, then verifies cleanup."],
  ["DETECTION_VARIATION", "Detection variation", "Creates several benign, clearly labelled indicators in an isolated temporary directory and removes them."],
  ["SEGMENTATION_PROBE", "Segmentation probe", "Attempts one TCP connection to another registered device without sending application data."],
  ["SIGNED_CANARY_ARTIFACT", "Signed canary artifact", "Creates a non-executable HMAC-signed canary, verifies it locally, and removes it."],
];

const LABELS = Object.fromEntries(JOB_TYPES.map(([value, label]) => [value, label]));

function formatDate(value) {
  if (!value) return "—";
  return new Intl.DateTimeFormat(undefined, { dateStyle: "medium", timeStyle: "medium" }).format(new Date(value));
}

function JobResult({ job }) {
  if (job.status === "FAILED" || job.status === "EXPIRED") {
    return <div className="diagnostic-error">{job.error || "The diagnostic did not complete."}</div>;
  }
  if (job.result === null || job.result === undefined) return null;
  return (
    <details className="diagnostic-result">
      <summary>View structured result</summary>
      <pre>{JSON.stringify(job.result, null, 2)}</pre>
    </details>
  );
}

export default function RemoteDiagnosticsPanel({ deviceId, agent, devices = [] }) {
  const [jobs, setJobs] = useState([]);
  const [jobType, setJobType] = useState("NETWORK_CONNECTIONS");
  const [maxRecords, setMaxRecords] = useState(100);
  const [durationSeconds, setDurationSeconds] = useState(10);
  const [simulationType, setSimulationType] = useState("CALLBACK_CANARY");
  const [targetDeviceId, setTargetDeviceId] = useState("");
  const [targetPort, setTargetPort] = useState(443);
  const [authorizationPhrase, setAuthorizationPhrase] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  const load = useCallback(async () => {
    if (!agent) return;
    try {
      setJobs(await listDiagnosticJobs(deviceId));
      setError("");
    } catch (requestError) {
      setError(requestError.message);
    }
  }, [agent, deviceId]);

  useEffect(() => {
    setTargetDeviceId("");
    setAuthorizationPhrase("");
  }, [deviceId]);

  useEffect(() => { load(); }, [load]);
  const activeJobs = useMemo(
    () => jobs.some((job) => job.status === "PENDING" || job.status === "RUNNING"),
    [jobs],
  );
  useEffect(() => {
    if (!activeJobs) return undefined;
    const timer = window.setInterval(load, 3000);
    return () => window.clearInterval(timer);
  }, [activeJobs, load]);

  async function createJob() {
    const label = LABELS[jobType];
    const simulationLabel = SIMULATION_TYPES.find(([value]) => value === simulationType)?.[1];
    const actionLabel = jobType === "VALIDATION_SIMULATION" ? `${label}: ${simulationLabel}` : label;
    const confirmation = jobType === "VALIDATION_SIMULATION"
      ? `Run ${actionLabel} on this enrolled host? Generated validation data will be cleaned up automatically.`
      : `Run ${actionLabel} on this enrolled host?`;
    if (!window.confirm(confirmation)) return;
    setBusy(true);
    setError("");
    try {
      const payload = {
        job_type: jobType,
        max_records: Number(maxRecords),
        duration_seconds: Number(durationSeconds),
      };
      if (jobType === "VALIDATION_SIMULATION") {
        payload.simulation_type = simulationType;
        payload.authorization_phrase = authorizationPhrase;
        if (simulationType === "SEGMENTATION_PROBE") {
          payload.target_device_id = Number(targetDeviceId);
          payload.target_port = Number(targetPort);
        }
      }
      await createDiagnosticJob(deviceId, payload);
      if (jobType === "VALIDATION_SIMULATION") setAuthorizationPhrase("");
      await load();
    } catch (requestError) {
      setError(requestError.message);
    } finally {
      setBusy(false);
    }
  }

  async function cancel(jobId) {
    setBusy(true);
    try {
      await cancelDiagnosticJob(jobId);
      await load();
    } catch (requestError) {
      setError(requestError.message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <section className="panel diagnostics-panel">
      <div className="panel-heading">
        <div><p className="eyebrow">Administrator · allowlisted execution</p><h2>Remote diagnostics</h2></div>
        <span>{agent?.diagnostics_enabled ? "Agent enabled" : "Agent opt-in required"}</span>
      </div>
      {!agent ? (
        <div className="empty-state empty-state--compact">Enroll the remote host agent before creating diagnostic jobs.</div>
      ) : !agent.diagnostics_enabled ? (
        <div className="diagnostic-notice">
          Reinstall or update the agent with <code>-EnableDiagnostics</code>. No remote jobs can be queued until the agent reports that opt-in.
        </div>
      ) : (
        <>
          <div className="diagnostic-controls">
            <label>Diagnostic<select value={jobType} onChange={(event) => setJobType(event.target.value)}>{JOB_TYPES.map(([value, label]) => <option value={value} key={value}>{label}</option>)}</select></label>
            <label>Maximum records<input type="number" min="10" max="500" value={maxRecords} onChange={(event) => setMaxRecords(event.target.value)} /></label>
            {jobType === "PACKET_CAPTURE" && <label>Seconds<input type="number" min="1" max="30" value={durationSeconds} onChange={(event) => setDurationSeconds(event.target.value)} /></label>}
            {jobType === "VALIDATION_SIMULATION" && <label>Simulation<select value={simulationType} onChange={(event) => setSimulationType(event.target.value)}>{SIMULATION_TYPES.map(([value, label]) => <option value={value} key={value}>{label}</option>)}</select></label>}
            {jobType === "VALIDATION_SIMULATION" && simulationType === "SEGMENTATION_PROBE" && <>
              <label>Registered destination<select value={targetDeviceId} onChange={(event) => setTargetDeviceId(event.target.value)} required><option value="">Select a device</option>{devices.filter((device) => Number(device.id) !== Number(deviceId)).map((device) => <option value={device.id} key={device.id}>{device.name} · {device.ip_address}</option>)}</select></label>
              <label>Destination TCP port<input type="number" min="1" max="65535" value={targetPort} onChange={(event) => setTargetPort(event.target.value)} /></label>
            </>}
            {jobType === "VALIDATION_SIMULATION" && <label>Authorization phrase<input value={authorizationPhrase} onChange={(event) => setAuthorizationPhrase(event.target.value)} placeholder="RUN SAFE VALIDATION" autoComplete="off" /></label>}
            <button className="button button--primary" onClick={createJob} disabled={busy || agent.health_status === "OFFLINE" || (jobType === "VALIDATION_SIMULATION" && (authorizationPhrase !== "RUN SAFE VALIDATION" || (simulationType === "SEGMENTATION_PROBE" && !targetDeviceId)))}>{busy ? "Working…" : jobType === "VALIDATION_SIMULATION" ? "Queue validation" : "Queue diagnostic"}</button>
          </div>
          <p className="diagnostic-description">{jobType === "VALIDATION_SIMULATION" ? SIMULATION_TYPES.find(([value]) => value === simulationType)?.[2] : JOB_TYPES.find(([value]) => value === jobType)?.[2]}</p>
        </>
      )}
      {error && <div className="form-error user-error" role="alert">{error}</div>}
      {jobs.length > 0 && <div className="diagnostic-jobs">{jobs.map((job) => (
        <article className="diagnostic-job" key={job.id}>
          <div className="diagnostic-job__heading">
            <div><strong>{LABELS[job.job_type] || job.job_type}</strong><small>Requested by {job.requested_by} · {formatDate(job.created_at)}</small></div>
            <div className="row-actions"><span className={`diagnostic-status diagnostic-status--${job.status.toLowerCase()}`}>{job.status}</span>{job.status === "PENDING" && <button className="button button--secondary" disabled={busy} onClick={() => cancel(job.id)}>Cancel</button>}</div>
          </div>
          <JobResult job={job} />
        </article>
      ))}</div>}
    </section>
  );
}
