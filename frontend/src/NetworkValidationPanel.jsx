import { useCallback, useEffect, useMemo, useState } from "react";

import {
  createSegmentationPolicy,
  deleteSegmentationPolicy,
  listSegmentationChecks,
  listSegmentationPolicies,
  listTroubleshootingRuns,
  runSegmentationCheck,
  runTroubleshooting,
} from "./api.js";

const STEP_LABELS = {
  CONFIG: "IP configuration",
  GATEWAY: "Gateway ICMP",
  DNS: "DNS answer",
  ROUTE: "Route trace",
  TARGET: "Target ICMP",
  PORT: "TCP port",
  SERVICE: "Application service",
};

function formatDate(value) {
  return new Intl.DateTimeFormat(undefined, { dateStyle: "medium", timeStyle: "short" }).format(new Date(value));
}

export default function NetworkValidationPanel({ device, devices = [], serviceChecks = [], agent }) {
  const [runs, setRuns] = useState([]);
  const [policies, setPolicies] = useState([]);
  const [checksByPolicy, setChecksByPolicy] = useState({});
  const [dnsName, setDnsName] = useState("");
  const [tcpPort, setTcpPort] = useState("");
  const [serviceCheckId, setServiceCheckId] = useState("");
  const [includeRoute, setIncludeRoute] = useState(false);
  const [destinationId, setDestinationId] = useState("");
  const [policyPort, setPolicyPort] = useState("443");
  const [expected, setExpected] = useState("ALLOW");
  const [description, setDescription] = useState("");
  const [authorizationPhrase, setAuthorizationPhrase] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  const load = useCallback(async () => {
    try {
      const [nextRuns, nextPolicies] = await Promise.all([
        listTroubleshootingRuns(device.id),
        listSegmentationPolicies(device.id),
      ]);
      const histories = await Promise.all(nextPolicies.map((policy) => listSegmentationChecks(policy.id)));
      setRuns(nextRuns);
      setPolicies(nextPolicies);
      setChecksByPolicy(Object.fromEntries(nextPolicies.map((policy, index) => [policy.id, histories[index]])));
      setError("");
    } catch (requestError) {
      setError(requestError.message);
    }
  }, [device.id]);

  useEffect(() => { load(); }, [load]);
  const hasPendingCheck = useMemo(
    () => Object.values(checksByPolicy).some((checks) => checks.some((check) => check.status === "PENDING")),
    [checksByPolicy],
  );
  useEffect(() => {
    if (!hasPendingCheck) return undefined;
    const timer = window.setInterval(load, 3000);
    return () => window.clearInterval(timer);
  }, [hasPendingCheck, load]);

  async function runSteps(event) {
    event.preventDefault();
    setBusy(true);
    setError("");
    try {
      await runTroubleshooting(device.id, {
        dns_name: dnsName.trim() || null,
        tcp_port: tcpPort === "" ? null : Number(tcpPort),
        service_check_id: serviceCheckId === "" ? null : Number(serviceCheckId),
        include_route: includeRoute,
      });
      await load();
    } catch (requestError) {
      setError(requestError.message);
    } finally {
      setBusy(false);
    }
  }

  async function addPolicy(event) {
    event.preventDefault();
    setBusy(true);
    setError("");
    try {
      await createSegmentationPolicy({
        source_device_id: device.id,
        target_device_id: Number(destinationId),
        target_port: Number(policyPort),
        expected_reachability: expected,
        description: description.trim() || null,
      });
      setDescription("");
      await load();
    } catch (requestError) {
      setError(requestError.message);
    } finally {
      setBusy(false);
    }
  }

  async function checkPolicy(policy) {
    if (!window.confirm(`Test TCP reachability from ${device.name} to ${policy.target_name}:${policy.target_port}?`)) return;
    setBusy(true);
    setError("");
    try {
      await runSegmentationCheck(policy.id, authorizationPhrase);
      setAuthorizationPhrase("");
      await load();
    } catch (requestError) {
      setError(requestError.message);
    } finally {
      setBusy(false);
    }
  }

  async function removePolicy(policy) {
    if (!window.confirm(`Delete this expectation and its test history for ${policy.target_name}:${policy.target_port}?`)) return;
    setBusy(true);
    setError("");
    try {
      await deleteSegmentationPolicy(policy.id);
      await load();
    } catch (requestError) {
      setError(requestError.message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <section className="panel network-validation-panel">
      <div className="panel-heading">
        <div><p className="eyebrow">Administrator · measured evidence</p><h2>Network validation</h2></div>
        <span>One device at a time</span>
      </div>
      <p className="topology-note">Troubleshooting probes run from the Aegis host. Segmentation probes run from this device's opted-in agent. A failed connection does not establish which firewall or service caused it.</p>
      {error && <div className="form-error user-error" role="alert">{error}</div>}
      <div className="network-validation-grid">
        <div>
          <h3>Step-by-step troubleshooting</h3>
          <form className="diagnostic-controls" onSubmit={runSteps}>
            <label>DNS hostname (optional)<input value={dnsName} onChange={(event) => setDnsName(event.target.value)} maxLength="253" placeholder="host.lab.example" /></label>
            <label>TCP port (optional)<input type="number" min="1" max="65535" value={tcpPort} onChange={(event) => setTcpPort(event.target.value)} disabled={serviceCheckId !== ""} /></label>
            <label>Service check<select value={serviceCheckId} onChange={(event) => {
              const selected = serviceChecks.find((check) => String(check.id) === event.target.value);
              setServiceCheckId(event.target.value);
              if (selected) setTcpPort(String(selected.port));
            }}><option value="">No application check</option>{serviceChecks.map((check) => <option value={check.id} key={check.id}>{check.name} · {check.check_type}/{check.port}</option>)}</select></label>
            <label className="check-field"><input type="checkbox" checked={includeRoute} onChange={(event) => setIncludeRoute(event.target.checked)} />Include bounded traceroute</label>
            <button className="button button--primary" type="submit" disabled={busy}>{busy ? "Working…" : "Run checks"}</button>
          </form>
          {runs.length === 0 && <p className="diagnostic-description">No troubleshooting run recorded yet.</p>}
          {runs.slice(0, 5).map((run) => (
            <details className="diagnostic-result network-validation-result" key={run.id} defaultOpen={run.id === runs[0]?.id}>
              <summary>{formatDate(run.created_at)} · {run.target_ip} · Aegis host</summary>
              <ol className="network-validation-steps">{run.steps.map((step) => (
                <li key={step.key}><strong>{STEP_LABELS[step.key]} · {step.status}</strong><span>{step.observation}</span></li>
              ))}</ol>
            </details>
          ))}
        </div>
        <div>
          <h3>Segmentation expectations</h3>
          <form className="diagnostic-controls" onSubmit={addPolicy}>
            <label>Registered destination<select value={destinationId} onChange={(event) => setDestinationId(event.target.value)} required><option value="">Select a device</option>{devices.filter((item) => item.id !== device.id).map((item) => <option value={item.id} key={item.id}>{item.name} · {item.ip_address}</option>)}</select></label>
            <label>Destination TCP port<input type="number" min="1" max="65535" value={policyPort} onChange={(event) => setPolicyPort(event.target.value)} required /></label>
            <label>Expected reachability<select value={expected} onChange={(event) => setExpected(event.target.value)}><option value="ALLOW">TCP connection allowed</option><option value="DENY">No TCP connection expected</option></select></label>
            <label>Reason (optional)<input value={description} onChange={(event) => setDescription(event.target.value)} maxLength="200" /></label>
            <button className="button button--secondary" type="submit" disabled={busy || !destinationId}>Add expectation</button>
          </form>
          {policies.length > 0 && <label className="network-validation-phrase">Authorization phrase<input value={authorizationPhrase} onChange={(event) => setAuthorizationPhrase(event.target.value)} placeholder="RUN SAFE VALIDATION" autoComplete="off" /></label>}
          {policies.length === 0 && <p className="diagnostic-description">No source-to-destination expectation recorded yet.</p>}
          {policies.map((policy) => (
            <article className="diagnostic-job network-validation-policy" key={policy.id}>
              <div className="diagnostic-job__heading">
                <div><strong>{policy.target_name}:{policy.target_port} · expect {policy.expected_reachability}</strong><small>{device.name} ({policy.source_ip}) → {policy.target_ip}{policy.description ? ` · ${policy.description}` : ""}</small></div>
                <div className="row-actions">
                  <button className="button button--secondary" onClick={() => checkPolicy(policy)} disabled={busy || authorizationPhrase !== "RUN SAFE VALIDATION" || !agent?.diagnostics_enabled || agent.health_status === "OFFLINE"}>Run test</button>
                  <button className="text-button text-button--danger" onClick={() => removePolicy(policy)} disabled={busy}>Delete</button>
                </div>
              </div>
              {(checksByPolicy[policy.id] || []).slice(0, 5).map((check) => (
                <p className="network-validation-check" key={check.id}><strong>{check.status}</strong> · {formatDate(check.created_at)} · {check.interpretation}{check.error_type ? ` (${check.error_type})` : ""}</p>
              ))}
            </article>
          ))}
          {!agent?.diagnostics_enabled && <p className="diagnostic-description">Testing requires an enrolled source agent with diagnostics enabled. Expectations can be prepared now.</p>}
        </div>
      </div>
    </section>
  );
}
