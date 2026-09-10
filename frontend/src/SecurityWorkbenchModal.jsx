import { useEffect, useMemo, useRef, useState } from "react";

import {
  cancelSecurityPlaybookRun,
  createSecurityPlaybookRun,
  getAttackPaths,
  getHostNetworkPolicy,
  getNeighborTable,
  getSecurityPlaybookRun,
  getWirelessAdapters,
  listSecurityPlaybookRunIndex,
  listSecurityPlaybookRuns,
  listPacketCaptures,
  runAvahiBrowse,
  runDnsQuery,
  runArpScan,
  runCurlRequest,
  runDigQuery,
  runNmapScan,
  runTestConnectionPorts,
  runSecurityTraceroute,
} from "./api.js";
import { formatDate } from "./format.js";
import aegisShield from "./assets/aegis-shield.png";
import aegisShieldDark from "./assets/aegis-shield-dark.png";

const TOOLS = [
  ["overview", "Overview", "01"],
  ["playbooks", "Playbooks", "02"],
  ["decoder", "Decoder & numbers", "03"],
  ["network", "Network", "04"],
  ["sniffer", "Sniffer", "05"],
  ["credentials", "Credential hygiene", "06"],
  ["traceroute", "Traceroute", "07"],
  ["configuration", "Configuration audit", "08"],
  ["wireless", "Wireless", "09"],
  ["query", "DNS query", "10"],
  ["policy", "Firewall & routing", "11"],
  ["lab-cli", "Network CLI", "12"],
  ["test-connection", "TCP port test", "13"],
];

const PLAYBOOK_PROFILES = [
  ["FAST", "Fast", "Tests 8 common TCP ports, discovers Nmap's top 1,000 ports, then uses lightweight service detection."],
  ["DETAILED", "Detailed", "Tests 24 common TCP ports, discovers the top 1,000, then runs -sV --version-light on open ports."],
  ["AGGRESSIVE", "Aggressive", "Tests 64 common TCP ports, discovers the top 1,000, then runs -sV --version-all on open ports."],
];
const ACTIVE_PLAYBOOK_STATUSES = new Set(["QUEUED", "RUNNING"]);
const FINISHED_STEP_STATUSES = new Set(["COMPLETED", "FAILED", "CANCELLED"]);

function upsertPlaybookRun(current, next) {
  const existingIndex = current.findIndex((run) => run.id === next.id);
  if (existingIndex < 0) return [next, ...current].slice(0, 10);
  return current.map((run, index) => (index === existingIndex ? next : run));
}

function mergeGlobalPlaybookRuns(current, incoming) {
  const byId = new Map(current.map((run) => [run.id, run]));
  incoming.forEach((run) => {
    const indexEntry = { ...run };
    delete indexEntry.steps;
    byId.set(run.id, indexEntry);
  });
  return [...byId.values()]
    .sort((left, right) => right.id - left.id)
    .slice(0, 50);
}

function playbookStatusLabel(status) {
  return status ? status.replaceAll("_", " ") : "UNKNOWN";
}

function playbookRunHeading(run, steps) {
  if (!run) return "Host assessment";
  const currentStep = steps.find((step) => step.step_key === run.current_step);
  if (currentStep) return currentStep.name;
  if (run.current_step) return run.current_step;
  return {
    QUEUED: "Waiting for assessment worker",
    RUNNING: "Preparing next assessment step",
    COMPLETED: "Assessment complete",
    PARTIAL: "Assessment completed with step errors",
    FAILED: "Assessment failed",
    CANCELLED: "Assessment cancelled",
  }[run.status] || "Host assessment";
}

function textToBytes(value) {
  return new TextEncoder().encode(value);
}

function bytesToText(bytes) {
  return new TextDecoder("utf-8", { fatal: true }).decode(bytes);
}

function encodeBase64(value) {
  const bytes = textToBytes(value);
  let binary = "";
  bytes.forEach((byte) => {
    binary += String.fromCharCode(byte);
  });
  return window.btoa(binary);
}

function decodeBase64(value) {
  const binary = window.atob(value.replaceAll(/\s/g, ""));
  return bytesToText(
    Uint8Array.from(binary, (character) => character.charCodeAt(0)),
  );
}

function encodeHex(value) {
  return [...textToBytes(value)]
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");
}

function decodeHex(value) {
  const normalized = value.replaceAll(/\s/g, "");
  if (!normalized || normalized.length % 2 || !/^[0-9a-f]+$/i.test(normalized))
    throw new Error("Hex input must contain complete byte pairs.");
  return bytesToText(
    Uint8Array.from(normalized.match(/.{2}/g), (pair) =>
      Number.parseInt(pair, 16),
    ),
  );
}

function parseInteger(value, base) {
  const compact = value.trim().replaceAll("_", "");
  if (!compact) throw new Error("Enter an integer to convert.");
  const negative = compact.startsWith("-");
  const unsigned = negative ? compact.slice(1) : compact;
  const detectedBase =
    base === "AUTO"
      ? unsigned.toLowerCase().startsWith("0x")
        ? 16
        : unsigned.toLowerCase().startsWith("0b")
          ? 2
          : unsigned.toLowerCase().startsWith("0o")
            ? 8
            : 10
      : Number(base);
  const prefixes = { 2: "0b", 8: "0o", 16: "0x" };
  const matchingPrefix = prefixes[detectedBase];
  const digits =
    matchingPrefix && unsigned.toLowerCase().startsWith(matchingPrefix)
      ? unsigned.slice(2)
      : unsigned;
  const patterns = {
    2: /^[01]+$/,
    8: /^[0-7]+$/,
    10: /^\d+$/,
    16: /^[0-9a-f]+$/i,
  };
  if (!patterns[detectedBase]?.test(digits))
    throw new Error(`The value is not valid base-${detectedBase} notation.`);
  const parsed = BigInt(`${prefixes[detectedBase] || ""}${digits}`);
  return negative ? -parsed : parsed;
}

function IntegerTool() {
  const [inputBase, setInputBase] = useState("AUTO");
  const [input, setInput] = useState("");
  const [operation, setOperation] = useState("AND");
  const [operand, setOperand] = useState("");
  let value = null;
  let bitwise = null;
  let conversionError = "";
  try {
    value = parseInteger(input, inputBase);
    if (operation === "NOT") {
      bitwise = ~value;
    } else if (operand.trim()) {
      const right = parseInteger(operand, "AUTO");
      if (["SHL", "SHR"].includes(operation)) {
        if (right < 0n || right > 1024n)
          throw new Error("Shift amount must be between 0 and 1024.");
        bitwise = operation === "SHL" ? value << right : value >> right;
      } else {
        bitwise = { AND: value & right, OR: value | right, XOR: value ^ right }[
          operation
        ];
      }
    }
  } catch (caughtError) {
    value = null;
    bitwise = null;
    if (input) conversionError = caughtError.message;
  }

  const rows = value === null ? [] : [
    ["Decimal", value.toString(10)],
    ["Hexadecimal", `${value < 0n ? "-" : ""}0x${(value < 0n ? -value : value).toString(16).toUpperCase()}`],
    ["Binary", `${value < 0n ? "-" : ""}0b${(value < 0n ? -value : value).toString(2)}`],
    ["Octal", `${value < 0n ? "-" : ""}0o${(value < 0n ? -value : value).toString(8)}`],
  ];

  return (
    <div className="integer-tool">
      <div className="integer-tool__heading">
        <div>
          <strong>Number and bitwise converter</strong>
          <span>Exact local conversion using integers of any practical size.</span>
        </div>
      </div>
      <div className="integer-tool__controls">
        <label>
          Input base
          <select value={inputBase} onChange={(event) => setInputBase(event.target.value)}>
            <option value="AUTO">Auto-detect prefix</option>
            <option value="10">Decimal</option>
            <option value="16">Hexadecimal</option>
            <option value="2">Binary</option>
            <option value="8">Octal</option>
          </select>
        </label>
        <label>
          Integer
          <input
            value={input}
            onChange={(event) => setInput(event.target.value)}
            placeholder="42, 0x2A, 0b101010, or 0o52"
            spellCheck="false"
          />
        </label>
      </div>
      {conversionError && <div className="form-error" role="alert">{conversionError}</div>}
      {rows.length > 0 && (
        <dl className="integer-results">
          {rows.map(([label, result]) => (
            <div key={label}><dt>{label}</dt><dd>{result}</dd></div>
          ))}
        </dl>
      )}
      <div className="bitwise-controls">
        <label>
          Bitwise operation
          <select value={operation} onChange={(event) => setOperation(event.target.value)}>
            <option value="AND">AND (&amp;)</option>
            <option value="OR">OR (|)</option>
            <option value="XOR">XOR (^)</option>
            <option value="NOT">NOT (~)</option>
            <option value="SHL">Shift left (&lt;&lt;)</option>
            <option value="SHR">Shift right (&gt;&gt;)</option>
          </select>
        </label>
        {operation !== "NOT" && (
          <label>
            {operation === "SHL" || operation === "SHR" ? "Shift amount" : "Second integer"}
            <input
              value={operand}
              onChange={(event) => setOperand(event.target.value)}
              placeholder={operation === "SHL" || operation === "SHR" ? "2" : "0x0F"}
              spellCheck="false"
            />
          </label>
        )}
        <div className="bitwise-result">
          <span>Decimal result</span>
          <strong>{bitwise === null ? "—" : bitwise.toString(10)}</strong>
        </div>
      </div>
      <small className="integer-tool__note">
        Bitwise operations use signed integer semantics; prefixes are optional
        when the input base is selected explicitly.
      </small>
    </div>
  );
}

function DecoderTool() {
  const [mode, setMode] = useState("BASE64_DECODE");
  const [input, setInput] = useState("");
  const [output, setOutput] = useState("");
  const [error, setError] = useState("");

  function transform() {
    setError("");
    try {
      const operations = {
        BASE64_DECODE: decodeBase64,
        BASE64_ENCODE: encodeBase64,
        HEX_DECODE: decodeHex,
        HEX_ENCODE: encodeHex,
        URL_DECODE: decodeURIComponent,
        URL_ENCODE: encodeURIComponent,
      };
      setOutput(operations[mode](input));
    } catch {
      setOutput("");
      setError("The input is not valid for the selected transformation.");
    }
  }

  return (
    <section className="workbench-tool">
      <header>
        <p className="eyebrow">Local-only utility</p>
        <h3>Safe text decoder</h3>
        <span>
          Input stays in this browser tab and is never submitted to Aegis.
        </span>
      </header>
      <div className="decoder-grid">
        <label>
          Operation
          <select
            value={mode}
            onChange={(event) => setMode(event.target.value)}
          >
            <option value="BASE64_DECODE">Decode Base64</option>
            <option value="BASE64_ENCODE">Encode Base64</option>
            <option value="HEX_DECODE">Decode hexadecimal</option>
            <option value="HEX_ENCODE">Encode hexadecimal</option>
            <option value="URL_DECODE">Decode URL component</option>
            <option value="URL_ENCODE">Encode URL component</option>
          </select>
        </label>
        <label>
          Input
          <textarea
            value={input}
            onChange={(event) => setInput(event.target.value)}
            placeholder="Paste non-sensitive lab text"
          />
        </label>
        <button
          className="button button--primary"
          onClick={transform}
          disabled={!input}
        >
          Transform
        </button>
        <label>
          Output
          <textarea value={output} readOnly placeholder="Result appears here" />
        </label>
      </div>
      {error && (
        <div className="form-error" role="alert">
          {error}
        </div>
      )}
      <IntegerTool />
    </section>
  );
}

function secureRandomIndex(limit) {
  const maximum = Math.floor(0x100000000 / limit) * limit;
  const buffer = new Uint32Array(1);
  do window.crypto.getRandomValues(buffer);
  while (buffer[0] >= maximum);
  return buffer[0] % limit;
}

function generatePassword(length) {
  const groups = [
    "ABCDEFGHJKLMNPQRSTUVWXYZ",
    "abcdefghijkmnopqrstuvwxyz",
    "23456789",
    "!@#$%^&*()-_=+[]{}",
  ];
  const all = groups.join("");
  const characters = groups.map((group) => group[secureRandomIndex(group.length)]);
  while (characters.length < length)
    characters.push(all[secureRandomIndex(all.length)]);
  for (let index = characters.length - 1; index > 0; index -= 1) {
    const swapIndex = secureRandomIndex(index + 1);
    [characters[index], characters[swapIndex]] = [characters[swapIndex], characters[index]];
  }
  return characters.join("");
}

function passwordScore(value) {
  if (!value)
    return {
      score: 0,
      label: "No sample",
      suggestions: ["Enter a disposable example—not a real password."],
    };
  let score = Math.min(4, Math.floor(value.length / 4));
  const classes = [/[a-z]/, /[A-Z]/, /\d/, /[^a-z\d]/i].filter((pattern) =>
    pattern.test(value),
  ).length;
  score += Math.max(0, classes - 2);
  if (/(.)\1{2,}|1234|password|qwerty|admin|letmein/i.test(value)) score -= 2;
  score = Math.max(0, Math.min(4, score));
  const suggestions = [];
  if (value.length < 14)
    suggestions.push("Use at least 14 characters or a long passphrase.");
  if (classes < 3)
    suggestions.push(
      "Add another character type, or make the passphrase longer.",
    );
  if (/(.)\1{2,}|1234|password|qwerty|admin|letmein/i.test(value))
    suggestions.push("Remove predictable words, sequences, and repetition.");
  if (!suggestions.length)
    suggestions.push("Use a unique value and store it in a password manager.");
  return {
    score,
    label: ["Very weak", "Weak", "Fair", "Strong", "Very strong"][score],
    suggestions,
  };
}

function CredentialTool() {
  const [sample, setSample] = useState("");
  const [passwordLength, setPasswordLength] = useState(20);
  const [generatedPassword, setGeneratedPassword] = useState("");
  const [showGenerated, setShowGenerated] = useState(false);
  const [copyStatus, setCopyStatus] = useState("");
  const result = passwordScore(sample);
  function createPassword() {
    const password = generatePassword(passwordLength);
    setGeneratedPassword(password);
    setShowGenerated(true);
    setCopyStatus("");
  }
  async function copyPassword() {
    try {
      await navigator.clipboard.writeText(generatedPassword);
      setCopyStatus("Copied");
    } catch {
      setCopyStatus("Copy failed");
    }
  }
  return (
    <section className="workbench-tool">
      <header>
        <p className="eyebrow">Safe replacement for cracking</p>
        <h3>Credential-hygiene check</h3>
        <span>
          No hashes are cracked, no credentials are intercepted, and the sample
          never leaves the browser.
        </span>
      </header>
      <div className="password-generator">
        <div className="password-generator__heading">
          <div>
            <strong>Random password generator</strong>
            <span>Generated securely in this browser and never sent to the server.</span>
          </div>
          <label>
            Length
            <select value={passwordLength} onChange={(event) => setPasswordLength(Number(event.target.value))}>
              {[16, 20, 24, 32].map((length) => <option key={length} value={length}>{length}</option>)}
            </select>
          </label>
          <button className="button button--primary" type="button" onClick={createPassword}>
            Generate password
          </button>
        </div>
        {generatedPassword && (
          <div className="password-generator__result">
            <input
              type={showGenerated ? "text" : "password"}
              value={generatedPassword}
              readOnly
              aria-label="Generated password"
            />
            <button className="button button--secondary" type="button" onClick={() => setShowGenerated((shown) => !shown)}>
              {showGenerated ? "Hide" : "Show"}
            </button>
            <button className="button button--secondary" type="button" onClick={copyPassword}>
              {copyStatus || "Copy"}
            </button>
          </div>
        )}
      </div>
      <div className="credential-check">
        <label>
          Disposable password example
          <input
            type="password"
            value={sample}
            onChange={(event) => setSample(event.target.value)}
            autoComplete="new-password"
            placeholder="Do not enter a real password"
          />
        </label>
        <div className={`strength strength--${result.score}`}>
          <div>
            {[0, 1, 2, 3].map((bar) => (
              <span key={bar} className={bar < result.score ? "filled" : ""} />
            ))}
          </div>
          <strong>{result.label}</strong>
        </div>
        <ul>
          {result.suggestions.map((suggestion) => (
            <li key={suggestion}>{suggestion}</li>
          ))}
        </ul>
      </div>
    </section>
  );
}

function NetworkTool({ devices, onSelectDevice }) {
  const [query, setQuery] = useState("");
  const visible = devices.filter((device) =>
    `${device.name} ${device.ip_address} ${device.mac_address || ""} ${device.device_type}`
      .toLowerCase()
      .includes(query.toLowerCase()),
  );
  return (
    <section className="workbench-tool">
      <header>
        <p className="eyebrow">Registered inventory</p>
        <h3>Network assets</h3>
        <span>
          Search the devices already known to Aegis; this view does not initiate
          discovery.
        </span>
      </header>
      <div className="workbench-search">
        <input
          type="search"
          value={query}
          onChange={(event) => setQuery(event.target.value)}
          placeholder="Search name, IP, MAC, or type"
        />
        <strong>{visible.length} assets</strong>
      </div>
      <div className="workbench-table">
        <table>
          <thead>
            <tr>
              <th>Asset</th>
              <th>Status</th>
              <th>Identity</th>
              <th>Group</th>
            </tr>
          </thead>
          <tbody>
            {visible.map((device) => (
              <tr key={device.id} onClick={() => onSelectDevice(device.id)}>
                <td>
                  <strong>{device.name}</strong>
                  <small>{device.ip_address}</small>
                </td>
                <td>
                  <span
                    className={`service-status service-status--${device.current_status === "ONLINE" ? "up" : device.current_status === "OFFLINE" ? "down" : "unknown"}`}
                  >
                    {device.current_status}
                  </span>
                </td>
                <td>
                  {device.mac_address || "No MAC"}
                  <small>{device.device_type}</small>
                </td>
                <td>{device.device_group || "Ungrouped"}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </section>
  );
}

function SnifferTool({ captures, onOpenCapture }) {
  return (
    <section className="workbench-tool">
      <header>
        <p className="eyebrow">Metadata only</p>
        <h3>Packet observation</h3>
        <span>
          AEGIS stores addresses, protocol, ports, time, and size—not payloads
          or credentials.
        </span>
        <button className="button button--primary" onClick={onOpenCapture}>
          Open controlled capture
        </button>
      </header>
      {captures.length === 0 ? (
        <div className="empty-state">No captures recorded yet.</div>
      ) : (
        <div className="capture-cards">
          {captures.map((capture) => {
            const protocols = capture.packets.reduce(
              (counts, packet) => ({
                ...counts,
                [packet.protocol]: (counts[packet.protocol] || 0) + 1,
              }),
              {},
            );
            return (
              <article key={capture.id}>
                <div>
                  <strong>{capture.status}</strong>
                  <span>{formatDate(capture.started_at)}</span>
                </div>
                <b>{capture.packets.length}</b>
                <small>packets</small>
                <p>
                  {Object.entries(protocols)
                    .sort((left, right) => right[1] - left[1])
                    .map(([protocol, count]) => `${protocol} ${count}`)
                    .join(" · ") || "No traffic observed"}
                </p>
              </article>
            );
          })}
        </div>
      )}
    </section>
  );
}

function TracerouteTool({ devices }) {
  const [deviceId, setDeviceId] = useState(devices[0]?.id || "");
  const [result, setResult] = useState(null);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  async function run() {
    setBusy(true);
    setError("");
    try {
      setResult(await runSecurityTraceroute(Number(deviceId)));
    } catch (requestError) {
      setError(requestError.message);
    } finally {
      setBusy(false);
    }
  }
  return (
    <section className="workbench-tool">
      <header>
        <p className="eyebrow">Bounded path check</p>
        <h3>Traceroute</h3>
        <span>
          Targets are selected from registered AEGIS devices; maximum 12 hops
          and 20 seconds.
        </span>
      </header>
      <div className="trace-controls">
        <select
          value={deviceId}
          onChange={(event) => setDeviceId(event.target.value)}
        >
          {devices.map((device) => (
            <option key={device.id} value={device.id}>
              {device.name} · {device.ip_address}
            </option>
          ))}
        </select>
        <button
          className="button button--primary"
          onClick={run}
          disabled={!deviceId || busy}
        >
          {busy ? "Tracing…" : "Run traceroute"}
        </button>
      </div>
      {error && <div className="form-error">{error}</div>}
      {result && (
        <div className="trace-result">
          <div>
            <strong>{result.device_name}</strong>
            <span>
              {result.target} ·{" "}
              {result.completed ? "Destination completed" : "Partial route"}
            </span>
          </div>
          <ol>
            {result.hops.map((hop) => (
              <li key={hop.hop}>
                <b>{hop.hop}</b>
                <span>{hop.address || "No response"}</span>
                <strong>
                  {hop.latency_ms === null ? "—" : `${hop.latency_ms} ms`}
                </strong>
              </li>
            ))}
          </ol>
        </div>
      )}
    </section>
  );
}

function ConfigurationTool({ devices, attackPaths, onSelectDevice }) {
  const issues = devices.flatMap((device) => {
    const missing = [
      ["owner", "owner"],
      ["location", "location"],
      ["operating_system", "operating system"],
      ["device_group", "device group"],
    ]
      .filter(([field]) => !device[field])
      .map(([, label]) => label);
    return missing.length
      ? [{ device, message: `Missing ${missing.join(", ")}` }]
      : [];
  });
  return (
    <section className="workbench-tool">
      <header>
        <p className="eyebrow">Safe replacement for configuration extraction</p>
        <h3>Configuration and exposure audit</h3>
        <span>
          Reviews AEGIS records only. It does not download router configurations
          or reveal stored secrets.
        </span>
      </header>
      <div className="audit-summary">
        <article>
          <span>Incomplete asset records</span>
          <strong>{issues.length}</strong>
        </article>
        <article>
          <span>Candidate attack paths</span>
          <strong>{attackPaths?.candidate_paths || 0}</strong>
        </article>
        <article>
          <span>Unclassified devices</span>
          <strong>
            {devices.filter((device) => device.device_type === "Other").length}
          </strong>
        </article>
      </div>
      <div className="workbench-findings">
        {issues.slice(0, 50).map(({ device, message }) => (
          <button key={device.id} onClick={() => onSelectDevice(device.id)}>
            <span>REVIEW</span>
            <div>
              <strong>{device.name}</strong>
              <small>
                {device.ip_address} · {message}
              </small>
            </div>
          </button>
        ))}
        {issues.length === 0 && (
          <div className="empty-state">Core inventory fields are complete.</div>
        )}
      </div>
    </section>
  );
}

function WirelessTool({ adapters }) {
  return (
    <section className="workbench-tool">
      <header>
        <p className="eyebrow">Local host visibility</p>
        <h3>Wireless adapters</h3>
        <span>
          Shows AEGIS-host adapter state only. It does not reveal Wi-Fi keys,
          capture handshakes, or attack access points.
        </span>
      </header>
      {adapters.length === 0 ? (
        <div className="empty-state">
          No wireless adapter was identified on the AEGIS host.
        </div>
      ) : (
        <div className="wireless-grid">
          {adapters.map((adapter) => (
            <article
              key={adapter.name}
              className={adapter.active_for_discovery ? "active" : ""}
            >
              <div className="wireless-signal">
                <i />
                <i />
                <i />
                <i />
              </div>
              <span>
                {adapter.active_for_discovery
                  ? "DISCOVERY INTERFACE"
                  : adapter.status}
              </span>
              <strong>{adapter.name}</strong>
              <small>{adapter.addresses.join(" · ") || "No IP address"}</small>
              <b>
                {adapter.link_speed_mbps
                  ? `${adapter.link_speed_mbps} Mbps`
                  : "Speed unavailable"}
              </b>
            </article>
          ))}
        </div>
      )}
    </section>
  );
}

function HostNetworkPolicyTool() {
  const [result, setResult] = useState(null);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  async function examine() {
    setBusy(true);
    setError("");
    try {
      setResult(await getHostNetworkPolicy());
    } catch (requestError) {
      setResult(null);
      setError(requestError.message);
    } finally {
      setBusy(false);
    }
  }
  useEffect(() => {
    examine();
  }, []);
  const defaultRoutes =
    result?.routes.filter((route) => route.is_default) || [];
  const disabledProfiles =
    result?.firewall_profiles.filter((profile) => !profile.enabled) || [];
  return (
    <section className="workbench-tool">
      <header>
        <p className="eyebrow">Read-only host examination</p>
        <h3>Firewall and routing</h3>
        <span>
          Examines the AEGIS host using fixed operating-system queries. It does
          not modify rules, routes, interfaces, or forwarding.
        </span>
        <button
          className="button button--primary"
          onClick={examine}
          disabled={busy}
        >
          {busy ? "Examining…" : "Refresh"}
        </button>
      </header>
      {error && <div className="form-error">{error}</div>}
      {result && (
        <>
          <div className="audit-summary policy-summary">
            <article>
              <span>Firewall source</span>
              <strong>{result.firewall_source}</strong>
            </article>
            <article>
              <span>Enabled rules shown</span>
              <strong>{result.enabled_firewall_rule_count}</strong>
            </article>
            <article>
              <span>IPv4 routes</span>
              <strong>{result.routes.length}</strong>
            </article>
            <article>
              <span>Default routes</span>
              <strong>{defaultRoutes.length}</strong>
            </article>
          </div>
          {disabledProfiles.length > 0 && (
            <div className="policy-warning">
              Review recommended:{" "}
              {disabledProfiles.map((profile) => profile.name).join(", ")}{" "}
              firewall profile{disabledProfiles.length === 1 ? " is" : "s are"}{" "}
              disabled.
            </div>
          )}
          <div className="policy-section">
            <h4>Firewall profiles</h4>
            {result.firewall_profiles.length === 0 ? (
              <div className="empty-state empty-state--compact">
                Structured firewall profiles are unavailable on{" "}
                {result.platform}.
              </div>
            ) : (
              <div className="policy-profiles">
                {result.firewall_profiles.map((profile) => (
                  <article key={profile.name}>
                    <span
                      className={`service-status service-status--${profile.enabled ? "up" : "down"}`}
                    >
                      {profile.enabled ? "ENABLED" : "DISABLED"}
                    </span>
                    <strong>{profile.name}</strong>
                    <small>
                      Inbound: {profile.default_inbound_action} · Outbound:{" "}
                      {profile.default_outbound_action}
                    </small>
                  </article>
                ))}
              </div>
            )}
          </div>
          <div className="policy-section">
            <h4>Routing table</h4>
            <div className="workbench-table">
              <table>
                <thead>
                  <tr>
                    <th>Destination</th>
                    <th>Next hop</th>
                    <th>Interface</th>
                    <th>Metric</th>
                  </tr>
                </thead>
                <tbody>
                  {result.routes.map((route, index) => (
                    <tr
                      key={`${route.destination}/${route.prefix_length}-${route.interface}-${index}`}
                    >
                      <td>
                        <strong>
                          {route.destination}/{route.prefix_length}
                        </strong>
                        {route.is_default && <small>Default route</small>}
                      </td>
                      <td>{route.next_hop || "On-link"}</td>
                      <td>{route.interface}</td>
                      <td>{route.metric ?? "—"}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
          <div className="policy-section">
            <h4>Enabled firewall rules</h4>
            {result.firewall_rules.length === 0 ? (
              <div className="empty-state empty-state--compact">
                No structured firewall rules were returned.
              </div>
            ) : (
              <div className="workbench-table">
                <table>
                  <thead>
                    <tr>
                      <th>Rule</th>
                      <th>Direction</th>
                      <th>Action</th>
                      <th>Profile</th>
                    </tr>
                  </thead>
                  <tbody>
                    {result.firewall_rules.map((rule, index) => (
                      <tr key={`${rule.name}-${index}`}>
                        <td>
                          <strong>{rule.name}</strong>
                        </td>
                        <td>{rule.direction}</td>
                        <td>
                          <span
                            className={`service-status service-status--${rule.action.toLowerCase().includes("allow") ? "up" : "down"}`}
                          >
                            {rule.action}
                          </span>
                        </td>
                        <td>{rule.profile}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
          {result.notes.length > 0 && (
            <ul className="policy-notes">
              {result.notes.map((note) => (
                <li key={note}>{note}</li>
              ))}
            </ul>
          )}
        </>
      )}
    </section>
  );
}

function QueryTool() {
  const [query, setQuery] = useState("");
  const [result, setResult] = useState(null);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  async function run(event) {
    event.preventDefault();
    setBusy(true);
    setError("");
    try {
      setResult(await runDnsQuery(query));
    } catch (requestError) {
      setError(requestError.message);
      setResult(null);
    } finally {
      setBusy(false);
    }
  }
  return (
    <section className="workbench-tool">
      <header>
        <p className="eyebrow">Validated lookup</p>
        <h3>DNS query</h3>
        <span>
          Resolve one hostname or reverse-resolve one IP address without
          constructing shell commands.
        </span>
      </header>
      <form className="query-form" onSubmit={run}>
        <input
          value={query}
          onChange={(event) => setQuery(event.target.value)}
          placeholder="server.lab.example or 198.18.1.10"
        />
        <button
          className="button button--primary"
          disabled={!query.trim() || busy}
        >
          {busy ? "Resolving…" : "Resolve"}
        </button>
      </form>
      {error && <div className="form-error">{error}</div>}
      {result && (
        <div className="query-result">
          <dl>
            <div>
              <dt>Query</dt>
              <dd>{result.query}</dd>
            </div>
            <div>
              <dt>Canonical name</dt>
              <dd>{result.canonical_name || "—"}</dd>
            </div>
            <div>
              <dt>Reverse name</dt>
              <dd>{result.reverse_name || "—"}</dd>
            </div>
            <div>
              <dt>Addresses</dt>
              <dd>{result.addresses.join(" · ") || "No records found"}</dd>
            </div>
          </dl>
        </div>
      )}
    </section>
  );
}

function LabCliTool({ devices }) {
  const [tool, setTool] = useState("nmap");
  const [deviceId, setDeviceId] = useState(devices[0]?.id || "");
  const [ports, setPorts] = useState("22,80,443,445,3389");
  const [scanMode, setScanMode] = useState("TOP_1000");
  const [target, setTarget] = useState("");
  const [recordType, setRecordType] = useState("A");
  const [interfaceName, setInterfaceName] = useState("");
  const [grep, setGrep] = useState("");
  const [nmapProfile, setNmapProfile] = useState("FAST");
  const [showNmapReason, setShowNmapReason] = useState(false);
  const [insecure, setInsecure] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  async function run(event) {
    event.preventDefault();
    setBusy(true);
    setError("");
    setResult(null);
    const common = grep.trim() ? { grep: grep.trim() } : {};
    try {
      let response;
      if (tool === "nmap") {
        const parsedPorts = ports.split(",").map((value) => Number(value.trim())).filter(Number.isInteger);
        response = await runNmapScan({
          device_id: Number(deviceId),
          ports: scanMode === "CUSTOM" ? parsedPorts : [80],
          scan_mode: scanMode,
          profile: nmapProfile,
          show_reason: showNmapReason,
          ...common,
        });
      } else if (tool === "arp-scan") {
        response = await runArpScan({ interface_name: interfaceName.trim() || null, ...common });
      } else if (tool === "ip-neigh") {
        response = await getNeighborTable(common);
      } else if (tool === "avahi-browse") {
        response = await runAvahiBrowse(common);
      } else if (tool === "curl") {
        response = await runCurlRequest({ url: target.trim(), method: "GET", insecure, ...common });
      } else {
        response = await runDigQuery({ query: target.trim(), record_type: recordType, ...common });
      }
      setResult(response);
    } catch (requestError) {
      setError(requestError.message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <section className="workbench-tool lab-cli-tool">
      <header>
        <p className="eyebrow">Administrator learning lab</p>
        <h3>Network command tools</h3>
        <span>Nmap, ARP discovery, Avahi DNS-SD browsing, neighbor tables, curl and dig run as typed commands without a shell.</span>
      </header>
      <form className="lab-cli-form" onSubmit={run}>
        <label>Tool
          <select value={tool} onChange={(event) => { setTool(event.target.value); setResult(null); }}>
            <option value="nmap">Nmap TCP scan</option>
            <option value="arp-scan">arp-scan local network</option>
            <option value="avahi-browse">avahi-browse names and models</option>
            <option value="ip-neigh">ip neigh show</option>
            <option value="curl">curl HTTP GET</option>
            <option value="dig">dig DNS query</option>
          </select>
        </label>
        {tool === "nmap" && <>
          <label>Registered target
            <select value={deviceId} onChange={(event) => setDeviceId(event.target.value)} required>
              <option value="">Select a device</option>
              {devices.map((device) => <option key={device.id} value={device.id}>{device.name} · {device.ip_address}</option>)}
            </select>
          </label>
          <label>Scan scope
            <select value={scanMode} onChange={(event) => setScanMode(event.target.value)}>
              <option value="TOP_1000">Nmap top 1,000 TCP ports</option>
              <option value="CUSTOM">Custom TCP port list</option>
            </select>
          </label>
          {scanMode === "CUSTOM" && <label>TCP ports (comma separated)
            <input value={ports} onChange={(event) => setPorts(event.target.value)} placeholder="22,80,443,8080" required />
          </label>}
          <label>Nmap profile
            <select value={nmapProfile} onChange={(event) => setNmapProfile(event.target.value)}>
              <option value="FAST">Fast · ports only</option>
              <option value="FAST_VERSION">Fast version · -sV intensity 0</option>
              <option value="DETAILED">Detailed · -sV --version-light</option>
              <option value="AGGRESSIVE">Aggressive · -sV --version-all</option>
            </select>
          </label>
          <label className="checkbox-label">
            <input
              type="checkbox"
              checked={showNmapReason}
              onChange={(event) => setShowNmapReason(event.target.checked)}
            />
            With reason (--reason)
          </label>
        </>}
        {tool === "arp-scan" && <label>Interface (optional)
          <input value={interfaceName} onChange={(event) => setInterfaceName(event.target.value)} placeholder="eth0" />
        </label>}
        {(tool === "curl" || tool === "dig") && <label>{tool === "curl" ? "HTTP(S) URL" : "DNS name or address"}
          <input value={target} onChange={(event) => setTarget(event.target.value)} required />
        </label>}
        {tool === "curl" && <label className="checkbox-label"><input type="checkbox" checked={insecure} onChange={(event) => setInsecure(event.target.checked)} /> Allow an untrusted lab certificate</label>}
        {tool === "dig" && <label>Record type
          <select value={recordType} onChange={(event) => setRecordType(event.target.value)}>
            {["A", "AAAA", "CNAME", "MX", "NS", "PTR", "SOA", "TXT", "ANY"].map((value) => <option key={value}>{value}</option>)}
          </select>
        </label>}
        <label>Grep output (optional text)
          <input value={grep} onChange={(event) => setGrep(event.target.value)} placeholder="open, tcp, 192.168..." />
        </label>
        <button className="button button--primary" disabled={busy || (tool === "nmap" && !deviceId)}>{busy ? "Running…" : tool === "nmap" && scanMode === "TOP_1000" ? "Scan 1,000 ports" : "Run tool"}</button>
      </form>
      {error && <div className="form-error">{error}</div>}
      {result && <div className="lab-cli-result">
        <div><strong>{result.tool}</strong><span> exit {result.exit_code} · {result.duration_ms} ms{result.scanned_port_count ? ` · ${result.scanned_port_count} ports scanned` : ""}{result.truncated ? " · truncated" : ""}</span></div>
        <pre>{result.output || "Command completed without output."}</pre>
      </div>}
    </section>
  );
}

function TestConnectionPortTool({ devices }) {
  const [deviceId, setDeviceId] = useState(devices[0]?.id || "");
  const [ports, setPorts] = useState("22,80,443,445,3389");
  const [timeoutSeconds, setTimeoutSeconds] = useState(2);
  const [grep, setGrep] = useState("");
  const [result, setResult] = useState(null);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  async function run(event) {
    event.preventDefault();
    const parsedPorts = ports
      .split(",")
      .map((value) => Number(value.trim()))
      .filter(Number.isInteger);
    if (!parsedPorts.length) {
      setError("Enter at least one TCP port.");
      return;
    }
    setBusy(true);
    setError("");
    setResult(null);
    try {
      setResult(await runTestConnectionPorts({
        device_id: Number(deviceId),
        ports: parsedPorts,
        timeout_seconds: Number(timeoutSeconds),
        ...(grep.trim() ? { grep: grep.trim() } : {}),
      }));
    } catch (requestError) {
      setError(requestError.message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <section className="workbench-tool lab-cli-tool">
      <header>
        <p className="eyebrow">PowerShell connectivity</p>
        <h3>PowerShell TCP port scan</h3>
        <span>Test selected TCP ports concurrently. Completed means the scan finished; each result identifies open, refused, or unanswered ports.</span>
      </header>
      <form className="lab-cli-form" onSubmit={run}>
        <label>Registered target
          <select value={deviceId} onChange={(event) => setDeviceId(event.target.value)} required>
            <option value="">Select a device</option>
            {devices.map((device) => <option key={device.id} value={device.id}>{device.name} · {device.ip_address}</option>)}
          </select>
        </label>
        <label>TCP ports (comma separated)
          <input value={ports} onChange={(event) => setPorts(event.target.value)} placeholder="22,80,443,445,3389" required />
        </label>
        <label>Per-port timeout
          <select value={timeoutSeconds} onChange={(event) => setTimeoutSeconds(event.target.value)}>
            {[1, 2, 3, 5, 10].map((value) => <option key={value} value={value}>{value} seconds</option>)}
          </select>
        </label>
        <label>Filter output (optional)
          <input value={grep} onChange={(event) => setGrep(event.target.value)} placeholder="Open, Closed, NoResponse, 443..." />
        </label>
        <button className="button button--primary" disabled={busy || !deviceId}>
          {busy ? "Testing ports…" : "Run TCP test"}
        </button>
      </form>
      {error && <div className="form-error">{error}</div>}
      {result && <div className="lab-cli-result">
        <div><strong>{result.tool}</strong><span> exit {result.exit_code} · {result.duration_ms} ms · {result.scanned_port_count} ports tested{result.truncated ? " · truncated" : ""}</span></div>
        <pre>{result.output || "Port test completed without output."}</pre>
      </div>}
    </section>
  );
}

function PlaybookStep({ step }) {
  const hasOutput = Boolean(step.output?.trim());
  let timing = "Waiting to run";
  if (step.duration_ms !== null && step.duration_ms !== undefined) {
    timing = `${Math.round(step.duration_ms)} ms`;
  } else if (step.status === "CANCELLED") {
    timing = "Not run";
  } else if (step.started_at) {
    timing = `Started ${formatDate(step.started_at)}`;
  }

  return (
    <article className="diagnostic-job playbook-step">
      <div className="diagnostic-job__heading">
        <div>
          <strong>{step.position}. {step.name}</strong>
          <small>{timing}</small>
        </div>
        <span className={`diagnostic-status diagnostic-status--${step.status.toLowerCase()}`}>
          {playbookStatusLabel(step.status)}
        </span>
      </div>
      {step.error && <div className="diagnostic-error">{step.error}</div>}
      {hasOutput && (
        <details className="diagnostic-result">
          <summary>View step output</summary>
          <div className="lab-cli-result playbook-step__output">
            <pre>{step.output}</pre>
          </div>
        </details>
      )}
    </article>
  );
}

function PlaybookRunLink({ run, selected, onSelect, busy = false, opening = false }) {
  return (
    <button
      type="button"
      className={selected ? "active" : ""}
      aria-pressed={selected}
      aria-busy={opening}
      disabled={busy}
      onClick={() => onSelect(run)}
    >
      <span>
        <strong>{run.target_name}</strong>
        <small>#{run.id} · {run.profile} · {run.target_ip}</small>
      </span>
      <span>
        <span className={`diagnostic-status diagnostic-status--${run.status.toLowerCase()}`}>
          {playbookStatusLabel(run.status)}
        </span>
        <small>{opening ? "Opening…" : formatDate(run.created_at)}</small>
      </span>
    </button>
  );
}

function PlaybookTool({ devices }) {
  const [deviceId, setDeviceId] = useState(devices[0]?.id ? String(devices[0].id) : "");
  const [profile, setProfile] = useState("FAST");
  const [runs, setRuns] = useState([]);
  const [allRuns, setAllRuns] = useState([]);
  const [selectedRunId, setSelectedRunId] = useState(null);
  const [loadingHistory, setLoadingHistory] = useState(false);
  const [loadingAllRuns, setLoadingAllRuns] = useState(true);
  const [openingRunId, setOpeningRunId] = useState(null);
  const [action, setAction] = useState("");
  const [error, setError] = useState("");
  const [pollError, setPollError] = useState("");
  const pendingRunRef = useRef(null);
  const runPanelRef = useRef(null);

  useEffect(() => {
    if (!devices.length) {
      setDeviceId("");
      return;
    }
    if (!devices.some((device) => String(device.id) === String(deviceId))) {
      setDeviceId(String(devices[0].id));
    }
  }, [deviceId, devices]);

  useEffect(() => {
    let disposed = false;
    setLoadingAllRuns(true);
    listSecurityPlaybookRunIndex(50)
      .then((response) => {
        if (!disposed) {
          const recentRuns = Array.isArray(response) ? response : [];
          setAllRuns((current) => mergeGlobalPlaybookRuns(current, recentRuns));
        }
      })
      .catch((requestError) => {
        if (!disposed) setError(requestError.message);
      })
      .finally(() => {
        if (!disposed) setLoadingAllRuns(false);
      });
    return () => {
      disposed = true;
    };
  }, []);

  useEffect(() => {
    if (!deviceId) {
      setRuns([]);
      setSelectedRunId(null);
      return undefined;
    }

    let disposed = false;
    const pendingRun = pendingRunRef.current?.device_id === Number(deviceId)
      ? pendingRunRef.current
      : null;
    setRuns(pendingRun ? [pendingRun] : []);
    setSelectedRunId(pendingRun?.id ?? null);
    setPollError("");
    setLoadingHistory(true);
    setError("");
    listSecurityPlaybookRuns(Number(deviceId), 10)
      .then((response) => {
        if (disposed) return;
        const recentRuns = Array.isArray(response) ? response : [];
        const selectedRuns = pendingRun && !recentRuns.some((run) => run.id === pendingRun.id)
          ? [pendingRun, ...recentRuns].slice(0, 10)
          : recentRuns;
        setRuns(selectedRuns);
        setAllRuns((current) => mergeGlobalPlaybookRuns(current, recentRuns));
        setSelectedRunId(pendingRun?.id ?? recentRuns[0]?.id ?? null);
      })
      .catch((requestError) => {
        if (!disposed) setError(requestError.message);
      })
      .finally(() => {
        if (!disposed) {
          if (pendingRunRef.current?.id === pendingRun?.id) pendingRunRef.current = null;
          setLoadingHistory(false);
        }
      });
    return () => {
      disposed = true;
    };
  }, [deviceId]);

  const selectedRun = useMemo(
    () => runs.find((run) => run.id === selectedRunId) || null,
    [runs, selectedRunId],
  );
  const activeRunKey = useMemo(
    () => allRuns
      .filter((run) => ACTIVE_PLAYBOOK_STATUSES.has(run.status))
      .map((run) => run.id)
      .sort((left, right) => left - right)
      .join(","),
    [allRuns],
  );

  useEffect(() => {
    if (!activeRunKey) return undefined;
    const runIds = activeRunKey.split(",").map(Number);
    const polledDeviceId = Number(deviceId);
    let disposed = false;
    let timerId;

    async function poll() {
      const updates = await Promise.allSettled(
        runIds.map((runId) => getSecurityPlaybookRun(runId)),
      );
      if (disposed) return;

      const refreshedRuns = updates
        .filter((result) => result.status === "fulfilled")
        .map((result) => result.value);
      if (refreshedRuns.length) {
        setAllRuns((current) => mergeGlobalPlaybookRuns(current, refreshedRuns));
        setRuns((current) => refreshedRuns
          .filter((run) => run.device_id === polledDeviceId)
          .reduce(upsertPlaybookRun, current));
      }
      const failed = updates.find((result) => result.status === "rejected");
      const failureMessage = failed
        ? failed.reason instanceof Error
          ? failed.reason.message
          : String(failed.reason)
        : "";
      setPollError(failed ? `Progress refresh failed: ${failureMessage}` : "");
      timerId = window.setTimeout(poll, 2500);
    }

    void poll();
    return () => {
      disposed = true;
      window.clearTimeout(timerId);
    };
  }, [activeRunKey, deviceId]);

  async function createRun(event) {
    event.preventDefault();
    if (!deviceId) return;
    setAction("create");
    setError("");
    setPollError("");
    try {
      const created = await createSecurityPlaybookRun({
        device_id: Number(deviceId),
        profile,
      });
      setRuns((current) => upsertPlaybookRun(current, created));
      setAllRuns((current) => mergeGlobalPlaybookRuns(current, [created]));
      setSelectedRunId(created.id);
    } catch (requestError) {
      setError(requestError.message);
    } finally {
      setAction("");
    }
  }

  async function cancelRun(runId) {
    setAction(`cancel-${runId}`);
    setError("");
    try {
      const cancelled = await cancelSecurityPlaybookRun(runId);
      setRuns((current) => upsertPlaybookRun(current, cancelled));
      setAllRuns((current) => mergeGlobalPlaybookRuns(current, [cancelled]));
    } catch (requestError) {
      setError(requestError.message);
    } finally {
      setAction("");
    }
  }

  async function openRun(run) {
    if (!devices.some((device) => device.id === run.device_id)) {
      setError("The device for this assessment is no longer registered.");
      return;
    }
    setOpeningRunId(run.id);
    setError("");
    try {
      const detailedRun = Array.isArray(run.steps) ? run : await getSecurityPlaybookRun(run.id);
      const switchingDevice = String(detailedRun.device_id) !== deviceId;
      pendingRunRef.current = switchingDevice ? detailedRun : null;
      setDeviceId(String(detailedRun.device_id));
      setProfile(detailedRun.profile);
      setRuns((current) => upsertPlaybookRun(current, detailedRun));
      setAllRuns((current) => mergeGlobalPlaybookRuns(current, [detailedRun]));
      setSelectedRunId(detailedRun.id);
      window.requestAnimationFrame(() => {
        runPanelRef.current?.focus({ preventScroll: true });
        runPanelRef.current?.scrollIntoView({ behavior: "smooth", block: "start" });
      });
    } catch (requestError) {
      setError(requestError.message);
    } finally {
      setOpeningRunId(null);
    }
  }

  const steps = selectedRun?.steps || [];
  const finishedSteps = steps.filter((step) => FINISHED_STEP_STATUSES.has(step.status)).length;
  const progress = steps.length ? Math.round((finishedSteps / steps.length) * 100) : 0;
  const selectedProfile = PLAYBOOK_PROFILES.find(([value]) => value === profile);
  const runHeading = playbookRunHeading(selectedRun, steps);
  const summary = selectedRun?.summary || {};
  const hasSummary = Object.keys(summary).length > 0;
  const activeRuns = allRuns.filter((run) => ACTIVE_PLAYBOOK_STATUSES.has(run.status));
  const finishedRuns = allRuns.filter((run) => !ACTIVE_PLAYBOOK_STATUSES.has(run.status));
  const targetHasActiveRun = activeRuns.some((run) => run.device_id === Number(deviceId))
    || runs.some((run) => (
      run.device_id === Number(deviceId) && ACTIVE_PLAYBOOK_STATUSES.has(run.status)
    ));

  return (
    <section className="workbench-tool playbook-tool">
      <header>
        <p className="eyebrow">Automated assessment</p>
        <h3>Host assessment playbooks</h3>
        <span>Run a bounded sequence of PowerShell and Linux network checks against one registered target.</span>
      </header>
      <form className="lab-cli-form playbook-form" onSubmit={createRun}>
        <label>Registered target
          <select
            value={deviceId}
            onChange={(event) => {
              pendingRunRef.current = null;
              setDeviceId(event.target.value);
            }}
            disabled={Boolean(action) || openingRunId !== null}
            required
          >
            <option value="">Select a device</option>
            {devices.map((device) => (
              <option key={device.id} value={device.id}>{device.name} · {device.ip_address}</option>
            ))}
          </select>
        </label>
        <label>Playbook
          <select value="HOST_ASSESSMENT" disabled aria-label="Playbook">
            <option value="HOST_ASSESSMENT">Full host assessment</option>
          </select>
        </label>
        <label>Assessment profile
          <select
            value={profile}
            onChange={(event) => setProfile(event.target.value)}
            disabled={Boolean(action) || openingRunId !== null}
          >
            {PLAYBOOK_PROFILES.map(([value, label]) => (
              <option key={value} value={value}>{label}</option>
            ))}
          </select>
        </label>
        <button
          className="button button--primary"
          disabled={!deviceId || loadingHistory || Boolean(action) || openingRunId !== null || targetHasActiveRun}
        >
          {action === "create"
            ? "Starting…"
            : loadingHistory
              ? "Loading runs…"
              : targetHasActiveRun
                ? "Assessment active"
                : "Run assessment"}
        </button>
      </form>
      <div className="playbook-profile-description">
        <span>{selectedProfile?.[2]}</span>
        <small>Cancellation is cooperative and takes effect after the currently running command finishes.</small>
      </div>
      {error && <div className="form-error playbook-error" role="alert">{error}</div>}
      {pollError && <div className="form-error playbook-error" role="status">{pollError}</div>}

      <nav className="playbook-run-navigator" aria-label="Assessment run switcher">
        <div className="playbook-run-navigator__heading">
          <div>
            <strong>Assessment runs</strong>
            <span>Choose from the 50 most recent runs to switch targets and open the results.</span>
          </div>
          {loadingAllRuns && <span role="status">Loading…</span>}
        </div>
        <div className="playbook-run-navigator__groups">
          <section aria-labelledby="active-playbook-runs-heading">
            <header>
              <strong id="active-playbook-runs-heading">Queued &amp; running</strong>
              <span>{activeRuns.length}</span>
            </header>
            <div className="playbook-run-navigator__list">
              {activeRuns.map((run) => (
                <PlaybookRunLink
                  key={run.id}
                  run={run}
                  selected={run.id === selectedRunId}
                  onSelect={openRun}
                  busy={openingRunId !== null}
                  opening={run.id === openingRunId}
                />
              ))}
              {!loadingAllRuns && !activeRuns.length && <p>No active assessments.</p>}
            </div>
          </section>
          <section aria-labelledby="finished-playbook-runs-heading">
            <header>
              <strong id="finished-playbook-runs-heading">Recent finished runs</strong>
              <span>{finishedRuns.length}</span>
            </header>
            <div className="playbook-run-navigator__list">
              {finishedRuns.map((run) => (
                <PlaybookRunLink
                  key={run.id}
                  run={run}
                  selected={run.id === selectedRunId}
                  onSelect={openRun}
                  busy={openingRunId !== null}
                  opening={run.id === openingRunId}
                />
              ))}
              {!loadingAllRuns && !finishedRuns.length && <p>No finished assessments.</p>}
            </div>
          </section>
        </div>
      </nav>

      <div className="playbook-layout">
        <aside className="playbook-history" aria-label="Recent playbook runs">
          <div className="playbook-history__heading">
            <strong>Recent runs</strong>
            {loadingHistory && <span role="status">Loading…</span>}
          </div>
          {!loadingHistory && !runs.length && (
            <div className="empty-state empty-state--compact">No assessments for this target yet.</div>
          )}
          {runs.map((run) => (
            <button
              type="button"
              key={run.id}
              className={run.id === selectedRunId ? "active" : ""}
              aria-pressed={run.id === selectedRunId}
              disabled={openingRunId !== null}
              onClick={() => openRun(run)}
            >
              <span>
                <strong>{run.profile.charAt(0) + run.profile.slice(1).toLowerCase()}</strong>
                <small>{formatDate(run.created_at)}</small>
              </span>
              <span className={`diagnostic-status diagnostic-status--${run.status.toLowerCase()}`}>
                {playbookStatusLabel(run.status)}
              </span>
            </button>
          ))}
        </aside>

        <section
          ref={runPanelRef}
          className="playbook-run"
          tabIndex="-1"
          aria-labelledby={selectedRun ? `playbook-run-${selectedRun.id}-title` : undefined}
          aria-busy={ACTIVE_PLAYBOOK_STATUSES.has(selectedRun?.status)}
        >
          {!selectedRun ? (
            <div className="empty-state">Select a target and start an assessment to see its steps.</div>
          ) : (
            <>
              <div className="playbook-run__heading">
                <div>
                  <span>RUN #{selectedRun.id} · {selectedRun.profile} · {selectedRun.target_ip}</span>
                  <h4 id={`playbook-run-${selectedRun.id}-title`}>{runHeading}</h4>
                  <small>
                    Requested by {selectedRun.requested_by} · {formatDate(selectedRun.started_at || selectedRun.created_at)}
                  </small>
                </div>
                <div className="row-actions">
                  <span
                    className={`diagnostic-status diagnostic-status--${selectedRun.status.toLowerCase()}`}
                    role="status"
                    aria-live="polite"
                  >
                    {playbookStatusLabel(selectedRun.status)}
                  </span>
                  {ACTIVE_PLAYBOOK_STATUSES.has(selectedRun.status) && (
                    <button
                      type="button"
                      className="button button--secondary"
                      onClick={() => cancelRun(selectedRun.id)}
                      disabled={selectedRun.cancel_requested || Boolean(action)}
                    >
                      {action === `cancel-${selectedRun.id}` || selectedRun.cancel_requested
                        ? "Cancelling…"
                        : "Cancel"}
                    </button>
                  )}
                </div>
              </div>
              <div
                className="setup-guide__progress playbook-progress"
                role="progressbar"
                aria-label="Playbook progress"
                aria-valuemin="0"
                aria-valuemax="100"
                aria-valuenow={progress}
              >
                <strong>{finishedSteps} of {steps.length} steps</strong>
                <span><i style={{ width: `${progress}%` }} /></span>
              </div>
              {hasSummary && (
                <div className="audit-summary playbook-summary" aria-label="Assessment summary">
                  <article><span>Completed steps</span><strong>{summary.completed_steps ?? 0}</strong></article>
                  <article><span>Failed steps</span><strong>{summary.failed_steps ?? 0}</strong></article>
                  <article><span>Findings</span><strong>{summary.findings ?? 0}</strong></article>
                  <article><span>CVE candidates</span><strong>{summary.cve_candidates ?? 0}</strong></article>
                </div>
              )}
              {selectedRun.error && <div className="diagnostic-error">{selectedRun.error}</div>}
              <div className="diagnostic-jobs playbook-steps">
                {steps.map((step) => <PlaybookStep key={step.id} step={step} />)}
              </div>
            </>
          )}
        </section>
      </div>
    </section>
  );
}

function Overview({ devices, captures, attackPaths, adapters, onChangeTab }) {
  const cards = [
    [
      "playbooks",
      "Assessment playbooks",
      "AUTOMATED",
      "Run a multi-step host assessment",
    ],
    [
      "network",
      "Registered assets",
      devices.length,
      "Review known hosts and identities",
    ],
    [
      "sniffer",
      "Packet captures",
      captures.length,
      "Inspect bounded traffic metadata",
    ],
    [
      "configuration",
      "Candidate paths",
      attackPaths?.candidate_paths || 0,
      "Prioritize stored exposure evidence",
    ],
    [
      "wireless",
      "Wireless adapters",
      adapters.length,
      "Inspect local adapter health",
    ],
    ["decoder", "Decoder & numbers", "LOCAL", "Decode text and convert integer bases"],
    [
      "credentials",
      "Credential hygiene",
      "LOCAL",
      "Estimate password-example strength",
    ],
    ["traceroute", "Traceroute", "12 HOPS", "Trace registered devices only"],
    ["query", "DNS query", "SAFE", "Validated forward and reverse lookup"],
    ["lab-cli", "Network CLI", "ADMIN", "Nmap, arp-scan, Avahi, neighbors, curl and dig"],
    ["test-connection", "TCP port test", "POWERSHELL", "Test selected ports on a registered host"],
    [
      "policy",
      "Firewall & routing",
      "READ ONLY",
      "Review local host policy and routes",
    ],
  ];
  return (
    <section className="workbench-overview">
      <div className="workbench-hero">
        <p className="eyebrow">Defensive investigation console</p>
        <h2>Understand the network without collecting secrets.</h2>
        <p>
          Every active tool is bounded, authenticated, and auditable. Local
          utilities keep their input in your browser.
        </p>
      </div>
      <div className="workbench-cards">
        {cards.map(([tab, title, value, description]) => (
          <button key={tab} onClick={() => onChangeTab(tab)}>
            <span>{title}</span>
            <strong>{value}</strong>
            <small>{description}</small>
            <b>Open →</b>
          </button>
        ))}
      </div>
    </section>
  );
}

export default function SecurityWorkbenchModal({
  devices,
  visualTheme,
  onClose,
  onOpenCapture,
  onSelectDevice,
  initialTab = "overview",
  onTabChange,
}) {
  const [tab, setTab] = useState(initialTab);
  const [captures, setCaptures] = useState([]);
  const [attackPaths, setAttackPaths] = useState(null);
  const [adapters, setAdapters] = useState([]);
  const [error, setError] = useState("");
  useEffect(() => {
    Promise.all([listPacketCaptures(), getAttackPaths(), getWirelessAdapters()])
      .then(([captureData, pathData, adapterData]) => {
        setCaptures(captureData);
        setAttackPaths(pathData);
        setAdapters(adapterData);
      })
      .catch((requestError) => setError(requestError.message));
  }, []);
  const selectedLabel = useMemo(
    () => TOOLS.find(([value]) => value === tab)?.[1],
    [tab],
  );
  function changeTab(nextTab) {
    setTab(nextTab);
    onTabChange?.(nextTab);
  }
  function selectDevice(deviceId) {
    onClose();
    onSelectDevice(deviceId);
  }
  function openCapture() {
    onClose();
    onOpenCapture();
  }
  return (
    <div className="modal-backdrop">
      <section
        className="modal security-workbench"
        role="dialog"
        aria-modal="true"
        aria-labelledby="workbench-title"
      >
        <aside>
          <div className="workbench-brand">
            <span>
              <img
                src={visualTheme === "goth" ? aegisShieldDark : aegisShield}
                alt=""
              />
            </span>
            <div>
              <strong id="workbench-title">Security workbench</strong>
              <small>Defensive toolkit</small>
            </div>
          </div>
          <nav aria-label="Security tools">
            {TOOLS.map(([value, label, index]) => (
              <button
                key={value}
                className={tab === value ? "active" : ""}
                onClick={() => changeTab(value)}
              >
                <span>{index}</span>
                {label}
              </button>
            ))}
          </nav>
          <div className="workbench-boundary">
            <strong>Safety boundary</strong>
            <small>
              No cracking, credential capture, MITM, Wi-Fi key recovery, or
              arbitrary command execution.
            </small>
          </div>
        </aside>
        <main>
          <header className="workbench-heading">
            <div>
              <span>ADMIN / {selectedLabel?.toUpperCase()}</span>
              <strong>Aegis</strong>
            </div>
            <button
              className="icon-button"
              onClick={onClose}
              aria-label="Close"
            >
              ×
            </button>
          </header>
          {error && (
            <div className="form-error workbench-error">
              Some live evidence could not be loaded: {error}
            </div>
          )}
          {tab === "overview" && (
            <Overview
              devices={devices}
              captures={captures}
              attackPaths={attackPaths}
              adapters={adapters}
              onChangeTab={changeTab}
            />
          )}
          {tab === "playbooks" && <PlaybookTool devices={devices} />}
          {tab === "decoder" && <DecoderTool />}
          {tab === "network" && (
            <NetworkTool devices={devices} onSelectDevice={selectDevice} />
          )}
          {tab === "sniffer" && (
            <SnifferTool captures={captures} onOpenCapture={openCapture} />
          )}
          {tab === "credentials" && <CredentialTool />}
          {tab === "traceroute" && <TracerouteTool devices={devices} />}
          {tab === "configuration" && (
            <ConfigurationTool
              devices={devices}
              attackPaths={attackPaths}
              onSelectDevice={selectDevice}
            />
          )}
          {tab === "wireless" && <WirelessTool adapters={adapters} />}
          {tab === "query" && <QueryTool />}
          {tab === "policy" && <HostNetworkPolicyTool />}
          {tab === "lab-cli" && <LabCliTool devices={devices} />}
          {tab === "test-connection" && <TestConnectionPortTool devices={devices} />}
        </main>
      </section>
    </div>
  );
}
