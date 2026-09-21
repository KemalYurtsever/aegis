import { useEffect, useMemo, useRef, useState } from "react";
import WiresharkPanel from "./WiresharkPanel.jsx";
import MacManagementPanel from "./MacManagementPanel.jsx";

import {
  cancelCveMirrorSync,
  cancelNmapScanJob,
  cancelSecurityPlaybookRun,
  createNmapScanJob,
  createSecurityPlaybookRun,
  getAttackPaths,
  getCveMirrorStatus,
  getHostNetworkPolicy,
  getNeighborTable,
  getNmapScanJob,
  getSecurityPlaybookRun,
  getWirelessAdapters,
  listSecurityPlaybookRunIndex,
  listSecurityPlaybookRuns,
  listPacketCaptures,
  listNmapScanJobs,
  runAvahiBrowse,
  runDnsQuery,
  runArpScan,
  runCurlRequest,
  runDigQuery,
  runDnsRecon,
  runFpingProbe,
  runHostQuery,
  runNiktoScan,
  runOpenSslProbe,
  runSmbClientScan,
  runSmbPostureScan,
  runTlsScan,
  runWhatWebScan,
  runNmapUdpScan,
  runTestConnectionPorts,
  runSecurityTraceroute,
  startCveMirrorSync,
} from "./api.js";
import { formatDate } from "./format.js";
import aegisShield from "./assets/aegis-shield.webp";
import aegisShieldDark from "./assets/aegis-shield-dark.webp";

const TOOLS = [
  ["overview", "Overview", "HOME"],
  ["playbooks", "Assessment", "RUN"],
  ["cve-mirror", "CVE mirror", "DATA"],
  ["network", "Registered assets", "HOST"],
  ["sniffer", "Wireshark", "PKT"],
  ["configuration", "Exposure review", "RISK"],
  ["wireless", "Wireless status", "WLAN"],
  ["policy", "Firewall & routing", "HOST"],
  ["mac", "MAC management", "MAC"],
  ["query", "DNS query", "DNS"],
  ["decoder", "Decoder & numbers", "LOCAL"],
  ["credentials", "Credential hygiene", "LOCAL"],
];
const TOOL_GROUPS = [
  ["Start here", ["overview", "playbooks", "cve-mirror"]],
  ["Review evidence", ["network", "sniffer", "configuration", "wireless", "policy"]],
  ["Local utilities", ["mac", "query", "decoder", "credentials"]],
];
const LEGACY_ASSESSMENT_TABS = new Set(["lab-cli", "traceroute", "test-connection"]);

function normalizeWorkbenchTab(value) {
  if (LEGACY_ASSESSMENT_TABS.has(value)) return "playbooks";
  return TOOLS.some(([tool]) => tool === value) ? value : "overview";
}

const PLAYBOOK_PROFILES = [
  ["FAST", "Fast", "Tests 8 common TCP ports, discovers Nmap's top 1,000 ports, then uses lightweight service detection."],
  ["DETAILED", "Detailed", "Tests 24 common TCP ports, discovers the top 1,000, then runs -sV --version-light on open ports."],
  ["AGGRESSIVE", "Aggressive", "Tests 64 common TCP ports, discovers the top 1,000, then runs -sV --version-all on open ports."],
];
const ACTIVE_PLAYBOOK_STATUSES = new Set(["QUEUED", "RUNNING"]);
const ACTIVE_NMAP_JOB_STATUSES = new Set(["QUEUED", "RUNNING"]);
const FINISHED_STEP_STATUSES = new Set(["COMPLETED", "FAILED", "CANCELLED"]);
const DEFAULT_TCP_PORTS = "22,80,443,445,3389";
const QUICK_NMAP_TCP_PORTS = "80,23,443,21,22,25,3389,110,445,139,143,53,135,3306,8080,1723,111,995,993,5900,1025,587,8888,199";
const DEFAULT_UDP_PORTS = [
  53, 67, 69, 123, 137, 161, 500, 514, 520, 623,
  1434, 1900, 4500, 5060, 5353, 5683, 10001, 11211, 20000, 47808,
].join(",");
const REGISTERED_CLI_TOOLS = new Set([
  "nmap", "nmap-udp", "sslscan", "openssl", "fping", "whatweb", "nikto", "smbclient", "smb-audit",
]);
const INVESTIGATION_COVERAGE = [
  ["Host discovery", "Built in", "Discovery, arp-scan, fping", "Netdiscover is packaged for approved toolbox use; Aegis discovery remains limited to the confirmed local /24."],
  ["Port and service mapping", "Built in", "Nmap, PowerShell TCP", "RustScan is intentionally not duplicated; Nmap top-1,000 and bounded custom scans use the same inventory controls."],
  ["mDNS / Bonjour", "Built in", "Avahi and native mDNS", "Equivalent to dns-sd for the services Aegis records."],
  ["Packet analysis", "Docker GUI", "Wireshark", "Full protocol analysis shares the toolbox network namespace. Windows-interface traffic needs an imported PCAP; old metadata records are preserved."],
  ["Web services", "Available", "curl, WhatWeb, Nikto", "WhatWeb uses its light profile; Nikto has a 45-second target budget."],
  ["TLS", "Available", "sslscan, OpenSSL", "Heartbleed probing is disabled and application data is not sent."],
  ["Windows / SMB", "Available", "smbclient, Nmap SMB posture", "Anonymous sessions only. Credentials, NetExec, and user enumeration are not accepted."],
  ["SNMP", "Built in", "Typed SNMP poller", "Community data stays in server environment variables rather than command input."],
  ["DNS", "Available", "dig, host, DNSRecon standard", "Brute-force, cache snooping, and reverse-range modes are unavailable."],
  ["Vulnerability assessment", "Built in", "Nmap, Nuclei, NVD, KEV, EPSS", "OpenVAS and Nessus require separately operated scanners and are not embedded."],
  ["Passive monitoring", "Integration boundary", "Prometheus and controlled capture", "Continuous Zeek or Suricata monitoring requires a dedicated sensor and retention pipeline."],
  ["Local host audit", "Integration boundary", "Agent telemetry", "Lynis and osquery need a host-agent execution and result model; running them inside the toolbox would only audit the container."],
];

function parsePortList(value, label, maximum) {
  const tokens = value.split(",").map((token) => token.trim()).filter(Boolean);
  if (!tokens.length) throw new Error(`Enter at least one ${label} port.`);
  if (tokens.some((token) => !/^\d+$/.test(token))) {
    throw new Error(`${label} ports must be comma-separated numbers.`);
  }
  const ports = [...new Set(tokens.map(Number))];
  if (ports.some((port) => port < 1 || port > 65535)) {
    throw new Error(`${label} ports must be between 1 and 65535.`);
  }
  if (ports.length > maximum) {
    throw new Error(`${label} scanning accepts at most ${maximum} ports.`);
  }
  return ports;
}

function upsertPlaybookRun(current, next) {
  const existingIndex = current.findIndex((run) => run.id === next.id);
  if (existingIndex < 0) return [next, ...current].slice(0, 10);
  return current.map((run, index) => (
    index === existingIndex
      ? { ...run, ...next, steps: next.steps ?? run.steps }
      : run
  ));
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

function SnifferTool({ captures, devices }) {
  return (
    <section className="workbench-tool">
      <header>
        <p className="eyebrow">Packet analysis</p>
        <h3>Wireshark workspace</h3>
      </header>
      <WiresharkPanel devices={devices} />
      {captures.length === 0 ? (
        <div className="empty-state">No legacy metadata records. Wireshark captures are saved in its dedicated Docker volume.</div>
      ) : (
        <details className="playbook-evidence__raw"><summary>Legacy metadata captures · {captures.length} records</summary><div className="capture-cards">
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
        </div></details>
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
  const [ports, setPorts] = useState(QUICK_NMAP_TCP_PORTS);
  const [scanMode, setScanMode] = useState("QUICK");
  const [target, setTarget] = useState("");
  const [recordType, setRecordType] = useState("A");
  const [tlsPort, setTlsPort] = useState(443);
  const [webScheme, setWebScheme] = useState("http");
  const [webPort, setWebPort] = useState(80);
  const [webPath, setWebPath] = useState("/");
  const [interfaceName, setInterfaceName] = useState("");
  const [grep, setGrep] = useState("");
  const [nmapProfile, setNmapProfile] = useState("FAST");
  const [nmapTrafficPolicy, setNmapTrafficPolicy] = useState("IDS_FRIENDLY");
  const [showNmapReason, setShowNmapReason] = useState(false);
  const [udpPorts, setUdpPorts] = useState(DEFAULT_UDP_PORTS);
  const [udpProfile, setUdpProfile] = useState("FAST");
  const [showUdpReason, setShowUdpReason] = useState(true);
  const [insecure, setInsecure] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const [elapsedSeconds, setElapsedSeconds] = useState(0);
  const [nmapJob, setNmapJob] = useState(null);
  const [nmapHistory, setNmapHistory] = useState([]);

  useEffect(() => {
    if (!deviceId) {
      setNmapHistory([]);
      return undefined;
    }
    let disposed = false;
    listNmapScanJobs(Number(deviceId), 5)
      .then((jobs) => {
        if (disposed) return;
        setNmapHistory(jobs);
        const active = jobs.find((job) => ACTIVE_NMAP_JOB_STATUSES.has(job.status));
        if (active) setNmapJob(active);
      })
      .catch(() => {
        if (!disposed) setNmapHistory([]);
      });
    return () => { disposed = true; };
  }, [deviceId]);

  useEffect(() => {
    if (!nmapJob || !ACTIVE_NMAP_JOB_STATUSES.has(nmapJob.status)) return undefined;
    let disposed = false;
    let polling = false;
    const refresh = async () => {
      if (polling) return;
      polling = true;
      try {
        const updated = await getNmapScanJob(nmapJob.id);
        if (!disposed) {
          setNmapJob(updated);
          setNmapHistory((current) => [updated, ...current.filter((item) => item.id !== updated.id)].slice(0, 5));
        }
      } catch (pollError) {
        if (!disposed) setError(pollError.message);
      } finally {
        polling = false;
      }
    };
    const timer = window.setInterval(refresh, 1000);
    refresh();
    return () => {
      disposed = true;
      window.clearInterval(timer);
    };
  }, [nmapJob?.id, nmapJob?.status]);

  useEffect(() => {
    if (!busy) return undefined;
    const started = performance.now();
    setElapsedSeconds(0);
    const timer = window.setInterval(() => {
      setElapsedSeconds(Math.floor((performance.now() - started) / 1000));
    }, 250);
    return () => window.clearInterval(timer);
  }, [busy]);

  async function run(event) {
    event.preventDefault();
    setBusy(true);
    setError("");
    setResult(null);
    const common = grep.trim() ? { grep: grep.trim() } : {};
    try {
      let response;
      if (tool === "nmap") {
        const nmapPorts = scanMode === "TOP_1000"
          ? [80]
          : parsePortList(scanMode === "QUICK" ? QUICK_NMAP_TCP_PORTS : ports, "TCP", 1000);
        response = await createNmapScanJob({
          device_id: Number(deviceId),
          ports: nmapPorts,
          scan_mode: scanMode === "TOP_1000" ? "TOP_1000" : "CUSTOM",
          profile: nmapProfile,
          traffic_policy: nmapTrafficPolicy,
          show_reason: showNmapReason,
          ...common,
        });
        setNmapJob(response);
        setNmapHistory((current) => [response, ...current.filter((item) => item.id !== response.id)].slice(0, 5));
        return;
      } else if (tool === "nmap-udp") {
        response = await runNmapUdpScan({
          device_id: Number(deviceId),
          ports: parsePortList(udpPorts, "UDP", 64),
          profile: udpProfile,
          show_reason: showUdpReason,
          ...common,
        });
      } else if (tool === "sslscan") {
        response = await runTlsScan({ device_id: Number(deviceId), port: Number(tlsPort), ...common });
      } else if (tool === "openssl") {
        response = await runOpenSslProbe({ device_id: Number(deviceId), port: Number(tlsPort), ...common });
      } else if (tool === "fping") {
        response = await runFpingProbe({ device_id: Number(deviceId), ...common });
      } else if (tool === "whatweb" || tool === "nikto") {
        const payload = {
          device_id: Number(deviceId),
          scheme: webScheme,
          port: Number(webPort),
          path: webPath.trim() || "/",
          ...common,
        };
        response = tool === "whatweb" ? await runWhatWebScan(payload) : await runNiktoScan(payload);
      } else if (tool === "smbclient") {
        response = await runSmbClientScan({ device_id: Number(deviceId), ...common });
      } else if (tool === "smb-audit") {
        response = await runSmbPostureScan({ device_id: Number(deviceId), ...common });
      } else if (tool === "arp-scan") {
        response = await runArpScan({ interface_name: interfaceName.trim() || null, ...common });
      } else if (tool === "ip-neigh") {
        response = await getNeighborTable(common);
      } else if (tool === "avahi-browse") {
        response = await runAvahiBrowse(common);
      } else if (tool === "curl") {
        response = await runCurlRequest({ url: target.trim(), method: "GET", insecure, ...common });
      } else if (tool === "host") {
        response = await runHostQuery({ query: target.trim(), ...common });
      } else if (tool === "dnsrecon") {
        response = await runDnsRecon({ query: target.trim(), ...common });
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

  async function cancelNmapJob() {
    if (!nmapJob || !ACTIVE_NMAP_JOB_STATUSES.has(nmapJob.status)) return;
    setBusy(true);
    setError("");
    try {
      const updated = await cancelNmapScanJob(nmapJob.id);
      setNmapJob(updated);
      setNmapHistory((current) => [updated, ...current.filter((item) => item.id !== updated.id)].slice(0, 5));
    } catch (cancelError) {
      setError(cancelError.message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <section className="workbench-tool lab-cli-tool">
      <header>
        <p className="eyebrow">Administrator learning lab</p>
        <h3>Network command tools</h3>
        <span>Bounded discovery, service, web, TLS, SMB and DNS checks run as typed commands without a shell or credentials.</span>
      </header>
      <details className="tool-coverage">
        <summary>Coverage of the recommended investigation areas</summary>
        <div className="workbench-table">
          <table>
            <thead><tr><th>Area</th><th>Status</th><th>Aegis capability</th><th>Boundary</th></tr></thead>
            <tbody>{INVESTIGATION_COVERAGE.map(([area, status, capability, boundary]) => (
              <tr key={area}>
                <td><strong>{area}</strong></td>
                <td>{status}</td>
                <td>{capability}</td>
                <td>{boundary}</td>
              </tr>
            ))}</tbody>
          </table>
        </div>
      </details>
      <form className="lab-cli-form" onSubmit={run}>
        <label>Tool
          <select value={tool} onChange={(event) => { setTool(event.target.value); setResult(null); }}>
            <option value="nmap">Nmap TCP scan</option>
            <option value="nmap-udp">Nmap UDP exposure scan</option>
            <option value="arp-scan">arp-scan local network</option>
            <option value="avahi-browse">mDNS names and models (host LAN)</option>
            <option value="ip-neigh">ip neigh show</option>
            <option value="curl">curl HTTP GET</option>
            <option value="dig">dig DNS query</option>
            <option value="sslscan">sslscan TLS protocols and ciphers</option>
            <option value="fping">fping registered host</option>
            <option value="whatweb">WhatWeb technology fingerprint</option>
            <option value="nikto">Nikto bounded web assessment</option>
            <option value="openssl">OpenSSL certificate and TLS session</option>
            <option value="smbclient">smbclient anonymous service listing</option>
            <option value="smb-audit">Nmap SMB protocol and signing posture</option>
            <option value="host">host DNS lookup</option>
            <option value="dnsrecon">DNSRecon standard records</option>
          </select>
        </label>
        {(tool === "sslscan" || tool === "openssl") && <label>TLS port
          <input type="number" min="1" max="65535" required value={tlsPort} onChange={(event) => setTlsPort(event.target.value)} />
        </label>}
        {REGISTERED_CLI_TOOLS.has(tool) && <label>Registered target
          <select value={deviceId} onChange={(event) => setDeviceId(event.target.value)} required>
            <option value="">Select a device</option>
            {devices.map((device) => <option key={device.id} value={device.id}>{device.name} · {device.ip_address}</option>)}
          </select>
        </label>}
        {tool === "nmap" && <>
          <label>Scan scope
            <select value={scanMode} onChange={(event) => setScanMode(event.target.value)}>
              <option value="QUICK">Quick · 24 common TCP ports</option>
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
              <option value="AGGRESSIVE">Aggressive · full -sV probes · up to 3 min</option>
            </select>
          </label>
          <label>Traffic policy
            <select value={nmapTrafficPolicy} onChange={(event) => setNmapTrafficPolicy(event.target.value)}>
              <option value="IDS_FRIENDLY">IDS-friendly · max 100 probes/s</option>
              <option value="FAST">Fast · 500+ probes/s</option>
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
        {tool === "nmap-udp" && <>
          <label>UDP ports (comma separated)
            <input value={udpPorts} onChange={(event) => setUdpPorts(event.target.value)} required />
          </label>
          <label>UDP profile
            <select value={udpProfile} onChange={(event) => setUdpProfile(event.target.value)}>
              <option value="FAST">Fast · ports only</option>
              <option value="DETAILED">Detailed · -sV --version-light</option>
              <option value="AGGRESSIVE">Aggressive · -sV --version-all</option>
            </select>
          </label>
          <label className="checkbox-label">
            <input
              type="checkbox"
              checked={showUdpReason}
              onChange={(event) => setShowUdpReason(event.target.checked)}
            />
            With reason (--reason)
          </label>
        </>}
        {(tool === "whatweb" || tool === "nikto") && <>
          <label>Web scheme
            <select value={webScheme} onChange={(event) => {
              const scheme = event.target.value;
              setWebScheme(scheme);
              if (webPort === 80 || webPort === 443) setWebPort(scheme === "https" ? 443 : 80);
            }}>
              <option value="http">HTTP</option>
              <option value="https">HTTPS</option>
            </select>
          </label>
          <label>Web port
            <input type="number" min="1" max="65535" required value={webPort} onChange={(event) => setWebPort(Number(event.target.value))} />
          </label>
          <label>URL path
            <input value={webPath} onChange={(event) => setWebPath(event.target.value)} placeholder="/" required />
          </label>
        </>}
        {tool === "arp-scan" && <label>Interface (optional)
          <input value={interfaceName} onChange={(event) => setInterfaceName(event.target.value)} placeholder="eth0" />
        </label>}
        {(tool === "curl" || tool === "dig" || tool === "host" || tool === "dnsrecon") && <label>{tool === "curl" ? "HTTP(S) URL" : tool === "dnsrecon" ? "DNS domain" : "DNS name or address"}
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
        <button className="button button--primary" disabled={busy || (tool === "nmap" && nmapJob && ACTIVE_NMAP_JOB_STATUSES.has(nmapJob.status)) || (REGISTERED_CLI_TOOLS.has(tool) && !deviceId) || (["curl", "dig", "host", "dnsrecon"].includes(tool) && !target.trim())}>{busy ? `Running · ${elapsedSeconds}s` : tool === "nmap" && scanMode === "QUICK" ? "Run quick scan" : tool === "nmap" && scanMode === "TOP_1000" ? "Scan 1,000 ports" : tool === "nmap-udp" ? "Scan UDP exposure" : "Run tool"}</button>
      </form>
      {tool === "nmap" && (
        <p className="panel-help">
          IDS-friendly mode is the default and paces discovery to at most 100 probes per second. Quick checks 24 common ports; top-1,000 scans discover open ports first, then fingerprint only those ports. External firewall and IDS allowlisting is still required to guarantee exclusion from automatic blocking.
          Detailed service detection has a 90-second host budget; Aggressive uses -sV --version-all with 180 seconds. Results record the engine, commands and execution context. Docker and a Kali VM can use different source IPs; match the Nmap release, probe database, ports and flags when comparing them.
          Cancellation takes effect after the current bounded phase finishes.
        </p>
      )}
      {tool === "nmap" && nmapJob && (
        <section className="nmap-job" aria-live="polite">
          <div className="nmap-job__header">
            <div>
              <strong>Scan #{nmapJob.id} · {nmapJob.status}</strong>
              <span>{nmapJob.phase} · {nmapJob.progress_percent}%</span>
            </div>
            {ACTIVE_NMAP_JOB_STATUSES.has(nmapJob.status) && (
              <button type="button" className="button button--secondary" disabled={busy || nmapJob.cancel_requested} onClick={cancelNmapJob}>
                {nmapJob.cancel_requested ? "Cancelling…" : "Cancel safely"}
              </button>
            )}
          </div>
          <progress value={nmapJob.progress_percent} max="100">{nmapJob.progress_percent}%</progress>
          <div className="nmap-job__facts">
            <span>{nmapJob.scanned_port_count ?? 0} network-tested</span>
            <span>{nmapJob.cached_closed_count} cached closed</span>
            <span>{nmapJob.open_ports.length} open</span>
            <span>{nmapJob.traffic_policy}</span>
          </div>
          {nmapJob.ban_signal && <div className="form-error">Possible firewall/IDS block: {nmapJob.ban_reason}</div>}
          {nmapJob.error && <div className="form-error">{nmapJob.error}</div>}
          {!ACTIVE_NMAP_JOB_STATUSES.has(nmapJob.status) && <pre>{nmapJob.output || `Scan ${nmapJob.status.toLowerCase()}.`}</pre>}
        </section>
      )}
      {tool === "nmap" && nmapHistory.length > 0 && (
        <details className="nmap-history">
          <summary>Recent Nmap audit records</summary>
          <div className="table-wrap"><table><thead><tr><th>Time</th><th>Administrator / source</th><th>Target</th><th>Policy</th><th>Status</th></tr></thead><tbody>
            {nmapHistory.map((job) => <tr key={job.id}>
              <td>{formatDate(job.created_at)}</td>
              <td><strong>{job.requested_by}</strong><br /><span>{job.client_ip || "local"}</span></td>
              <td>{job.target_name}<br /><span>{job.target_ip}</span></td>
              <td>{job.profile}<br /><span>{job.traffic_policy}</span></td>
              <td>{job.status}</td>
            </tr>)}
          </tbody></table></div>
        </details>
      )}
      {tool === "nmap-udp" && (
        <p className="panel-help">UDP results marked open are responsive. Open|filtered is inconclusive because UDP services often stay silent and firewalls may drop the probe.</p>
      )}
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
  const [ports, setPorts] = useState(DEFAULT_TCP_PORTS);
  const [timeoutSeconds, setTimeoutSeconds] = useState(2);
  const [grep, setGrep] = useState("");
  const [result, setResult] = useState(null);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  async function run(event) {
    event.preventDefault();
    setBusy(true);
    setError("");
    setResult(null);
    try {
      setResult(await runTestConnectionPorts({
        device_id: Number(deviceId),
        ports: parsePortList(ports, "TCP", 128),
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

function AttackSurfaceStepOutput({ output }) {
  let result;
  try {
    result = JSON.parse(output);
  } catch {
    return <pre>{output}</pre>;
  }
  if (!result || typeof result !== "object" || Array.isArray(result)) {
    return <pre>{output}</pre>;
  }

  const findings = Array.isArray(result.findings)
    ? result.findings.filter((finding) => finding.category !== "SCAN_PROVENANCE")
    : [];
  const evidence = result.cve_evidence && typeof result.cve_evidence === "object"
    ? result.cve_evidence
    : null;
  const mdns = result.mdns_enrichment && typeof result.mdns_enrichment === "object"
    ? result.mdns_enrichment
    : null;
  const legacy = (result.output_schema_version ?? 1) < 2 || !evidence;
  const cveMatches = result.cve_matches ?? result.cve_candidates ?? 0;

  return (
    <div className="playbook-evidence">
      <div className="nmap-job__facts playbook-evidence__facts">
        <span>Scan #{result.scan_id ?? "—"}</span>
        <span>{result.profile || "Unknown profile"}</span>
        <span>{result.finding_count ?? findings.length} findings</span>
        <span>{cveMatches} CVE matches</span>
        <span>
          CVE evidence {evidence
            ? `${evidence.cve_ready_services ?? 0}/${evidence.open_services ?? 0} · ${evidence.coverage_percent ?? 0}%`
            : "not recorded"}
        </span>
      </div>
      {legacy && (
        <div className="playbook-evidence__notice">
          Legacy saved result: fingerprint coverage was not recorded. Unknown values are hidden; rerun the assessment for the current evidence format.
        </div>
      )}
      {mdns && (
        <div className="playbook-evidence__identity">
          <strong>mDNS identity · {mdns.status || "UNKNOWN"}</strong>
          <span>{mdns.records?.length || 0} matching record(s){mdns.target ? ` · ${mdns.target}` : ""}</span>
          {mdns.raw_output && <small>{mdns.raw_output}</small>}
        </div>
      )}
      {result.scan_provenance && (
        <details className="playbook-evidence__raw">
          <summary>Scanner version and execution context</summary>
          <pre>{JSON.stringify(result.scan_provenance, null, 2)}</pre>
        </details>
      )}
      {Array.isArray(result.tool_runs) && result.tool_runs.length > 0 && (
        <section className="playbook-evidence__findings" aria-label="Automatic service checks">
          <strong>Automatic service checks</strong>
          <p>Open HTTP(S) services → WhatWeb. TLS services → OpenSSL certificate/session and sslscan protocols/ciphers. SMB → the existing NSE protocol/signing pass. Explicit software versions feed CVE matching; certificate names and cipher suites do not.</p>
          {result.tool_runs.map((run, index) => (
            <article key={`${run.tool}-${run.port}-${index}`}>
              <strong>{run.tool} · TCP {run.port} · {String(run.status || "UNKNOWN").replaceAll("_", " ")}</strong>
              <small>{Math.round(run.duration_ms || 0)} ms{run.details?.target ? ` · ${run.details.target}` : ""}</small>
              {run.details?.error && <p className="diagnostic-error">{run.details.error}</p>}
              {run.details?.note && <p>{run.details.note}</p>}
              <details className="playbook-evidence__raw">
                <summary>Collected evidence and command</summary>
                <pre>{JSON.stringify(run.details || {}, null, 2)}</pre>
              </details>
            </article>
          ))}
          <small>Cipher/technology previews are capped at 20 entries; full tool reports are retained on the saved scan.</small>
        </section>
      )}
      {(result.omitted_finding_count > 0 || result.omitted_tool_run_count > 0) && (
        <p className="playbook-evidence__notice">This preview omits {result.omitted_finding_count || 0} findings and {result.omitted_tool_run_count || 0} tool reports. Full evidence remains on the saved vulnerability scan.</p>
      )}
      <div className="playbook-evidence__findings">
        {findings.length === 0 ? (
          <div className="empty-state empty-state--compact">No findings were stored for this step.</div>
        ) : findings.map((finding, index) => {
          const metadata = [
            finding.cve_id,
            finding.cvss_score != null ? `CVSS ${finding.cvss_score}` : null,
            finding.match_confidence ? `${finding.match_confidence} confidence` : null,
            finding.service_product
              ? `${finding.service_product}${finding.service_version ? ` ${finding.service_version}` : ""}`
              : null,
            finding.validation_tool,
            finding.validation_check_id,
            finding.known_exploited ? "CISA KEV" : null,
            finding.epss_score != null ? `EPSS ${(finding.epss_score * 100).toFixed(1)}%` : null,
          ].filter(Boolean);
          return (
            <article key={`${finding.category || "finding"}-${finding.port ?? "none"}-${index}`}>
              <div>
                <span className={`diagnostic-status diagnostic-status--${String(finding.severity || "info").toLowerCase()}`}>
                  {finding.severity || "INFO"}
                </span>
                <small>{String(finding.category || "FINDING").replaceAll("_", " ")}</small>
              </div>
              <strong>{finding.title || "Untitled finding"}{finding.port != null ? ` · TCP ${finding.port}` : ""}</strong>
              {finding.description && <p>{finding.description}</p>}
              {metadata.length > 0 && <div className="playbook-evidence__metadata">{metadata.map((item, metadataIndex) => <span key={`${item}-${metadataIndex}`}>{item}</span>)}</div>}
              {finding.service_cpe && <code>{finding.service_cpe}</code>}
              {finding.recommendation && <small>{finding.recommendation}</small>}
            </article>
          );
        })}
      </div>
      <details className="playbook-evidence__raw">
        <summary>View preserved JSON</summary>
        <pre>{output}</pre>
      </details>
    </div>
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
            {step.step_key === "attack_surface"
              ? <AttackSurfaceStepOutput output={step.output} />
              : <pre>{step.output}</pre>}
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
  const selectedActiveRunId = ACTIVE_PLAYBOOK_STATUSES.has(selectedRun?.status)
    ? selectedRun.id
    : null;

  useEffect(() => {
    if (!activeRunKey) return undefined;
    const polledDeviceId = Number(deviceId);
    let disposed = false;
    let timerId;

    async function poll() {
      if (document.visibilityState === "hidden") {
        timerId = window.setTimeout(poll, 10000);
        return;
      }
      const requests = [listSecurityPlaybookRunIndex(50)];
      if (selectedActiveRunId) requests.push(getSecurityPlaybookRun(selectedActiveRunId));
      const updates = await Promise.allSettled(requests);
      if (disposed) return;

      const indexResult = updates[0];
      if (indexResult.status === "fulfilled") {
        const refreshedIndex = Array.isArray(indexResult.value) ? indexResult.value : [];
        setAllRuns((current) => mergeGlobalPlaybookRuns(current, refreshedIndex));
        const currentTargetIndex = new Map(
          refreshedIndex
            .filter((run) => run.device_id === polledDeviceId)
            .map((run) => [run.id, run]),
        );
        setRuns((current) => current.map((run) => {
          const update = currentTargetIndex.get(run.id);
          return update ? { ...run, ...update, steps: run.steps } : run;
        }));
      }
      const detailResult = updates[1];
      if (detailResult?.status === "fulfilled") {
        setRuns((current) => upsertPlaybookRun(current, detailResult.value));
        setAllRuns((current) => mergeGlobalPlaybookRuns(current, [detailResult.value]));
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
  }, [activeRunKey, deviceId, selectedActiveRunId]);

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
        <p className="eyebrow">Recommended workflow</p>
        <h3>Automated host assessment</h3>
        <span>Choose a target and depth. Aegis runs the ordered checks, stores their evidence, and keeps progress available if you leave this page.</span>
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
                  <article><span>CVE matches</span><strong>{summary.cve_candidates ?? 0}</strong></article>
                  <article><span>CVE evidence</span><strong>{summary.cve_ready_services ?? 0}/{summary.open_services ?? 0} · {summary.cve_coverage_percent ?? 0}%</strong></article>
                  <article><span>mDNS identity</span><strong>{summary.mdns_status || "Not checked"}</strong></article>
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

function AssessmentTool({ devices }) {
  const [mode, setMode] = useState("automated");
  return (
    <section className="assessment-workspace">
      <header className="assessment-workspace__header">
        <p className="eyebrow">Unified assessment</p>
        <h2>Choose how you want to investigate</h2>
        <p>Use the automated workflow for a complete, repeatable assessment. Use manual checks when you only need one specific test.</p>
        <div className="assessment-mode-switch" role="tablist" aria-label="Assessment mode">
          <button
            type="button"
            role="tab"
            aria-selected={mode === "automated"}
            className={mode === "automated" ? "active" : ""}
            onClick={() => setMode("automated")}
          >
            <strong>Automated workflow</strong>
            <span>Recommended · complete sequence with saved evidence</span>
          </button>
          <button
            type="button"
            role="tab"
            aria-selected={mode === "manual"}
            className={mode === "manual" ? "active" : ""}
            onClick={() => setMode("manual")}
          >
            <strong>Manual checks</strong>
            <span>Run one focused command or repeat a single stage</span>
          </button>
        </div>
      </header>
      {mode === "automated" && <PlaybookTool devices={devices} />}
      {mode === "manual" && <section className="assessment-manual-tools" aria-labelledby="manual-assessment-tools-title">
        <header>
          <p className="eyebrow">On-demand checks</p>
          <h3 id="manual-assessment-tools-title">Manual assessment tools</h3>
          <span>Select the smallest tool that answers your question. Each tool remains bounded to registered targets and fixed command options.</span>
        </header>
        <details open>
          <summary>
            <span>Network command tools</span>
            <small>Nmap TCP/UDP, Avahi, ARP, web, TLS, SMB and DNS</small>
          </summary>
          <LabCliTool devices={devices} />
        </details>
        <details>
          <summary>
            <span>TCP port test</span>
            <small>Quick PowerShell reachability check for selected ports</small>
          </summary>
          <TestConnectionPortTool devices={devices} />
        </details>
        <details>
          <summary>
            <span>Traceroute</span>
            <small>Inspect the bounded network path to a registered device</small>
          </summary>
          <TracerouteTool devices={devices} />
        </details>
      </section>}
    </section>
  );
}

function CveMirrorTool() {
  const [status, setStatus] = useState(null);
  const [mode, setMode] = useState("MODIFIED");
  const [year, setYear] = useState(new Date().getFullYear());
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const datasetState = !status
    ? "Loading"
    : status.baseline_complete
      ? "Ready for matching"
      : status.record_count > 0
        ? "Partial"
        : "Empty";
  const refreshState = !status
    ? "Loading"
    : ({
        IDLE: "Not started",
        SYNCING: "Updating now",
        READY: "Completed",
        CANCELLED: "Cancelled",
        FAILED: "Failed",
      }[status.status] || status.status);
  const syncHint = {
    MODIFIED: "Recommended after the first Full import. Downloads recently changed NVD records.",
    RECENT: "Downloads newly published and recently updated records only.",
    YEAR: "Imports or repairs one publication year without rebuilding the whole mirror.",
    FULL: "Builds the authoritative 2002-current baseline. Use this for first setup or recovery.",
  }[mode];

  useEffect(() => {
    let disposed = false;
    let timer;
    async function refresh() {
      try {
        const next = await getCveMirrorStatus();
        if (disposed) return;
        setStatus(next);
        if (next.status === "SYNCING") timer = window.setTimeout(refresh, 1500);
      } catch (requestError) {
        if (!disposed) setError(requestError.message);
      }
    }
    refresh();
    return () => {
      disposed = true;
      if (timer) window.clearTimeout(timer);
    };
  }, [status?.status === "SYNCING"]);

  async function synchronize(event) {
    event.preventDefault();
    setBusy(true);
    setError("");
    try {
      setStatus(await startCveMirrorSync({
        mode,
        ...(mode === "YEAR" ? { year: Number(year) } : {}),
      }));
    } catch (requestError) {
      setError(requestError.message);
    } finally {
      setBusy(false);
    }
  }

  async function cancelSync() {
    setBusy(true);
    setError("");
    try {
      setStatus(await cancelCveMirrorSync());
    } catch (requestError) {
      setError(requestError.message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <section className="workbench-tool cve-mirror-tool">
      <header>
        <p className="eyebrow">Local vulnerability intelligence</p>
        <h3>NVD CVE mirror</h3>
        <span>Keeps a verified local copy of NVD applicability data so Aegis can match detected products and versions quickly, even when the public NVD API is unavailable.</span>
      </header>
      <div className="cve-mirror-explainer" aria-label="How CVE correlation works">
        <article><span>1</span><div><strong>Identify</strong><small>Nmap supplies product, version and preferably an exact CPE.</small></div></article>
        <article><span>2</span><div><strong>Match locally</strong><small>The mirror checks vendor, product and NVD version boundaries.</small></div></article>
        <article><span>3</span><div><strong>Prioritize</strong><small>CVSS, CISA KEV and FIRST EPSS help order candidates for review.</small></div></article>
      </div>
      <p className="cve-mirror-caution"><strong>Result meaning:</strong> a match is a review candidate, not proof that the device is exploitable. Confirm fingerprints, vendor backports and local mitigations.</p>
      <div className="audit-summary cve-mirror-summary">
        <article><span>CVE records</span><strong>{status?.record_count?.toLocaleString() || 0}</strong></article>
        <article><span>CPE matches</span><strong>{status?.cpe_match_count?.toLocaleString() || 0}</strong></article>
        <article><span>Local dataset</span><strong>{datasetState}</strong></article>
        <article><span>Latest refresh</span><strong>{refreshState}</strong></article>
      </div>
      <form className="lab-cli-form cve-mirror-form" onSubmit={synchronize}>
        <label>Synchronization scope
          <select value={mode} onChange={(event) => setMode(event.target.value)} disabled={status?.status === "SYNCING"}>
            <option value="MODIFIED">Modified · recent changes</option>
            <option value="RECENT">Recent · newly published</option>
            <option value="YEAR">One publication year</option>
            <option value="FULL">Full baseline · all years</option>
          </select>
        </label>
        {mode === "YEAR" && <label>Publication year
          <input type="number" min="2002" max={new Date().getFullYear()} value={year} onChange={(event) => setYear(event.target.value)} required />
        </label>}
        <button className="button button--primary" disabled={busy || status?.status === "SYNCING"}>{busy ? "Starting…" : "Update local mirror"}</button>
        {status?.status === "SYNCING" && <button type="button" className="button button--secondary" disabled={busy || status.cancel_requested} onClick={cancelSync}>{status.cancel_requested ? "Cancelling…" : "Cancel safely"}</button>}
        <p className="cve-mirror-form__hint" aria-live="polite">{syncHint}</p>
      </form>
      {status?.status === "SYNCING" && <div className="nmap-job cve-mirror-progress">
        <div className="nmap-job__header"><div><strong>{status.current_feed || "Preparing feed"}</strong><span>{status.feeds_completed} / {status.feeds_total} feeds · {status.progress_percent}%</span></div></div>
        <progress value={status.progress_percent} max="100">{status.progress_percent}%</progress>
      </div>}
      {status?.source_last_modified && <p className="panel-help">NVD source timestamp: {status.source_last_modified} · Latest refresh activity: {formatDate(status.completed_at)}</p>}
      {status?.record_count > 0 && ["FAILED", "CANCELLED"].includes(status.status) && <p className="panel-help">The last refresh did not finish, but the existing verified dataset remains active.</p>}
      {status?.error && <div className="form-error">{status.error}</div>}
      {error && <div className="form-error">{error}</div>}
      <p className="panel-help">A full baseline downloads each annual feed from 2002 onward and may require substantial time and disk I/O. Interrupted imports retain verified completed batches and online lookup remains available.</p>
    </section>
  );
}

function Overview({ devices, captures, attackPaths, adapters, onChangeTab }) {
  const goals = [
    ["playbooks", "Assess a registered device", "Recommended", "Run the repeatable four-step workflow and save evidence for comparison."],
    ["cve-mirror", "Refresh vulnerability data", "Offline-ready", "Update the local NVD dataset used for exact CPE and version-range matching."],
    ["configuration", "Prioritize existing evidence", `${attackPaths?.candidate_paths || 0} candidate paths`, "Review stored findings and likely exposure paths without sending more traffic."],
  ];
  const cards = [
    [
      "network",
      "Registered assets",
      devices.length,
      "Review known hosts and identities",
    ],
    [
      "sniffer",
      "Wireshark",
      "DOCKER",
      "Analyze toolbox packets or import a PCAP",
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
    ["query", "DNS query", "SAFE", "Validated forward and reverse lookup"],
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
        <h2>Start with the question you need to answer.</h2>
        <p>
          Assess a host for the full repeatable workflow. Open a focused tool
          only when you already know the individual check you need.
        </p>
      </div>
      <section className="workbench-explainer" aria-labelledby="workbench-flow-title">
        <div>
          <p className="eyebrow">Mental model</p>
          <h3 id="workbench-flow-title">How Aegis turns a host into an action</h3>
        </div>
        <ol>
          <li><span>1</span><strong>Register</strong><small>Add or discover an authorized device.</small></li>
          <li><span>2</span><strong>Observe</strong><small>Monitor reachability, services and telemetry.</small></li>
          <li><span>3</span><strong>Assess</strong><small>Collect bounded network and version evidence.</small></li>
          <li><span>4</span><strong>Prioritize</strong><small>Correlate findings with CVE, KEV and EPSS data.</small></li>
          <li><span>5</span><strong>Verify</strong><small>Remediate, then reassess to confirm the change.</small></li>
        </ol>
      </section>
      <section className="workbench-starting-points" aria-labelledby="workbench-goals-title">
        <div className="workbench-section-heading">
          <p className="eyebrow">Choose by goal</p>
          <h3 id="workbench-goals-title">What do you want to do?</h3>
        </div>
        <div>
          {goals.map(([tab, title, value, description]) => (
            <button key={tab} onClick={() => onChangeTab(tab)}>
              <span>{value}</span>
              <strong>{title}</strong>
              <small>{description}</small>
              <b>Start →</b>
            </button>
          ))}
        </div>
      </section>
      <div className="workbench-section-heading workbench-section-heading--tools">
        <p className="eyebrow">Focused tools</p>
        <h3>Browse individual evidence sources</h3>
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
  const normalizedInitialTab = normalizeWorkbenchTab(initialTab);
  const [tab, setTab] = useState(normalizedInitialTab);
  const [captures, setCaptures] = useState([]);
  const [attackPaths, setAttackPaths] = useState(null);
  const [adapters, setAdapters] = useState([]);
  const [error, setError] = useState("");
  const [loadingEvidence, setLoadingEvidence] = useState(false);
  const loadedEvidence = useRef(new Set());
  const evidenceRequests = useRef(0);
  const mounted = useRef(true);
  useEffect(() => {
    mounted.current = true;
    return () => {
      mounted.current = false;
    };
  }, []);
  useEffect(() => {
    if (initialTab !== normalizedInitialTab) onTabChange?.(normalizedInitialTab);
  }, [initialTab, normalizedInitialTab, onTabChange]);
  useEffect(() => {
    const required = tab === "overview"
      ? ["captures", "attackPaths", "adapters"]
      : tab === "sniffer"
        ? ["captures"]
        : tab === "configuration"
          ? ["attackPaths"]
          : tab === "wireless"
            ? ["adapters"]
            : [];
    const pending = required.filter((key) => !loadedEvidence.current.has(key));
    if (!pending.length) return undefined;

    const loaders = {
      captures: listPacketCaptures,
      attackPaths: getAttackPaths,
      adapters: getWirelessAdapters,
    };
    pending.forEach((key) => loadedEvidence.current.add(key));
    evidenceRequests.current += 1;
    setLoadingEvidence(true);
    Promise.allSettled(pending.map((key) => loaders[key]()))
      .then((results) => {
        if (!mounted.current) return;
        const failures = [];
        results.forEach((result, index) => {
          const key = pending[index];
          if (result.status === "rejected") {
            loadedEvidence.current.delete(key);
            failures.push(result.reason instanceof Error ? result.reason.message : String(result.reason));
            return;
          }
          if (key === "captures") setCaptures(result.value);
          if (key === "attackPaths") setAttackPaths(result.value);
          if (key === "adapters") setAdapters(result.value);
        });
        setError(failures.join(" · "));
      })
      .finally(() => {
        evidenceRequests.current = Math.max(0, evidenceRequests.current - 1);
        if (mounted.current) setLoadingEvidence(evidenceRequests.current > 0);
      });
    return undefined;
  }, [tab]);
  const selectedLabel = useMemo(
    () => TOOLS.find(([value]) => value === tab)?.[1],
    [tab],
  );
  function changeTab(nextTab) {
    const normalizedTab = normalizeWorkbenchTab(nextTab);
    setTab(normalizedTab);
    onTabChange?.(normalizedTab);
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
            {TOOL_GROUPS.map(([group, values]) => (
              <section className="workbench-nav-group" key={group} aria-label={group}>
                <strong>{group}</strong>
                {values.map((value) => {
                  const [, label, tag] = TOOLS.find(([tool]) => tool === value);
                  return (
                    <button
                      key={value}
                      className={tab === value ? "active" : ""}
                      onClick={() => changeTab(value)}
                    >
                      <span>{tag}</span>
                      {label}
                    </button>
                  );
                })}
              </section>
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
          {loadingEvidence && (
            <div className="panel-help" role="status">Loading this tool's live evidence…</div>
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
          {tab === "playbooks" && <AssessmentTool devices={devices} />}
          {tab === "cve-mirror" && <CveMirrorTool />}
          {tab === "decoder" && <DecoderTool />}
          {tab === "network" && (
            <NetworkTool devices={devices} onSelectDevice={selectDevice} />
          )}
          {tab === "sniffer" && (
            <SnifferTool captures={captures} devices={devices} />
          )}
          {tab === "credentials" && <CredentialTool />}
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
          {tab === "mac" && <MacManagementPanel />}
        </main>
      </section>
    </div>
  );
}
