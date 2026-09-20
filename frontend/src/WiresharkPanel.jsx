import { useState } from "react";
import { packetFilters, resolveWiresharkUrl } from "./wireshark.js";

const wiresharkUrl = resolveWiresharkUrl(import.meta.env.VITE_WIRESHARK_URL);

export default function WiresharkPanel({ devices = [] }) {
  const [deviceId, setDeviceId] = useState("");
  const selected = devices.find((device) => String(device.id) === deviceId);
  const filters = packetFilters(selected?.ip_address);

  return (
    <section className="wireshark-panel" aria-label="Wireshark packet analysis">
      <div className="wireshark-panel__intro">
        <div>
          <p className="eyebrow">Docker · full protocol analyzer</p>
          <h3>Wireshark</h3>
          <p>Open the real Wireshark desktop in your browser. Inspect packet details, TCP streams, TLS handshakes, DNS and SMB traffic instead of a metadata-only summary.</p>
        </div>
        <a className="button button--primary" href={wiresharkUrl} target="_blank" rel="noopener noreferrer">Open Wireshark ↗</a>
      </div>
      <div className="wireshark-panel__scope">
        <strong>Capture scope: Aegis Docker toolbox traffic</strong>
        <p>Wireshark shares the network toolbox's network namespace. Select <code>eth0</code> to observe its scans and tool requests. It does not directly see your Windows Wi-Fi/Ethernet interfaces or every device-to-device conversation on the LAN.</p>
      </div>
      <label className="wireshark-panel__target">Filter example for a registered device
        <select value={deviceId} onChange={(event) => setDeviceId(event.target.value)}>
          <option value="">General protocol examples</option>
          {devices.map((device) => <option key={device.id} value={device.id}>{device.name} · {device.ip_address}</option>)}
        </select>
      </label>
      <ol className="wireshark-panel__steps">
        <li><strong>Choose scope before capturing</strong><span>In Wireshark select <code>eth0</code> and enter capture filter <code>{filters.capture}</code>. This limits the packets collected.</span></li>
        <li><strong>Start Wireshark, then run an Aegis assessment</strong><span>Capture first, launch the network check, then stop capture. Display filter <code>{filters.display}</code> narrows the view, not the stored packets.</span></li>
        <li><strong>Analyze or save the result</strong><span>Inspect protocol fields or Follow TCP Stream. Save PCAP/PCAPNG under <code>/config/captures</code>. For Windows-interface traffic, import a PCAP captured on the Windows host.</span></li>
      </ol>
      <p className="panel-help">Unlike the previous capture, Wireshark can retain full packet payloads. TLS application data remains encrypted unless valid session secrets are separately supplied; none are collected automatically.</p>
      <p className="panel-help">Use a target/protocol capture filter and stop after the check. An unfiltered capture can include Wireshark's own remote-desktop traffic on port 3001; for longer sessions configure a size-limited ring buffer in Capture Options.</p>
      <details className="playbook-evidence__raw">
        <summary>Startup and first connection</summary>
        <p>With the Aegis toolbox running, execute <code>.\start-wireshark.ps1</code> from the project folder. GUI address: <code>{wiresharkUrl}</code>.</p>
        <p>The local HTTPS endpoint uses a self-signed certificate; your browser may ask you to approve it. Sign in as <code>aegis</code> using the generated local password in <code>secrets/wireshark_password.txt</code>. The GUI has separate authentication from Aegis and is published only on loopback.</p>
        <p>If the toolbox was recreated, rerun the launcher to reattach Wireshark. PCAP files stay in the dedicated Docker volume, not the Git repository or Aegis database backups.</p>
      </details>
    </section>
  );
}
