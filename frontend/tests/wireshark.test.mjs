import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import { packetFilters, resolveWiresharkUrl } from "../src/wireshark.js";

test("Wireshark link is HTTPS and never embeds credentials", () => {
  assert.equal(resolveWiresharkUrl(), "https://127.0.0.1:8444/");
  for (const invalid of ["javascript:alert(1)", "http://example.com", "https://aegis:secret@example.com", "broken"]) {
    assert.equal(resolveWiresharkUrl(invalid), "https://127.0.0.1:8444/");
  }
  assert.equal(resolveWiresharkUrl("https://localhost:9444/"), "https://localhost:9444/");
});

test("filter examples distinguish capture from display and handle IPv6", () => {
  assert.deepEqual(packetFilters("198.18.10.22"), { capture: "host 198.18.10.22", display: "ip.addr == 198.18.10.22" });
  assert.deepEqual(packetFilters("2001:db8::22"), { capture: "host 2001:db8::22", display: "ipv6.addr == 2001:db8::22" });
  assert.equal(packetFilters("198.18.1.1 or host victim").capture, "tcp port 445 or tcp port 443 or port 53");
  for (const invalid of ["999.1.1.1", "a.b.c.d", "192.168.1", "2001:db8:::22"]) {
    assert.equal(packetFilters(invalid).capture, packetFilters().capture);
  }
});

test("primary packet UI opens Wireshark instead of submitting legacy captures", () => {
  const app = readFileSync(new URL("../src/App.jsx", import.meta.url), "utf8");
  const panel = readFileSync(new URL("../src/WiresharkPanel.jsx", import.meta.url), "utf8");
  assert.match(app, /WiresharkPanel/);
  assert.doesNotMatch(app, /await startPacketCapture/);
  assert.match(panel, /network namespace/);
  assert.match(panel, /full packet payloads/);
  assert.match(panel, /not the stored packets/);
});

test("Docker GUI keeps credentials and network exposure local", () => {
  const compose = readFileSync(new URL("../../docker-compose.wireshark.yml", import.meta.url), "utf8");
  assert.match(compose, /127\.0\.0\.1:\$\{AEGIS_WIRESHARK_PORT/);
  assert.match(compose, /network_mode: "container:/);
  assert.match(compose, /FILE__PASSWORD: \/run\/secrets\/wireshark_password/);
  assert.doesNotMatch(compose, /privileged:\s*true|docker\.sock|network_mode:\s*host/);
  assert.equal((compose.match(/image: .*@sha256:[a-f0-9]{64}/g) || []).length, 2);
});

test("hybrid restart reattaches the optional GUI and stop preserves its volume", () => {
  const start = readFileSync(new URL("../../start-hybrid.ps1", import.meta.url), "utf8");
  const stop = readFileSync(new URL("../../stop-hybrid.ps1", import.meta.url), "utf8");
  assert.match(start, /\[switch\]\$WithWireshark/);
  assert.match(start, /start-wireshark\.ps1/);
  assert.ok(stop.indexOf('label=aegis.wireshark.managed=true') < stop.indexOf('docker-compose.observability.yml'));
  assert.doesNotMatch(stop, /down\s+(-v|--volumes)/);
});
