import assert from "node:assert/strict";
import test from "node:test";
import { rowsFromDhcpCsv } from "../src/dhcpCsv.js";

test("DHCP CSV accepts header aliases, quoted values, CRLF and embedded newlines", () => {
  const rows = rowsFromDhcpCsv(
    'Host Name,Leased IP,Hardware Address,Prefix,Expiration,VLAN ID\r\n' +
    '"Lab, device",198.18.0.4,02-11-22-33-44-55,24,2026-09-22T12:00:00Z,lab\r\n' +
    '"Line one\nLine ""two""",198.18.0.5,,0,,\r\n',
  );
  assert.equal(rows.length, 2);
  assert.deepEqual(rows[0], {
    hostname: "Lab, device", ip_address: "198.18.0.4", mac_address: "02-11-22-33-44-55",
    lease_expires_at: "2026-09-22T12:00:00.000Z", vlan: "lab", prefix_length: 24, gateway_ip: null,
  });
  assert.equal(rows[1].hostname, 'Line one\nLine "two"');
  assert.equal(rows[1].prefix_length, 0);
  assert.equal(rows[1].lease_expires_at, null);
});

test("DHCP CSV rejects invalid input before import", () => {
  for (const [csv, message] of [
    ["ip_address\n198.18.0.4\0", /Binary data/],
    ["hostname\nexample", /Missing required IP column/],
    ["ip_address\n999.1.1.1", /not a valid IPv4/],
    ["ip_address,mac_address\n198.18.0.4,invalid", /invalid MAC/],
    ["ip_address,prefix\n198.18.0.4,33", /prefix length/],
    ["ip_address,expiration\n198.18.0.4,not-a-date", /lease expiry/],
    ['ip_address\n"198.18.0.4', /unterminated quoted field/],
  ]) {
    assert.throws(() => rowsFromDhcpCsv(csv), message);
  }
  assert.throws(() => rowsFromDhcpCsv("ip_address\n" + "198.18.0.4\n".repeat(1001)), /at most 1,000/);
});
