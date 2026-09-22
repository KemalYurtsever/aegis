const DHCP_HEADER_ALIASES = {
  hostname: ["hostname", "host_name", "host", "name", "client_name"],
  ip_address: ["ip_address", "ip", "address", "leased_ip"],
  mac_address: ["mac_address", "mac", "hardware_address", "chaddr"],
  lease_expires_at: [
    "lease_expires_at",
    "lease_expires",
    "expires_at",
    "expiration",
    "expiry",
  ],
  vlan: ["vlan", "vlan_id", "network"],
  prefix_length: ["prefix_length", "prefix", "cidr_prefix"],
  gateway_ip: ["gateway_ip", "gateway", "default_gateway"],
};

function parseCsvRecords(text) {
  const records = [];
  let record = [];
  let field = "";
  let quoted = false;
  for (let index = 0; index < text.length; index += 1) {
    const character = text[index];
    if (quoted) {
      if (character === '"' && text[index + 1] === '"') {
        field += '"';
        index += 1;
      } else if (character === '"') quoted = false;
      else field += character;
    } else if (character === '"' && field.length === 0) quoted = true;
    else if (character === ",") {
      record.push(field);
      field = "";
    } else if (character === "\n") {
      record.push(field);
      records.push(record);
      record = [];
      field = "";
    } else if (character !== "\r") field += character;
  }
  if (quoted) throw new Error("The CSV contains an unterminated quoted field.");
  if (field.length > 0 || record.length > 0) {
    record.push(field);
    records.push(record);
  }
  return records.filter((row) => row.some((value) => value.trim() !== ""));
}

function normalizeHeader(value) {
  return value
    .replace(/^\uFEFF/, "")
    .trim()
    .toLocaleLowerCase()
    .replace(/[\s-]+/g, "_");
}

export function rowsFromDhcpCsv(text) {
  if (text.includes("\0"))
    throw new Error("Binary data is not a valid CSV file.");
  const records = parseCsvRecords(text);
  if (records.length < 2)
    throw new Error(
      "The CSV must contain a header and at least one lease row.",
    );
  const headers = records[0].map(normalizeHeader);
  const columnFor = (field) =>
    headers.findIndex((header) => DHCP_HEADER_ALIASES[field].includes(header));
  const columns = Object.fromEntries(
    Object.keys(DHCP_HEADER_ALIASES).map((field) => [field, columnFor(field)]),
  );
  if (columns.ip_address < 0)
    throw new Error(
      "Missing required IP column. Use ip_address, ip, address, or leased_ip.",
    );
  if (records.length - 1 > 1000)
    throw new Error("A single import can contain at most 1,000 lease rows.");

  return records.slice(1).map((record, index) => {
    const value = (field) =>
      columns[field] < 0 ? "" : (record[columns[field]] || "").trim();
    const ip = value("ip_address");
    const octets = ip.split(".");
    if (
      octets.length !== 4 ||
      octets.some((part) => !/^\d{1,3}$/.test(part) || Number(part) > 255)
    ) {
      throw new Error(
        `Row ${index + 2}: ${ip || "empty value"} is not a valid IPv4 address.`,
      );
    }
    const mac = value("mac_address");
    const prefix = value("prefix_length");
    if (prefix && (!/^\d{1,2}$/.test(prefix) || Number(prefix) > 32))
      throw new Error(`Row ${index + 2}: prefix length must be 0–32.`);
    const compactMac = mac.replace(/[:.\-]/g, "");
    if (mac && !/^[0-9a-fA-F]{12}$/.test(compactMac))
      throw new Error(`Row ${index + 2}: invalid MAC address.`);
    const expires = value("lease_expires_at");
    const parsedExpiry = expires ? new Date(expires) : null;
    if (parsedExpiry && Number.isNaN(parsedExpiry.getTime()))
      throw new Error(
        `Row ${index + 2}: lease expiry must be an ISO date/time.`,
      );
    return {
      hostname: value("hostname") || null,
      ip_address: ip,
      mac_address: mac || null,
      lease_expires_at: parsedExpiry ? parsedExpiry.toISOString() : null,
      vlan: value("vlan") || null,
      prefix_length: prefix === "" ? null : Number(prefix),
      gateway_ip: value("gateway_ip") || null,
    };
  });
}
