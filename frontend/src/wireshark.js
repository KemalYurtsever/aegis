export function resolveWiresharkUrl(configured) {
  const fallback = "https://127.0.0.1:8444/";
  try {
    const url = new URL(configured || fallback);
    if (url.protocol !== "https:" || url.username || url.password) return fallback;
    return url.href;
  } catch {
    return fallback;
  }
}

export function packetFilters(address) {
  // Generated examples, never executable commands. Only plain address tokens
  // from registered assets can be interpolated into filter syntax.
  const token = String(address || "");
  const ipv4 = /^\d{1,3}(\.\d{1,3}){3}$/.test(token)
    && token.split(".").every((part) => Number(part) <= 255);
  let ipv6 = false;
  if (/^[0-9a-f:.]+$/i.test(token) && token.includes(":")) {
    try { ipv6 = new URL(`http://[${token}]/`).hostname.startsWith("["); } catch { /* Not an IPv6 literal. */ }
  }
  const valid = ipv4 || ipv6;
  return valid
    ? { capture: `host ${token}`, display: `ip${token.includes(":") ? "v6" : ""}.addr == ${token}` }
    : { capture: "tcp port 445 or tcp port 443 or port 53", display: "smb2 || tls || dns" };
}
