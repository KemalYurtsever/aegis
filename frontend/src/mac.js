export function normalizeMac(value) {
  const text = value.trim();
  if (!/^(?:[\da-f]{12}|(?:[\da-f]{2}:){5}[\da-f]{2}|(?:[\da-f]{2}-){5}[\da-f]{2})$/i.test(text)) {
    throw new Error("12 hex karakter veya ':' / '-' ile ayrılmış 6 çift gir.");
  }
  const compact = text.replaceAll(":", "").replaceAll("-", "").toUpperCase();
  if (compact === "0".repeat(12) || (parseInt(compact.slice(0, 2), 16) & 1)) {
    throw new Error("MAC sıfır olmayan unicast bir adres olmalı; multicast/broadcast kullanılamaz.");
  }
  return compact.match(/../g).join(":");
}

export function newRandomMac(excluded = [], cryptoProvider = globalThis.crypto) {
  const used = new Set(excluded.filter(Boolean).map(normalizeMac));
  for (let attempt = 0; attempt < 32; attempt += 1) {
    const bytes = cryptoProvider.getRandomValues(new Uint8Array(6));
    bytes[0] = (bytes[0] | 2) & 0xfe;
    const address = normalizeMac(Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join(""));
    if (!used.has(address)) return address;
  }
  throw new Error("Farklı bir rastgele MAC üretilemedi; tekrar dene.");
}

export function preferredMacAdapter(adapters, currentId = "") {
  return adapters.find((item) => item.interface_id === currentId) ||
    adapters.find((item) => item.status === "Up" && item.supports_override) ||
    adapters.find((item) => item.supports_override) ||
    adapters.find((item) => item.status === "Up") || adapters[0] || null;
}

export function macApplyPayload(plan) {
  if (!plan?.plan_token) throw new Error("Değişiklik planı oluşturulamadı; tekrar Uygula’ya bas.");
  return {
    interface_id: plan.interface_id,
    mode: plan.mode,
    mac_address: plan.mode === "restore" ? null : normalizeMac(plan.target_mac),
    expected_mac: normalizeMac(plan.previous_mac),
    acknowledgement: "CHANGE LOCAL MAC",
    plan_token: plan.plan_token,
  };
}

export function macChangeRequest(interfaceId, mode, macAddress) {
  if (!interfaceId) throw new Error("Yerel bağlantıyı seç.");
  if (!["manual", "random", "restore"].includes(mode)) throw new Error("Geçerli bir MAC modu seç.");
  return { interface_id: interfaceId, mode, mac_address: mode === "restore" ? null : normalizeMac(macAddress) };
}

export async function changeMacDirectly(payload, { prepare, apply, onPrepared = () => {}, isActive = () => true }) {
  const plan = await prepare(payload);
  if (!isActive()) return null;
  onPrepared(plan);
  if (!plan.can_apply) throw new Error("MAC değiştirmek için Windows backend’ini Yönetici olarak çalıştır.");
  const result = await apply(macApplyPayload(plan));
  return { plan, result };
}
