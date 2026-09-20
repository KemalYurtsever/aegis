import { useEffect, useRef, useState } from "react";
import { applyMacChange, getMacAdapters, prepareMacChange } from "./api.js";
import { changeMacDirectly, macChangeRequest, newRandomMac } from "./mac.js";

function downloadScript(script, filename) {
  const url = URL.createObjectURL(new Blob(["\uFEFF", script], { type: "text/plain;charset=utf-8" }));
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = filename;
  anchor.click();
  window.setTimeout(() => URL.revokeObjectURL(url), 1000);
}

export default function MacManagementPanel() {
  const [state, setState] = useState(null);
  const [selected, setSelected] = useState("");
  const [mode, setMode] = useState("manual");
  const [mac, setMac] = useState("");
  const [plan, setPlan] = useState(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [result, setResult] = useState(null);
  const mounted = useRef(false);
  const changing = useRef(false);
  const adapter = state?.adapters.find((item) => item.interface_id === selected);
  const supported = !!adapter?.supports_override && !!adapter?.current_mac && (mode !== "restore" || !!adapter?.permanent_mac);

  async function refresh() {
    if (changing.current) return;
    setBusy(true);
    setError("");
    setPlan(null);
    setResult(null);
    try {
      const next = await getMacAdapters();
      if (!mounted.current) return;
      setState(next);
      setSelected((current) => next.adapters.some((item) => item.interface_id === current) ? current :
        (next.adapters.find((item) => item.status === "Up" && item.supports_override) ||
         next.adapters.find((item) => item.status === "Up") || next.adapters[0])?.interface_id || "");
    } catch (failure) {
      if (mounted.current) setError(failure.message);
    } finally {
      if (mounted.current) setBusy(false);
    }
  }

  useEffect(() => {
    mounted.current = true;
    refresh();
    return () => { mounted.current = false; };
  }, []);

  function invalidate() {
    setPlan(null);
    setResult(null);
    setError("");
  }

  function randomize() {
    invalidate();
    try {
      setMode("random");
      setMac(newRandomMac(state?.adapters.flatMap((item) => [item.current_mac, item.permanent_mac, item.override_mac]) || []));
    } catch (failure) {
      setError(failure.message);
    }
  }

  async function downloadChange() {
    if (busy || changing.current || !supported) return;
    changing.current = true;
    invalidate();
    setBusy(true);
    try {
      const next = await prepareMacChange(macChangeRequest(selected, mode, mac));
      if (!mounted.current) return;
      setPlan(next);
      downloadScript(next.script, "aegis-mac-change.ps1");
    } catch (failure) {
      if (mounted.current) setError(failure.message);
    } finally {
      changing.current = false;
      if (mounted.current) setBusy(false);
    }
  }

  async function apply(event) {
    event.preventDefault();
    if (busy || changing.current || !supported || !state?.can_apply) return;
    changing.current = true;
    invalidate();
    setBusy(true);
    try {
      const changed = await changeMacDirectly(macChangeRequest(selected, mode, mac), {
        prepare: prepareMacChange, apply: applyMacChange,
        onPrepared: setPlan, isActive: () => mounted.current,
      });
      if (!changed || !mounted.current) return;
      const { plan: applied, result: outcome } = changed;
      setResult(outcome);
      setState((current) => current ? {
        ...current,
        adapters: current.adapters.map((item) => item.interface_id === applied.interface_id ? {
          ...item, current_mac: outcome.actual_mac,
          ...(outcome.status === "APPLIED" ? { override_mac: applied.mode === "restore" ? null : outcome.actual_mac } : {}),
        } : item),
      } : current);
    } catch (failure) {
      if (mounted.current) {
        setError(`${failure.message} Durum değişmiş olabilir; aktif MAC’i görmek için bağlantıları yenile.`);
      }
    } finally {
      changing.current = false;
      if (mounted.current) setBusy(false);
    }
  }

  return <section className="workbench-tool">
    <header>
      <p className="eyebrow">Windows host / Administrator</p>
      <h3>MAC yönetimi</h3>
      <span>Bağlantıyı seç, MAC gir veya rastgele üret, Uygula’ya bas. Fabrika adresine de dönebilirsin.</span>
      <button className="button button--secondary" onClick={refresh} disabled={busy}>{busy ? "İşlem sürüyor…" : "Bağlantıları yenile"}</button>
    </header>
    <p className="panel-help">Seçili yerel bağlantının MAC’i değişir ve bağlantı yeniden başlar; kısa kesinti olabilir.</p>
    {!state && <p className="panel-help">Yerel bağlantılar yükleniyor…</p>}
    {state?.platform !== "windows" && state && <p className="panel-help">{state.message}</p>}
    {state?.platform === "windows" && !state.can_apply && <p className="panel-help">Doğrudan değiştirmek için Windows backend’ini Yönetici olarak çalıştır. Alternatif: yönetici scriptini indir ve Yönetici PowerShell’de çalıştır.</p>}
    {error && <div className="form-error" role="alert">{error}</div>}
    {state?.platform === "windows" && !state.adapters.length && <p>Fiziksel adaptör bulunamadı.</p>}
    {!!state?.adapters.length && <form className="playbook-form" onSubmit={apply}>
      <label>Yerel bağlantı<select value={selected} disabled={busy} onChange={(event) => { invalidate(); setSelected(event.target.value); }}>
        {state.adapters.map((item) => <option value={item.interface_id} key={item.interface_id}>{item.name} · {item.status}{!item.supports_override ? " · MAC değiştirme desteklenmiyor" : ""}</option>)}
      </select></label>
      <label>Mod<select value={mode} disabled={busy} onChange={(event) => {
        invalidate();
        if (event.target.value === "random") randomize();
        else setMode(event.target.value);
      }}>
        <option value="manual">Manuel adres</option>
        <option value="random">Rastgele yerel/unicast</option>
        <option value="restore">Fabrika adresine dön</option>
      </select></label>
      {mode !== "restore" && <label>Yeni MAC<input value={mac} maxLength={17} placeholder="02:00:00:00:00:01" spellCheck={false} autoComplete="off" disabled={busy} onChange={(event) => { invalidate(); setMac(event.target.value); setMode("manual"); }} /></label>}
      <div className="row-actions">
        <button type="button" className="button button--secondary" onClick={randomize} disabled={busy}>Rastgele üret</button>
        <button type="submit" className="button" disabled={busy || !supported || !state.can_apply}>{busy ? "İşlem sürüyor…" : "Uygula"}</button>
        {!state.can_apply && <button type="button" className="button button--secondary" disabled={busy || !supported} onClick={downloadChange}>Yönetici scriptini indir</button>}
      </div>
    </form>}
    {adapter && <dl className="playbook-summary">
      <div><dt>Aktif MAC</dt><dd>{adapter.current_mac || "Okunamadı"}</dd></div>
      <div><dt>Fabrika MAC</dt><dd>{adapter.permanent_mac || "Sürücü bildirmiyor"}</dd></div>
      <div><dt>Sürücü desteği</dt><dd>{adapter.supports_override ? "NetworkAddress mevcut; uygulama sonrası doğrulanır" : "NetworkAddress yok"}</dd></div>
    </dl>}
    {plan && <article className="playbook-run">
      <h4>İşlem: {plan.previous_mac} → {plan.target_mac}</h4>
      <div className="row-actions">
        <button className="button button--secondary" disabled={busy} onClick={() => downloadScript(plan.rollback_script, "aegis-mac-rollback.ps1")}>Geri dönüş scriptini indir</button>
      </div>
    </article>}
    {result && <div className={result.status === "APPLIED" ? "panel-help" : "form-error"} role="status">
      {result.status === "APPLIED" ? "Doğrulandı" : "Doğrulanamadı"}: {result.actual_mac} · {result.message}
    </div>}
  </section>;
}
