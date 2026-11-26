import { useEffect, useRef, useState, type FormEvent } from "react";
import { api, AuthError } from "../api";
import { useApp } from "../store";
import { isActive } from "../types";
import { jobTitle } from "../util";

export function TopBar() {
  const { status: st, jobs, setJobsOpen, jobsOpen } = useApp();
  const active = jobs.filter(isActive);
  const running = active.find((j) => j.status === "running");
  return (
    <header className="topbar">
      <div className="brand">
        <img src="/favicon.svg" alt="" /> labscout <small>{st ? "v" + st.version : ""}</small>
      </div>
      <div className="status-pills">
        {st && (
          <>
            {st.use_llm ? (
              <>
                <span className="pill" title={st.ollama_error || st.ollama_host}>
                  <span className={"dot " + (st.ollama ? "ok" : "bad")} />
                  {st.ollama ? `Ollama ${st.ollama}` : "Ollama unreachable"}
                </span>
                <ModelPicker />
              </>
            ) : (
              <span className="pill" title="use_llm is false in the config"><span className="dot warn" />AI off: rules only</span>
            )}
            <span className="pill" title={st.nmap || "nmap is not installed: TCP connect scan, no service versions or MACs"}>
              <span className={"dot " + (st.nmap ? "ok" : "warn")} />
              {st.nmap ? "nmap" : "no nmap"}
            </span>
            <span className="pill" title={st.netbox || "netbox_url is not set"}>
              <span className={"dot " + (st.netbox ? "ok" : "off")} />
              NetBox
            </span>
          </>
        )}
        <button className={"pill keep jobs-pill" + (active.length ? " busy" : "")} onClick={() => setJobsOpen(!jobsOpen)} aria-expanded={jobsOpen}>
          <span className={"dot " + (running ? "run" : active.length ? "wait" : "ok")} />
          {active.length ? (running ? jobTitle(running) : "Waiting") : "Jobs"}
          {active.length > 1 && <span className="count-badge">+{active.length - 1}</span>}
        </button>
      </div>
    </header>
  );
}

/** The model every new scan uses; click to pick another one. */
export function ModelPicker() {
  const { status: st, setModel } = useApp();
  const [open, setOpen] = useState(false);
  const [choice, setChoice] = useState("");
  const [busy, setBusy] = useState(false);
  const box = useRef<HTMLDivElement>(null);
  const current = st?.model ?? "";
  useEffect(() => {
    if (open) setChoice(current);   // only when it opens: a status refresh must not wipe what you typed
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [open]);
  useEffect(() => {
    if (!open) return;
    const away = (e: MouseEvent) => box.current && !box.current.contains(e.target as Node) && setOpen(false);
    const esc = (e: KeyboardEvent) => e.key === "Escape" && setOpen(false);
    document.addEventListener("mousedown", away);
    window.addEventListener("keydown", esc);
    return () => {
      document.removeEventListener("mousedown", away);
      window.removeEventListener("keydown", esc);
    };
  }, [open]);
  if (!st) return null;

  const installed = st.models || [];
  const name = choice.trim();
  const known = installed.includes(name);
  const valid = /^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$/.test(name);
  const save = async (value: string) => {
    setBusy(true);
    const ok = await setModel(value);
    setBusy(false);
    if (ok) setOpen(false);
  };
  const dot = !st.ollama ? "bad" : st.model_available ? "ok" : "warn";
  return (
    <div className="model-picker" ref={box}>
      <button className="pill keep pill-button" aria-expanded={open} aria-haspopup="dialog" onClick={() => setOpen(!open)}
        title={!st.ollama ? "Ollama is not reachable" : st.model_available ? "Model in use; click to change" : `Not in Ollama yet: ollama pull ${st.model}`}>
        <span className={"dot " + dot} />
        {st.model}
        <span className="caret">▾</span>
      </button>
      {open && (
        <div className="popover" role="dialog" aria-label="Model">
          <h3>Model</h3>
          <p className="muted small">Used to identify hosts in every new scan. A model set on the Scan page still wins there.</p>
          {installed.length > 0 ? (
            <ul className="model-list" role="listbox" aria-label="Models in Ollama">
              {installed.map((m) => (
                <li key={m}>
                  <button role="option" aria-selected={m === name} className={m === name ? "on" : undefined} onClick={() => setChoice(m)}>
                    <span className="mono">{m}</span>
                    {m === st.default_model && <span className="tag">default</span>}
                    {m === st.model && <span className="tag now">in use</span>}
                  </button>
                </li>
              ))}
            </ul>
          ) : (
            <p className="muted small">{st.ollama ? "Ollama has no models yet." : "Ollama is not reachable, so its models are not listed."}</p>
          )}
          <label className="field">
            <span className="small muted">Or type a name</span>
            <input className="mono" value={choice} onChange={(e) => setChoice(e.target.value)} placeholder="qwen2.5:14b" spellCheck={false} />
          </label>
          {name && valid && !known && st.ollama && (
            <p className="hint-warn small">Not in Ollama yet. On the Ollama machine run <code>ollama pull {name}</code>, or identification will fail.</p>
          )}
          {name && !valid && <p className="hint-warn small">Not a valid model name.</p>}
          <div className="popover-actions">
            {st.model_source === "ui" && (
              <button className="btn small" disabled={busy} onClick={() => save("")} title="Use the model from the config / LABSCOUT_MODEL again">
                Use default ({st.default_model})
              </button>
            )}
            <button className="btn small primary" disabled={busy || !valid || name === st.model} onClick={() => save(name)}>
              {busy ? "Saving…" : "Use this model"}
            </button>
          </div>
        </div>
      )}
    </div>
  );
}

export function Login() {
  const { setAuthed, refreshHosts } = useApp();
  const [token, setToken] = useState("");
  const [error, setError] = useState("");
  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setError("");
    try {
      await api("login", { method: "POST", body: { token } });
      setToken("");
      setAuthed(true);
      refreshHosts();
    } catch (err) {
      setError(err instanceof AuthError ? "Wrong token." : (err as Error).message);
    }
  };
  return (
    <div className="center-box">
      <img src="/favicon.svg" alt="" width={44} height={44} />
      <h1>Access token needed</h1>
      <p>Open the link that <code>labscout serve</code> printed in the terminal, or paste the token here.</p>
      <form onSubmit={submit}>
        <input type="password" placeholder="token" autoComplete="off" required autoFocus value={token} onChange={(e) => setToken(e.target.value)} />
        <button className="btn primary" type="submit">Sign in</button>
      </form>
      <div className="form-error">{error}</div>
    </div>
  );
}

export function Toasts() {
  const { toasts, dismiss } = useApp();
  if (!toasts.length) return null;
  return (
    <div className="toasts" role="status" aria-live="polite">
      {toasts.map((t) => (
        <div key={t.id} className={"toast" + (t.kind ? " " + t.kind : "")}>
          <span>{t.text}</span>
          {t.link && (t.link.href ? (
            <a href={t.link.href} download={t.link.download || undefined} onClick={() => dismiss(t.id)}>{t.link.label}</a>
          ) : (
            <button className="linklike" onClick={() => { t.link!.onClick?.(); dismiss(t.id); }}>{t.link.label}</button>
          ))}
          <button className="toast-x" onClick={() => dismiss(t.id)} aria-label="Dismiss">✕</button>
        </div>
      ))}
    </div>
  );
}
