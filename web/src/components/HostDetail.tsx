import { useEffect, useState, type FormEvent } from "react";
import { useApp } from "../store";
import type { Host } from "../types";
import { healthUrl } from "../util";
import { Confidence, DecisionBadge } from "./HostsPage";

/** Side drawer with everything that was found about one host, and the form to correct it. */
export function HostDetail({ host, busy, onClose }: { host: Host; busy: boolean; onClose: () => void }) {
  const { updateHosts } = useApp();
  const i = host.identity;
  const [app, setApp] = useState(i?.app || "");
  const [port, setPort] = useState(String(i?.web_port || ""));
  const [path, setPath] = useState(i?.health_path || "/");
  const [note, setNote] = useState(host.note);
  useEffect(() => {
    setApp(host.identity?.app || "");
    setPort(String(host.identity?.web_port || ""));
    setPath(host.identity?.health_path || "/");
    setNote(host.note);
  }, [host.ip, host.identity, host.note]);
  useEffect(() => {
    const esc = (e: KeyboardEvent) => e.key === "Escape" && onClose();
    window.addEventListener("keydown", esc);
    return () => window.removeEventListener("keydown", esc);
  }, [onClose]);

  const dirty = app !== (i?.app || "") || port !== String(i?.web_port || "") || path !== (i?.health_path || "/");
  const save = async (e: FormEvent) => {
    e.preventDefault();
    const body: Record<string, unknown> = { note };
    if (dirty) Object.assign(body, { app: app.trim().toLowerCase(), web_port: port ? Number(port) : 0, health_path: path || "/" });
    await updateHosts([host.ip], body);
  };
  const url = healthUrl(host);

  return (
    <>
      <div className="scrim" onClick={onClose} />
      <aside className="jobs-panel host-drawer" aria-label={`Host ${host.ip}`}>
        <header>
          <div>
            <h2>{host.name}</h2>
            <div className="muted small mono">{host.ip}{host.hostname && host.hostname !== host.name ? ` · ${host.hostname}` : ""}</div>
          </div>
          <button className="btn small" onClick={onClose} aria-label="Close">✕</button>
        </header>

        <div className="drawer-row">
          <DecisionBadge d={host.decision} />
          <Confidence host={host} />
          <span className="f-src">{i?.source || "not identified"}</span>
          <div className="actions">
            <button className="btn small primary" disabled={busy || host.decision === "approved"} onClick={() => updateHosts([host.ip], { decision: "approved" })}>Approve</button>
            <button className="btn small danger" disabled={busy || host.decision === "rejected"} onClick={() => updateHosts([host.ip], { decision: "rejected" })}>Reject</button>
          </div>
        </div>

        {i?.app && (
          <section>
            <h3>Identified as</h3>
            <p className="ident"><strong>{i.display_name || i.app}</strong> {i.version && <span className="mono small">{i.version}</span>} <span className="muted">· {i.category}</span></p>
            {i.description && <p className="muted small">{i.description}</p>}
            <dl className="facts-grid">
              {url && (<><dt>Health check</dt><dd className="mono"><a href={url} target="_blank" rel="noreferrer noopener">{url}</a></dd></>)}
              {i.metrics_port > 0 && (<><dt>Metrics</dt><dd className="mono">:{i.metrics_port}{i.metrics_path}</dd></>)}
              {i.exporter && (<><dt>Exporter</dt><dd className="mono">{i.exporter}</dd></>)}
              {i.community_script && (<><dt>Installed by</dt><dd className="mono">community-scripts: {i.community_script}</dd></>)}
            </dl>
            {i.reasons.length > 0 && (
              <>
                <h4>Why</h4>
                <ul className="reasons">{i.reasons.map((r, n) => <li key={n}>{r}</li>)}</ul>
              </>
            )}
          </section>
        )}

        <section>
          <h3>Correct it</h3>
          <form className="edit-host" onSubmit={save}>
            <label className="field"><span>App</span><input className="mono" value={app} onChange={(e) => setApp(e.target.value)} placeholder="jellyfin" spellCheck={false} pattern="[a-z0-9][a-z0-9._-]{0,59}" title="lower-case name like grafana or home-assistant" /></label>
            <label className="field"><span>Web port</span><input className="mono" value={port} onChange={(e) => setPort(e.target.value.replace(/\D/g, ""))} placeholder="8096" inputMode="numeric" /></label>
            <label className="field"><span>Health path</span><input className="mono" value={path} onChange={(e) => setPath(e.target.value)} placeholder="/health" spellCheck={false} /></label>
            <label className="field wide"><span>Note</span><textarea value={note} onChange={(e) => setNote(e.target.value)} maxLength={500} placeholder="Anything worth remembering about this host" /></label>
            <div className="popover-actions wide">
              <button className="btn small primary" type="submit" disabled={busy || (!dirty && note === host.note) || (dirty && !app.trim())}>
                {dirty ? "Save & approve" : "Save note"}
              </button>
            </div>
          </form>
          {dirty && <p className="muted small">Saving an app marks it as identified by hand (confidence 100%) and approves the host.</p>}
        </section>

        <section>
          <h3>Open ports</h3>
          {host.ports.length ? (
            <table className="mini">
              <thead><tr><th>Port</th><th>Service</th><th>Product</th><th>Version</th></tr></thead>
              <tbody>{host.ports.map((p) => <tr key={p.proto + p.port}><td className="mono">{p.port}/{p.proto}</td><td>{p.service}</td><td>{p.product}</td><td className="mono small">{p.version} {p.extra}</td></tr>)}</tbody>
            </table>
          ) : <p className="muted small">No open ports found.</p>}
        </section>

        {host.http.length > 0 && (
          <section>
            <h3>Web</h3>
            <table className="mini">
              <thead><tr><th>Port</th><th>Status</th><th>Title</th><th>Server</th></tr></thead>
              <tbody>{host.http.map((w) => <tr key={w.port}><td className="mono">{w.scheme}:{w.port}</td><td className="mono">{w.status || "—"}</td><td>{w.title || w.body_hint || <span className="muted">—</span>}{w.location && <div className="cell-sub">→ {w.location}</div>}</td><td className="small">{[w.server, w.powered_by, w.generator].filter(Boolean).join(" · ")}</td></tr>)}</tbody>
            </table>
          </section>
        )}

        <section>
          <h3>Found by</h3>
          <dl className="facts-grid">
            <dt>Sources</dt><dd>{host.sources.join(", ") || "—"}</dd>
            {host.mac && (<><dt>MAC</dt><dd className="mono">{host.mac} {host.vendor && <span className="muted">· {host.vendor}</span>}</dd></>)}
            {host.proxmox && (
              <>
                <dt>Proxmox</dt>
                <dd>{host.proxmox.type} {host.proxmox.vmid} on {host.proxmox.node} ({host.proxmox.endpoint}) · {host.proxmox.status}</dd>
                {host.proxmox.tags.length > 0 && (<><dt>Tags</dt><dd>{host.proxmox.tags.map((t) => <span key={t} className="tag">{t}</span>)}</dd></>)}
                {(host.proxmox.cores > 0 || host.proxmox.memory_mb > 0) && (<><dt>Size</dt><dd>{host.proxmox.cores} cores · {Math.round(host.proxmox.memory_mb / 102.4) / 10} GB</dd></>)}
              </>
            )}
          </dl>
        </section>
      </aside>
    </>
  );
}
