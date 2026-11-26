import { useEffect, useMemo, useState } from "react";
import { go, useApp } from "../store";
import { DECISIONS, type Decision, type Host } from "../types";
import { ago, confLevel, ipKey, plural, searchText, stored, store } from "../util";
import { HostDetail } from "./HostDetail";

const SOURCES = ["all", "rule", "ai", "rule+ai", "manual", "proxmox", "none"] as const;
type Source = (typeof SOURCES)[number];

function catFromHash(): string {
  const m = location.hash.match(/[?&]cat=([^&]+)/);
  return m ? decodeURIComponent(m[1]) : "";
}

export function filterHosts(hosts: Host[], f: { q: string; decisions: Decision[]; source: Source; cat: string }): Host[] {
  const q = f.q.trim().toLowerCase();
  return hosts
    .filter((h) => f.decisions.includes(h.decision))
    .filter((h) => f.source === "all" || (f.source === "none" ? !h.identity?.app : h.identity?.source === f.source))
    .filter((h) => !f.cat || (h.identity?.app ? h.identity.category || "other" : "unknown") === f.cat)
    .filter((h) => !q || q.split(/\s+/).every((w) => searchText(h).includes(w)))
    .sort((a, b) => ipKey(a.ip).localeCompare(ipKey(b.ip)));
}

export function Confidence({ host }: { host: Host }) {
  const i = host.identity;
  if (!i?.app) return <span className="muted small">—</span>;
  const pct = Math.round(i.confidence * 100);
  return (
    <span className={"conf conf-" + confLevel(host)} title={`${pct}% · ${i.source}`}>
      <span className="conf-bar"><span style={{ width: `${pct}%` }} /></span>
      <span className="mono">{pct}%</span>
    </span>
  );
}

export function DecisionBadge({ d }: { d: Decision }) {
  return <span className={"badge dec-" + d}>{d}</span>;
}

export function HostsPage({ ip }: { ip: string | null }) {
  const { data, approveAbove, updateHosts, jobs, startJob } = useApp();
  const [q, setQ] = useState("");
  const [decisions, setDecisions] = useState<Decision[]>(() => stored("decisions", ["pending", "approved"] as Decision[]));
  const [source, setSource] = useState<Source>("all");
  const [cat, setCat] = useState(catFromHash);
  const [sel, setSel] = useState<Set<string>>(new Set());
  const [threshold, setThreshold] = useState(() => stored("threshold", 0.9));

  useEffect(() => {
    const on = () => setCat(catFromHash());
    window.addEventListener("hashchange", on);
    return () => window.removeEventListener("hashchange", on);
  }, []);
  useEffect(() => store("decisions", decisions), [decisions]);
  useEffect(() => store("threshold", threshold), [threshold]);

  const hosts = data?.hosts || [];
  const shown = useMemo(() => filterHosts(hosts, { q, decisions, source, cat }), [hosts, q, decisions, source, cat]);
  const selected = shown.filter((h) => sel.has(h.ip)).map((h) => h.ip);
  const busy = jobs.some((j) => j.status === "running" && ["run", "scan", "identify"].includes(j.action));
  const current = ip ? hosts.find((h) => h.ip === ip) : undefined;
  const unknown = hosts.filter((h) => !h.identity?.app).length;
  const sure = hosts.filter((h) => h.decision === "pending" && h.identity?.app && h.identity.confidence >= threshold).length;

  if (!data) return null;
  if (!hosts.length) {
    return (
      <div className="empty">
        <h3>No scan results yet</h3>
        <p>Start a scan of your networks: labscout finds the hosts, then works out what runs on them.</p>
        <button className="btn primary" disabled={busy} onClick={() => startJob("run")}>Scan the configured networks</button>{" "}
        <button className="btn" onClick={() => go("scan")}>Scan options…</button>
      </div>
    );
  }

  const toggleDecision = (d: Decision) => setDecisions((cur) => (cur.includes(d) ? (cur.length > 1 ? cur.filter((x) => x !== d) : cur) : [...cur, d]));
  const toggle = (h: Host) =>
    setSel((s) => {
      const n = new Set(s);
      if (n.has(h.ip)) n.delete(h.ip);
      else n.add(h.ip);
      return n;
    });
  const all = shown.length > 0 && selected.length === shown.length;
  const bulk = async (decision: Decision) => {
    if (await updateHosts(selected, { decision })) setSel(new Set());
  };

  return (
    <>
      <div className="repo-head">
        <div>
          <h1>Hosts</h1>
          <div className="repo-sub">
            <span>{plural(hosts.length, "host")} · scanned {ago(data.scanned)}</span>
            {busy && <span className="badge dirty">a scan is rewriting these results</span>}
          </div>
        </div>
        <div className="actions">
          <label className="inline-field" title="Approve every pending host identified with at least this confidence">
            <select value={threshold} onChange={(e) => setThreshold(Number(e.target.value))} aria-label="Confidence threshold">
              {[0.99, 0.95, 0.9, 0.85, 0.75, 0.6].map((t) => <option key={t} value={t}>≥ {Math.round(t * 100)}%</option>)}
            </select>
            <button className="btn" disabled={busy || !sure} onClick={() => approveAbove(threshold)}>{sure ? `Approve ${sure} sure ${sure === 1 ? "one" : "ones"}` : "Approve sure ones"}</button>
          </label>
          <button className="btn primary" disabled={busy} onClick={() => startJob("run")}>Rescan</button>
        </div>
      </div>

      <div className="summary-row">
        {DECISIONS.map((d) => (
          <button key={d} className="sev-chip" aria-pressed={decisions.includes(d)} onClick={() => toggleDecision(d)}>
            <span className="n">{data.counts[d] || 0}</span>
            <span className="l"><span className={"sw dec-sw-" + d} />{d}</span>
          </button>
        ))}
        <button className="sev-chip" aria-pressed={source === "none"} onClick={() => setSource(source === "none" ? "all" : "none")}>
          <span className="n">{unknown}</span>
          <span className="l"><span className="sw dec-sw-unknown" />not identified</span>
        </button>
      </div>

      <div className="filters">
        <input type="search" placeholder="Search IP, name, app, port, MAC, tag…" value={q} onChange={(e) => setQ(e.target.value)} aria-label="Search hosts" />
        <div className="seg" role="group" aria-label="Identified by">
          {SOURCES.filter((s) => s !== "none").map((s) => (
            <button key={s} aria-pressed={source === s} onClick={() => setSource(s)}>{s}</button>
          ))}
        </div>
        {cat && (
          <button className="btn small" onClick={() => (location.hash = "#/hosts")} title="Clear the category filter">
            category: {cat} ✕
          </button>
        )}
      </div>

      {selected.length > 0 && (
        <div className="bulk-bar">
          <strong>{plural(selected.length, "host")} selected</strong>
          <button className="btn small primary" disabled={busy} onClick={() => bulk("approved")}>Approve</button>
          <button className="btn small danger" disabled={busy} onClick={() => bulk("rejected")}>Reject</button>
          <button className="btn small" disabled={busy} onClick={() => bulk("pending")}>Back to pending</button>
          <button className="btn small" onClick={() => setSel(new Set())}>Clear</button>
        </div>
      )}

      <div className="card table-card">
        <table className="hosts">
          <thead>
            <tr>
              <th className="cb"><input type="checkbox" checked={all} onChange={() => setSel(all ? new Set() : new Set(shown.map((h) => h.ip)))} aria-label="Select all shown hosts" /></th>
              <th>IP</th>
              <th>Name</th>
              <th>Runs</th>
              <th className="hide-s">Ports</th>
              <th className="hide-s">Source</th>
              <th>Confidence</th>
              <th>Decision</th>
              <th />
            </tr>
          </thead>
          <tbody>
            {shown.map((h) => (
              <tr key={h.ip} className={h.ip === ip ? "on" : undefined} onClick={() => go("hosts", h.ip)}>
                <td className="cb" onClick={(e) => e.stopPropagation()}>
                  <input type="checkbox" checked={sel.has(h.ip)} onChange={() => toggle(h)} aria-label={`Select ${h.ip}`} />
                </td>
                <td className="mono">{h.ip}</td>
                <td>
                  <div className="cell-main">{h.name}</div>
                  {h.proxmox && <div className="cell-sub">{h.proxmox.type === "node" ? `Proxmox node · ${h.proxmox.endpoint}` : `${h.proxmox.type} ${h.proxmox.vmid} · ${h.proxmox.node}`}</div>}
                </td>
                <td>
                  {h.identity?.app ? (
                    <>
                      <div className="cell-main">{h.identity.display_name || h.identity.app} {h.identity.version && <span className="muted small">{h.identity.version}</span>}</div>
                      <div className="cell-sub">{h.identity.category}</div>
                    </>
                  ) : (
                    <span className="muted">not identified</span>
                  )}
                </td>
                <td className="mono small hide-s">{h.ports.slice(0, 6).map((p) => p.port).join(" ")}{h.ports.length > 6 ? " …" : ""}</td>
                <td className="hide-s"><span className="f-src">{h.identity?.source || "—"}</span></td>
                <td><Confidence host={h} /></td>
                <td><DecisionBadge d={h.decision} /></td>
                <td className="row-actions" onClick={(e) => e.stopPropagation()}>
                  <button className="icon-btn ok" title="Approve" aria-label={`Approve ${h.ip}`} disabled={busy || h.decision === "approved"} onClick={() => updateHosts([h.ip], { decision: "approved" })}>✓</button>
                  <button className="icon-btn bad" title="Reject" aria-label={`Reject ${h.ip}`} disabled={busy || h.decision === "rejected"} onClick={() => updateHosts([h.ip], { decision: "rejected" })}>✕</button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
        {!shown.length && <div className="empty"><p>No host matches these filters.</p></div>}
      </div>

      {current && <HostDetail host={current} busy={busy} onClose={() => go("hosts")} />}
    </>
  );
}
