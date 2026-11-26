import { useEffect, useState } from "react";
import { api } from "../api";
import { useApp } from "../store";
import type { PlanResponse } from "../types";
import { plural } from "../util";

function Section({ title, count, children, hint }: { title: string; count: number; hint?: string; children: React.ReactNode }) {
  return (
    <div className="card">
      <div className="card-head">
        <h3>{title}</h3>
        <span className="count mono">{count}</span>
        {hint && <span className="muted small">{hint}</span>}
      </div>
      <div className="card-body">{count ? children : <p className="muted small">Nothing.</p>}</div>
    </div>
  );
}

const flow = (spec: Record<string, unknown>) =>
  "{ " + Object.entries(spec).map(([k, v]) => `${k}: ${typeof v === "object" ? JSON.stringify(v) : String(v)}`).join(", ") + " }";

export function PlanPage() {
  const { status, version, startJob, jobs, handleError } = useApp();
  const [pending, setPending] = useState(false);
  const [data, setData] = useState<PlanResponse | null>(null);
  const [confirm, setConfirm] = useState<"netbox" | "infra" | null>(null);

  useEffect(() => {
    let stop = false;
    api<PlanResponse>(`plan${pending ? "?include_pending=1" : ""}`)
      .then((d) => !stop && setData(d))
      .catch((e) => !stop && handleError(e));
    return () => {
      stop = true;
    };
  }, [pending, version, handleError]);

  const busy = jobs.some((j) => j.status === "running" || j.status === "queued");
  const p = data?.plan;
  const apply = (target: "netbox" | "infra" | "both", dry: boolean) => {
    setConfirm(null);
    const opts: Record<string, unknown> = { include_pending: pending || undefined, dry_run: dry || undefined };
    if (target !== "infra") opts.netbox = true;
    if (target !== "netbox") opts.infra = true;
    startJob("apply", opts);
  };
  const canNetbox = !!status?.netbox;
  const canInfra = !!status?.infra;

  return (
    <>
      <div className="repo-head">
        <div>
          <h1>Plan & apply</h1>
          <div className="repo-sub">
            <span>{p ? `${plural(p.monitoring.length, "monitoring entry", "monitoring entries")} · ${plural(p.netbox.length, "NetBox address", "NetBox addresses")} · ${p.skipped.length} not planned` : "…"}</span>
          </div>
        </div>
        <div className="actions">
          <label className="check" title="Also plan hosts nobody has approved yet">
            <input type="checkbox" checked={pending} onChange={(e) => setPending(e.target.checked)} /> include pending hosts
          </label>
          <button className="btn" disabled={busy} onClick={() => startJob("plan", { include_pending: pending || undefined })}>Write report</button>
          <a className="btn" href="/api/download/report.md" download>↓ report.md</a>
          <a className="btn" href="/api/download/plan.json" download>↓ plan.json</a>
        </div>
      </div>

      <div className="card apply-card">
        <div className="card-head"><h3>Apply</h3><span className="muted small">Runs as a background job. A preview changes nothing.</span></div>
        <div className="card-body apply-grid">
          <div>
            <strong>NetBox</strong>
            <p className="muted small">{canNetbox ? `IP addresses and services in ${status!.netbox}, tagged labscout. Descriptions people wrote are kept.` : "Set netbox_url in labscout.yml and the token in $NETBOX_TOKEN."}</p>
            <button className="btn small" disabled={!canNetbox || busy} onClick={() => apply("netbox", true)}>Preview</button>{" "}
            <button className="btn small primary" disabled={!canNetbox || busy} onClick={() => setConfirm("netbox")}>Write to NetBox</button>
          </div>
          <div>
            <strong>Infra repo</strong>
            <p className="muted small">{canInfra ? `Catalog entries and aliases, committed on branch labscout/apps of ${status!.infra}. Never pushed.` : "Set infra_repo in labscout.yml."}</p>
            <button className="btn small" disabled={!canInfra || busy} onClick={() => apply("infra", true)}>Preview diff</button>{" "}
            <button className="btn small primary" disabled={!canInfra || busy} onClick={() => setConfirm("infra")}>Commit on a branch</button>
          </div>
        </div>
        {confirm && (
          <div className="confirm-bar">
            <span>{confirm === "netbox" ? `Write ${plural(p?.netbox.length || 0, "address", "addresses")} to NetBox?` : `Commit ${plural(Object.keys(p?.catalog_add || {}).length, "catalog entry", "catalog entries")} and ${plural(Object.keys(p?.aliases_add || {}).length, "alias", "aliases")} to labscout/apps?`}</span>
            <button className="btn small primary" onClick={() => apply(confirm, false)}>Yes, apply</button>
            <button className="btn small" onClick={() => setConfirm(null)}>Cancel</button>
          </div>
        )}
      </div>

      {p && (
        <>
          <Section title="New apps for the infra catalog" count={Object.keys(p.catalog_add).length} hint="apps.yml">
            <pre className="code-block">{Object.entries(p.catalog_add).map(([k, v]) => `${k}: ${flow(v)}`).join("\n")}</pre>
          </Section>
          <Section title="Aliases" count={Object.keys(p.aliases_add).length} hint="guest name → app">
            <pre className="code-block">{Object.entries(p.aliases_add).map(([k, v]) => `${k}: ${v}`).join("\n")}</pre>
          </Section>
          <Section title="Monitoring" count={p.monitoring.length}>
            <table className="mini">
              <thead><tr><th>Host</th><th>App</th><th>Health check</th><th>Metrics</th><th>Exporter</th><th>node_exporter</th></tr></thead>
              <tbody>{p.monitoring.map((m) => <tr key={m.ip + m.app}><td>{m.host}<div className="cell-sub mono">{m.ip}</div></td><td>{m.app}</td><td className="mono small">{m.check}</td><td className="mono small">{m.metrics}</td><td className="small">{m.exporter}</td><td>{m.node_exporter ? "add" : ""}</td></tr>)}</tbody>
            </table>
          </Section>
          <Section title="NetBox" count={p.netbox.length}>
            <table className="mini">
              <thead><tr><th>Address</th><th>DNS name</th><th>Description</th><th>VM</th><th>Services</th></tr></thead>
              <tbody>{p.netbox.map((n) => <tr key={n.ip}><td className="mono">{n.ip}<span className="muted">/{n.cidr.split("/")[1] || "32"}</span></td><td className="mono small">{n.dns_name}</td><td className="small">{n.description}</td><td>{n.vm}</td><td className="mono small">{n.services.map((s) => `${s.name}:${s.port}`).join(", ")}</td></tr>)}</tbody>
            </table>
          </Section>
          <Section title="Not identified" count={p.unknown.length} hint="look at these by hand">
            <table className="mini">
              <thead><tr><th>IP</th><th>Name</th><th>Vendor</th><th>Ports</th><th>Guess</th></tr></thead>
              <tbody>{p.unknown.map((u) => <tr key={u.ip}><td className="mono"><a href={`#/hosts/${encodeURIComponent(u.ip)}`}>{u.ip}</a></td><td>{u.name}</td><td className="small">{u.vendor}</td><td className="mono small">{u.ports.join(" ")}</td><td>{u.guess}</td></tr>)}</tbody>
            </table>
          </Section>
        </>
      )}
    </>
  );
}
