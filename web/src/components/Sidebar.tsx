import { useMemo } from "react";
import { go, useApp, type Page } from "../store";
import { ago } from "../util";

export function Sidebar({ page }: { page: Page }) {
  const { data, status } = useApp();
  const cats = useMemo(() => {
    const c = new Map<string, number>();
    for (const h of data?.hosts || []) {
      const k = h.identity?.app ? h.identity.category || "other" : "unknown";
      c.set(k, (c.get(k) || 0) + 1);
    }
    return [...c.entries()].sort((a, b) => b[1] - a[1]);
  }, [data]);
  const n = data?.hosts.length ?? 0;
  const item = (p: Page, label: string, meta: string) => (
    <li>
      <button aria-current={page === p} onClick={() => go(p)}>
        <div className="repo-name">{label}</div>
        <div className="repo-meta">{meta}</div>
      </button>
    </li>
  );
  return (
    <nav className="sidebar" aria-label="Pages">
      <h2>labscout</h2>
      <ul className="repo-list">
        {item("hosts", "Hosts", n ? `${n} found · ${data!.counts.pending} to review` : "no scan yet")}
        {item("plan", "Plan & apply", data ? `${data.counts.approved} approved` : "")}
        {item("scan", "Scan", data?.scanned ? `last ${ago(data.scanned)}` : "start here")}
      </ul>
      {cats.length > 0 && (
        <>
          <h2 className="side-gap">Categories</h2>
          <ul className="cat-list">
            {cats.map(([c, k]) => (
              <li key={c}>
                <a href={`#/hosts?cat=${encodeURIComponent(c)}`}>{c}</a>
                <span className="mono">{k}</span>
              </li>
            ))}
          </ul>
        </>
      )}
      {status && (
        <>
          <h2 className="side-gap">Sources</h2>
          <ul className="cat-list">
            <li><span>networks</span><span className="mono">{status.networks.length}</span></li>
            <li><span>Proxmox APIs</span><span className="mono">{status.proxmox.length}</span></li>
            <li><span>NetAlertX</span><span className="mono">{status.netalertx ? "on" : "off"}</span></li>
            <li><span>infra repo</span><span className="mono">{status.infra ? "set" : "off"}</span></li>
          </ul>
        </>
      )}
    </nav>
  );
}
