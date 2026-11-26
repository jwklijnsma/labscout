import { useEffect, useState } from "react";
import { useApp } from "../store";
import type { Action } from "../types";
import { ago, parseNetworks, stored, store, validCidr } from "../util";

export function ScanPage() {
  const { status, data, startJob, jobs } = useApp();
  const [nets, setNets] = useState<string>(() => stored("networks", ""));
  const [noAi, setNoAi] = useState(false);
  const [force, setForce] = useState(false);
  const [workers, setWorkers] = useState(1);
  useEffect(() => store("networks", nets), [nets]);

  const list = parseNetworks(nets);
  const bad = list.filter((n) => !validCidr(n));
  const busy = jobs.some((j) => j.status === "running" && ["run", "scan", "identify"].includes(j.action));
  const go = (action: Action) => {
    const opts: Record<string, unknown> = {};
    if (action !== "identify" && list.length) opts.networks = list;
    if (noAi) opts.no_ai = true;
    if (workers > 1) opts.workers = workers;
    if (action === "identify" && force) opts.force = true;
    startJob(action, opts);
  };

  return (
    <>
      <div className="repo-head">
        <div>
          <h1>Scan</h1>
          <div className="repo-sub"><span>Last scan {ago(data?.scanned)} · {data?.hosts.length ?? 0} hosts</span></div>
        </div>
      </div>

      <div className="card">
        <div className="card-head"><h3>What to scan</h3></div>
        <div className="opt-grid">
          <fieldset>
            <legend>Networks</legend>
            <label className="field">
              <span className="small muted">Empty = the networks from labscout.yml{status?.networks.length ? `: ${status.networks.join(", ")}` : ""}</span>
              <textarea className="mono" value={nets} onChange={(e) => setNets(e.target.value)} placeholder={(status?.networks || ["10.0.3.0/24"]).join("\n")} rows={3} spellCheck={false} />
            </label>
            {bad.length > 0 && <p className="hint-warn small">Not a network (or larger than /16): {bad.join(", ")}</p>}
          </fieldset>
          <fieldset>
            <legend>Identification</legend>
            <label className="check"><input type="checkbox" checked={noAi} onChange={(e) => setNoAi(e.target.checked)} /> Built-in rules only (no Ollama)</label>
            <label className="check"><input type="checkbox" checked={force} onChange={(e) => setForce(e.target.checked)} /> Identify: ask the model again, ignore the cache</label>
            <label className="field">
              <span className="small muted">Parallel model requests (match OLLAMA_NUM_PARALLEL)</span>
              <select value={workers} onChange={(e) => setWorkers(Number(e.target.value))}>
                {[1, 2, 3, 4, 6, 8].map((n) => <option key={n} value={n}>{n}</option>)}
              </select>
            </label>
            <p className="muted small">Model: <span className="mono">{status?.use_llm ? status.model : "off"}</span> (change it in the top bar).</p>
          </fieldset>
          <fieldset>
            <legend>Sources</legend>
            <ul className="cat-list">
              <li><span>nmap</span><span className="mono">{status?.nmap ? "yes" : "TCP connect fallback"}</span></li>
              <li><span>Proxmox</span><span className="mono">{status?.proxmox.join(", ") || "none"}</span></li>
              <li><span>NetAlertX</span><span className="mono">{status?.netalertx ? "yes" : "no"}</span></li>
            </ul>
            <p className="muted small">Tokens and endpoints come from labscout.yml and the environment, never from this page.</p>
          </fieldset>
        </div>
        <div className="card-body scan-actions">
          <button className="btn primary" disabled={busy || bad.length > 0} onClick={() => go("run")}>Scan, identify & plan</button>
          <button className="btn" disabled={busy || bad.length > 0} onClick={() => go("scan")}>Scan only</button>
          <button className="btn" disabled={busy || !data?.hosts.length} onClick={() => go("identify")}>Identify again</button>
          {busy && <span className="muted small">A scan is running; see Jobs.</span>}
        </div>
      </div>
      <p className="muted small">Your decisions (approve, reject, set by hand) carry over to the next scan as long as a host keeps its IP. Unchanged hosts are not sent to the model again.</p>
    </>
  );
}
