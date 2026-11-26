"use strict";
// labscout web UI: plain JS, no build step, no external assets.
const $ = (s, el = document) => el.querySelector(s);
let S = null;
let detailIp = null;

async function api(path, body) {
  const opts = body === undefined ? {} : {
    method: "POST", headers: { "Content-Type": "application/json", "X-Labscout": "1" },
    body: JSON.stringify(body),
  };
  const r = await fetch(path, opts);
  const data = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(data.error || r.statusText);
  return data;
}

function el(tag, attrs = {}, ...kids) {
  const e = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (k === "class") e.className = v;
    else if (k.startsWith("on")) e.addEventListener(k.slice(2), v);
    else e.setAttribute(k, v);
  }
  for (const k of kids.flat()) if (k !== null && k !== undefined) e.append(k.nodeType ? k : String(k));
  return e;
}

const confClass = c => (c >= 0.85 ? "c-hi" : c >= 0.6 ? "c-mid" : "c-lo");

function renderSummary() {
  const hosts = S.hosts;
  const by = d => hosts.filter(h => h.decision === d).length;
  const ai = hosts.filter(h => h.identity && h.identity.source.includes("ai")).length;
  const p = S.plan;
  $("#summary").replaceChildren(
    ...[["hosts", hosts.length], ["approved", by("approved")], ["pending", by("pending")],
        ["identified by AI", ai], ["new apps for infra", Object.keys(p.catalog_add).length],
        ["not identified", p.unknown.length]]
      .map(([k, v]) => el("div", { class: "card" }, el("b", {}, v), el("span", { class: "muted" }, k))));
  $("#meta").textContent = `v${S.version} · ${S.model ? "model " + S.model : "AI off"} · ${S.networks.join(", ")}`;
  $("#btn-netbox").disabled = !S.netbox;
  $("#btn-infra").disabled = !S.infra;
}

function renderHosts() {
  const f = $("#filter").value.toLowerCase();
  const onlyPending = $("#only-pending").checked;
  const rows = S.hosts.filter(h => {
    if (onlyPending && h.decision !== "pending") return false;
    const i = h.identity || {};
    return !f || [h.ip, h.name, i.app, i.category, h.vendor].join(" ").toLowerCase().includes(f);
  }).map(h => {
    const i = h.identity || {};
    const check = i.web_port ? `${i.scheme}://${h.ip}:${i.web_port}${i.health_path}` : "";
    const mon = [i.metrics_port ? `metrics :${i.metrics_port}${i.metrics_path}` : "",
                 i.exporter ? `exporter: ${i.exporter}` : ""].filter(Boolean).join(" · ");
    const dec = el("td", { class: "dec" }, ...["approved", "rejected", "pending"].map(d =>
      el("button", { class: (h.decision === d ? "on " : "") + d, title: d,
                     onclick: () => setHost({ ip: h.ip, decision: d }) },
         d === "approved" ? "✓" : d === "rejected" ? "✗" : "?")));
    return el("tr", {},
      el("td", { class: "ip" }, el("a", { href: "#", onclick: e => { e.preventDefault(); openDetail(h); } }, h.ip)),
      el("td", {}, h.name, h.proxmox ? el("span", { class: "tag" }, `${h.proxmox.type} ${h.proxmox.vmid || ""}`) : null),
      el("td", {}, i.display_name || i.app || "?", i.version ? el("span", { class: "muted" }, " " + i.version) : null),
      el("td", {}, i.category || ""),
      el("td", {}, i.source || ""),
      el("td", { class: "conf " + confClass(i.confidence || 0) }, i.confidence ? i.confidence.toFixed(2) : ""),
      el("td", {}, check ? el("code", {}, check) : ""),
      el("td", {}, mon),
      dec);
  });
  $("#hosts tbody").replaceChildren(...rows);
}

function renderPlan() {
  const p = S.plan;
  const kids = [el("h2", {}, "Plan (approved hosts)")];
  const cat = Object.entries(p.catalog_add);
  if (cat.length) kids.push(el("p", {}, "New apps for the infra catalog:"),
    el("pre", {}, cat.map(([k, v]) => `${k}: ${JSON.stringify(v)}`).join("\n")));
  const al = Object.entries(p.aliases_add);
  if (al.length) kids.push(el("p", {}, "Aliases:"), el("pre", {}, al.map(([k, v]) => `${k}: ${v}`).join("\n")));
  if (!cat.length && !al.length) kids.push(el("p", { class: "muted" }, "Nothing new for the infra repo (approve hosts first)."));
  kids.push(el("p", { class: "muted" }, `${p.netbox.length} addresses for NetBox, ${p.monitoring.length} monitoring entries.`));
  $("#plan").replaceChildren(...kids);
}

function renderJob(j) {
  $("#job-state").textContent = j.name ? `${j.name} · ${j.running ? "running…" : "exit " + j.rc}` : "";
  $("#log").textContent = j.log.join("\n");
  $("#log").scrollTop = 1e9;
  document.querySelectorAll("nav button[data-job]").forEach(b => {
    if (b.id === "btn-netbox" && !S?.netbox) return;
    if (b.id === "btn-infra" && !S?.infra) return;
    b.disabled = j.running;
  });
}

async function refresh() {
  S = await api("/api/state");
  renderSummary(); renderHosts(); renderPlan(); renderJob(S.job);
}

async function setHost(body) {
  try { await api("/api/host", body); await refresh(); } catch (e) { alert(e.message); }
}

function openDetail(h) {
  detailIp = h.ip;
  const i = h.identity || {};
  const form = $("#detail form");
  form.app.value = i.app || ""; form.web_port.value = i.web_port || "";
  form.health_path.value = i.health_path || "/"; form.note.value = h.note || "";
  $("#detail-body").replaceChildren(
    el("h2", {}, `${h.ip} · ${h.name}`),
    el("p", {}, i.description || ""),
    el("p", { class: "muted" }, `MAC ${h.mac || "-"} ${h.vendor || ""} · sources: ${h.sources.join(", ")}`),
    el("p", {}, "Ports: ", h.ports.map(p => `${p.port}${p.product ? "/" + p.product : ""}`).join(", ") || "-"),
    ...h.http.map(w => el("p", { class: "muted" }, `:${w.port} ${w.status} “${w.title || w.body_hint}” ${w.server}`)),
    el("ul", {}, ...(i.reasons || []).map(r => el("li", {}, r))));
  $("#detail").showModal();
}

async function poll() {
  try {
    const j = await api("/api/job");
    renderJob(j);
    if (!j.running && poll.wasRunning) await refresh();
    poll.wasRunning = j.running;
  } catch (_) { /* server restarting */ }
  setTimeout(poll, 1500);
}

document.querySelectorAll("nav button[data-job]").forEach(b =>
  b.addEventListener("click", async () => {
    if (b.dataset.job.startsWith("apply") && !confirm(`Run "${b.textContent}" for the approved hosts?`)) return;
    try { renderJob(await api("/api/job", { name: b.dataset.job })); poll.wasRunning = true; }
    catch (e) { alert(e.message); }
  }));
$("#filter").addEventListener("input", renderHosts);
$("#only-pending").addEventListener("change", renderHosts);
$("#approve-sure").addEventListener("click", async () => {
  for (const h of S.hosts) {
    if (h.decision === "pending" && h.identity && h.identity.confidence >= 0.85) {
      await api("/api/host", { ip: h.ip, decision: "approved" });
    }
  }
  await refresh();
});
$("#detail form").addEventListener("close", () => {});
$("#detail").addEventListener("close", async () => {
  if ($("#detail").returnValue !== "save") return;
  const f = $("#detail form");
  await setHost({ ip: detailIp, app: f.app.value, web_port: f.web_port.value,
                  health_path: f.health_path.value, note: f.note.value, decision: "approved" });
});

refresh().then(poll).catch(e => { document.body.textContent = "labscout: " + e.message; });
