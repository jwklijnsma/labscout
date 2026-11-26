import type { Host, Job } from "./types";

export function ago(ts: number | null | undefined, now = Date.now() / 1000): string {
  if (!ts) return "never";
  const s = Math.max(0, now - ts);
  if (s < 60) return "just now";
  if (s < 3600) return `${Math.floor(s / 60)} min ago`;
  if (s < 86400) return `${Math.floor(s / 3600)} h ago`;
  return `${Math.floor(s / 86400)} d ago`;
}

export function dur(s: number | null | undefined): string {
  if (s == null) return "";
  s = Math.round(s);
  return s < 60 ? `${s}s` : `${Math.floor(s / 60)}m ${String(s % 60).padStart(2, "0")}s`;
}

export function plural(n: number, word: string, many = word + "s"): string {
  return `${n} ${n === 1 ? word : many}`;
}

/** Sort key for IPv4 addresses, so 10.0.0.9 comes before 10.0.0.10. */
export function ipKey(ip: string): string {
  const parts = ip.split(".");
  return parts.length === 4 && parts.every((p) => /^\d+$/.test(p)) ? parts.map((p) => p.padStart(3, "0")).join(".") : "~" + ip;
}

export function jobTitle(j: Pick<Job, "action" | "dry_run">): string {
  switch (j.action) {
    case "run":
      return "Scan, identify & plan";
    case "scan":
      return "Scan";
    case "identify":
      return "Identify";
    case "plan":
      return "Plan";
    case "apply":
      return j.dry_run ? "Apply preview" : "Apply";
  }
}

export function jobTarget(j: Pick<Job, "action" | "options">): string {
  const o = j.options || {};
  if (j.action === "apply") return [o.netbox && "NetBox", o.infra && "infra repo"].filter(Boolean).join(" + ");
  if ((j.action === "run" || j.action === "scan") && Array.isArray(o.networks) && o.networks.length) return (o.networks as string[]).join(", ");
  if (j.action === "identify" && o.force) return "ask the model again";
  return "";
}

export function exitText(j: Job): string {
  switch (j.status) {
    case "queued":
      return j.position ? `waiting · #${j.position} in the queue` : "waiting";
    case "running":
      return j.action === "apply" ? "writing" : j.action === "plan" ? "planning" : "scanning and identifying";
    case "cancelled":
      return j.started ? "cancelled" : "cancelled before it started";
    case "failed":
      return `failed (exit ${j.exit_code})`;
    case "done":
      return "completed";
  }
}

export function logClass(text: string): string {
  if (text.startsWith("$ ")) return "l-cmd";
  if (/^(error|NetBox:|infra:)|✗|failed/i.test(text)) return "l-bad";
  if (/^warning|^\s*!/.test(text)) return "l-warn";
  if (/✓|^saved |^written: /.test(text)) return "l-ok";
  return "";
}

export type Level = "high" | "mid" | "low" | "none";

/** How sure the identification is, for colouring. */
export function confLevel(h: Pick<Host, "identity">): Level {
  const c = h.identity?.app ? h.identity.confidence : -1;
  if (c < 0) return "none";
  return c >= 0.85 ? "high" : c >= 0.6 ? "mid" : "low";
}

export function healthUrl(h: Host): string {
  const i = h.identity;
  if (!i || !i.web_port) return "";
  return `${i.scheme || "http"}://${h.ip}:${i.web_port}${i.health_path || "/"}`;
}

/** Text a host is found by in the search box. */
export function searchText(h: Host): string {
  const i = h.identity;
  return [h.ip, h.name, h.hostname, h.mac, h.vendor, h.note, h.proxmox?.node, ...(h.proxmox?.tags || []), i?.app, i?.display_name, i?.category, i?.version, ...h.ports.map((p) => `${p.port} ${p.product} ${p.service}`)]
    .filter(Boolean)
    .join(" ")
    .toLowerCase();
}

/** Parse "10.0.3.0/24, 10.0.0.0/24" or one per line. */
export function parseNetworks(text: string): string[] {
  return text.split(/[\s,]+/).map((s) => s.trim()).filter(Boolean);
}

export function validCidr(s: string): boolean {
  const m = s.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})(?:\/(\d{1,2}))?$/);
  if (!m) return false;
  if (m.slice(1, 5).some((o) => Number(o) > 255)) return false;
  return m[5] === undefined || (Number(m[5]) >= 16 && Number(m[5]) <= 32);
}

/** Read and write per-browser conveniences; storage can be missing or throw. */
export function stored<T>(key: string, fallback: T): T {
  try {
    const v = localStorage.getItem("labscout:" + key);
    return v === null ? fallback : (JSON.parse(v) as T);
  } catch {
    return fallback;
  }
}
export function store(key: string, value: unknown): void {
  try {
    localStorage.setItem("labscout:" + key, JSON.stringify(value));
  } catch {
    /* private mode etc. */
  }
}
