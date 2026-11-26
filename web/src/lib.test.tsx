import { describe, expect, it } from "vitest";
import { renderToStaticMarkup } from "react-dom/server";
import { filterHosts, Confidence, DecisionBadge } from "./components/HostsPage";
import { parseRoute } from "./store";
import type { Host, Job } from "./types";
import { ago, confLevel, dur, exitText, healthUrl, ipKey, jobTarget, jobTitle, parseNetworks, validCidr } from "./util";

const host = (over: Partial<Host> = {}): Host => ({
  ip: "10.0.3.30", name: "grafana", mac: "", vendor: "", hostname: "", sources: ["nmap"], ports: [],
  http: [], proxmox: null, decision: "pending", note: "",
  identity: {
    app: "grafana", display_name: "Grafana", category: "monitoring", version: "11.2", confidence: 0.97,
    source: "rule", web_port: 3000, scheme: "http", health_path: "/api/health", metrics_port: 3000,
    metrics_path: "/metrics", exporter: "", community_script: "", description: "", reasons: [],
  },
  ...over,
});

const job = (over: Partial<Job>): Job => ({
  id: "abc", action: "run", options: {}, status: "running", dry_run: false, exit_code: null,
  created: 0, started: 1, ended: null, seconds: 3, position: null, ...over,
});

describe("hosts", () => {
  const hosts = [
    host({ ip: "10.0.3.100" }),
    host({ ip: "10.0.3.9", name: "pihole", decision: "approved", identity: { ...host().identity!, app: "pihole", category: "network", source: "ai", confidence: 0.7 } }),
    host({ ip: "10.0.0.5", name: "printer", identity: null }),
    host({ ip: "10.0.2.1", decision: "rejected" }),
  ];
  it("sorts by IP numerically and filters by decision", () => {
    const shown = filterHosts(hosts, { q: "", decisions: ["pending", "approved"], source: "all", cat: "" });
    expect(shown.map((h) => h.ip)).toEqual(["10.0.0.5", "10.0.3.9", "10.0.3.100"]);
  });
  it("filters by source, category and search words", () => {
    const f = (o: Partial<Parameters<typeof filterHosts>[1]>) =>
      filterHosts(hosts, { q: "", decisions: ["pending", "approved", "rejected"], source: "all", cat: "", ...o }).map((h) => h.ip);
    expect(f({ source: "ai" })).toEqual(["10.0.3.9"]);
    expect(f({ source: "none" })).toEqual(["10.0.0.5"]);
    expect(f({ cat: "unknown" })).toEqual(["10.0.0.5"]);
    expect(f({ cat: "network" })).toEqual(["10.0.3.9"]);
    expect(f({ q: "pihole network" })).toEqual(["10.0.3.9"]);
  });
  it("shows confidence and decisions", () => {
    expect(confLevel(hosts[0])).toBe("high");
    expect(confLevel(hosts[1])).toBe("mid");
    expect(confLevel(hosts[2])).toBe("none");
    expect(renderToStaticMarkup(<Confidence host={hosts[0]} />)).toContain("97%");
    expect(renderToStaticMarkup(<DecisionBadge d="approved" />)).toContain("dec-approved");
    expect(healthUrl(hosts[0])).toBe("http://10.0.3.100:3000/api/health");
    expect(healthUrl(hosts[2])).toBe("");
  });
  it("never renders host data as HTML", () => {
    const h = host({ identity: { ...host().identity!, app: "<img src=x onerror=alert(1)>" } });
    expect(renderToStaticMarkup(<Confidence host={h} />)).not.toContain("<img");
  });
});

describe("routing and input", () => {
  it("parses routes", () => {
    expect(parseRoute("")).toEqual({ page: "hosts", ip: null });
    expect(parseRoute("#/hosts/10.0.3.30")).toEqual({ page: "hosts", ip: "10.0.3.30" });
    expect(parseRoute("#/plan")).toEqual({ page: "plan", ip: null });
    expect(parseRoute("#/hosts?cat=media")).toEqual({ page: "hosts", ip: null });
  });
  it("checks networks like the server", () => {
    expect(parseNetworks("10.0.3.0/24, 10.0.0.0/24\n10.0.2.0/24")).toEqual(["10.0.3.0/24", "10.0.0.0/24", "10.0.2.0/24"]);
    expect(validCidr("10.0.3.0/24")).toBe(true);
    expect(validCidr("10.0.3.7")).toBe(true);
    expect(validCidr("10.0.0.0/8")).toBe(false);
    expect(validCidr("10.0.300.0/24")).toBe(false);
    expect(validCidr("-x")).toBe(false);
    expect(ipKey("10.0.0.9") < ipKey("10.0.0.10")).toBe(true);
  });
});

describe("jobs", () => {
  it("names jobs the way the UI shows them", () => {
    expect(jobTitle(job({}))).toBe("Scan, identify & plan");
    expect(jobTitle(job({ action: "apply", dry_run: true }))).toBe("Apply preview");
    expect(jobTarget(job({ action: "apply", options: { netbox: true, infra: true } }))).toBe("NetBox + infra repo");
    expect(jobTarget(job({ action: "scan", options: { networks: ["10.0.3.0/24"] } }))).toBe("10.0.3.0/24");
  });
  it("describes state", () => {
    expect(exitText(job({ status: "queued", position: 2 }))).toBe("waiting · #2 in the queue");
    expect(exitText(job({ status: "failed", exit_code: 2 }))).toBe("failed (exit 2)");
    expect(exitText(job({ status: "cancelled", started: null }))).toBe("cancelled before it started");
  });
  it("formats", () => {
    expect(dur(75)).toBe("1m 15s");
    expect(ago(1000, 1000 + 7200)).toBe("2 h ago");
    expect(ago(null)).toBe("never");
  });
});
