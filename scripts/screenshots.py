#!/usr/bin/env python3
"""Regenerate the screenshots in docs/assets/screenshots/ (`make screenshots`).

Starts the real web UI on sample data (made-up hosts, a fake Ollama from the tests, a
sample infra catalog) and photographs every page with Playwright. Nothing touches your
network or your real labscout-data.

    pip install playwright && playwright install chromium
    make screenshots            # or: python3 scripts/screenshots.py [--chrome PATH]
"""

from __future__ import annotations

import argparse
import os
import stat
import sys
import tempfile
import threading
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / "src"), str(ROOT / "tests")]

import mock_ollama

from labscout import state
from labscout.config import Config, ProxmoxEndpoint
from labscout.models import Host, HttpInfo, Identity, Port, ProxmoxGuest
from labscout.web.server import Job, WebApp, make_server

OUT = ROOT / "docs" / "assets" / "screenshots"
APPS_YML = """app_catalog:
  grafana: { port: 3000, probe_path: /api/health, subdomain: grafana }
  pve: { port: 8006, scheme: https, subdomain: false }
  pbs: { port: 8007, scheme: https, subdomain: pbs }
app_aliases: {}
"""


def ident(app, name, cat, conf, src, port, path="/", ver="", reasons=(), **kw) -> Identity:
    return Identity(app=app, display_name=name, category=cat, confidence=conf, source=src,
                    web_port=port, health_path=path, version=ver, reasons=list(reasons), **kw)


def guest(vmid, node, name, *tags, **kw) -> ProxmoxGuest:
    return ProxmoxGuest(endpoint="home-cluster", node=node, vmid=vmid, type="lxc", name=name,
                        status="running", tags=list(tags), **kw)


def sample_hosts() -> list[Host]:
    return [
        Host(ip="10.0.3.116", hostname="grafana.lan", sources=["nmap", "proxmox"],
             ports=[Port(22, service="ssh", product="OpenSSH", version="9.6"), Port(3000, service="http")],
             http=[HttpInfo(3000, status=302, title="Grafana", location="/login")],
             proxmox=guest(118, "node05", "grafana", "community-script", "monitoring", cores=2, memory_mb=2048),
             identity=ident("grafana", "Grafana", "monitoring", 0.99, "rule", 3000, "/api/health", "11.2.0",
                            ["page title is Grafana", "port 3000"]), decision="approved"),
        Host(ip="10.0.3.99", sources=["nmap", "proxmox"], ports=[Port(8085, service="http"), Port(22, service="ssh")],
             http=[HttpInfo(8085, status=200, title="Kitchen Owl")],
             proxmox=guest(170, "node06", "recipes", "community-script", cores=1, memory_mb=1024),
             identity=ident("kitchenowl", "KitchenOwl", "home", 0.82, "ai", 8085, "/api/health",
                            reasons=["page title is Kitchen Owl", "Flask app on 8085, as the community script installs it"],
                            description="Grocery list and recipe manager"),
             decision="approved"),
        Host(ip="10.0.3.40", sources=["proxmox"], ports=[Port(8006, service="https"), Port(22, service="ssh")],
             proxmox=ProxmoxGuest(endpoint="home-cluster", node="node04", type="node", name="node04"),
             identity=ident("proxmox-ve", "Proxmox VE node", "virtualisation", 1.0, "proxmox", 8006)),
        Host(ip="10.0.3.58", sources=["nmap", "proxmox"], ports=[Port(20211, service="http")],
             http=[HttpInfo(20211, status=200, title="NetAlertX")], proxmox=guest(160, "node04", "netalertx"),
             identity=ident("netalertx", "NetAlertX", "network", 0.96, "rule+ai", 20211,
                            metrics_port=20211, metrics_path="/metrics"), decision="approved"),
        Host(ip="10.0.0.14", mac="BC:24:11:AA:01:02", vendor="Proxmox", sources=["nmap", "netalertx"],
             ports=[Port(8007, service="https")], identity=ident("pbs", "Proxmox Backup Server", "storage", 0.71, "ai", 8007),
             decision="approved"),
        Host(ip="10.0.2.31", mac="00:17:88:12:34:56", vendor="Signify (Philips Hue)", sources=["nmap", "netalertx"],
             ports=[Port(80, service="http"), Port(443, service="https")],
             http=[HttpInfo(80, status=200, title="hue personal wireless lighting")],
             identity=ident("philips-hue", "Philips Hue bridge", "iot", 0.55, "ai", 80)),
        Host(ip="10.0.2.77", mac="3C:22:FB:00:11:22", vendor="Apple", sources=["netalertx"]),
        Host(ip="10.0.3.250", sources=["nmap"], ports=[Port(9100, service="jetdirect")],
             identity=ident("printer", "Printer", "printer", 0.6, "rule", 0), decision="rejected"),
    ]


def demo_job() -> Job:
    j = Job(id="demo", action="run", argv=[], options={}, status="done", exit_code=0,
            started=time.time() - 94, ended=time.time() - 30)
    for line in ["$ labscout run --state-dir labscout-data",
                 "nmap: 3 networks, 58 ports (-sV --version-light -T4)",
                 "proxmox home-cluster: 9 nodes, 74 guests",
                 "identifying 8 hosts (model: qwen2.5:14b)",
                 "  10.0.3.116      grafana                      grafana (rule 0.99)",
                 "  10.0.3.99       recipes                      kitchenowl (ai 0.82)",
                 "saved labscout-data/hosts.json; next: labscout review, then labscout plan / apply",
                 "written: labscout-data/report.md, labscout-data/plan.json"]:
        j.add_line(line)
    return j


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--chrome", help="Chromium/Chrome binary (default: Playwright's own)")
    a = ap.parse_args()
    from playwright.sync_api import sync_playwright

    tmp = Path(tempfile.mkdtemp(prefix="labscout-shots-"))
    # The status bar shows "nmap" when it is on PATH; the screenshots show a normal install.
    (tmp / "bin").mkdir()
    fake = tmp / "bin" / "nmap"
    fake.write_text("#!/bin/sh\necho 'Nmap version 7.95'\n")
    fake.chmod(fake.stat().st_mode | stat.S_IEXEC)
    os.environ["PATH"] = f"{tmp / 'bin'}{os.pathsep}{os.environ['PATH']}"
    apps = tmp / "infra" / "inventory" / "group_vars" / "all" / "apps.yml"
    apps.parent.mkdir(parents=True)
    apps.write_text(APPS_YML)

    get = mock_ollama._Handler.do_GET

    def do_get(self):   # a real-looking version in the top bar
        if self.path == "/api/version":
            return self._send(200, {"version": "0.12.6"})
        return get(self)

    mock_ollama._Handler.do_GET = do_get
    ollama, url = mock_ollama.start()

    cfg = Config()
    cfg.state_dir = str(tmp / "state")
    cfg.networks = ["10.0.3.0/24", "10.0.0.0/24", "10.0.2.0/24"]
    cfg.domain = "home.example.org"
    cfg.netbox_url = "https://netbox.home.example.org"
    cfg.ollama_host, cfg.model = url, mock_ollama.MODEL
    cfg.proxmox = [ProxmoxEndpoint(name="home-cluster", url="https://10.0.3.40:8006",
                                   token_id="labscout@pve!scan", token_env="PVE_TOKEN_HOME_CLUSTER"),
                   ProxmoxEndpoint(name="node01", url="https://10.0.3.20:8006",
                                   token_id="labscout@pve!scan", token_env="PVE_TOKEN_NODE01")]
    cfg.netalertx_url = "http://10.0.3.58:20212"
    cfg.infra_repo = str(tmp / "infra")
    state.save(cfg.state_dir, sample_hosts())

    app = WebApp(cfg, None, None)
    app.jobs["demo"] = demo_job()
    srv = make_server(app, "127.0.0.1", 0)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{srv.server_address[1]}"
    OUT.mkdir(parents=True, exist_ok=True)

    def shot(page, name):
        time.sleep(0.5)
        page.screenshot(path=str(OUT / f"{name}.png"))
        print(f"  {OUT.relative_to(ROOT) / name}.png")

    with sync_playwright() as p:
        browser = p.chromium.launch(executable_path=a.chrome) if a.chrome else p.chromium.launch()
        errors: list[str] = []
        for scheme, suffix in (("light", ""), ("dark", "-dark")):
            pg = browser.new_page(viewport={"width": 1400, "height": 860}, color_scheme=scheme,
                                  device_scale_factor=1)
            pg.on("console", lambda m: m.type == "error" and errors.append(m.text))
            pg.goto(base + "/#/hosts")
            pg.wait_for_selector("table.hosts")
            shot(pg, "hosts" + suffix)
            if suffix:
                pg.close()
                continue
            pg.goto(base + "/#/hosts/10.0.3.99")
            pg.wait_for_selector(".host-drawer")
            shot(pg, "host-detail")
            pg.goto(base + "/#/plan")
            pg.wait_for_selector(".apply-card")
            shot(pg, "plan")
            pg.goto(base + "/#/scan")
            pg.wait_for_selector(".scan-actions")
            shot(pg, "scan")
            pg.goto(base + "/#/hosts")
            pg.wait_for_selector("table.hosts")
            pg.click(".jobs-pill")
            pg.click(".jobs-panel >> text=Log")
            pg.wait_for_selector(".log .l-ok")
            shot(pg, "jobs")
            pg.close()
        browser.close()
    srv.shutdown()
    ollama.shutdown()
    if errors:
        print("console errors:", *errors, sep="\n  ")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
