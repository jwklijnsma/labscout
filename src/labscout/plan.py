"""`labscout plan`: turn identified hosts into concrete changes.

* infra repo (jwklijnsma/infra layout): new ``app_catalog`` entries for apps it does not
  know yet, and ``app_aliases`` where a Proxmox guest's name would resolve to the wrong app.
  The infra playbooks then do the rest: blackbox probe, Traefik route, DNS, exporters,
  Grafana, NetBox VM sync.
* monitoring: per host what should watch it (health check, /metrics, exporter).
* NetBox: IP addresses for every host plus a service for each web port.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import asdict, dataclass, field
from pathlib import Path

import yaml

from .models import Host

# labscout app slug -> infra catalog key where they differ
SYNONYMS = {"proxmox-ve": "pve", "proxmox-backup": "pbs", "home-assistant": "homeassistant",
            "uptime-kuma": "uptimekuma", "adguard": "adguard", "powerdns": "powerdns-recursor",
            "nginx-proxy-manager": "nginxproxymanager", "mariadb": "mariadb", "nut": "nut",
            "proxmox-datacenter-manager": "pdm"}
DEVICE_APPS = {"unknown", "network-device", "printer", "workstation", "phone", "iot", "laptop"}


@dataclass
class Plan:
    catalog_add: dict = field(default_factory=dict)      # infra app -> spec
    aliases_add: dict = field(default_factory=dict)      # guest name -> infra app
    monitoring: list = field(default_factory=list)       # [{host, ip, app, check, metrics, exporter}]
    netbox: list = field(default_factory=list)           # [{ip, cidr, dns_name, description, vm, services}]
    unknown: list = field(default_factory=list)          # hosts the scan could not place
    skipped: list = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)

    @property
    def empty(self) -> bool:
        return not (self.catalog_add or self.aliases_add)


def load_infra(repo: str, apps_file: str) -> tuple[dict, dict, Path | None]:
    if not repo:
        return {}, {}, None
    p = Path(repo) / apps_file
    if not p.is_file():
        return {}, {}, None
    data = yaml.safe_load(p.read_text()) or {}
    return data.get("app_catalog") or {}, data.get("app_aliases") or {}, p


def infra_key(app: str, catalog: dict) -> str:
    if app in catalog:
        return app
    syn = SYNONYMS.get(app)
    return syn if syn else app


def infra_resolve(name: str, catalog: dict, aliases: dict) -> str:
    """The app the infra repo derives from a guest name (filter_plugins/infra.py)."""
    if name in aliases:
        return aliases[name]
    base = re.sub(r"[-_]?\d+$", "", name)
    if base in catalog:
        return base
    if name in catalog:
        return name
    for key in sorted(catalog, key=len, reverse=True):
        if name.startswith(key):
            return key
    return base


def _cidr_for(ip: str, networks: list[str]) -> str:
    addr = ipaddress.ip_address(ip)
    for n in networks:
        net = ipaddress.ip_network(n, strict=False)
        if addr in net:
            return f"{ip}/{net.prefixlen}"
    return f"{ip}/32"


def catalog_entry(host: Host, domain: str) -> dict:
    i = host.identity
    spec: dict = {}
    if i.web_port:
        spec["port"] = i.web_port
        if i.scheme == "https":
            spec["scheme"] = "https"
        if i.health_path and i.health_path != "/":
            spec["probe_path"] = i.health_path
        spec["subdomain"] = i.app if domain else False
    else:
        tcp = next((p.port for p in host.ports if p.port not in (22, 9100)), 0)
        if tcp:
            spec["port"] = tcp
            spec["probe"] = "tcp"
        else:
            spec["probe"] = "none"
        spec["subdomain"] = False
    if i.metrics_path and i.metrics_port:
        spec["metrics"] = {"port": i.metrics_port, "path": i.metrics_path}
    return spec


def build(hosts: list[Host], cfg, include_pending: bool = False) -> Plan:
    catalog, aliases, _ = load_infra(cfg.infra_repo, cfg.infra_apps_file)
    plan = Plan()
    for h in hosts:
        i = h.identity
        if h.decision == "rejected" or (h.decision != "approved" and not include_pending):
            plan.skipped.append(h.ip)
            continue
        if not i or i.app in DEVICE_APPS:
            plan.unknown.append({"ip": h.ip, "name": h.name, "vendor": h.vendor,
                                 "ports": [p.port for p in h.ports],
                                 "guess": i.app if i else ""})
        # --- monitoring -----------------------------------------------------------------
        if i and i.app not in DEVICE_APPS:
            check = (f"{i.scheme}://{h.ip}:{i.web_port}{i.health_path}" if i.web_port
                     else (f"tcp {h.ip}:{h.ports[0].port}" if h.ports else "ping"))
            plan.monitoring.append({
                "host": h.name, "ip": h.ip, "app": i.app, "check": check,
                "metrics": (f"{h.ip}:{i.metrics_port}{i.metrics_path}" if i.metrics_port else ""),
                "exporter": i.exporter,
                "node_exporter": bool(h.proxmox and h.proxmox.type in ("lxc", "qemu")
                                      and not any(p.port == 9100 for p in h.ports))})
        # --- NetBox -----------------------------------------------------------------------
        services = []
        if i and i.web_port:
            services.append({"name": i.app, "port": i.web_port,
                             "description": f"{i.display_name or i.app} web UI"})
        if i and i.metrics_port and i.metrics_port != i.web_port:
            services.append({"name": f"{i.app}-metrics", "port": i.metrics_port,
                             "description": "Prometheus metrics"})
        plan.netbox.append({
            "ip": h.ip, "cidr": _cidr_for(h.ip, cfg.networks),
            "dns_name": (f"{i.app}.{cfg.domain}" if (i and cfg.domain and i.web_port
                                                     and i.app not in DEVICE_APPS)
                         else h.hostname),
            "description": ((f"{i.display_name or i.app}: {i.description}" if i.description
                             else (i.display_name or i.app))[:200] if i else h.name),
            "vm": h.proxmox.name if h.proxmox and h.proxmox.type in ("lxc", "qemu") else "",
            "services": services})
        # --- infra repo (only Proxmox guests are in its inventory) ----------------------------
        if not (catalog and i and h.proxmox and h.proxmox.type in ("lxc", "qemu")):
            continue
        if i.app in DEVICE_APPS or i.confidence < 0.6:
            continue
        key = infra_key(i.app, catalog)
        if key not in catalog and key not in plan.catalog_add:
            plan.catalog_add[key] = catalog_entry(h, cfg.domain)
        name = h.proxmox.name
        if infra_resolve(name, {**catalog, **plan.catalog_add}, aliases) != key:
            plan.aliases_add[name] = key
    return plan


# ------------------------------------------------------------------------- apply to infra
def _flow(spec: dict) -> str:
    return yaml.safe_dump(spec, default_flow_style=True, sort_keys=False, width=200).strip()


def patch_apps_yml(text: str, plan: Plan, source: str = "labscout") -> str:
    """Insert aliases and catalog entries into apps.yml, keeping its comments and layout."""
    lines = text.splitlines()
    out = list(lines)

    def block_end(key: str) -> int:
        start = next((n for n, line in enumerate(out) if line.startswith(f"{key}:")), None)
        if start is None:
            out.extend(["", f"{key}:"])
            return len(out)
        n = start + 1
        while n < len(out) and (out[n].startswith(" ") or not out[n].strip()):
            n += 1
        while n > start + 1 and not out[n - 1].strip():   # stay before trailing blank lines
            n -= 1
        return n

    if plan.aliases_add:
        at = block_end("app_aliases")
        new = [f"  {k}: {v}   # {source}" for k, v in sorted(plan.aliases_add.items())]
        out[at:at] = new
    if plan.catalog_add:
        at = block_end("app_catalog")
        new = [f"  {k}: {_flow(v)}   # {source}" for k, v in sorted(plan.catalog_add.items())]
        out[at:at] = new
    return "\n".join(out) + ("\n" if text.endswith("\n") else "")
