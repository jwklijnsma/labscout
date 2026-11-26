"""Proxmox VE: nodes and guests (name, tags, description, IPs) from a read-only API token."""

from __future__ import annotations

import re
import warnings

import requests

from ..models import ProxmoxGuest

_IP_IN_NET = re.compile(r"(?:^|,)ip=(\d+\.\d+\.\d+\.\d+)")
_HWADDR = re.compile(r"(?:hwaddr|virtio|e1000|vmxnet3|rtl8139)=([0-9A-Fa-f:]{17})")


class ProxmoxAPI:
    def __init__(self, endpoint, timeout: float = 10):
        self.ep = endpoint
        self.base = endpoint.url.rstrip("/") + "/api2/json"
        self.s = requests.Session()
        self.s.verify = endpoint.verify_tls
        self.s.headers["Authorization"] = f"PVEAPIToken={endpoint.token_id}={endpoint.token_secret}"
        self.timeout = timeout
        if not endpoint.verify_tls:
            warnings.filterwarnings("ignore", message="Unverified HTTPS request")

    def get(self, path: str, **params):
        r = self.s.get(self.base + path, params=params, timeout=self.timeout)
        r.raise_for_status()
        return r.json().get("data")

    def try_get(self, path: str, **params):
        try:
            return self.get(path, **params)
        except (requests.RequestException, ValueError):
            return None


def guest_ips(api: ProxmoxAPI, g: dict, config: dict) -> tuple[list[str], list[str]]:
    """IPv4 addresses (static config first, then what the guest reports) and MACs."""
    ips, macs = [], []
    for k, v in sorted((config or {}).items()):
        if re.fullmatch(r"net\d+", k) and isinstance(v, str):
            ips += _IP_IN_NET.findall(v)
            macs += [m.lower() for m in _HWADDR.findall(v)]
        if re.fullmatch(r"ipconfig\d+", k) and isinstance(v, str):
            ips += _IP_IN_NET.findall(v)
    path = f"/nodes/{g['node']}/{g['type']}/{g['vmid']}"
    if g.get("status") == "running":
        if g["type"] == "lxc":
            for iface in api.try_get(path + "/interfaces") or []:
                for addr in [iface.get("inet") or ""]:
                    ip = addr.split("/")[0]
                    if ip and not ip.startswith("127."):
                        ips.append(ip)
        else:
            data = api.try_get(path + "/agent/network-get-interfaces") or {}
            for iface in (data.get("result") or []):
                for a in iface.get("ip-addresses") or []:
                    ip = a.get("ip-address", "")
                    if a.get("ip-address-type") == "ipv4" and ip and not ip.startswith("127."):
                        ips.append(ip)
    seen, out = set(), []
    for ip in ips:
        if ip not in seen:
            seen.add(ip)
            out.append(ip)
    return out, macs


def collect(endpoints, log=print) -> list[tuple[ProxmoxGuest, list[str], list[str]]]:
    """[(guest, ips, macs)] for every node and guest of every endpoint."""
    out = []
    for ep in endpoints:
        if not ep.token_secret:
            log(f"proxmox {ep.name}: no token in ${ep.token_env}, skipped")
            continue
        api = ProxmoxAPI(ep)
        try:
            status = api.get("/cluster/status") or []
            resources = api.get("/cluster/resources", type="vm") or []
        except requests.RequestException as exc:
            log(f"proxmox {ep.name}: {exc}")
            continue
        for n in status:
            if n.get("type") == "node" and n.get("ip"):
                out.append((ProxmoxGuest(endpoint=ep.name, node=n["name"], type="node",
                                         name=n["name"], status="online" if n.get("online") else "offline"),
                            [n["ip"]], []))
        if not any(s.get("type") == "node" and s.get("ip") for s in status):
            # standalone node: /cluster/status has no IP; use the API host
            host = re.sub(r"^https?://([^:/]+).*$", r"\1", ep.url)
            for node in api.try_get("/nodes") or []:
                out.append((ProxmoxGuest(endpoint=ep.name, node=node["node"], type="node",
                                         name=node["node"], status=node.get("status", "")), [host], []))
        for g in resources:
            if g.get("template"):
                continue
            cfg = api.try_get(f"/nodes/{g['node']}/{g['type']}/{g['vmid']}/config") or {}
            guest = ProxmoxGuest(
                endpoint=ep.name, node=g["node"], vmid=int(g["vmid"]), type=g["type"],
                name=g.get("name", ""), status=g.get("status", ""),
                tags=[t for t in re.split(r"[;, ]+", g.get("tags", "") or "") if t],
                description=(cfg.get("description") or "")[:2000],
                ostype=cfg.get("ostype", ""), cores=int(cfg.get("cores") or g.get("maxcpu") or 0),
                memory_mb=int(cfg.get("memory") or (g.get("maxmem", 0) // 2**20)))
            ips, macs = guest_ips(api, g, cfg)
            out.append((guest, ips, macs))
        log(f"proxmox {ep.name}: {sum(1 for x in out if x[0].endpoint == ep.name)} nodes/guests")
    return out
