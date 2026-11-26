"""`labscout scan`: combine the network, Proxmox and NetAlertX into one host list."""

from __future__ import annotations

from ..models import Host, ip_key
from . import netalertx, network, proxmox
from .http import fingerprint_http


def merge(net_hosts: dict[str, Host], pve: list, nax: list[dict]) -> list[Host]:
    hosts = dict(net_hosts)
    by_mac = {h.mac: h for h in hosts.values() if h.mac}
    for guest, ips, macs in pve:
        target = next((hosts[ip] for ip in ips if ip in hosts), None)
        if target is None:
            target = next((by_mac[m] for m in macs if m in by_mac), None)
        if target is None:
            if not ips:
                continue          # stopped guest without a static IP: nothing to point at
            target = hosts.setdefault(ips[0], Host(ip=ips[0]))
        target.proxmox = guest
        if "proxmox" not in target.sources:
            target.sources.append("proxmox")
        if not target.mac and macs:
            target.mac = macs[0]
    for d in nax:
        h = hosts.get(d["ip"])
        if h is None:
            continue              # only enrich: NetAlertX may hold stale IPs
        h.hostname = h.hostname or d["name"]
        h.vendor = h.vendor or d["vendor"]
        h.mac = h.mac or d["mac"]
        if "netalertx" not in h.sources:
            h.sources.append("netalertx")
    return sorted(hosts.values(), key=lambda h: ip_key(h.ip))


def scan(cfg, log=print) -> list[Host]:
    net_hosts = network.scan_network(cfg, log)
    pve = proxmox.collect(cfg.proxmox, log) if cfg.proxmox else []
    nax = netalertx.collect(cfg.netalertx_url, cfg.netalertx_token_env, log)
    hosts = merge(net_hosts, pve, nax)
    fingerprint_http({h.ip: h for h in hosts if h.ports}, cfg.http_timeout, log=log)
    log(f"{len(hosts)} hosts, {sum(len(h.ports) for h in hosts)} open ports, "
        f"{sum(len(h.http) for h in hosts)} web interfaces")
    return hosts
