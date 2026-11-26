"""Network discovery: which IPs are alive and which ports are open.

With nmap installed (the Docker image has it) this is ``nmap -sn`` for discovery and
``nmap -sV`` on the configured ports. Without nmap it falls back to a threaded TCP connect
scan, which finds the same open ports but no product/version strings and only the MAC
addresses the kernel happens to know (/proc/net/arp).
"""

from __future__ import annotations

import ipaddress
import shutil
import socket
import subprocess
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor

from ..models import Host, Port

NMAP_TIMEOUT = 3600


def expand_targets(networks: list[str], exclude: list[str]) -> list[str]:
    skip = [ipaddress.ip_network(e, strict=False) for e in exclude]
    out: list[str] = []
    for net in networks:
        n = ipaddress.ip_network(net, strict=False)
        hosts = [n.network_address] if n.num_addresses == 1 else n.hosts()
        for ip in hosts:
            if not any(ip in s for s in skip):
                out.append(str(ip))
    return out


def parse_ports(spec: str) -> list[int]:
    ports: set[int] = set()
    for part in str(spec).split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            a, b = part.split("-", 1)
            ports.update(range(int(a), int(b) + 1))
        else:
            ports.add(int(part))
    return sorted(p for p in ports if 0 < p < 65536)


# ---------------------------------------------------------------------------- nmap
def parse_nmap_xml(xml_text: str) -> dict[str, Host]:
    """nmap -oX output -> {ip: Host} for hosts that are up."""
    hosts: dict[str, Host] = {}
    if not xml_text.strip():
        return hosts
    root = ET.fromstring(xml_text)
    for h in root.findall("host"):
        status = h.find("status")
        if status is not None and status.get("state") != "up":
            continue
        ip = mac = vendor = ""
        for a in h.findall("address"):
            if a.get("addrtype") == "ipv4":
                ip = a.get("addr", "")
            elif a.get("addrtype") == "mac":
                mac = a.get("addr", "").lower()
                vendor = a.get("vendor", "")
        if not ip:
            continue
        host = Host(ip=ip, mac=mac, vendor=vendor, sources=["nmap"])
        hn = h.find("hostnames/hostname")
        if hn is not None:
            host.hostname = hn.get("name", "")
        for p in h.findall("ports/port"):
            st = p.find("state")
            if st is None or st.get("state") != "open":
                continue
            svc = p.find("service")
            host.ports.append(Port(
                port=int(p.get("portid", 0)), proto=p.get("protocol", "tcp"),
                service=(svc.get("name", "") if svc is not None else ""),
                product=(svc.get("product", "") if svc is not None else ""),
                version=(svc.get("version", "") if svc is not None else ""),
                extra=((svc.get("extrainfo", "") + (" ssl" if svc.get("tunnel") == "ssl" else "")).strip()
                       if svc is not None else "")))
        hosts[ip] = host
    return hosts


def _nmap(args: list[str]) -> str:
    r = subprocess.run(["nmap", *args, "-oX", "-"], capture_output=True, text=True,
                       timeout=NMAP_TIMEOUT)
    if r.returncode != 0 and not r.stdout:
        raise RuntimeError(f"nmap failed: {r.stderr.strip()[:300]}")
    return r.stdout


def nmap_scan(networks: list[str], exclude: list[str], ports: list[int], extra_args: str,
              log=print) -> dict[str, Host]:
    excl = ["--exclude", ",".join(exclude)] if exclude else []
    log(f"nmap host discovery on {', '.join(networks)}")
    alive = parse_nmap_xml(_nmap(["-sn", "-n", *excl, *networks]))
    if not alive:
        return {}
    log(f"{len(alive)} hosts up; scanning {len(ports)} ports with nmap {extra_args}")
    scanned = parse_nmap_xml(_nmap(["-n", "-Pn", "-p", ",".join(map(str, ports)),
                                    *extra_args.split(), *sorted(alive)]))
    for ip, h in alive.items():           # keep MAC/vendor from the discovery run
        s = scanned.setdefault(ip, h)
        s.mac = s.mac or h.mac
        s.vendor = s.vendor or h.vendor
    return scanned


# ---------------------------------------------------------------------------- fallback
def _connect(ip: str, port: int, timeout: float) -> bool:
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return True
    except OSError:
        return False


def arp_table() -> dict[str, str]:
    out = {}
    try:
        with open("/proc/net/arp") as f:
            next(f)
            for line in f:
                cols = line.split()
                if len(cols) >= 4 and cols[3] != "00:00:00:00:00:00":
                    out[cols[0]] = cols[3].lower()
    except OSError:
        pass
    return out


def connect_scan(targets: list[str], ports: list[int], timeout: float, workers: int,
                 log=print) -> dict[str, Host]:
    log(f"TCP connect scan: {len(targets)} addresses x {len(ports)} ports (nmap not found)")
    pairs = [(ip, p) for ip in targets for p in ports]
    hosts: dict[str, Host] = {}
    with ThreadPoolExecutor(max_workers=workers) as pool:
        for (ip, port), ok in zip(pairs, pool.map(lambda x: _connect(x[0], x[1], timeout), pairs)):
            if ok:
                hosts.setdefault(ip, Host(ip=ip, sources=["tcp"])).ports.append(Port(port=port))
    macs = arp_table()
    for ip, h in hosts.items():
        h.mac = macs.get(ip, "")
    return hosts


def reverse_dns(hosts: dict[str, Host], workers: int = 32) -> None:
    def lookup(ip):
        try:
            return socket.gethostbyaddr(ip)[0]
        except (OSError, UnicodeError):
            return ""
    todo = [ip for ip, h in hosts.items() if not h.hostname]
    with ThreadPoolExecutor(max_workers=workers) as pool:
        for ip, name in zip(todo, pool.map(lookup, todo)):
            if name:
                hosts[ip].hostname = name


def scan_network(cfg, log=print) -> dict[str, Host]:
    ports = parse_ports(cfg.ports)
    if cfg.use_nmap and shutil.which("nmap"):
        hosts = nmap_scan(cfg.networks, cfg.exclude, ports, cfg.nmap_args, log)
    else:
        hosts = connect_scan(expand_targets(cfg.networks, cfg.exclude), ports,
                             cfg.connect_timeout, cfg.scan_workers, log)
    reverse_dns(hosts)
    return hosts
