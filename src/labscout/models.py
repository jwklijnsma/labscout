"""Data model: what was found about a host, what it is, and what to do with it."""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field


@dataclass
class Port:
    port: int
    proto: str = "tcp"
    service: str = ""        # nmap service name (http, ssh, ...)
    product: str = ""        # nmap product (nginx, OpenSSH, ...)
    version: str = ""
    extra: str = ""


@dataclass
class HttpInfo:
    port: int
    scheme: str = "http"
    status: int = 0
    title: str = ""
    server: str = ""
    powered_by: str = ""
    generator: str = ""
    location: str = ""       # redirect target, if any
    body_hint: str = ""      # first meaningful text when there is no <title>


@dataclass
class ProxmoxGuest:
    endpoint: str = ""       # which Proxmox API (cluster or standalone node)
    node: str = ""
    vmid: int = 0
    type: str = ""           # lxc | qemu
    name: str = ""
    status: str = ""
    tags: list[str] = field(default_factory=list)
    description: str = ""
    ostype: str = ""
    cores: int = 0
    memory_mb: int = 0


@dataclass
class Identity:
    app: str = ""            # catalog key, lower-case slug (grafana, netbox, ...)
    display_name: str = ""
    category: str = ""       # monitoring, media, network, storage, home-automation, ...
    version: str = ""
    confidence: float = 0.0
    source: str = ""         # rule | ai | proxmox | manual
    web_port: int = 0
    scheme: str = "http"
    health_path: str = "/"
    metrics_port: int = 0
    metrics_path: str = ""
    exporter: str = ""       # suggested exporter when the app has no /metrics of its own
    community_script: str = ""   # community-scripts.org slug, when it looks installed by one
    description: str = ""
    reasons: list[str] = field(default_factory=list)


@dataclass
class Host:
    ip: str
    mac: str = ""
    vendor: str = ""
    hostname: str = ""
    sources: list[str] = field(default_factory=list)    # nmap, proxmox, netalertx
    ports: list[Port] = field(default_factory=list)
    http: list[HttpInfo] = field(default_factory=list)
    proxmox: ProxmoxGuest | None = None
    identity: Identity | None = None
    decision: str = "pending"    # pending | approved | rejected
    note: str = ""

    @property
    def name(self) -> str:
        if self.proxmox and self.proxmox.name:
            return self.proxmox.name
        return self.hostname.split(".")[0] if self.hostname else self.ip

    def fingerprint(self) -> str:
        """Stable hash of what the AI sees, so unchanged hosts are not re-classified."""
        facts = {
            "ports": sorted((p.port, p.service, p.product, p.version) for p in self.ports),
            "http": sorted((h.port, h.title, h.server, h.generator, h.powered_by) for h in self.http),
            "name": self.name, "vendor": self.vendor,
            "pve": [self.proxmox.tags, self.proxmox.description[:400]] if self.proxmox else None,
        }
        return hashlib.sha256(json.dumps(facts, sort_keys=True, default=str).encode()).hexdigest()[:16]

    def to_dict(self) -> dict:
        d = asdict(self)
        d["name"] = self.name
        return d

    @classmethod
    def from_dict(cls, d: dict) -> Host:
        d = dict(d)
        d.pop("name", None)
        d["ports"] = [Port(**p) for p in d.get("ports") or []]
        d["http"] = [HttpInfo(**h) for h in d.get("http") or []]
        d["proxmox"] = ProxmoxGuest(**d["proxmox"]) if d.get("proxmox") else None
        d["identity"] = Identity(**d["identity"]) if d.get("identity") else None
        return cls(**d)


def ip_key(ip: str) -> tuple:
    try:
        return tuple(int(x) for x in ip.split("."))
    except ValueError:
        return (999, ip)
