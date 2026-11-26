"""`labscout identify`: what runs on each host.

Built-in fingerprints answer the easy cases instantly. Everything else (and every rule hit
below ``min_rule_confidence``) goes to the local Ollama model with the raw scan facts.
Answers are cached per host fingerprint, so a re-scan only asks about what changed, and a
manual decision in the UI is never overwritten.
"""

from __future__ import annotations

import json
import re
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from . import fingerprints
from .models import Host, Identity
from .ollama import OllamaClient, OllamaError

SYSTEM = """You identify the software running on hosts in a homelab from network scan facts.
You get: the host name, Proxmox metadata (tags, description) when it is a VM/LXC, open TCP
ports with nmap service/product strings, and per web port the HTTP status, <title>, Server
header and a snippet of the page.

Answer with ONE JSON object describing the main application of this host:
- app: short lower-case slug (e.g. grafana, home-assistant, jellyfin). Prefer a slug from
  the KNOWN list when it fits. Use "unknown" when the facts do not support an answer, and
  "network-device" / "printer" / "workstation" / "phone" / "iot" for plain devices.
- display_name, category (monitoring, media, network, storage, security, home-automation,
  downloads, dashboard, development, ai, database, files, devices, virtualisation, other).
- version: only when a banner or title shows it, else "".
- web_port / scheme / health_path: the port and path of the web UI or API that returns 2xx
  when the app is healthy ("/" if unsure). web_port MUST be one of the open ports, or 0.
- metrics_port / metrics_path: a native Prometheus endpoint if this app has one, else 0 / "".
- exporter: the Prometheus exporter you would add when there is no native endpoint
  (node-exporter, postgres-exporter, exportarr, snmp-exporter, ...) or "".
- community_script: the community-scripts.org (tteck) script slug if it looks installed by
  one (Proxmox tag "community-script" is a strong hint), else "".
- description: one sentence for an inventory, in English.
- confidence 0..1 and reasons: short list of the facts you relied on.
Never invent ports, versions or facts that are not in the input."""

SCHEMA = {
    "type": "object",
    "properties": {
        "app": {"type": "string"}, "display_name": {"type": "string"},
        "category": {"type": "string"}, "version": {"type": "string"},
        "confidence": {"type": "number"}, "web_port": {"type": "integer"},
        "scheme": {"type": "string", "enum": ["http", "https"]},
        "health_path": {"type": "string"}, "metrics_port": {"type": "integer"},
        "metrics_path": {"type": "string"}, "exporter": {"type": "string"},
        "community_script": {"type": "string"}, "description": {"type": "string"},
        "reasons": {"type": "array", "items": {"type": "string"}},
    },
    "required": ["app", "category", "confidence", "web_port", "health_path", "description"],
}


def facts(host: Host) -> dict:
    d: dict = {"ip": host.ip, "name": host.name}
    if host.hostname and host.hostname != host.name:
        d["dns_name"] = host.hostname
    if host.vendor:
        d["mac_vendor"] = host.vendor
    if host.proxmox:
        p = host.proxmox
        d["proxmox"] = {"type": p.type, "name": p.name, "tags": p.tags, "os": p.ostype,
                        "description": re.sub(r"<[^>]+>", " ", p.description)[:600]}
    d["open_ports"] = [
        {k: v for k, v in (("port", x.port), ("service", x.service), ("product", x.product),
                           ("version", x.version), ("extra", x.extra)) if v}
        for x in host.ports]
    d["web"] = [
        {k: v for k, v in (("port", h.port), ("scheme", h.scheme), ("status", h.status),
                           ("title", h.title), ("server", h.server), ("powered_by", h.powered_by),
                           ("generator", h.generator), ("redirect", h.location),
                           ("page", h.body_hint)) if v}
        for h in host.http]
    return d


def _slug(s: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", (s or "").lower()).strip("-") or "unknown"


def from_model(data: dict, host: Host) -> Identity:
    open_ports = {p.port for p in host.ports}
    ident = Identity(
        app=_slug(data.get("app", "")), display_name=str(data.get("display_name", ""))[:80],
        category=_slug(data.get("category", "other")), version=str(data.get("version", ""))[:40],
        confidence=max(0.0, min(1.0, float(data.get("confidence") or 0))), source="ai",
        web_port=int(data.get("web_port") or 0), scheme=data.get("scheme") or "http",
        health_path=str(data.get("health_path") or "/")[:200],
        metrics_port=int(data.get("metrics_port") or 0),
        metrics_path=str(data.get("metrics_path") or "")[:200],
        exporter=_slug(data.get("exporter", "")) if data.get("exporter") else "",
        community_script=_slug(data.get("community_script", "")) if data.get("community_script") else "",
        description=str(data.get("description", ""))[:300],
        reasons=[str(r)[:160] for r in (data.get("reasons") or [])][:6])
    # Guard rails: the model may not invent ports
    if ident.web_port and ident.web_port not in open_ports:
        ident.reasons.append(f"model suggested closed port {ident.web_port}; dropped")
        ident.web_port = 0
    if ident.metrics_port and ident.metrics_port not in open_ports:
        ident.metrics_port, ident.metrics_path = 0, ""
    if ident.web_port:
        seen = next((h for h in host.http if h.port == ident.web_port), None)
        if seen:
            ident.scheme = seen.scheme
    return ident


class Identifier:
    def __init__(self, cfg, client: OllamaClient | None = None, log=print):
        self.cfg = cfg
        self.log = log
        self.client = client
        self.cache_file = Path(cfg.state_dir) / "ai-cache.json"
        try:
            self.cache = json.loads(self.cache_file.read_text())
        except (OSError, ValueError):
            self.cache = {}

    def _ask(self, host: Host, hint: Identity | None, force: bool = False) -> Identity | None:
        key = f"{self.cfg.model}:{host.fingerprint()}"
        if key in self.cache and not force:
            ident = Identity(**self.cache[key])
            ident.reasons = ident.reasons + ["(cached)"] if "(cached)" not in ident.reasons else ident.reasons
            return ident
        user = "KNOWN: " + ", ".join(fingerprints.known_apps()) + "\n\n"
        if hint:
            user += (f"A built-in rule guessed '{hint.app}' with confidence {hint.confidence} "
                     f"({'; '.join(hint.reasons)}). Confirm or correct it.\n\n")
        if self.cfg.house_rules:
            user += "House rules: " + self.cfg.house_rules + "\n\n"
        user += "HOST FACTS:\n" + json.dumps(facts(host), indent=1)
        try:
            data = self.client.chat_json(SYSTEM, user, SCHEMA)
        except (OllamaError, ValueError) as exc:
            self.log(f"  {host.ip}: model failed ({exc}); keeping the rule result")
            return None
        ident = from_model(data, host)
        self.cache[key] = ident.__dict__
        return ident

    def identify_one(self, host: Host, force: bool = False) -> Identity | None:
        if host.identity and host.identity.source == "manual" and not force:
            return host.identity
        if host.proxmox and host.proxmox.type == "node":
            return Identity(app="proxmox-ve", display_name="Proxmox VE node", category="virtualisation",
                            confidence=1.0, source="proxmox", web_port=8006, scheme="https",
                            health_path="/", exporter="pve-exporter",
                            description=f"Proxmox VE node {host.proxmox.node}",
                            reasons=["Proxmox API lists it as a node"])
        rule = fingerprints.match(host)
        if rule and (rule.confidence >= self.cfg.min_rule_confidence or not self.client):
            return rule
        if not self.client or not (host.ports or host.proxmox):
            return rule
        ai = self._ask(host, rule, force)
        if ai is None:
            return rule
        # When both agree, keep the rule's monitoring defaults but take the higher confidence
        if rule and ai.app == rule.app:
            rule.confidence = max(rule.confidence, ai.confidence)
            rule.description = ai.description or rule.description
            rule.version = rule.version or ai.version
            rule.source = "rule+ai"
            return rule
        return ai

    def run(self, hosts: list[Host], force: bool = False, workers: int = 1) -> None:
        todo = [h for h in hosts if force or h.identity is None or h.identity.source != "manual"]
        self.log(f"identifying {len(todo)} hosts (model: {self.cfg.model if self.client else 'off'})")

        def work(h: Host):
            ident = self.identify_one(h, force)
            if ident:
                h.identity = ident
            name = f"{ident.app} ({ident.source} {ident.confidence:.2f})" if ident else "?"
            self.log(f"  {h.ip:<15} {h.name[:28]:<28} {name}")

        with ThreadPoolExecutor(max_workers=max(1, workers)) as pool:
            list(pool.map(work, todo))
        self.cache_file.parent.mkdir(parents=True, exist_ok=True)
        self.cache_file.write_text(json.dumps(self.cache, indent=1))
