"""Built-in fingerprints for common homelab software.

A rule matches on what a scan sees (HTTP title/server/body, nmap product, open ports,
Proxmox tags and name). The best match wins; when its confidence is below
``min_rule_confidence`` the local model is asked as well. The monitoring fields are the
defaults the plan uses (health check path, /metrics, the exporter to add).
"""

from __future__ import annotations

from dataclasses import dataclass, field
import re

from .models import Host, Identity


@dataclass
class Rule:
    app: str
    name: str
    category: str
    title: str = ""            # regex on the HTML <title> (or body hint)
    server: str = ""           # regex on Server / X-Powered-By / generator
    product: str = ""          # regex on the nmap product string
    ports: tuple[int, ...] = ()        # typical ports; a port-only hit is weak evidence
    port_only: bool = False    # port alone is distinctive enough (9100, 8006, ...)
    names: tuple[str, ...] = ()        # hostname / Proxmox name / tag hints
    health_path: str = "/"
    metrics_path: str = ""     # /metrics on the web port, if the app has it
    metrics_port: int = 0      # separate metrics port
    exporter: str = ""         # exporter to add when the app has no metrics itself
    community_script: str = ""
    extra: dict = field(default_factory=dict)


RULES: list[Rule] = [
    # --- monitoring ------------------------------------------------------------------------
    Rule("prometheus", "Prometheus", "monitoring", title=r"^Prometheus", ports=(9090,),
         names=("prometheus",), health_path="/-/healthy", metrics_path="/metrics",
         community_script="prometheus"),
    Rule("alertmanager", "Alertmanager", "monitoring", title=r"Alertmanager", ports=(9093,),
         names=("alertmanager",), health_path="/-/healthy", metrics_path="/metrics",
         community_script="prometheus-alertmanager"),
    Rule("grafana", "Grafana", "monitoring", title=r"^Grafana", ports=(3000,), names=("grafana",),
         health_path="/api/health", metrics_path="/metrics", community_script="grafana"),
    Rule("node-exporter", "Prometheus node_exporter", "monitoring", title=r"Node Exporter",
         ports=(9100,), port_only=True, health_path="/metrics", metrics_path="/metrics"),
    Rule("blackbox-exporter", "Blackbox exporter", "monitoring", title=r"Blackbox Exporter",
         ports=(9115,), port_only=True, health_path="/-/healthy", metrics_path="/metrics"),
    Rule("pve-exporter", "Prometheus PVE exporter", "monitoring", title=r"Proxmox VE Exporter",
         ports=(9221,), port_only=True, health_path="/", metrics_path="/pve",
         community_script="prometheus-pve-exporter"),
    Rule("uptime-kuma", "Uptime Kuma", "monitoring", title=r"Uptime Kuma", ports=(3001,),
         names=("uptime", "kuma"), health_path="/", metrics_path="/metrics",
         community_script="uptimekuma"),
    Rule("netalertx", "NetAlertX", "network", title=r"NetAlertX|Pi\.Alert", ports=(20211,),
         port_only=True, names=("netalertx",), health_path="/", community_script="netalertx"),
    Rule("homelable", "Homelable", "network", title=r"Homelable", names=("homelable",),
         health_path="/", community_script="homelable"),
    # --- virtualisation / storage ----------------------------------------------------------
    Rule("proxmox-ve", "Proxmox VE", "virtualisation", title=r"Proxmox Virtual Environment|- Proxmox Virtual",
         product=r"Proxmox", ports=(8006,), port_only=True, health_path="/",
         exporter="pve-exporter", extra={"scheme": "https"}),
    Rule("proxmox-backup", "Proxmox Backup Server", "backup", title=r"Proxmox Backup Server",
         ports=(8007,), port_only=True, health_path="/", extra={"scheme": "https"}),
    Rule("proxmox-datacenter-manager", "Proxmox Datacenter Manager", "virtualisation",
         title=r"Proxmox Datacenter Manager", ports=(8443,), health_path="/",
         community_script="proxmox-datacenter-manager", extra={"scheme": "https"}),
    Rule("synology", "Synology DSM", "storage", title=r"Synology|DiskStation|DSM", ports=(5000, 5001),
         health_path="/", exporter="snmp-exporter"),
    Rule("truenas", "TrueNAS", "storage", title=r"TrueNAS", health_path="/", exporter="node-exporter"),
    Rule("portainer", "Portainer", "containers", title=r"Portainer", ports=(9443, 9000),
         health_path="/api/system/status", community_script="portainer"),
    # --- network ---------------------------------------------------------------------------
    Rule("adguard", "AdGuard Home", "network", title=r"AdGuard Home", names=("adguard",),
         health_path="/login.html", exporter="adguard-exporter", community_script="adguard"),
    Rule("pihole", "Pi-hole", "network", title=r"Pi-hole", names=("pihole", "pi-hole"),
         health_path="/admin/", exporter="pihole-exporter", community_script="pihole"),
    Rule("technitium", "Technitium DNS", "network", title=r"Technitium DNS", ports=(5380,),
         health_path="/", community_script="technitiumdns"),
    Rule("powerdns", "PowerDNS", "network", product=r"PowerDNS", names=("powerdns", "pdns"),
         ports=(53,), health_path="", exporter="powerdns"),
    Rule("traefik", "Traefik", "network", title=r"Traefik", server=r"Traefik", ports=(8080,),
         names=("traefik",), health_path="/ping", metrics_path="/metrics"),
    Rule("nginx-proxy-manager", "Nginx Proxy Manager", "network", title=r"Nginx Proxy Manager",
         ports=(81,), health_path="/", community_script="nginxproxymanager"),
    Rule("unifi", "UniFi Network", "network", title=r"UniFi", ports=(8443,), names=("unifi",),
         health_path="/status", exporter="unpoller", community_script="unifi"),
    Rule("wireguard", "WireGuard / wg-easy", "network", title=r"WireGuard|wg-easy",
         names=("wireguard", "wg-easy"), health_path="/"),
    Rule("netbox", "NetBox", "network", title=r"NetBox", names=("netbox",), health_path="/login/",
         metrics_path="/metrics", community_script="netbox"),
    Rule("crowdsec", "CrowdSec", "security", product=r"crowdsec", ports=(6060,), health_path="",
         metrics_port=6060, metrics_path="/metrics"),
    # --- automation / dev ------------------------------------------------------------------
    Rule("home-assistant", "Home Assistant", "home-automation", title=r"Home Assistant",
         ports=(8123,), port_only=True, names=("homeassistant", "home-assistant", "haos"),
         health_path="/manifest.json", metrics_path="/api/prometheus"),
    Rule("mqtt", "MQTT broker", "home-automation", product=r"mosquitto|mqtt", ports=(1883,),
         port_only=True, names=("mqtt", "mosquitto"), health_path="", exporter="mqtt-exporter"),
    Rule("zigbee2mqtt", "Zigbee2MQTT", "home-automation", title=r"Zigbee2MQTT",
         names=("zigbee2mqtt", "z2m"), health_path="/"),
    Rule("esphome", "ESPHome", "home-automation", title=r"ESPHome", ports=(6052,), health_path="/"),
    Rule("node-red", "Node-RED", "home-automation", title=r"Node-RED", ports=(1880,), health_path="/"),
    Rule("semaphore", "Semaphore UI", "automation", title=r"Semaphore", names=("semaphore",),
         health_path="/api/ping", community_script="semaphore"),
    Rule("gitea", "Gitea / Forgejo", "development", title=r"Gitea|Forgejo", health_path="/api/healthz",
         metrics_path="/metrics"),
    Rule("gitlab", "GitLab", "development", title=r"GitLab", health_path="/-/health"),
    Rule("n8n", "n8n", "automation", title=r"\bn8n\b", ports=(5678,), health_path="/healthz"),
    # --- apps ------------------------------------------------------------------------------
    Rule("homarr", "Homarr", "dashboard", title=r"Homarr", ports=(7575,), names=("homarr",),
         health_path="/api/health/live", community_script="homarr"),
    Rule("heimdall", "Heimdall", "dashboard", title=r"Heimdall", health_path="/"),
    Rule("vaultwarden", "Vaultwarden", "security", title=r"Vaultwarden|Bitwarden",
         names=("vaultwarden", "vault"), health_path="/alive", community_script="vaultwarden"),
    Rule("aliasvault", "AliasVault", "security", title=r"AliasVault", names=("aliasvault",),
         health_path="/"),
    Rule("immich", "Immich", "media", title=r"Immich", ports=(2283,), names=("immich",),
         health_path="/api/server/ping", metrics_port=8081, metrics_path="/metrics",
         community_script="immich"),
    Rule("jellyfin", "Jellyfin", "media", title=r"Jellyfin", ports=(8096,), health_path="/health"),
    Rule("emby", "Emby", "media", title=r"Emby", ports=(8096,), names=("emby",),
         health_path="/emby/System/Info/Public", community_script="emby"),
    Rule("plex", "Plex", "media", title=r"Plex", ports=(32400,), port_only=True,
         health_path="/identity", community_script="plex"),
    Rule("sonarr", "Sonarr", "media", title=r"^Sonarr", ports=(8989,), names=("sonarr",),
         health_path="/ping", exporter="exportarr", community_script="sonarr"),
    Rule("radarr", "Radarr", "media", title=r"^Radarr", ports=(7878,), names=("radarr",),
         health_path="/ping", exporter="exportarr", community_script="radarr"),
    Rule("lidarr", "Lidarr", "media", title=r"^Lidarr", ports=(8686,), health_path="/ping",
         exporter="exportarr", community_script="lidarr"),
    Rule("prowlarr", "Prowlarr", "media", title=r"^Prowlarr", ports=(9696,), names=("prowlarr",),
         health_path="/ping", exporter="exportarr", community_script="prowlarr"),
    Rule("bazarr", "Bazarr", "media", title=r"^Bazarr", ports=(6767,), names=("bazarr",),
         health_path="/", exporter="exportarr", community_script="bazarr"),
    Rule("overseerr", "Overseerr / Jellyseerr", "media", title=r"Overseerr|Jellyseerr", ports=(5055,),
         health_path="/api/v1/status"),
    Rule("nzbget", "NZBGet", "downloads", title=r"NZBGet", ports=(6789,), names=("nzbget",),
         health_path="/", community_script="nzbget"),
    Rule("sabnzbd", "SABnzbd", "downloads", title=r"SABnzbd", health_path="/"),
    Rule("qbittorrent", "qBittorrent", "downloads", title=r"qBittorrent", health_path="/"),
    Rule("open-webui", "Open WebUI", "ai", title=r"Open WebUI", names=("openwebui", "open-webui"),
         health_path="/health", community_script="openwebui"),
    Rule("ollama", "Ollama", "ai", title=r"Ollama is running", ports=(11434,), port_only=True,
         names=("ollama",), health_path="/", exporter="ollama-exporter", community_script="ollama"),
    Rule("it-tools", "IT-Tools", "tools", title=r"IT Tools", names=("it-tools",), health_path="/"),
    Rule("nextcloud", "Nextcloud", "files", title=r"Nextcloud", health_path="/status.php",
         exporter="nextcloud-exporter"),
    Rule("paperless", "Paperless-ngx", "files", title=r"Paperless", health_path="/"),
    Rule("syncthing", "Syncthing", "files", title=r"Syncthing", ports=(8384,), health_path="/rest/noauth/health"),
    # --- infrastructure services (no web UI) -------------------------------------------------
    Rule("postgresql", "PostgreSQL", "database", product=r"PostgreSQL", ports=(5432,), port_only=True,
         health_path="", exporter="postgres-exporter"),
    Rule("mariadb", "MariaDB / MySQL", "database", product=r"MySQL|MariaDB", ports=(3306,),
         port_only=True, health_path="", exporter="mysqld-exporter"),
    Rule("redis", "Redis", "database", product=r"Redis", ports=(6379,), port_only=True,
         health_path="", exporter="redis-exporter"),
    Rule("nut", "NUT UPS server", "power", product=r"NUT|upsd", ports=(3493,), port_only=True,
         health_path="", exporter="nut-exporter"),
    Rule("chrony", "Chrony NTP", "network", names=("chrony", "ntp"), health_path="",
         exporter="chrony-exporter", community_script="chrony"),
    Rule("clamav", "ClamAV", "security", product=r"ClamAV", names=("clamav",), health_path=""),
    Rule("ups-snmp", "Network UPS / PDU", "power", title=r"\bUPS\b|PowerChute|Eaton", health_path="/",
         exporter="snmp-exporter"),
    Rule("printer", "Printer", "devices", title=r"\b(HP|Brother|Canon|Epson)\b.*(Printer|LaserJet|MFC)|EWS",
         product=r"printer|JetDirect", ports=(631, 9100), health_path=""),
]

_TITLE_W, _PRODUCT_W, _NAME_W, _PORT_W, _PORT_ONLY_W = 0.95, 0.9, 0.75, 0.35, 0.8


def _texts(host: Host) -> list[str]:
    out = []
    for h in host.http:
        out += [h.title, h.body_hint]
    return [t for t in out if t]


def _servers(host: Host) -> list[str]:
    out = []
    for h in host.http:
        out += [h.server, h.powered_by, h.generator]
    return [t for t in out if t]


def _names(host: Host) -> list[str]:
    names = [host.name.lower(), host.hostname.lower()]
    if host.proxmox:
        names += [t.lower() for t in host.proxmox.tags] + [host.proxmox.name.lower()]
    return [n for n in names if n]


def score(rule: Rule, host: Host) -> tuple[float, list[str], int]:
    """Confidence that `host` runs `rule`, the reasons, and the port it was seen on."""
    best, reasons, port = 0.0, [], 0
    open_ports = {p.port for p in host.ports}
    if rule.title:
        for h in host.http:
            for t in (h.title, h.body_hint):
                if t and re.search(rule.title, t, re.I):
                    if _TITLE_W > best:
                        best, port = _TITLE_W, h.port
                    reasons.append(f"HTTP title on :{h.port} matches '{t[:60]}'")
                    break
    if rule.server:
        for h in host.http:
            for t in (h.server, h.powered_by, h.generator):
                if t and re.search(rule.server, t, re.I):
                    best, port = max(best, _PRODUCT_W), port or h.port
                    reasons.append(f"server header on :{h.port} is '{t[:40]}'")
    if rule.product:
        for p in host.ports:
            text = f"{p.product} {p.version} {p.extra}".strip()
            if text and re.search(rule.product, text, re.I):
                best, port = max(best, _PRODUCT_W), port or p.port
                reasons.append(f"nmap identifies :{p.port} as '{text[:50]}'")
    if rule.names:
        for n in _names(host):
            if any(re.search(rf"(^|[^a-z]){re.escape(k)}([^a-z]|$)", n) for k in rule.names):
                best = max(best, _NAME_W)
                reasons.append(f"name/tag '{n}'")
                break
    hit_ports = [p for p in rule.ports if p in open_ports]
    if hit_ports:
        w = _PORT_ONLY_W if rule.port_only else _PORT_W
        if best >= _NAME_W:            # a port on top of other evidence: more confident
            best = min(0.99, best + 0.04)
        elif w > best:
            best = w
        port = port or hit_ports[0]
        reasons.append(f"port {hit_ports[0]} open")
    return best, reasons, port


def match(host: Host) -> Identity | None:
    """The best rule for this host, as an Identity (None when nothing matches)."""
    scored = [(score(r, host), r) for r in RULES]
    scored = [(s, r) for s, r in scored if s[0] > 0]
    if not scored:
        return None
    (conf, reasons, port), rule = max(scored, key=lambda x: x[0][0])
    scheme = rule.extra.get("scheme", "")
    if not scheme:
        scheme = next((h.scheme for h in host.http if h.port == port), "http")
    return Identity(
        app=rule.app, display_name=rule.name, category=rule.category,
        version=next((p.version for p in host.ports if p.port == port and p.version), ""),
        confidence=round(conf, 2), source="rule", web_port=port if rule.health_path else 0,
        scheme=scheme, health_path=rule.health_path,
        metrics_port=rule.metrics_port or (port if rule.metrics_path else 0),
        metrics_path=rule.metrics_path, exporter=rule.exporter,
        community_script=rule.community_script, reasons=reasons[:5])


def known_apps() -> list[str]:
    return sorted({r.app for r in RULES})
