"""Configuration: defaults < ~/.labscout.yml < ./labscout.yml < environment < CLI flags.

Secrets are never stored in the config itself: every token is read from the environment
variable the config names (``*_token_env``), so the YAML file can live in git.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field, fields
from pathlib import Path

import yaml

CONFIG_NAMES = ("labscout.yml", ".labscout.yml")


@dataclass
class ProxmoxEndpoint:
    name: str
    url: str                          # https://10.0.3.40:8006
    token_id: str = ""                # user@realm!tokenid (read-only, PVEAuditor is enough)
    token_env: str = ""               # env var holding the token secret
    verify_tls: bool = False

    @property
    def token_secret(self) -> str:
        return os.environ.get(self.token_env, "") if self.token_env else ""


@dataclass
class Config:
    # --- Ollama -----------------------------------------------------------------------
    ollama_host: str = "http://localhost:11434"
    model: str = "qwen2.5:14b"
    api_key: str = ""
    temperature: float = 0.1
    num_ctx: int = 8192
    num_predict: int = 1024
    timeout: int = 300
    keep_alive: str = "30m"
    use_llm: bool = True
    min_rule_confidence: float = 0.85   # below this, the model gets a say too
    # --- discovery ----------------------------------------------------------------------
    networks: list[str] = field(default_factory=lambda: ["192.168.1.0/24"])
    exclude: list[str] = field(default_factory=list)      # IPs or CIDRs to leave alone
    ports: str = ("22,53,80,81,443,1883,2283,3000,3001,3306,3493,5000,5001,5055,5380,5432,"
                  "5601,5678,6379,6767,7575,7878,8000,8006,8007,8080,8081,8082,8083,8086,"
                  "8088,8090,8096,8123,8181,8200,8384,8443,8686,8787,8888,8989,9000,9090,"
                  "9091,9093,9100,9115,9117,9221,9443,9696,10000,11434,20211,32400")
    use_nmap: bool = True              # nmap -sV when installed, else a plain TCP connect scan
    nmap_args: str = "-sV --version-light -T4"
    scan_workers: int = 64
    connect_timeout: float = 0.8
    http_timeout: float = 4.0
    proxmox: list[ProxmoxEndpoint] = field(default_factory=list)
    netalertx_url: str = ""            # http://10.0.3.58:20212 (NetAlertX API port)
    netalertx_token_env: str = "NETALERTX_API_TOKEN"
    # --- output -------------------------------------------------------------------------
    domain: str = ""                   # home.example.org -> subdomain suggestions
    state_dir: str = "labscout-data"
    # --- apply --------------------------------------------------------------------------
    netbox_url: str = ""
    netbox_token_env: str = "NETBOX_TOKEN"
    netbox_verify_tls: bool = True
    netbox_tag: str = "labscout"
    infra_repo: str = ""               # path to a jwklijnsma/infra style repo
    infra_apps_file: str = "inventory/group_vars/all/apps.yml"
    infra_branch: str = "labscout/apps"
    house_rules: str = ""              # extra instructions for the model

    def update(self, data: dict, source: str = "") -> list[str]:
        warnings = []
        known = {f.name for f in fields(self)}
        for key, value in (data or {}).items():
            k = key.replace("-", "_")
            if k not in known:
                warnings.append(f"{source}: unknown setting '{key}' ignored")
                continue
            if k == "proxmox":
                value = [v if isinstance(v, ProxmoxEndpoint) else ProxmoxEndpoint(**v)
                         for v in (value or [])]
            setattr(self, k, value)
        return warnings

    @property
    def state_path(self) -> Path:
        return Path(self.state_dir)


ENV_MAP = {
    "OLLAMA_HOST": "ollama_host",
    "LABSCOUT_MODEL": "model",
    "LABSCOUT_NETWORKS": "networks",
    "LABSCOUT_NETBOX_URL": "netbox_url",
    "LABSCOUT_INFRA_REPO": "infra_repo",
    "LABSCOUT_STATE_DIR": "state_dir",
}


def load_config(path: str | None = None) -> tuple[Config, list[str]]:
    cfg = Config()
    warnings: list[str] = []
    candidates = [Path.home() / ".labscout.yml"]
    candidates += [Path(path)] if path else [Path(n) for n in CONFIG_NAMES]
    for p in candidates:
        if p.is_file():
            warnings += cfg.update(yaml.safe_load(p.read_text()) or {}, str(p))
        elif path and p == Path(path):
            warnings.append(f"config file {path} not found")
    for env, key in ENV_MAP.items():
        if os.environ.get(env):
            value = os.environ[env]
            if key == "networks":
                value = [n.strip() for n in value.replace(";", ",").split(",") if n.strip()]
            setattr(cfg, key, value)
    if cfg.ollama_host and not cfg.ollama_host.startswith("http"):
        cfg.ollama_host = "http://" + cfg.ollama_host
    return cfg, warnings


SAMPLE = """\
# labscout configuration. Secrets come from environment variables, never from this file.
ollama_host: http://localhost:11434
model: qwen2.5:14b            # any instruct model; 7-14B is plenty for classification

networks:                     # every range to scan
  - 10.0.3.0/24
  - 10.0.0.0/24
  - 10.0.2.0/24
exclude: []                   # IPs/CIDRs to skip (printers that dislike port scans, ...)

proxmox:                      # read-only API tokens (PVEAuditor) per cluster/standalone node
  - name: home-cluster
    url: https://10.0.3.40:8006
    token_id: prometheus@pve!monitoring
    token_env: PVE_TOKEN_HOME_CLUSTER

netalertx_url: ""             # e.g. http://10.0.3.58:20212 (token in $NETALERTX_API_TOKEN)

domain: home.example.org      # subdomain suggestions: <app>.<domain>

netbox_url: ""                # e.g. https://netbox.home.example.org (token in $NETBOX_TOKEN)
infra_repo: ""                # path to your jwklijnsma/infra style repo
"""
