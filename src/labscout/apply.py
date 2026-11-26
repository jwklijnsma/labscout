"""`labscout apply`: write the plan to NetBox and to a branch of the infra repo."""

from __future__ import annotations

import os
from pathlib import Path
import subprocess

import requests

from .plan import Plan, load_infra, patch_apps_yml


class NetBox:
    def __init__(self, url: str, token: str, verify: bool = True, tag: str = "labscout"):
        self.base = url.rstrip("/") + "/api"
        self.s = requests.Session()
        self.s.verify = verify
        self.s.headers.update({"Authorization": f"Token {token}", "Accept": "application/json",
                               "Content-Type": "application/json"})
        self.tag = tag

    def _req(self, method: str, path: str, **kw):
        r = self.s.request(method, self.base + path, timeout=20, **kw)
        if r.status_code >= 400:
            raise RuntimeError(f"NetBox {method} {path}: {r.status_code} {r.text[:200]}")
        return r.json() if r.text else {}

    def one(self, path: str, **params) -> dict | None:
        res = self._req("GET", path, params={**params, "limit": 2}).get("results", [])
        return res[0] if res else None

    def ensure_tag(self) -> None:
        if not self.one("/extras/tags/", slug=self.tag):
            self._req("POST", "/extras/tags/", json={"name": self.tag, "slug": self.tag,
                                                     "color": "2196f3",
                                                     "description": "Found by labscout"})

    def upsert_ip(self, item: dict) -> tuple[str, dict]:
        existing = self.one("/ipam/ip-addresses/", address=item["ip"])
        body = {"address": item["cidr"], "status": "active",
                "description": item["description"][:200],
                "dns_name": item["dns_name"] or "", "tags": [{"slug": self.tag}]}
        if existing:
            had = {t["slug"] for t in existing.get("tags", [])}
            body["tags"] = [{"slug": s} for s in sorted(had | {self.tag})]
            if existing.get("assigned_object"):
                body.pop("address")       # owned by an interface (e.g. the infra VM sync)
            if (existing.get("description") or "").strip() and self.tag not in had:
                body["description"] = existing["description"]   # never overwrite someone else's text
            if (existing.get("dns_name") or "").strip() and self.tag not in had:
                body["dns_name"] = existing["dns_name"]
            return "updated", self._req("PATCH", f"/ipam/ip-addresses/{existing['id']}/", json=body)
        return "created", self._req("POST", "/ipam/ip-addresses/", json=body)

    def upsert_services(self, vm_name: str, services: list[dict]) -> int:
        if not vm_name or not services:
            return 0
        vm = self.one("/virtualization/virtual-machines/", name=vm_name)
        if not vm:
            return 0
        n = 0
        for svc in services:
            body_new = {"parent_object_type": "virtualization.virtualmachine",
                        "parent_object_id": vm["id"], "name": svc["name"], "protocol": "tcp",
                        "ports": [svc["port"]], "description": svc["description"][:200],
                        "tags": [{"slug": self.tag}]}
            existing = (self.one("/ipam/services/", virtual_machine_id=vm["id"], name=svc["name"]))
            try:
                if existing:
                    self._req("PATCH", f"/ipam/services/{existing['id']}/",
                              json={"ports": [svc["port"]], "description": body_new["description"]})
                else:
                    self._req("POST", "/ipam/services/", json=body_new)
            except RuntimeError:
                # NetBox < 4.3 has virtual_machine instead of parent_object_*
                body_old = {k: v for k, v in body_new.items() if not k.startswith("parent_object")}
                body_old["virtual_machine"] = vm["id"]
                if not existing:
                    self._req("POST", "/ipam/services/", json=body_old)
            n += 1
        return n


def apply_netbox(plan: Plan, cfg, log=print, dry_run: bool = False) -> dict:
    token = os.environ.get(cfg.netbox_token_env, "")
    if not cfg.netbox_url or not token:
        raise RuntimeError(f"set netbox_url and ${cfg.netbox_token_env}")
    stats = {"created": 0, "updated": 0, "services": 0}
    if dry_run:
        for item in plan.netbox:
            log(f"  would upsert {item['cidr']:<18} {item['description'][:60]}")
        return stats
    nb = NetBox(cfg.netbox_url, token, cfg.netbox_verify_tls, cfg.netbox_tag)
    nb.ensure_tag()
    for item in plan.netbox:
        action, _ = nb.upsert_ip(item)
        stats[action] += 1
        stats["services"] += nb.upsert_services(item["vm"], item["services"])
    log(f"NetBox: {stats['created']} IPs created, {stats['updated']} updated, "
        f"{stats['services']} services")
    return stats


def _git(repo: Path, *args: str) -> str:
    r = subprocess.run(["git", "-C", str(repo), *args], capture_output=True, text=True)
    if r.returncode != 0:
        raise RuntimeError(f"git {' '.join(args)}: {r.stderr.strip()[:300]}")
    return r.stdout.strip()


def apply_infra(plan: Plan, cfg, log=print, commit: bool = True) -> str:
    """Edit apps.yml on a branch of the infra repo. Never pushes."""
    _, _, apps = load_infra(cfg.infra_repo, cfg.infra_apps_file)
    if apps is None:
        raise RuntimeError(f"{cfg.infra_apps_file} not found in {cfg.infra_repo!r}")
    if plan.empty:
        log("infra: nothing new for the app catalog")
        return ""
    repo = Path(cfg.infra_repo)
    if commit:
        if _git(repo, "status", "--porcelain", "--", cfg.infra_apps_file):
            raise RuntimeError(f"{cfg.infra_apps_file} has uncommitted changes; commit or stash first")
        current = _git(repo, "rev-parse", "--abbrev-ref", "HEAD")
        if current != cfg.infra_branch:
            exists = subprocess.run(["git", "-C", str(repo), "rev-parse", "--verify", cfg.infra_branch],
                                    capture_output=True).returncode == 0
            _git(repo, "checkout", *([] if exists else ["-b"]), cfg.infra_branch)
    apps.write_text(patch_apps_yml(apps.read_text(), plan))
    summary = (f"{len(plan.catalog_add)} new apps ({', '.join(sorted(plan.catalog_add)) or '-'}), "
               f"{len(plan.aliases_add)} aliases")
    if commit:
        _git(repo, "add", cfg.infra_apps_file)
        _git(repo, "commit", "-m", f"labscout: {summary}",
             "-m", "Found by labscout (local Ollama). Review, push, then run playbooks "
                   "exporters/monitoring/proxy.")
        log(f"infra: committed on branch {cfg.infra_branch}: {summary} (not pushed)")
    else:
        log(f"infra: {apps} updated: {summary}")
    return summary
