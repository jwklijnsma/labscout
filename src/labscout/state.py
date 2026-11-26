"""Scan results on disk (labscout-data/hosts.json), merged so decisions survive a re-scan."""

from __future__ import annotations

import json
import time
from pathlib import Path

from .models import Host, ip_key


def path(state_dir: str) -> Path:
    return Path(state_dir) / "hosts.json"


def load(state_dir: str) -> list[Host]:
    try:
        data = json.loads(path(state_dir).read_text())
    except (OSError, ValueError):
        return []
    return [Host.from_dict(h) for h in data.get("hosts", [])]


def save(state_dir: str, hosts: list[Host]) -> Path:
    p = path(state_dir)
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_suffix(".tmp")
    tmp.write_text(json.dumps({"updated": int(time.time()),
                               "hosts": [h.to_dict() for h in sorted(hosts, key=lambda h: ip_key(h.ip))]},
                              indent=1))
    tmp.replace(p)
    return p


def carry_over(new: list[Host], old: list[Host]) -> list[Host]:
    """Keep decisions, notes and manual identities from the previous run; keep the
    previous AI answer when nothing about the host changed."""
    prev = {h.ip: h for h in old}
    for h in new:
        o = prev.get(h.ip)
        if not o:
            continue
        h.decision, h.note = o.decision, o.note
        if o.identity and (o.identity.source == "manual" or o.fingerprint() == h.fingerprint()):
            h.identity = o.identity
    return new
