"""NetAlertX: device names, vendors and MACs it has collected (optional source)."""

from __future__ import annotations

import os

import requests


def collect(url: str, token_env: str, log=print) -> list[dict]:
    """[{ip, mac, name, vendor}] from the NetAlertX API (GET /devices)."""
    if not url:
        return []
    token = os.environ.get(token_env, "")
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    try:
        r = requests.get(url.rstrip("/") + "/devices", headers=headers, timeout=15)
        r.raise_for_status()
        data = r.json()
    except (requests.RequestException, ValueError) as exc:
        log(f"netalertx: {exc}")
        return []
    rows = data.get("devices", data) if isinstance(data, dict) else data
    out = []
    for d in rows or []:
        if not isinstance(d, dict):
            continue
        ip = d.get("devLastIP") or d.get("ip") or ""
        if not ip:
            continue
        out.append({"ip": ip, "mac": (d.get("devMac") or d.get("mac") or "").lower(),
                    "name": d.get("devName") or d.get("name") or "",
                    "vendor": d.get("devVendor") or d.get("vendor") or ""})
    log(f"netalertx: {len(out)} devices")
    return out
