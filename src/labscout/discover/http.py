"""HTTP fingerprinting: title, Server header and a hint of the body for every web port."""

from __future__ import annotations

import html
import re
import warnings
from concurrent.futures import ThreadPoolExecutor

import requests

from ..models import Host, HttpInfo

# Ports that are never HTTP (saves time and avoids confusing banner text)
NOT_HTTP = {21, 22, 23, 25, 53, 110, 143, 389, 445, 587, 993, 995, 1883, 3306, 3493, 5432, 6379}
TLS_FIRST = {443, 5001, 8006, 8007, 8443, 9443}
_TITLE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)
_GEN = re.compile(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)', re.IGNORECASE)
_TAGS = re.compile(r"<[^>]+>")


def _clean(text: str, n: int = 120) -> str:
    return re.sub(r"\s+", " ", html.unescape(text or "")).strip()[:n]


def _looks_tls(host: Host, port: int) -> bool:
    if port in TLS_FIRST:
        return True
    return any(p.port == port and ("ssl" in p.extra or p.service in ("https", "ssl/http"))
               for p in host.ports)


def probe(session: requests.Session, ip: str, port: int, tls_first: bool,
          timeout: float) -> HttpInfo | None:
    schemes = ("https", "http") if tls_first else ("http", "https")
    for scheme in schemes:
        url = f"{scheme}://{ip}:{port}/"
        try:
            r = session.get(url, timeout=timeout, allow_redirects=False, verify=False,
                            stream=True)
            body = r.raw.read(65536, decode_content=True).decode(r.encoding or "utf-8", "replace")
            r.close()
        except (requests.RequestException, OSError, ValueError):
            continue
        # "Client sent an HTTP request to an HTTPS server" and friends: try the other scheme
        if scheme == "http" and r.status_code == 400 and "https" in body.lower():
            continue
        info = HttpInfo(port=port, scheme=scheme, status=r.status_code,
                        server=r.headers.get("Server", "")[:80],
                        powered_by=r.headers.get("X-Powered-By", "")[:80],
                        location=r.headers.get("Location", "")[:200])
        m = _TITLE.search(body)
        info.title = _clean(m.group(1)) if m else ""
        g = _GEN.search(body)
        info.generator = _clean(g.group(1), 80) if g else ""
        if not info.title:
            info.body_hint = _clean(_TAGS.sub(" ", body), 120)
        if 300 <= r.status_code < 400 and info.location and not info.title:
            # follow one redirect on the same host to see the login page title
            loc = info.location if info.location.startswith("http") else f"{scheme}://{ip}:{port}{info.location}"
            if ip in loc:
                try:
                    r2 = session.get(loc, timeout=timeout, verify=False)
                    m2 = _TITLE.search(r2.text[:65536])
                    info.title = _clean(m2.group(1)) if m2 else ""
                    if not info.title:
                        info.body_hint = _clean(_TAGS.sub(" ", r2.text[:4096]), 120)
                except requests.RequestException:
                    pass
        return info
    return None


def fingerprint_http(hosts: dict[str, Host], timeout: float = 4.0, workers: int = 32,
                     log=print) -> None:
    jobs = [(h, p.port) for h in hosts.values() for p in h.ports
            if p.port not in NOT_HTTP and p.proto == "tcp"]
    if not jobs:
        return
    log(f"HTTP fingerprinting {len(jobs)} ports")
    session = requests.Session()
    session.headers["User-Agent"] = "labscout (homelab inventory)"
    warnings.filterwarnings("ignore", message="Unverified HTTPS request")
    with ThreadPoolExecutor(max_workers=workers) as pool:
        results = pool.map(lambda j: probe(session, j[0].ip, j[1], _looks_tls(j[0], j[1]), timeout), jobs)
        for (host, _port), info in zip(jobs, results):
            if info:
                host.http.append(info)
