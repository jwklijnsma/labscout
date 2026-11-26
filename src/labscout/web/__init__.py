"""`labscout serve`: review hosts and run scans from the browser.

Standard library only, no CDN assets. Locked down like ansreview: binds to 127.0.0.1,
every API call needs the access token (cookie set from ``/?token=...``), POSTs need the
``X-Labscout`` header, and jobs run as ``python -m labscout <command>`` subprocesses so a
crash in a scan cannot take the server down. The Ollama host, tokens and networks come from
the config/environment only, never from the browser.
"""

from __future__ import annotations

import hmac
from http import cookies
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import secrets
import subprocess
import sys
import threading
import time
from urllib.parse import parse_qs, urlsplit

from .. import __version__, state
from ..models import Identity
from ..plan import build as build_plan

STATIC = Path(__file__).resolve().parent / "static"
FILES = {"/": ("index.html", "text/html; charset=utf-8"),
         "/app.js": ("app.js", "text/javascript; charset=utf-8"),
         "/app.css": ("app.css", "text/css; charset=utf-8")}
COOKIE = "labscout_token"
HEADER = "X-Labscout"
JOBS = {"scan": ["scan"], "identify": ["identify"], "identify-force": ["identify", "--force"],
        "plan": ["plan"], "apply-netbox": ["apply", "--netbox"], "apply-infra": ["apply", "--infra"],
        "dry-run": ["apply", "--netbox", "--infra", "--dry-run"]}


class Job:
    def __init__(self):
        self.lock = threading.Lock()
        self.name = ""
        self.proc: subprocess.Popen | None = None
        self.log: list[str] = []
        self.started = self.ended = 0.0
        self.rc: int | None = None

    def running(self) -> bool:
        return self.proc is not None and self.proc.poll() is None

    def start(self, name: str, argv: list[str]) -> None:
        with self.lock:
            if self.running():
                raise RuntimeError(f"'{self.name}' is still running")
            self.name, self.log, self.rc = name, [], None
            self.started, self.ended = time.time(), 0.0
            self.proc = subprocess.Popen([sys.executable, "-m", "labscout", *argv],
                                         stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                         text=True, bufsize=1)
        threading.Thread(target=self._pump, daemon=True).start()

    def _pump(self) -> None:
        for line in self.proc.stdout:
            self.log.append(line.rstrip())
            del self.log[:-4000]
        self.rc = self.proc.wait()
        self.ended = time.time()

    def to_dict(self) -> dict:
        return {"name": self.name, "running": self.running(), "rc": self.rc,
                "started": self.started, "ended": self.ended, "log": self.log[-400:]}


def make_handler(cfg, config_path: str | None, token: str, job: Job):
    base_args = (["-c", config_path] if config_path else []) + ["--state-dir", cfg.state_dir]

    class H(BaseHTTPRequestHandler):
        server_version = f"labscout/{__version__}"

        def log_message(self, fmt, *args):   # quiet
            pass

        def _authed(self) -> bool:
            c = cookies.SimpleCookie(self.headers.get("Cookie", ""))
            got = c[COOKIE].value if COOKIE in c else ""
            return bool(got) and hmac.compare_digest(got, token)

        def _send(self, code: int, body: bytes, ctype: str, extra: dict | None = None):
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Content-Security-Policy", "default-src 'self'; style-src 'self'")
            for k, v in (extra or {}).items():
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(body)

        def _json(self, code: int, data) -> None:
            self._send(code, json.dumps(data).encode(), "application/json")

        def do_GET(self):  # noqa: N802
            u = urlsplit(self.path)
            q = parse_qs(u.query)
            if u.path == "/" and q.get("token") and hmac.compare_digest(q["token"][0], token):
                return self._send(303, b"", "text/plain", {
                    "Location": "/", "Set-Cookie": f"{COOKIE}={token}; HttpOnly; SameSite=Strict; Path=/"})
            if u.path in FILES:
                name, ctype = FILES[u.path]
                if u.path == "/" and not self._authed():
                    return self._send(401, b"labscout: open the URL with ?token=... printed at start",
                                      "text/plain")
                return self._send(200, (STATIC / name).read_bytes(), ctype)
            if not self._authed():
                return self._json(401, {"error": "token"})
            if u.path == "/api/state":
                hosts = state.load(cfg.state_dir)
                plan = build_plan(hosts, cfg)
                return self._json(200, {"version": __version__, "model": cfg.model if cfg.use_llm else "",
                                        "networks": cfg.networks, "hosts": [h.to_dict() for h in hosts],
                                        "plan": plan.to_dict(), "job": job.to_dict(),
                                        "netbox": bool(cfg.netbox_url), "infra": bool(cfg.infra_repo)})
            if u.path == "/api/job":
                return self._json(200, job.to_dict())
            if u.path == "/report.md":
                p = Path(cfg.state_dir) / "report.md"
                if p.is_file():
                    return self._send(200, p.read_bytes(), "text/markdown; charset=utf-8",
                                      {"Content-Disposition": "attachment; filename=labscout-report.md"})
            return self._json(404, {"error": "not found"})

        def do_POST(self):  # noqa: N802
            if not self._authed() or self.headers.get(HEADER) != "1":
                return self._json(401, {"error": "token"})
            n = int(self.headers.get("Content-Length") or 0)
            if n > 64 * 1024:
                return self._json(413, {"error": "too large"})
            try:
                body = json.loads(self.rfile.read(n) or b"{}")
            except ValueError:
                return self._json(400, {"error": "bad json"})
            path = urlsplit(self.path).path
            if path == "/api/job":
                name = body.get("name", "")
                if name not in JOBS:
                    return self._json(400, {"error": "unknown job"})
                try:
                    job.start(name, [JOBS[name][0], *base_args, *JOBS[name][1:]])
                except RuntimeError as exc:
                    return self._json(409, {"error": str(exc)})
                return self._json(202, job.to_dict())
            if path == "/api/host":
                if job.running():
                    return self._json(409, {"error": "a job is running; try again when it is done"})
                hosts = state.load(cfg.state_dir)
                h = next((x for x in hosts if x.ip == body.get("ip")), None)
                if not h:
                    return self._json(404, {"error": "unknown host"})
                if body.get("decision") in ("pending", "approved", "rejected"):
                    h.decision = body["decision"]
                if body.get("app"):
                    old = h.identity or Identity()
                    h.identity = Identity(**{**old.__dict__, "app": str(body["app"])[:60],
                                             "web_port": int(body.get("web_port") or old.web_port or 0),
                                             "health_path": str(body.get("health_path") or old.health_path or "/")[:200],
                                             "source": "manual", "confidence": 1.0,
                                             "reasons": ["set in the web UI"]})
                if "note" in body:
                    h.note = str(body["note"])[:500]
                state.save(cfg.state_dir, hosts)
                return self._json(200, h.to_dict())
            return self._json(404, {"error": "not found"})

    return H


def serve(cfg, config_path: str | None, bind: str = "127.0.0.1", port: int = 8766) -> int:
    token = os.environ.get("LABSCOUT_WEB_TOKEN") or secrets.token_urlsafe(24)
    job = Job()
    httpd = ThreadingHTTPServer((bind, port), make_handler(cfg, config_path, token, job))
    host = "localhost" if bind in ("127.0.0.1", "0.0.0.0") else bind
    print(f"labscout {__version__} web UI: http://{host}:{port}/?token={token}", flush=True)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        if job.running():
            job.proc.terminate()
        httpd.server_close()
    return 0
