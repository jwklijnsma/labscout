"""`labscout serve`: the JSON API behind the React UI, plus the built UI itself.

Standard library only. Built like the ansreview server:

* binds to 127.0.0.1 by default; every API call needs the access token (cookie set from
  ``/?token=...`` or ``POST /api/login``, or ``Authorization: Bearer``);
* every POST needs the ``X-Labscout: 1`` header and a same-origin ``Origin``;
* jobs run one at a time from a queue as ``python -m labscout <command>`` subprocesses, so
  a crash in a scan cannot take the server down, and options are whitelisted: the Ollama
  host, tokens and output paths come from the config/environment only, never the browser.
"""

from __future__ import annotations

import hmac
import ipaddress
import itertools
import json
import os
import re
import secrets
import shutil
import signal
import subprocess
import sys
import threading
import time
import uuid
from collections import deque
from dataclasses import dataclass, field
from http import cookies
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlsplit

from .. import __version__, report, state
from ..models import Identity
from ..plan import build as build_plan

STATIC_DIR = Path(__file__).resolve().parent / "static"
STATIC_FILES = {
    "/": ("index.html", "text/html; charset=utf-8"),
    "/index.html": ("index.html", "text/html; charset=utf-8"),
    "/app.js": ("app.js", "text/javascript; charset=utf-8"),
    "/app.css": ("app.css", "text/css; charset=utf-8"),
    "/favicon.svg": ("favicon.svg", "image/svg+xml"),
}
SECURITY_HEADERS = {
    "Content-Security-Policy": "default-src 'none'; script-src 'self'; style-src 'self'; "
                               "img-src 'self' data:; connect-src 'self'; base-uri 'none'; "
                               "form-action 'self'; frame-ancestors 'none'",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
}
COOKIE = "labscout_token"
CSRF_HEADER = "X-Labscout"
MAX_BODY = 64 * 1024
MAX_LOG_LINES = 5000
MAX_PENDING = 10
MAX_JOBS_KEPT = 50
MODEL_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$")
APP_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,59}$")
PATH_RE = re.compile(r"^/[A-Za-z0-9._~/?=&%+-]{0,199}$")
ACTIONS = ("run", "scan", "identify", "plan", "apply")
# Jobs that rewrite hosts.json: host edits wait until they are done.
WRITES_HOSTS = ("run", "scan", "identify")
DECISIONS = ("pending", "approved", "rejected")


class ApiError(Exception):
    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status = status
        self.message = message


def _flag(value) -> bool:
    if isinstance(value, bool):
        return value
    raise ApiError(400, "flags must be true or false")


def build_argv(action: str, opts: dict) -> list[str]:
    """Turn UI options into CLI arguments. Anything not whitelisted here is refused."""
    if action not in ACTIONS:
        raise ApiError(400, f"unknown action {action!r}")
    opts = dict(opts or {})
    argv = [action]
    allowed: set[str] = set()
    if action in ("run", "scan"):
        allowed |= {"networks", "no_ai", "model", "workers"}
        nets = opts.get("networks") or []
        if not isinstance(nets, list) or len(nets) > 16:
            raise ApiError(400, "networks must be a list of at most 16 CIDRs")
        for n in nets:
            try:
                net = ipaddress.ip_network(str(n), strict=False)
            except ValueError:
                raise ApiError(400, f"not a network: {n!r}") from None
            if net.version == 4 and net.prefixlen < 16:
                raise ApiError(400, f"{n} is too large to scan (use /16 or smaller)")
            argv.append(str(net))
        if action == "scan":
            argv.append("--no-identify")
    if action == "identify":
        allowed |= {"force", "no_ai", "model", "workers"}
        if opts.get("force") and _flag(opts["force"]):
            argv.append("--force")
    if action in ("run", "scan", "identify"):
        if opts.get("no_ai") and _flag(opts["no_ai"]):
            argv.append("--no-ai")
        if opts.get("model"):
            if not MODEL_RE.match(str(opts["model"])):
                raise ApiError(400, "invalid model name")
            argv.append(f"--model={opts['model']}")
        if opts.get("workers") not in (None, ""):
            try:
                w = int(opts["workers"])
            except (TypeError, ValueError):
                raise ApiError(400, "workers must be a number") from None
            if not 1 <= w <= 8:
                raise ApiError(400, "workers must be 1-8")
            argv.append(f"--workers={w}")
    if action in ("plan", "apply"):
        allowed |= {"include_pending"}
        if opts.get("include_pending") and _flag(opts["include_pending"]):
            argv.append("--include-pending")
    if action == "apply":
        allowed |= {"netbox", "infra", "dry_run"}
        targets = [t for t in ("netbox", "infra") if opts.get(t) and _flag(opts[t])]
        if not targets:
            raise ApiError(400, "choose NetBox and/or the infra repo")
        argv += [f"--{t}" for t in targets]
        if opts.get("dry_run") and _flag(opts["dry_run"]):
            argv.append("--dry-run")
    extra = {k for k, v in opts.items() if v not in (None, "", False, [])} - allowed
    if extra:
        raise ApiError(400, f"option not allowed for {action}: {', '.join(sorted(extra))}")
    return argv


# --------------------------------------------------------------------------- jobs

@dataclass
class Job:
    id: str
    action: str
    argv: list[str]
    options: dict
    status: str = "queued"          # queued | running | done | failed | cancelled
    exit_code: int | None = None
    created: float = field(default_factory=time.time)
    started: float | None = None
    ended: float | None = None
    lines: deque = field(default_factory=lambda: deque(maxlen=MAX_LOG_LINES))
    total_lines: int = 0
    proc: subprocess.Popen | None = None
    cancel_requested: bool = False

    @property
    def active(self) -> bool:
        return self.status in ("queued", "running")

    def add_line(self, text: str) -> None:
        self.lines.append(text)
        self.total_lines += 1

    def log_since(self, since: int) -> tuple[list[str], int]:
        first = self.total_lines - len(self.lines)
        start = max(since, first) - first
        return list(itertools.islice(self.lines, start, None)), self.total_lines

    def summary(self) -> dict:
        begin = self.started or self.created
        return {"id": self.id, "action": self.action, "options": self.options,
                "status": self.status, "dry_run": bool(self.options.get("dry_run")),
                "exit_code": self.exit_code, "created": self.created, "started": self.started,
                "ended": self.ended,
                "seconds": round((self.ended or time.time()) - begin, 1) if self.started else 0}


# --------------------------------------------------------------------------- app

class WebApp:
    """Everything the HTTP handler needs; kept separate so tests can drive it directly."""

    def __init__(self, cfg, config_path: str | None, token: str | None,
                 python: str | None = None):
        self.cfg = cfg
        self.config_path = config_path
        self.token = token
        self.python = python or sys.executable
        self.state_dir = Path(cfg.state_dir)
        self.settings_path = self.state_dir / "settings.json"
        self.settings = self._load_settings()
        self.lock = threading.Lock()
        self.cv = threading.Condition(self.lock)
        self.jobs: dict[str, Job] = {}
        self.pending: deque[str] = deque()
        self.hosts_lock = threading.Lock()
        self._status_cache: tuple[float, dict] | None = None
        threading.Thread(target=self._worker, name="labscout-jobs", daemon=True).start()

    # ---- auth
    def check_token(self, candidate: str | None) -> bool:
        if self.token is None:
            return True
        return bool(candidate) and hmac.compare_digest(candidate.encode(), self.token.encode())

    # ---- settings (the model picked in the UI)
    def _load_settings(self) -> dict:
        try:
            data = json.loads(self.settings_path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return {}
        model = data.get("model") if isinstance(data, dict) else None
        return {"model": model} if isinstance(model, str) and MODEL_RE.match(model) else {}

    def effective_model(self) -> str:
        return self.settings.get("model") or self.cfg.model

    def set_model(self, model: str | None) -> dict:
        model = (model or "").strip()
        if model and not MODEL_RE.match(model):
            raise ApiError(400, "invalid model name")
        with self.lock:
            if model:
                self.settings["model"] = model
            else:
                self.settings.pop("model", None)
            try:
                self.state_dir.mkdir(parents=True, exist_ok=True)
                tmp = self.settings_path.with_suffix(".tmp")
                tmp.write_text(json.dumps(self.settings), encoding="utf-8")
                tmp.replace(self.settings_path)
            except OSError as exc:
                raise ApiError(500, f"could not save the setting: {exc}") from None
            self._status_cache = None
        return {"model": self.effective_model(), "model_source": self._model_source()}

    def _model_source(self) -> str:
        return "ui" if self.settings.get("model") else "config"

    def server_status(self) -> dict:
        now = time.time()
        if self._status_cache and now - self._status_cache[0] < 15:
            return self._status_cache[1]
        from ..ollama import OllamaClient
        cfg = self.cfg
        model = self.effective_model()
        nmap = shutil.which("nmap")
        st = {"version": __version__, "ollama_host": cfg.ollama_host, "use_llm": cfg.use_llm,
              "model": model, "model_source": self._model_source(), "default_model": cfg.model,
              "ollama": None, "model_available": None, "models": [],
              "nmap": nmap or "", "networks": list(cfg.networks),
              "proxmox": [ep.name for ep in cfg.proxmox], "netalertx": bool(cfg.netalertx_url),
              "netbox": cfg.netbox_url or "", "infra": cfg.infra_repo or "",
              "domain": cfg.domain or "", "auth": self.token is not None}
        if cfg.use_llm:
            client = OllamaClient(cfg.ollama_host, model, api_key=cfg.api_key, timeout=5)
            try:
                st["ollama"] = client.version()
                st["models"] = client.models()[:50]
                st["model_available"] = client.has_model()
            except Exception as exc:  # noqa: BLE001 - surface any connection problem
                st["ollama_error"] = f"{exc.__class__.__name__}: {str(exc)[:200]}"
        self._status_cache = (now, st)
        return st

    # ---- hosts
    def _hosts_busy(self) -> Job | None:
        return next((j for j in self.jobs.values()
                     if j.status == "running" and j.action in WRITES_HOSTS), None)

    def hosts(self) -> dict:
        p = state.path(str(self.state_dir))
        hosts = state.load(str(self.state_dir))
        counts = {d: 0 for d in DECISIONS}
        for h in hosts:
            counts[h.decision] = counts.get(h.decision, 0) + 1
        return {"hosts": [h.to_dict() for h in hosts], "counts": counts,
                "scanned": p.stat().st_mtime if p.is_file() else None}

    def update_hosts(self, ips: list[str], body: dict) -> list[dict]:
        busy = self._hosts_busy()
        if busy:
            raise ApiError(409, f"the {busy.action} job is rewriting the results; "
                                "try again when it is done")
        decision = body.get("decision")
        if decision is not None and decision not in DECISIONS:
            raise ApiError(400, "decision must be pending, approved or rejected")
        app = str(body.get("app") or "").strip().lower()
        if app and not APP_RE.match(app):
            raise ApiError(400, "app must be a lower-case name like grafana or home-assistant")
        port = body.get("web_port")
        if port not in (None, ""):
            try:
                port = int(port)
            except (TypeError, ValueError):
                raise ApiError(400, "web_port must be a number") from None
            if not 0 <= port <= 65535:
                raise ApiError(400, "web_port must be 0-65535")
        hpath = str(body.get("health_path") or "").strip()
        if hpath and not PATH_RE.match(hpath):
            raise ApiError(400, "health_path must start with / and be a plain URL path")
        with self.hosts_lock:
            hosts = state.load(str(self.state_dir))
            by_ip = {h.ip: h for h in hosts}
            missing = [ip for ip in ips if ip not in by_ip]
            if missing:
                raise ApiError(404, f"unknown host {missing[0]}")
            for ip in ips:
                h = by_ip[ip]
                if app:
                    old = h.identity or Identity()
                    h.identity = Identity(**{
                        **old.__dict__, "app": app,
                        "display_name": app if old.app != app else (old.display_name or app),
                        "web_port": port if isinstance(port, int) else old.web_port,
                        "health_path": hpath or old.health_path or "/",
                        "source": "manual", "confidence": 1.0, "reasons": ["set in the web UI"]})
                    if decision is None:
                        h.decision = "approved"
                if decision is not None:
                    h.decision = decision
                if "note" in body:
                    h.note = str(body.get("note") or "")[:500]
            state.save(str(self.state_dir), hosts)
        return [by_ip[ip].to_dict() for ip in ips]

    def approve_above(self, threshold) -> int:
        try:
            t = float(threshold)
        except (TypeError, ValueError):
            raise ApiError(400, "threshold must be a number") from None
        if not 0 < t <= 1:
            raise ApiError(400, "threshold must be between 0 and 1")
        hosts = state.load(str(self.state_dir))
        ips = [h.ip for h in hosts if h.decision == "pending" and h.identity
               and h.identity.app and h.identity.confidence >= t]
        if ips:
            self.update_hosts(ips, {"decision": "approved"})
        return len(ips)

    def plan(self, include_pending: bool) -> dict:
        hosts = state.load(str(self.state_dir))
        plan = build_plan(hosts, self.cfg, include_pending=include_pending)
        return {"plan": plan.to_dict(), "report": report.markdown(hosts, plan, self.cfg),
                "include_pending": include_pending}

    def download(self, name: str) -> tuple[bytes, str]:
        files = {"report.md": "text/markdown; charset=utf-8", "plan.json": "application/json",
                 "hosts.json": "application/json"}
        if name not in files:
            raise ApiError(404, "not found")
        p = self.state_dir / name
        if not p.is_file():
            raise ApiError(404, f"{name} does not exist yet: run a plan first")
        return p.read_bytes(), files[name]

    # ---- jobs
    def start_job(self, action: str, opts: dict) -> Job:
        opts = {k: v for k, v in (opts or {}).items() if v not in (None, "", False, [])}
        if action in ("run", "scan", "identify") and "model" not in opts \
                and self.settings.get("model"):
            opts["model"] = self.settings["model"]
        argv = build_argv(action, opts)
        common = (["-c", self.config_path] if self.config_path else []) + \
                 ["--state-dir", str(self.state_dir)]
        argv = [argv[0], *common, *argv[1:]]
        with self.cv:
            for j in self.jobs.values():
                if j.active and j.action == action and j.options == opts:
                    raise ApiError(409, f"the same {action} is already "
                                        f"{'running' if j.status == 'running' else 'queued'}")
            if len(self.pending) >= MAX_PENDING:
                raise ApiError(429, "the queue is full; wait for a job to finish")
            job = Job(id=uuid.uuid4().hex[:12], action=action, argv=argv, options=opts)
            self.jobs[job.id] = job
            self.pending.append(job.id)
            self._prune()
            self.cv.notify_all()
        return job

    def _prune(self) -> None:
        done = sorted((j for j in self.jobs.values() if not j.active), key=lambda j: j.created)
        for j in done[:max(0, len(self.jobs) - MAX_JOBS_KEPT)]:
            self.jobs.pop(j.id, None)

    def _worker(self) -> None:
        while True:
            with self.cv:
                while not self.pending:
                    self.cv.wait()
                job = self.jobs.get(self.pending.popleft())
                if not job or job.status != "queued":
                    continue
                job.status, job.started = "running", time.time()
            self._run(job)

    def _run(self, job: Job) -> None:
        job.add_line("$ labscout " + " ".join(job.argv))
        try:
            job.proc = subprocess.Popen(
                [self.python, "-m", "labscout", *job.argv], stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT, text=True, bufsize=1, errors="replace",
                env={**os.environ, "PYTHONUNBUFFERED": "1"}, start_new_session=True)
            if job.cancel_requested:
                self._kill(job)
            for line in job.proc.stdout:
                job.add_line(line.rstrip("\n"))
            job.exit_code = job.proc.wait()
        except OSError as exc:
            job.add_line(f"could not start: {exc}")
            job.exit_code = -1
        job.ended = time.time()
        if job.cancel_requested:
            job.status = "cancelled"
            job.add_line("cancelled")
        else:
            job.status = "done" if job.exit_code == 0 else "failed"
        job.proc = None

    @staticmethod
    def _kill(job: Job) -> None:
        if job.proc and job.proc.poll() is None:
            try:
                if hasattr(os, "killpg"):
                    os.killpg(job.proc.pid, signal.SIGTERM)
                else:
                    job.proc.terminate()
            except ProcessLookupError:
                pass

    def cancel_job(self, job_id: str) -> Job:
        job = self.jobs.get(job_id)
        if not job:
            raise ApiError(404, "unknown job")
        with self.cv:
            if job.status == "queued":
                try:
                    self.pending.remove(job.id)
                except ValueError:
                    pass
                job.status, job.ended = "cancelled", time.time()
                job.add_line("cancelled before it started")
                return job
        if job.status == "running":
            job.cancel_requested = True
            self._kill(job)
        return job

    def job_list(self) -> list[dict]:
        with self.cv:
            order = list(self.pending)
        out = []
        for j in sorted(self.jobs.values(), key=lambda j: j.created, reverse=True):
            d = j.summary()
            d["position"] = order.index(j.id) + 1 if j.id in order else None
            out.append(d)
        return out

    def job_detail(self, job_id: str, since: int = 0) -> dict:
        job = self.jobs.get(job_id)
        if not job:
            raise ApiError(404, "unknown job")
        lines, nxt = job.log_since(since)
        out = next((d for d in self.job_list() if d["id"] == job_id), job.summary())
        out.update(lines=lines, next=nxt)
        return out

    def shutdown(self) -> None:
        for j in list(self.jobs.values()):
            if j.status == "running":
                j.cancel_requested = True
                self._kill(j)


# --------------------------------------------------------------------------- HTTP

class Handler(BaseHTTPRequestHandler):
    server_version = f"labscout/{__version__}"
    protocol_version = "HTTP/1.1"

    @property
    def app(self) -> WebApp:
        return self.server.app  # type: ignore[attr-defined]

    def log_message(self, fmt, *args):
        if getattr(self.server, "verbose", False):
            super().log_message(fmt, *args)

    def _send(self, status: int, body: bytes, ctype: str, extra: dict | None = None):
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        for k, v in SECURITY_HEADERS.items():
            self.send_header(k, v)
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _json(self, status: int, data, extra: dict | None = None):
        self._send(status, json.dumps(data, ensure_ascii=False).encode("utf-8"),
                   "application/json; charset=utf-8", extra)

    def _token(self) -> str | None:
        auth = self.headers.get("Authorization", "")
        if auth.startswith("Bearer "):
            return auth[7:].strip()
        jar = cookies.SimpleCookie()
        try:
            jar.load(self.headers.get("Cookie", ""))
        except cookies.CookieError:
            return None
        morsel = jar.get(COOKIE)
        return morsel.value if morsel else None

    def _cookie_header(self, token: str) -> str:
        return f"{COOKIE}={token}; Path=/; HttpOnly; SameSite=Strict"

    def _read_body(self):
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            length = -1
        if length < 0 or length > MAX_BODY:
            self.close_connection = True
            raise ApiError(413, "request too large")
        self._raw = self.rfile.read(length) if length else b""

    def _body(self) -> dict:
        raw = getattr(self, "_raw", b"")
        if not raw:
            return {}
        try:
            data = json.loads(raw)
        except ValueError:
            raise ApiError(400, "body must be JSON") from None
        if not isinstance(data, dict):
            raise ApiError(400, "body must be a JSON object")
        return data

    def _check_post(self):
        if self.headers.get(CSRF_HEADER) != "1":
            raise ApiError(403, f"missing {CSRF_HEADER} header")
        origin = self.headers.get("Origin")
        if origin and origin != "null" and urlsplit(origin).netloc != self.headers.get("Host", ""):
            raise ApiError(403, "cross-origin request refused")

    def do_HEAD(self):
        self._dispatch("GET")

    def do_GET(self):
        self._dispatch("GET")

    def do_POST(self):
        self._dispatch("POST")

    def _dispatch(self, method: str):
        url = urlsplit(self.path)
        path, qs = url.path, parse_qs(url.query)
        try:
            if method == "POST":
                self._read_body()
            if method == "GET" and path in STATIC_FILES:
                return self._static(path, qs)
            if not path.startswith("/api/"):
                raise ApiError(404, "not found")
            if method == "POST":
                self._check_post()
            if path == "/api/login" and method == "POST":
                return self._login()
            if not self.app.check_token(self._token()):
                raise ApiError(401, "access token required")
            return self._api(method, path, qs)
        except ApiError as exc:
            self._json(exc.status, {"error": exc.message})
        except (BrokenPipeError, ConnectionResetError):
            pass
        except Exception as exc:  # noqa: BLE001 - never leak a traceback page
            self._json(500, {"error": f"{exc.__class__.__name__}: {exc}"})

    def _static(self, path: str, qs: dict):
        name, ctype = STATIC_FILES[path]
        token = (qs.get("token") or [None])[0]
        if path == "/" and token:
            if not self.app.check_token(token):
                raise ApiError(401, "wrong access token")
            return self._send(303, b"", "text/plain",
                              {"Location": "/", "Set-Cookie": self._cookie_header(token)})
        f = STATIC_DIR / name
        if not f.is_file():
            raise ApiError(404, "the UI is not built: run `make web`")
        self._send(200, f.read_bytes(), ctype)

    def _login(self):
        token = str(self._body().get("token") or "").strip()
        if not self.app.check_token(token):
            time.sleep(0.5)
            raise ApiError(401, "wrong access token")
        self._json(200, {"ok": True}, {"Set-Cookie": self._cookie_header(token)})

    def _api(self, method: str, path: str, qs: dict):
        app = self.app
        parts = [unquote(p) for p in path[len("/api/"):].split("/") if p]
        q = lambda k, d=None: (qs.get(k) or [d])[0]

        if method == "GET" and parts == ["status"]:
            return self._json(200, app.server_status())
        if method == "POST" and parts == ["settings"]:
            body = self._body()
            if "model" not in body:
                raise ApiError(400, "nothing to change")
            return self._json(200, app.set_model(body.get("model")))
        if method == "GET" and parts == ["hosts"]:
            return self._json(200, app.hosts())
        if method == "POST" and parts == ["hosts"]:
            body = self._body()
            ips = body.pop("ips", None)
            if not isinstance(ips, list) or not ips or len(ips) > 1024 \
                    or not all(isinstance(i, str) for i in ips):
                raise ApiError(400, "ips must be a list of addresses")
            return self._json(200, {"hosts": app.update_hosts(ips, body)})
        if method == "POST" and len(parts) == 2 and parts[0] == "hosts":
            return self._json(200, app.update_hosts([parts[1]], self._body())[0])
        if method == "POST" and parts == ["review", "approve-above"]:
            return self._json(200, {"approved": app.approve_above(self._body().get("threshold"))})
        if method == "GET" and parts == ["plan"]:
            return self._json(200, app.plan(q("include_pending") in ("1", "true")))
        if method == "GET" and len(parts) == 2 and parts[0] == "download":
            data, ctype = app.download(parts[1])
            return self._send(200, data, ctype, {
                "Content-Disposition": f'attachment; filename="labscout-{parts[1]}"'})
        if method == "GET" and parts == ["jobs"]:
            return self._json(200, {"jobs": app.job_list()})
        if method == "POST" and parts == ["jobs"]:
            body = self._body()
            opts = body.get("options") or {}
            if not isinstance(opts, dict):
                raise ApiError(400, "options must be an object")
            return self._json(202, app.start_job(str(body.get("action") or ""), opts).summary())
        if method == "GET" and len(parts) == 2 and parts[0] == "jobs":
            try:
                since = int(q("since", "0"))
            except ValueError:
                since = 0
            return self._json(200, app.job_detail(parts[1], since))
        if method == "POST" and len(parts) == 3 and parts[0] == "jobs" and parts[2] == "cancel":
            return self._json(200, app.cancel_job(parts[1]).summary())
        raise ApiError(404, "not found")


class _Server(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, addr, app: WebApp, verbose: bool = False):
        if ":" in addr[0]:
            import socket
            self.address_family = socket.AF_INET6
        super().__init__(addr, Handler)
        self.app = app
        self.verbose = verbose


def is_loopback(host: str) -> bool:
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def make_server(app: WebApp, bind: str = "127.0.0.1", port: int = 8766,
                verbose: bool = False) -> _Server:
    return _Server((bind, port), app, verbose)


PLACEHOLDER_TOKENS = {"change-me", "changeme", "change_me", "secret", "token",
                      "change-me-openssl-rand-hex-24"}


def serve(cfg, config_path: str | None, bind: str = "127.0.0.1", port: int = 8766,
          no_auth: bool = False, verbose: bool = False) -> int:
    token: str | None = None
    if no_auth:
        if not is_loopback(bind):
            print("error: --no-auth is only allowed when binding to localhost", file=sys.stderr)
            return 2
    else:
        token = os.environ.get("LABSCOUT_WEB_TOKEN") or secrets.token_urlsafe(24)
        if token.strip().lower() in PLACEHOLDER_TOKENS:
            print(f"error: LABSCOUT_WEB_TOKEN is still the example value '{token}'; set your "
                  "own (openssl rand -hex 24)", file=sys.stderr)
            return 2
    app = WebApp(cfg, config_path, token)
    try:
        httpd = make_server(app, bind, port, verbose)
    except OSError as exc:
        print(f"error: cannot listen on {bind}:{port}: {exc}", file=sys.stderr)
        return 2
    host = "localhost" if bind in ("127.0.0.1", "0.0.0.0", "::") else bind
    link = f"http://{host}:{port}/" + (f"?token={token}" if token and
                                         not os.environ.get("LABSCOUT_WEB_TOKEN") else "")
    print(f"labscout {__version__} web UI: {link}", flush=True)
    if token and os.environ.get("LABSCOUT_WEB_TOKEN"):
        print("access token: from $LABSCOUT_WEB_TOKEN", flush=True)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        app.shutdown()
        httpd.server_close()
    return 0
