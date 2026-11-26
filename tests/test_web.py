"""Web UI: auth, CSRF, option whitelisting, host edits and real scan jobs against mock Ollama."""

from __future__ import annotations

import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import mock_ollama
import pytest
import requests
import yaml

from labscout import state
from labscout.config import load_config
from labscout.web.server import ApiError, WebApp, build_argv, make_server

TOKEN = "s3cret-token"
AUTH = {"Authorization": f"Bearer {TOKEN}"}
POST = {**AUTH, "X-Labscout": "1"}


# ------------------------------------------------------------------ fixtures

class _Page(BaseHTTPRequestHandler):
    title = "Grafana"

    def log_message(self, *args):
        pass

    def do_GET(self):
        body = f"<html><head><title>{self.title}</title></head><body>hi</body></html>".encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def _page(ip: str, title: str) -> ThreadingHTTPServer:
    handler = type("P", (_Page,), {"title": title})
    srv = ThreadingHTTPServer((ip, 0), handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


@pytest.fixture()
def lab(tmp_path, monkeypatch):
    """Two fake web apps on 127.0.0.1 / 127.0.0.2, a mock Ollama and a config for them."""
    ollama, url = mock_ollama.start()
    try:
        kitchen = _page("127.0.0.2", "Kitchen Owl")
    except OSError:
        pytest.skip("127.0.0.2 is not usable here")
    grafana = _page("127.0.0.1", "Grafana")
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))              # no ~/.labscout.yml leaks in
    src = str(Path(__file__).resolve().parents[1] / "src")
    monkeypatch.setenv("PYTHONPATH", src)              # job subprocesses import this checkout
    for var in ("OLLAMA_HOST", "LABSCOUT_MODEL", "LABSCOUT_STATE_DIR", "LABSCOUT_NETWORKS"):
        monkeypatch.delenv(var, raising=False)
    conf = tmp_path / "labscout.yml"
    conf.write_text(yaml.safe_dump({
        "ollama_host": url, "model": mock_ollama.MODEL, "use_nmap": False,
        "networks": ["127.0.0.1/32", "127.0.0.2/32"],
        "ports": f"{grafana.server_address[1]},{kitchen.server_address[1]}",
        "state_dir": str(tmp_path / "state"), "connect_timeout": 0.5}))
    yield conf
    for s in (ollama, kitchen, grafana):
        s.shutdown()


def start(app):
    srv = make_server(app, "127.0.0.1", 0)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, f"http://127.0.0.1:{srv.server_address[1]}"


@pytest.fixture()
def web(lab):
    cfg, _ = load_config(str(lab))
    app = WebApp(cfg, str(lab), TOKEN)
    srv, base = start(app)
    yield app, base
    app.shutdown()
    srv.shutdown()


def wait(base, job_id, timeout=90):
    t0 = time.time()
    while time.time() - t0 < timeout:
        d = requests.get(f"{base}/api/jobs/{job_id}", headers=AUTH).json()
        if d["status"] not in ("queued", "running"):
            return d
        time.sleep(0.25)
    raise AssertionError("job did not finish")


def run_job(base, action, options=None):
    r = requests.post(f"{base}/api/jobs", json={"action": action, "options": options or {}}, headers=POST)
    assert r.status_code == 202, r.text
    d = wait(base, r.json()["id"])
    log = requests.get(f"{base}/api/jobs/{d['id']}", headers=AUTH).json()["lines"]
    assert d["status"] == "done", "\n".join(log)
    return d, log


# ------------------------------------------------------------------ option whitelist

def test_build_argv_whitelist():
    argv = build_argv("run", {"networks": ["10.0.3.0/24", "10.0.0.7"], "model": "qwen2.5:14b",
                              "workers": 2, "no_ai": True})
    assert argv == ["run", "10.0.3.0/24", "10.0.0.7/32", "--no-ai", "--model=qwen2.5:14b", "--workers=2"]
    assert build_argv("scan", {}) == ["scan", "--no-identify"]
    assert build_argv("identify", {"force": True}) == ["identify", "--force"]
    assert build_argv("apply", {"netbox": True, "dry_run": True}) == ["apply", "--netbox", "--dry-run"]
    assert build_argv("plan", {"include_pending": True}) == ["plan", "--include-pending"]


@pytest.mark.parametrize("action,opts", [
    ("serve", {}), ("doctor", {}), ("init", {}),
    ("run", {"networks": ["10.0.0.0/8"]}), ("run", {"networks": ["-oX /tmp/x"]}),
    ("run", {"networks": "10.0.3.0/24"}), ("run", {"model": "--host=http://evil"}),
    ("run", {"model": "a b"}), ("run", {"workers": 50}), ("run", {"no_ai": "yes"}),
    ("run", {"state_dir": "/etc"}), ("run", {"config": "/etc/passwd"}),
    ("run", {"ollama_host": "http://evil:11434"}), ("identify", {"networks": ["10.0.3.0/24"]}),
    ("apply", {}), ("apply", {"netbox": True, "infra_repo": "/tmp"}),
])
def test_build_argv_refuses(action, opts):
    with pytest.raises(ApiError):
        build_argv(action, opts)


# ------------------------------------------------------------------ auth & safety

def test_static_page_and_security_headers(web):
    _, base = web
    r = requests.get(base + "/")
    assert r.status_code == 200 and "labscout" in r.text
    assert "script-src 'self'" in r.headers["Content-Security-Policy"]
    assert r.headers["X-Frame-Options"] == "DENY"
    for f in ("/app.js", "/app.css", "/favicon.svg"):
        assert requests.get(base + f).status_code == 200, f
    assert requests.get(base + "/../pyproject.toml").status_code == 404
    assert requests.get(base + "/hosts.json").status_code == 404


def test_auth(web):
    _, base = web
    assert requests.get(base + "/api/status").status_code == 401
    assert requests.get(base + "/api/status", headers={"Authorization": "Bearer wrong"}).status_code == 401
    assert requests.get(base + "/api/hosts", headers=AUTH).status_code == 200
    # ?token= is traded for an HttpOnly cookie
    r = requests.get(base + f"/?token={TOKEN}", allow_redirects=False)
    assert r.status_code == 303 and r.headers["Location"] == "/"
    assert "HttpOnly" in r.headers["Set-Cookie"] and "SameSite=Strict" in r.headers["Set-Cookie"]
    s = requests.Session()
    assert s.post(base + "/api/login", json={"token": "nope"}, headers={"X-Labscout": "1"}).status_code == 401
    assert s.post(base + "/api/login", json={"token": TOKEN}, headers={"X-Labscout": "1"}).status_code == 200
    assert s.get(base + "/api/hosts").status_code == 200


def test_posts_need_header_and_same_origin(web):
    _, base = web
    assert requests.post(base + "/api/jobs", json={"action": "plan"}, headers=AUTH).status_code == 403
    r = requests.post(base + "/api/jobs", json={"action": "plan"},
                      headers={**POST, "Origin": "http://evil.example"})
    assert r.status_code == 403
    r = requests.post(base + "/api/jobs", data="x" * 70000, headers=POST)
    assert r.status_code == 413
    assert requests.post(base + "/api/jobs", data="[1]", headers=POST).status_code == 400


def test_status_and_model_setting(web):
    app, base = web
    st = requests.get(base + "/api/status", headers=AUTH).json()
    assert st["ollama"] == "0.12.0-mock" and st["model_available"] is True
    assert mock_ollama.MODEL in st["models"] and st["model_source"] == "config"
    assert requests.post(base + "/api/settings", json={"model": "bad name"}, headers=POST).status_code == 400
    r = requests.post(base + "/api/settings", json={"model": "llama3.2:3b"}, headers=POST).json()
    assert r == {"model": "llama3.2:3b", "model_source": "ui"}
    assert app.start_job("identify", {}).argv[-1] == "--model=llama3.2:3b"
    # kept across restarts
    assert WebApp(app.cfg, app.config_path, TOKEN).effective_model() == "llama3.2:3b"
    requests.post(base + "/api/settings", json={"model": ""}, headers=POST)
    assert app.effective_model() == mock_ollama.MODEL


# ------------------------------------------------------------------ hosts

def test_host_edits(web, grafana_host, mystery_host):
    app, base = web
    state.save(app.cfg.state_dir, [grafana_host, mystery_host])
    d = requests.get(base + "/api/hosts", headers=AUTH).json()
    assert [h["ip"] for h in d["hosts"]] and d["counts"]["pending"] == 2

    r = requests.post(base + "/api/hosts/10.0.3.99", headers=POST,
                      json={"app": "kitchenowl", "web_port": 8085, "health_path": "/api/health", "note": "recipes"})
    h = r.json()
    assert h["identity"]["source"] == "manual" and h["decision"] == "approved" and h["note"] == "recipes"

    for bad in ({"decision": "maybe"}, {"app": "<script>"}, {"web_port": 70000},
                {"health_path": "javascript:alert(1)"}):
        assert requests.post(base + "/api/hosts/10.0.3.99", json=bad, headers=POST).status_code == 400, bad
    assert requests.post(base + "/api/hosts/10.9.9.9", json={"decision": "approved"}, headers=POST).status_code == 404

    r = requests.post(base + "/api/hosts", headers=POST,
                      json={"ips": ["10.0.3.116", "10.0.3.99"], "decision": "rejected"})
    assert {h["decision"] for h in r.json()["hosts"]} == {"rejected"}
    assert {h.decision for h in state.load(app.cfg.state_dir)} == {"rejected"}


def test_approve_above_and_plan(web, grafana_host, mystery_host):
    app, base = web
    from labscout.identify import Identifier
    hosts = [grafana_host, mystery_host]
    Identifier(app.cfg, None, lambda *_: None).run(hosts)   # rules only: grafana is sure
    state.save(app.cfg.state_dir, hosts)
    r = requests.post(base + "/api/review/approve-above", json={"threshold": 0.9}, headers=POST).json()
    assert r == {"approved": 1}
    assert requests.post(base + "/api/review/approve-above", json={"threshold": 5}, headers=POST).status_code == 400
    p = requests.get(base + "/api/plan", headers=AUTH).json()
    assert [m["app"] for m in p["plan"]["monitoring"]] == ["grafana"]
    assert "10.0.3.99" in p["plan"]["skipped"] and p["report"].startswith("# labscout report")
    p = requests.get(base + "/api/plan?include_pending=1", headers=AUTH).json()
    assert len(p["plan"]["netbox"]) == 2
    assert requests.get(base + "/api/download/report.md", headers=AUTH).status_code == 404
    assert requests.get(base + "/api/download/..%2Flabscout.yml", headers=AUTH).status_code == 404


# ------------------------------------------------------------------ real jobs

def test_scan_identify_plan_jobs(web):
    app, base = web
    _, log = run_job(base, "run")
    assert any("TCP connect scan" in line for line in log)
    hosts = {h["ip"]: h for h in requests.get(base + "/api/hosts", headers=AUTH).json()["hosts"]}
    assert hosts["127.0.0.1"]["identity"]["app"] == "grafana"
    assert hosts["127.0.0.1"]["identity"]["source"] == "rule"
    k = hosts["127.0.0.2"]["identity"]
    assert k["app"] == "kitchenowl" and k["source"] == "ai" and k["web_port"] > 0
    asked = len(mock_ollama.calls())
    assert asked >= 1

    # decisions survive a rescan; unchanged hosts are not sent to the model again
    requests.post(base + "/api/hosts/127.0.0.2", json={"decision": "approved"}, headers=POST)
    run_job(base, "scan")
    run_job(base, "identify")
    hosts = {h["ip"]: h for h in requests.get(base + "/api/hosts", headers=AUTH).json()["hosts"]}
    assert hosts["127.0.0.2"]["decision"] == "approved"
    assert len(mock_ollama.calls()) == asked
    run_job(base, "identify", {"force": True})
    assert len(mock_ollama.calls()) > asked

    run_job(base, "plan")
    assert (Path(app.cfg.state_dir) / "report.md").is_file()
    r = requests.get(base + "/api/download/report.md", headers=AUTH)
    assert r.status_code == 200 and "kitchenowl" in r.text
    assert "attachment" in r.headers["Content-Disposition"]


def test_apply_without_target_config_fails_cleanly(web):
    _, base = web
    r = requests.post(base + "/api/jobs", json={"action": "apply", "options": {"netbox": True, "dry_run": True}}, headers=POST)
    d = wait(base, r.json()["id"])
    assert d["status"] in ("done", "failed")
    jobs = requests.get(base + "/api/jobs", headers=AUTH).json()["jobs"]
    assert jobs[0]["action"] == "apply" and jobs[0]["dry_run"] is True


def test_queue_duplicates_and_cancel(web):
    app, base = web
    # Hold the worker so jobs stay queued
    first = app.start_job("run", {"networks": ["127.0.0.1/32"]})
    r = requests.post(base + "/api/jobs", json={"action": "run", "options": {"networks": ["127.0.0.1/32"]}}, headers=POST)
    assert r.status_code == 409
    second = app.start_job("plan", {})
    if second.status == "queued":
        c = requests.post(f"{base}/api/jobs/{second.id}/cancel", headers=POST).json()
        assert c["status"] in ("cancelled", "running", "done")
    requests.post(f"{base}/api/jobs/{first.id}/cancel", headers=POST)
    assert wait(base, first.id)["status"] in ("cancelled", "done")
    assert requests.post(base + "/api/jobs/nope/cancel", headers=POST).status_code == 404
    assert requests.post(base + "/api/jobs", json={"action": "serve"}, headers=POST).status_code == 400


def test_host_edits_wait_for_a_running_scan(web, grafana_host):
    app, base = web
    state.save(app.cfg.state_dir, [grafana_host])
    from labscout.web.server import Job
    fake = Job(id="x", action="scan", argv=[], options={}, status="running")
    app.jobs["x"] = fake
    r = requests.post(base + "/api/hosts/10.0.3.116", json={"decision": "approved"}, headers=POST)
    assert r.status_code == 409
    fake.status = "done"
    assert requests.post(base + "/api/hosts/10.0.3.116", json={"decision": "approved"}, headers=POST).status_code == 200
