import json
import threading
import urllib.error
import urllib.request

from conftest import FakeOllama
import yaml

from labscout import fingerprints, state
from labscout.apply import NetBox, apply_netbox
from labscout.discover import merge
from labscout.discover.network import expand_targets, parse_nmap_xml, parse_ports
from labscout.identify import Identifier, facts, from_model
from labscout.models import Host, HttpInfo, Identity, Port, ProxmoxGuest
from labscout.plan import build, infra_resolve, patch_apps_yml

NMAP_XML = """<?xml version="1.0"?><nmaprun>
<host><status state="up"/><address addr="10.0.3.116" addrtype="ipv4"/>
 <address addr="BC:24:11:AA:BB:CC" addrtype="mac" vendor="Proxmox Server Solutions"/>
 <hostnames><hostname name="grafana.lan"/></hostnames>
 <ports><port protocol="tcp" portid="3000"><state state="open"/><service name="http" product="Grafana http"/></port>
 <port protocol="tcp" portid="23"><state state="closed"/></port></ports></host>
<host><status state="down"/><address addr="10.0.3.5" addrtype="ipv4"/></host>
</nmaprun>"""


# ----------------------------------------------------------------------------- discovery
def test_parse_nmap_xml():
    hosts = parse_nmap_xml(NMAP_XML)
    assert list(hosts) == ["10.0.3.116"]
    h = hosts["10.0.3.116"]
    assert h.mac == "bc:24:11:aa:bb:cc" and h.vendor.startswith("Proxmox")
    assert h.hostname == "grafana.lan"
    assert [(p.port, p.product) for p in h.ports] == [(3000, "Grafana http")]


def test_targets_and_ports():
    assert expand_targets(["10.0.0.0/30"], ["10.0.0.2"]) == ["10.0.0.1"]
    assert parse_ports("22, 80,8000-8002") == [22, 80, 8000, 8001, 8002]


def test_merge_proxmox_by_ip_and_mac():
    net = {"10.0.3.10": Host(ip="10.0.3.10", mac="aa:aa:aa:aa:aa:aa", ports=[Port(80)])}
    pve = [(ProxmoxGuest(name="web", type="lxc", vmid=1), [], ["aa:aa:aa:aa:aa:aa"]),
           (ProxmoxGuest(name="off", type="lxc", vmid=2, status="stopped"), ["10.0.3.20"], [])]
    hosts = merge(net, pve, [{"ip": "10.0.3.10", "mac": "", "name": "webby", "vendor": "X"}])
    assert [h.name for h in hosts] == ["web", "off"]
    assert "netalertx" in hosts[0].sources and hosts[0].vendor == "X"


# ----------------------------------------------------------------------------- fingerprints
def test_rule_title_beats_port(grafana_host):
    ident = fingerprints.match(grafana_host)
    assert ident.app == "grafana" and ident.confidence >= 0.95
    assert ident.web_port == 3000 and ident.health_path == "/api/health"


def test_rule_port_only_is_weak():
    h = Host(ip="10.0.3.9", ports=[Port(3000)])
    ident = fingerprints.match(h)
    assert ident.confidence < 0.85          # 3000 is Grafana *or* AdGuard *or* Homelable...


def test_distinctive_port():
    h = Host(ip="10.0.3.2", ports=[Port(9100)])
    assert fingerprints.match(h).app == "node-exporter"


# ----------------------------------------------------------------------------- identify
def test_model_cannot_invent_ports(mystery_host):
    ident = from_model({"app": "KitchenOwl", "category": "Home", "confidence": 0.9,
                        "web_port": 9999, "health_path": "/", "description": "x",
                        "metrics_port": 1234, "metrics_path": "/m"}, mystery_host)
    assert ident.app == "kitchenowl" and ident.web_port == 0 and ident.metrics_port == 0


def test_identify_uses_rule_without_asking(cfg, grafana_host):
    fake = FakeOllama({"app": "x", "category": "x", "confidence": 1, "web_port": 0,
                       "health_path": "/", "description": ""})
    Identifier(cfg, fake, log=lambda *_: None).run([grafana_host])
    assert grafana_host.identity.app == "grafana" and fake.calls == []


def test_identify_asks_model_and_caches(cfg, mystery_host):
    answer = {"app": "kitchenowl", "display_name": "KitchenOwl", "category": "home",
              "confidence": 0.8, "web_port": 8085, "health_path": "/api/health",
              "description": "Recipe and grocery app", "reasons": ["title Kitchen Owl"]}
    fake = FakeOllama(answer)
    Identifier(cfg, fake, log=lambda *_: None).run([mystery_host])
    assert mystery_host.identity.app == "kitchenowl" and mystery_host.identity.source == "ai"
    assert "Kitchen Owl" in fake.calls[0] and "KNOWN:" in fake.calls[0]
    # second run: answered from the cache
    mystery_host.identity = None
    fake2 = FakeOllama(answer)
    Identifier(cfg, fake2, log=lambda *_: None).run([mystery_host])
    assert fake2.calls == [] and mystery_host.identity.app == "kitchenowl"


def test_manual_identity_is_kept(cfg, mystery_host):
    mystery_host.identity = Identity(app="mine", source="manual", confidence=1)
    Identifier(cfg, FakeOllama({}), log=lambda *_: None).run([mystery_host])
    assert mystery_host.identity.app == "mine"


def test_facts_strip_html(mystery_host):
    mystery_host.proxmox.description = "<b>Recipes</b> app"
    assert facts(mystery_host)["proxmox"]["description"].strip() == "Recipes  app".strip()


# ----------------------------------------------------------------------------- state
def test_state_roundtrip_keeps_decisions(cfg, grafana_host, mystery_host):
    grafana_host.decision = "approved"
    grafana_host.identity = fingerprints.match(grafana_host)
    state.save(cfg.state_dir, [grafana_host, mystery_host])
    loaded = state.load(cfg.state_dir)
    assert [h.ip for h in loaded] == ["10.0.3.99", "10.0.3.116"]
    fresh = Host(ip="10.0.3.116", ports=grafana_host.ports, http=grafana_host.http,
                 proxmox=grafana_host.proxmox, hostname="grafana.lan")
    state.carry_over([fresh], loaded)
    assert fresh.decision == "approved" and fresh.identity.app == "grafana"


# ----------------------------------------------------------------------------- plan
APPS_YML = """---
# comment that must survive
app_aliases:
  bazarrplus: bazarr

app_catalog:
  grafana:
    port: 3000
    subdomain: grafana

app_defaults:
  probe: http
"""


def test_infra_resolve():
    cat = {"grafana": {}, "ollama": {}}
    assert infra_resolve("grafana01", cat, {}) == "grafana"
    assert infra_resolve("ollama-nvidia-20gb", cat, {}) == "ollama"
    assert infra_resolve("x", cat, {"x": "grafana"}) == "grafana"


def test_plan_and_patch(cfg, tmp_path, grafana_host, mystery_host):
    repo = tmp_path / "infra"
    (repo / "inventory/group_vars/all").mkdir(parents=True)
    (repo / "inventory/group_vars/all/apps.yml").write_text(APPS_YML)
    cfg.infra_repo = str(repo)
    grafana_host.identity = fingerprints.match(grafana_host)
    mystery_host.identity = Identity(app="kitchenowl", display_name="KitchenOwl", category="home",
                                     confidence=0.8, source="ai", web_port=8085,
                                     health_path="/api/health", description="Recipes")
    for h in (grafana_host, mystery_host):
        h.decision = "approved"
    plan = build([grafana_host, mystery_host], cfg)
    assert plan.catalog_add == {"kitchenowl": {"port": 8085, "probe_path": "/api/health",
                                               "subdomain": "kitchenowl"}}
    assert plan.aliases_add == {"recipes": "kitchenowl"}      # guest name != app
    assert {n["ip"]: n["dns_name"] for n in plan.netbox}["10.0.3.99"] == "kitchenowl.home.example.org"
    new = patch_apps_yml(APPS_YML, plan)
    assert "# comment that must survive" in new
    data = yaml.safe_load(new)
    assert data["app_catalog"]["kitchenowl"]["port"] == 8085
    assert data["app_aliases"] == {"bazarrplus": "bazarr", "recipes": "kitchenowl"}
    assert data["app_defaults"] == {"probe": "http"}


def test_plan_skips_unapproved(cfg, grafana_host):
    grafana_host.identity = fingerprints.match(grafana_host)
    assert build([grafana_host], cfg).netbox == []
    assert len(build([grafana_host], cfg, include_pending=True).netbox) == 1


# ----------------------------------------------------------------------------- NetBox
class FakeNetBox(NetBox):
    def __init__(self):
        super().__init__("http://nb", "t")
        self.db = {"/ipam/ip-addresses/": [], "/extras/tags/": [], "/ipam/services/": [],
                   "/virtualization/virtual-machines/": [{"id": 7, "name": "grafana"}]}
        self.calls = []

    def _req(self, method, path, **kw):
        self.calls.append((method, path))
        base = "/" + "/".join(p for p in path.split("/") if p and not p.isdigit()) + "/"
        if method == "GET":
            params = kw.get("params", {})
            rows = [r for r in self.db[base]
                    if all(str(r.get(k)) == str(v) for k, v in params.items()
                           if k in ("address", "slug", "name"))]
            return {"results": rows}
        if method == "POST":
            row = dict(kw["json"], id=len(self.db[base]) + 1)
            if base == "/ipam/ip-addresses/":
                row["address"] = row["address"].split("/")[0]
            self.db[base].append(row)
            return row
        if method == "PATCH":
            return kw["json"]


def test_netbox_upsert(cfg, grafana_host, monkeypatch):
    grafana_host.identity = fingerprints.match(grafana_host)
    grafana_host.decision = "approved"
    plan = build([grafana_host], cfg)
    fake = FakeNetBox()
    monkeypatch.setenv("NETBOX_TOKEN", "x")
    cfg.netbox_url = "http://nb"
    import labscout.apply as ap
    monkeypatch.setattr(ap, "NetBox", lambda *a, **k: fake)
    stats = apply_netbox(plan, cfg, log=lambda *_: None)
    assert stats == {"created": 1, "updated": 0, "services": 1}
    stats = apply_netbox(plan, cfg, log=lambda *_: None)
    assert stats["updated"] == 1 and len(fake.db["/ipam/ip-addresses/"]) == 1


# ----------------------------------------------------------------------------- web
def test_web_auth_and_decision(cfg, grafana_host):
    from http.server import ThreadingHTTPServer

    from labscout.web import Job, make_handler
    state.save(cfg.state_dir, [grafana_host])
    srv = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(cfg, None, "tok", Job()))
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{srv.server_address[1]}"
    try:
        try:
            urllib.request.urlopen(base + "/api/state")
            raise AssertionError("no token must be refused")
        except urllib.error.HTTPError as e:
            assert e.code == 401
        hdr = {"Cookie": "labscout_token=tok"}
        st = json.loads(urllib.request.urlopen(urllib.request.Request(base + "/api/state", headers=hdr)).read())
        assert st["hosts"][0]["ip"] == "10.0.3.116"
        req = urllib.request.Request(base + "/api/host", method="POST",
                                     data=json.dumps({"ip": "10.0.3.116", "decision": "approved"}).encode(),
                                     headers={**hdr, "X-Labscout": "1", "Content-Type": "application/json"})
        assert json.loads(urllib.request.urlopen(req).read())["decision"] == "approved"
        # POST without the custom header (cross-site form) is refused
        bad = urllib.request.Request(base + "/api/host", method="POST", data=b"{}", headers=hdr)
        try:
            urllib.request.urlopen(bad)
            raise AssertionError("missing header must be refused")
        except urllib.error.HTTPError as e:
            assert e.code == 401
        assert state.load(cfg.state_dir)[0].decision == "approved"
    finally:
        srv.shutdown()


def test_http_info_roundtrip():
    h = Host(ip="1.2.3.4", http=[HttpInfo(port=80, title="x")], ports=[Port(80)])
    assert Host.from_dict(h.to_dict()).http[0].title == "x"
