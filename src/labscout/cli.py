"""Command line: labscout run | scan | identify | review | plan | apply | serve | doctor | init."""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import shutil
import sys

from . import __version__, discover, report, state
from .config import SAMPLE, Config, load_config
from .identify import Identifier
from .models import Identity
from .ollama import OllamaClient
from .plan import build as build_plan


def log(msg: str) -> None:
    print(msg, file=sys.stderr, flush=True)


def make_client(cfg: Config) -> OllamaClient | None:
    if not cfg.use_llm:
        return None
    return OllamaClient(cfg.ollama_host, cfg.model, api_key=cfg.api_key, timeout=cfg.timeout,
                        temperature=cfg.temperature, num_ctx=cfg.num_ctx,
                        num_predict=cfg.num_predict, keep_alive=cfg.keep_alive)


def _cfg(a: argparse.Namespace) -> Config:
    cfg, warnings = load_config(a.config)
    for w in warnings:
        log(f"warning: {w}")
    if getattr(a, "networks", None):
        cfg.networks = a.networks
    if getattr(a, "no_ai", False):
        cfg.use_llm = False
    if getattr(a, "model", None):
        cfg.model = a.model
    if getattr(a, "state_dir", None):
        cfg.state_dir = a.state_dir
    return cfg


# ------------------------------------------------------------------------------ commands
def cmd_scan(a) -> int:
    cfg = _cfg(a)
    hosts = discover.scan(cfg, log)
    hosts = state.carry_over(hosts, state.load(cfg.state_dir))
    if not a.no_identify:
        Identifier(cfg, make_client(cfg), log).run(hosts, workers=a.workers)
    p = state.save(cfg.state_dir, hosts)
    report.write(hosts, build_plan(hosts, cfg, include_pending=True), cfg)
    print(report.terminal_table(hosts))
    log(f"saved {p}; next: labscout review, then labscout plan / apply")
    return 0


def cmd_identify(a) -> int:
    cfg = _cfg(a)
    hosts = state.load(cfg.state_dir)
    if not hosts:
        log("no scan results yet: run `labscout scan` first")
        return 2
    Identifier(cfg, make_client(cfg), log).run(hosts, force=a.force, workers=a.workers)
    state.save(cfg.state_dir, hosts)
    print(report.terminal_table(hosts))
    return 0


def cmd_review(a) -> int:
    """Approve / reject hosts, or set what a host is by hand."""
    cfg = _cfg(a)
    hosts = state.load(cfg.state_dir)
    by_ip = {h.ip: h for h in hosts}
    changed = 0
    if a.approve_above is not None:
        for h in hosts:
            if h.decision == "pending" and h.identity and h.identity.confidence >= a.approve_above:
                h.decision = "approved"
                changed += 1
    for ip in a.approve or []:
        if ip in by_ip:
            by_ip[ip].decision, changed = "approved", changed + 1
    for ip in a.reject or []:
        if ip in by_ip:
            by_ip[ip].decision, changed = "rejected", changed + 1
    if a.set:
        ip, _, app = a.set.partition("=")
        h = by_ip.get(ip)
        if not h or not app:
            log("use --set IP=app[:port[/health/path]]")
            return 2
        app, _, rest = app.partition(":")
        port, _, path = rest.partition("/")
        h.identity = Identity(app=app, display_name=app, category="manual", confidence=1.0,
                              source="manual", web_port=int(port or 0),
                              health_path="/" + path if port else "/", reasons=["set by hand"])
        h.decision = "approved"
        changed += 1
    state.save(cfg.state_dir, hosts)
    print(report.terminal_table(hosts))
    log(f"{changed} hosts changed")
    return 0


def cmd_plan(a) -> int:
    cfg = _cfg(a)
    hosts = state.load(cfg.state_dir)
    plan = build_plan(hosts, cfg, include_pending=a.include_pending)
    files = report.write(hosts, plan, cfg)
    print(f"new apps for the infra catalog: {', '.join(sorted(plan.catalog_add)) or '-'}")
    print(f"aliases: {', '.join(f'{k}->{v}' for k, v in sorted(plan.aliases_add.items())) or '-'}")
    print(f"monitoring entries: {len(plan.monitoring)}, NetBox addresses: {len(plan.netbox)}, "
          f"not identified: {len(plan.unknown)}, skipped (not approved): {len(plan.skipped)}")
    print("written: " + ", ".join(map(str, files)))
    return 0


def cmd_apply(a) -> int:
    from .apply import apply_infra, apply_netbox
    cfg = _cfg(a)
    hosts = state.load(cfg.state_dir)
    plan = build_plan(hosts, cfg, include_pending=a.include_pending)
    if not (a.netbox or a.infra):
        log("choose what to apply: --netbox and/or --infra")
        return 2
    rc = 0
    if a.netbox:
        try:
            apply_netbox(plan, cfg, log, dry_run=a.dry_run)
        except RuntimeError as exc:
            log(f"NetBox: {exc}")
            rc = 1
    if a.infra:
        try:
            if a.dry_run:
                from .plan import load_infra, patch_apps_yml
                _, _, apps = load_infra(cfg.infra_repo, cfg.infra_apps_file)
                if apps:
                    import difflib
                    new = patch_apps_yml(apps.read_text(), plan).splitlines()
                    print("\n".join(difflib.unified_diff(apps.read_text().splitlines(), new,
                                                         "apps.yml", "apps.yml (labscout)", lineterm="")))
            else:
                apply_infra(plan, cfg, log)
        except RuntimeError as exc:
            log(f"infra: {exc}")
            rc = 1
    return rc


def cmd_run(a) -> int:
    a.no_identify = False
    rc = cmd_scan(a)
    if rc == 0:
        a.include_pending = True
        rc = cmd_plan(a)
    return rc


def cmd_doctor(a) -> int:
    cfg = _cfg(a)
    ok = True
    print(f"labscout {__version__}")
    print(f"nmap: {shutil.which('nmap') or 'not found (TCP connect scan fallback, no versions/MACs)'}")
    if cfg.use_llm:
        c = make_client(cfg)
        try:
            print(f"ollama {cfg.ollama_host}: version {c.version()}, model {cfg.model}: "
                  f"{'present' if c.has_model() else 'MISSING (ollama pull ' + cfg.model + ')'}")
        except Exception as exc:  # noqa: BLE001 - doctor reports, never crashes
            print(f"ollama {cfg.ollama_host}: {exc}")
            ok = False
    for ep in cfg.proxmox:
        print(f"proxmox {ep.name} {ep.url}: token {'set' if ep.token_secret else 'MISSING in $' + ep.token_env}")
    if cfg.netbox_url:
        print(f"netbox {cfg.netbox_url}: token {'set' if os.environ.get(cfg.netbox_token_env) else 'MISSING in $' + cfg.netbox_token_env}")
    if cfg.infra_repo:
        apps = Path(cfg.infra_repo) / cfg.infra_apps_file
        print(f"infra repo: {apps} {'found' if apps.is_file() else 'NOT FOUND'}")
    print(f"networks: {', '.join(cfg.networks)}")
    return 0 if ok else 1


def cmd_init(a) -> int:
    p = Path(a.path)
    if p.exists() and not a.force:
        log(f"{p} exists (use --force)")
        return 1
    p.write_text(SAMPLE)
    print(f"wrote {p}")
    return 0


def cmd_serve(a) -> int:
    from .web import serve
    cfg = _cfg(a)
    return serve(cfg, a.config, bind=a.bind, port=a.port)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="labscout", description=__doc__)
    p.add_argument("--version", action="version", version=f"labscout {__version__}")
    sub = p.add_subparsers(dest="cmd")

    def common(sp):
        sp.add_argument("-c", "--config", help="config file (default ./labscout.yml)")
        sp.add_argument("--state-dir", help="where results are kept (default ./labscout-data)")

    for name, fn, hlp in (("run", cmd_run, "scan + identify + plan in one go"),
                          ("scan", cmd_scan, "scan the networks and Proxmox, then identify")):
        s = sub.add_parser(name, help=hlp)
        common(s)
        s.add_argument("networks", nargs="*", help="CIDRs (default: from the config)")
        s.add_argument("--no-ai", action="store_true", help="built-in fingerprints only")
        s.add_argument("--model", help="Ollama model")
        s.add_argument("--workers", type=int, default=1, help="parallel model requests")
        s.add_argument("--no-identify", action="store_true", help=argparse.SUPPRESS if name == "run" else "only scan")
        s.set_defaults(func=fn)

    s = sub.add_parser("identify", help="(re)identify the hosts of the last scan")
    common(s)
    s.add_argument("--force", action="store_true", help="ask again, ignore the cache")
    s.add_argument("--no-ai", action="store_true")
    s.add_argument("--model")
    s.add_argument("--workers", type=int, default=1)
    s.set_defaults(func=cmd_identify)

    s = sub.add_parser("review", help="approve/reject hosts or set what they are")
    common(s)
    s.add_argument("--approve", nargs="*", metavar="IP")
    s.add_argument("--reject", nargs="*", metavar="IP")
    s.add_argument("--approve-above", type=float, metavar="CONF",
                   help="approve every pending host identified with at least this confidence")
    s.add_argument("--set", metavar="IP=APP[:PORT[/PATH]]", help="identify a host by hand")
    s.set_defaults(func=cmd_review)

    s = sub.add_parser("plan", help="write report.md and plan.json")
    common(s)
    s.add_argument("--include-pending", action="store_true", help="also plan hosts not approved yet")
    s.set_defaults(func=cmd_plan)

    s = sub.add_parser("apply", help="write the plan to NetBox and/or the infra repo")
    common(s)
    s.add_argument("--netbox", action="store_true", help="IP addresses + services in NetBox")
    s.add_argument("--infra", action="store_true", help="app catalog changes on a branch of the infra repo")
    s.add_argument("--dry-run", action="store_true", help="show what would change")
    s.add_argument("--include-pending", action="store_true")
    s.set_defaults(func=cmd_apply)

    s = sub.add_parser("serve", help="web UI")
    common(s)
    s.add_argument("--bind", default="127.0.0.1")
    s.add_argument("--port", type=int, default=8766)
    s.set_defaults(func=cmd_serve)

    s = sub.add_parser("doctor", help="check Ollama, nmap, tokens and paths")
    common(s)
    s.set_defaults(func=cmd_doctor)

    s = sub.add_parser("init", help="write a sample labscout.yml")
    s.add_argument("path", nargs="?", default="labscout.yml")
    s.add_argument("--force", action="store_true")
    s.set_defaults(func=cmd_init)
    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    a = parser.parse_args(argv)
    if not getattr(a, "func", None):
        parser.print_help()
        return 0
    try:
        return a.func(a)
    except KeyboardInterrupt:
        return 130
