"""Reports: Markdown for people, JSON for tools, a compact table for the terminal."""

from __future__ import annotations

from collections import Counter
import json
from pathlib import Path
import time

from .models import Host
from .plan import Plan


def terminal_table(hosts: list[Host]) -> str:
    rows = [f"{'IP':<15} {'NAME':<26} {'APP':<22} {'SRC':<8} {'CONF':>4}  {'WEB':<26} DECISION"]
    for h in hosts:
        i = h.identity
        web = f"{i.scheme}://:{i.web_port}{i.health_path}" if i and i.web_port else ""
        rows.append(f"{h.ip:<15} {h.name[:26]:<26} {(i.app if i else '?')[:22]:<22} "
                    f"{(i.source if i else '')[:8]:<8} {(i.confidence if i else 0):>4.2f}  "
                    f"{web[:26]:<26} {h.decision}")
    return "\n".join(rows)


def markdown(hosts: list[Host], plan: Plan | None, cfg) -> str:
    cats = Counter((h.identity.category if h.identity else "unknown") for h in hosts)
    md = [f"# labscout report — {time.strftime('%Y-%m-%d %H:%M')}", "",
          f"Networks: {', '.join(cfg.networks)} · model: `{cfg.model if cfg.use_llm else 'off'}` · "
          f"{len(hosts)} hosts", "",
          "| Category | Hosts |", "|---|---|"]
    md += [f"| {c} | {n} |" for c, n in cats.most_common()]
    md += ["", "## Hosts", "", "| IP | Name | App | Version | Source | Conf. | Health check | Decision |",
           "|---|---|---|---|---|---|---|---|"]
    for h in hosts:
        i = h.identity
        chk = f"`{i.scheme}://{h.ip}:{i.web_port}{i.health_path}`" if i and i.web_port else ""
        md.append(f"| {h.ip} | {h.name} | {i.display_name or i.app if i else '?'} | "
                  f"{i.version if i else ''} | {i.source if i else ''} | "
                  f"{f'{i.confidence:.2f}' if i else ''} | {chk} | {h.decision} |")
    if plan:
        md += ["", "## Plan", ""]
        if plan.catalog_add:
            md += ["### New apps for the infra catalog", "", "```yaml"]
            md += [f"{k}: {json.dumps(v)}" for k, v in sorted(plan.catalog_add.items())]
            md += ["```", ""]
        if plan.aliases_add:
            md += ["### Aliases (guest name → app)", "", "```yaml"]
            md += [f"{k}: {v}" for k, v in sorted(plan.aliases_add.items())]
            md += ["```", ""]
        if plan.monitoring:
            md += ["### Monitoring", "", "| Host | App | Health check | Metrics | Exporter | node_exporter |",
                   "|---|---|---|---|---|---|"]
            md += [f"| {m['host']} | {m['app']} | `{m['check']}` | {m['metrics']} | {m['exporter']} | "
                   f"{'add' if m['node_exporter'] else ''} |" for m in plan.monitoring]
        if plan.unknown:
            md += ["", "### Not identified", "", "| IP | Name | Vendor | Ports | Guess |", "|---|---|---|---|---|"]
            md += [f"| {u['ip']} | {u['name']} | {u['vendor']} | {', '.join(map(str, u['ports']))} | "
                   f"{u['guess']} |" for u in plan.unknown]
    md += ["", "## Details", ""]
    for h in hosts:
        i = h.identity
        if not i:
            continue
        md += [f"<details><summary>{h.ip} · {h.name} · {i.app}</summary>", "",
               f"- {i.description}" if i.description else "",
               f"- sources: {', '.join(h.sources)}; MAC {h.mac or '-'} {h.vendor}",
               f"- ports: {', '.join(f'{p.port}/{p.product or p.service}' for p in h.ports) or '-'}",
               *[f"- web :{w.port} {w.status} \"{w.title}\" {w.server}" for w in h.http],
               *[f"- why: {r}" for r in i.reasons], "", "</details>", ""]
    return "\n".join(x for x in md if x is not None)


def write(hosts: list[Host], plan: Plan | None, cfg) -> list[Path]:
    out = Path(cfg.state_dir)
    out.mkdir(parents=True, exist_ok=True)
    md = out / "report.md"
    md.write_text(markdown(hosts, plan, cfg))
    js = out / "plan.json"
    js.write_text(json.dumps({"plan": plan.to_dict() if plan else None,
                              "hosts": [h.to_dict() for h in hosts]}, indent=1))
    return [md, js]
