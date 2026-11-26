# labscout

**Find out what runs in your homelab, with a local Ollama model, and plan its monitoring and NetBox entries.**

labscout scans your networks, works out what software each host runs, and turns that into a
plan: catalog entries and monitoring targets for an Ansible infra repo, plus IP addresses and
services in NetBox. It is a sibling of [ansreview](https://github.com/jwklijnsma/ansreview) and
[helmreview](https://github.com/jwklijnsma/helmreview). The model runs on your own Ollama and
no scan data leaves your network.

```text
 scan ──► identify ──► review ──► plan ──► apply
 nmap      rules +      you        report   NetBox REST
 HTTP      Ollama       approve    plan.json infra repo branch
 Proxmox   (cached)     or fix               (never pushed)
 NetAlertX
```

## What it does

| Step | What happens |
|---|---|
| **scan** | nmap (`-sV`, or a plain TCP connect scan when nmap is missing) over every configured range. HTTP(S) fingerprints of web ports (title, server header, redirects, favicon hash). Guest names, nodes and IPs from the Proxmox API. Device names and MACs from NetAlertX. |
| **identify** | About 65 built-in fingerprint rules come first. Hosts that the rules don't settle go to Ollama with a strict JSON schema. Guard rails drop web ports the model names that were never seen open. Answers are cached per host fingerprint, so a rescan only asks about hosts that changed. |
| **review** | You approve, reject or correct every identification on the command line or in the web UI. Nothing is planned without your approval unless you ask for it. |
| **plan** | `report.md` and `plan.json`: new `apps.yml` catalog entries and aliases, Prometheus targets (node exporter, app metrics, blackbox probes), and NetBox IPs and services. |
| **apply** | `--netbox` upserts IP addresses and services through the REST API and keeps descriptions people wrote. `--infra` commits the catalog changes on branch `labscout/apps` of your infra repo and never pushes. `--dry-run` shows what would change. |

## Quick start

```bash
pipx install git+https://github.com/jwklijnsma/labscout
ollama pull qwen2.5:14b

labscout init                 # writes labscout.yml, edit networks/proxmox/netbox
labscout doctor               # checks Ollama, nmap, tokens and paths
labscout run                  # scan + identify
labscout review --approve-above 0.9
labscout plan                 # labscout-data/report.md
labscout apply --netbox --dry-run
labscout serve                # web UI on http://127.0.0.1:8766
```

Or with Docker (host network, so nmap sees the real interfaces):

```bash
docker run -d --name labscout --network host --cap-add NET_RAW --cap-add NET_ADMIN \
  -v ~/.config/labscout:/config -v labscout-data:/data \
  -e LABSCOUT_WEB_TOKEN="$(openssl rand -hex 24)" --env-file ~/.config/labscout/secrets.env \
  ghcr.io/jwklijnsma/labscout
```

## Secrets

Tokens are read from environment variables named in `labscout.yml` (`token_env`), never from
the file itself: `PVE_TOKEN_<NAME>` (read-only PVEAuditor tokens), `NETBOX_TOKEN`,
`NETALERTX_API_TOKEN` and `LABSCOUT_WEB_TOKEN`. Credentials found on hosts are never collected.

## Documentation

Full docs: <https://jwklijnsma.github.io/labscout/>. Preview them locally with `make docs`.

## Web UI

`labscout serve` opens a React UI with three pages:

- **Hosts:** filter, search, and approve or reject in bulk. Click a host for everything found about it and to correct the app.
- **Plan & apply:** preview first, then write to NetBox or commit to the infra branch.
- **Scan:** start a scan or identify again.

Jobs run in a queue in the background and show live logs. The top bar shows Ollama, the model picker, nmap and NetBox.

## Development

```bash
make install     # editable install with pytest
make test        # Python + web API tests against a fake Ollama
make web-test    # typecheck and test the UI
make web         # rebuild the UI bundle (committed, so pip/Docker need no Node)
make help        # everything else, including releases
```

MIT licensed.
