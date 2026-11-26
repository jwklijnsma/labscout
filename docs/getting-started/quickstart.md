# Quick start

```bash
labscout init                     # writes ./labscout.yml
$EDITOR labscout.yml              # networks, proxmox endpoints, netbox_url, infra_repo
export PVE_TOKEN_HOME_CLUSTER=…   # read-only PVEAuditor token secret
labscout run                      # scan + identify, prints a table
```

The table shows every host with its identification, the confidence and where it came from:
`rule`, `ai`, `rule+ai` (both agree) or `manual`.

```bash
labscout review --approve-above 0.9          # accept the confident ones
labscout review --set 10.0.3.77=jellyfin:8096/health
labscout review --reject 10.0.3.250          # never plan this host
labscout plan                                # labscout-data/report.md + plan.json
labscout apply --netbox --infra --dry-run
labscout apply --netbox --infra
```

Run `labscout serve` to do the same in the browser.
