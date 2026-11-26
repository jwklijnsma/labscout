# Review, plan and apply

## Review

```bash
labscout review                         # list pending hosts
labscout review --approve 10.0.3.30 10.0.3.31
labscout review --approve-above 0.9
labscout review --reject 10.0.3.250
labscout review --set 10.0.3.77=jellyfin:8096/health
```

`--set IP=APP[:PORT[/PATH]]` identifies a host by hand. The host is then approved with source
`manual`.

## Plan

`labscout plan` writes `labscout-data/report.md` and `plan.json` from the approved hosts
(`--include-pending` adds the rest). The plan has these sections:

| Section | Content |
|---|---|
| Catalog | New `apps.yml` entries for apps the infra repo doesn't know yet (port, health path, metrics) |
| Aliases | Names that map onto an existing catalog entry (for example `proxmox-ve` → `pve`) |
| Monitoring | node exporter, app metrics and blackbox HTTP probes per host |
| NetBox | IP addresses with DNS name and description, services with ports |
| Unknown | Hosts nobody could identify, to look at by hand |

## Apply

```bash
labscout apply --netbox --infra --dry-run
labscout apply --netbox
labscout apply --infra
```

- `--netbox` upserts IP addresses and services and tags them `labscout`. A description or DNS
  name that a person already set is kept.
- `--infra` adds the catalog entries to `infra_apps_file` with a `# labscout` comment and commits them
  on the branch `labscout/apps`. It never pushes, so open the merge request yourself after
  reading the diff.
