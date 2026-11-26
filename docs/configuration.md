# Configuration

labscout reads `~/.labscout.yml`, then `./labscout.yml` (or `-c FILE`), then environment
variables. Later sources win. `labscout init` writes a sample.

```yaml
ollama_host: http://localhost:11434
model: qwen2.5:14b
networks: [10.0.3.0/24, 10.0.0.0/24, 10.0.2.0/24]
exclude: []
proxmox:
  - name: home-cluster
    url: https://10.0.3.40:8006
    token_id: labscout@pve!scan
    token_env: PVE_TOKEN_HOME_CLUSTER
    verify_tls: false
netalertx_url: http://10.0.3.58:20212
domain: home.example.org
netbox_url: https://netbox.home.example.org
netbox_tag: labscout
infra_repo: /srv/infra
infra_apps_file: inventory/group_vars/all/apps.yml
house_rules: |
  Containers named *-exporter are Prometheus exporters, not apps.
```

| Key | Default | Meaning |
|---|---|---|
| `ollama_host` | `http://localhost:11434` | Ollama server (env `OLLAMA_HOST`) |
| `model` | `qwen2.5:14b` | Model for identification (env `LABSCOUT_MODEL`) |
| `networks` | none | CIDRs to scan |
| `exclude` | `[]` | IPs or CIDRs to skip |
| `ports` | common homelab ports | TCP ports to scan, comma-separated |
| `min_rule_confidence` | `0.85` | Rule matches below this also go to the model |
| `use_llm` | `true` | Set `false` to use the built-in rules only |
| `use_nmap` | `true` | Fall back to a connect scan when `false` or nmap is missing |
| `proxmox` | `[]` | API endpoints with `name`, `url`, `token_id`, `token_env`, `verify_tls` |
| `netalertx_url` / `netalertx_token_env` | none / `NETALERTX_API_TOKEN` | NetAlertX API |
| `domain` | none | Used for `<app>.<domain>` suggestions |
| `state_dir` | `labscout-data` | Results, cache and reports (env `LABSCOUT_STATE_DIR`) |
| `netbox_url` / `netbox_token_env` | none / `NETBOX_TOKEN` | NetBox API |
| `netbox_verify_tls` | `true` | TLS verification for NetBox |
| `netbox_tag` | `labscout` | Tag on every object labscout creates |
| `infra_repo` / `infra_apps_file` / `infra_branch` | none / `inventory/group_vars/all/apps.yml` / `labscout/apps` | Infra repo target |
| `house_rules` | none | Extra instructions for the model about your lab |

Secrets are only read from environment variables. The config file holds the variable names, not
the values.
