# Scan and identify

```bash
labscout scan [CIDR ...]      # only discover
labscout identify [--force]   # (re)identify the last scan
labscout run [CIDR ...]       # both
```

Without arguments the `networks` from the config are scanned. Common options:

| Option | Meaning |
|---|---|
| `--no-ai` | Use the built-in rules only; hosts they don't match stay unknown |
| `--model NAME` | Override the Ollama model for this run |
| `--workers N` | Parallel model requests (match `OLLAMA_NUM_PARALLEL`) |
| `--force` | Ignore the cache and ask the model again |

## Sources

- **nmap** `-sV` over the configured `ports` list, with reverse DNS. Without nmap labscout does
  a TCP connect scan of the same ports.
- **HTTP** fingerprints on every web port: status, title, `Server` header, redirect target,
  favicon hash and a short body sample.
- **Proxmox**: node names, guest names, tags and IPs (from the guest config, the LXC interfaces
  or the QEMU guest agent). Proxmox nodes are identified as `proxmox-ve` directly.
- **NetAlertX**: device names, vendors and MAC addresses.

## How the model is used

The model receives only facts: open ports with service banners, HTTP fingerprints, and the
Proxmox and NetAlertX names. It must answer with the JSON schema (app, category, version, web
port, health path, metrics port, exporter, confidence, reasons). A web port the model names
that was not seen open is dropped. Rule matches at or above `min_rule_confidence` (0.85) skip
the model; weaker matches are sent along as a hint for the model to confirm or correct.

Results are cached in `labscout-data/ai-cache.json` per host fingerprint (ports + banners +
names), so a rescan of an unchanged lab makes no model calls.

Your decisions (approve, reject, manual identification) are carried over to the next scan as
long as the host keeps its IP.
