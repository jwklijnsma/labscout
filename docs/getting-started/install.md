# Install

labscout needs Python 3.10 or newer, an Ollama server and, preferably, nmap.

```bash
pipx install git+https://github.com/jwklijnsma/labscout
sudo apt install nmap          # optional: without it labscout does a TCP connect scan
ollama pull qwen2.5:14b         # or any instruct model; 7-14B is enough
labscout doctor
```

`doctor` checks that Ollama answers and has the model, that nmap is present, that the Proxmox
and NetBox token variables are set and that the infra repo's apps file exists.

!!! tip "Root or NET_RAW"
    nmap reports MAC addresses and does ARP discovery only with raw sockets. Run labscout as
    root, or give the container `NET_RAW` and `NET_ADMIN`. Without them it still finds every host
    that answers on a TCP port.

For a container or a systemd service, see [Deploy](../deploy.md).
