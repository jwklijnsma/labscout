# Deploy

## Docker

```bash
mkdir -p ~/.config/labscout && labscout init ~/.config/labscout/labscout.yml
cp deploy/systemd/labscout.env.example ~/.config/labscout/secrets.env && chmod 600 $_
docker run -d --name labscout --network host --cap-add NET_RAW --cap-add NET_ADMIN \
  -v ~/.config/labscout:/config -v labscout-data:/data \
  --env-file ~/.config/labscout/secrets.env \
  ghcr.io/jwklijnsma/labscout
```

The image contains nmap and git but not Ollama. Point `OLLAMA_HOST` at your Ollama server. With
`--network host`, `http://127.0.0.1:11434` reaches an Ollama on the same machine.

To use `apply --infra`, mount your infra repo, for example `-v /srv/infra:/infra`, and set
`infra_repo: /infra`.

Run one-off commands in the same container:

```bash
docker exec labscout labscout -c /config/labscout.yml run
```

## systemd (Podman Quadlet)

`deploy/systemd/labscout.container` runs the image as a rootful Quadlet with automatic updates:

```bash
install -d -m 700 /etc/labscout
labscout init /etc/labscout/labscout.yml
install -m 600 deploy/systemd/labscout.env.example /etc/labscout/secrets.env
cp deploy/systemd/labscout.container /etc/containers/systemd/
systemctl daemon-reload && systemctl start labscout
```

## Proxmox read-only token

```bash
pveum user add labscout@pve
pveum aclmod / -user labscout@pve -role PVEAuditor
pveum user token add labscout@pve scan --privsep 0
```

Put the token secret in the variable named by `token_env`.
