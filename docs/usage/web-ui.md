# Web UI

```bash
labscout serve                       # http://127.0.0.1:8766
labscout serve --bind 0.0.0.0        # reachable from the LAN
```

The UI shows the host table with identification, confidence and source. Click a host for every
fact that was collected and the model's reasons. Approve, reject or correct hosts there, start a
scan, identify or plan job and watch its log, and read the plan.

Access needs a token. It comes from `LABSCOUT_WEB_TOKEN`, or labscout generates one and prints
the login URL (`/?token=…`). After the first visit the token is kept in an HttpOnly cookie, and
every change needs the `X-Labscout` header, which stops cross-site requests.

!!! warning
    Put the UI behind your reverse proxy with TLS (for example Traefik with CrowdSec) when you
    bind it to anything other than localhost.
