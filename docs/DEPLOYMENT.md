# Deployment

## Topology

```
internet ─► TLS terminator (Caddy / nginx / HAProxy / cloud LB / CDN)
              │  sets X-Forwarded-For
              ▼
            pattern-guard-gateway  :8080   (admin :9901 on loopback)
              │
              ▼
            your app              :3000
```

The gateway speaks HTTP/1.1. Put TLS, HTTP/2/3 and certificates in the terminator in front
of it, and list that hop in `client_ip.trusted_proxies`. Your app should only accept
traffic from the gateway (bind it to localhost, or firewall it), otherwise attackers can
go around the gateway.

## 0. Docker (quickest)

```bash
docker build -t pattern-guard .
docker run -d --name pattern-guard -p 8080:8080 -p 127.0.0.1:9901:9901 \
  --stop-timeout 15 \
  -v "$PWD/gateway.toml:/etc/pattern-guard/gateway.toml:ro" \
  -v pattern-guard-logs:/var/log/pattern-guard \
  -v pattern-guard-state:/var/lib/pattern-guard \
  pattern-guard
docker run --rm -v "$PWD/gateway.toml:/etc/pattern-guard/gateway.toml:ro" pattern-guard \
  --config /etc/pattern-guard/gateway.toml --check
```

- `docker stop` sends SIGTERM. The gateway then refuses new connections, gives the
  requests in progress `limits.shutdown_grace_secs` (default 7) to finish, and after that writes the
  queued decision-log lines. Docker kills a container 10 s after SIGTERM by default, so
  give it a few seconds more (`--stop-timeout 15`, or `stop_grace_period: 15s` in
  compose). See [GATEWAY.md](GATEWAY.md#graceful-shutdown).

- The image (~125 MB, Debian slim) runs as an unprivileged user (uid 10001). It contains
  `pattern-guard-gateway`, the `pattern-guard` CLI and the example configs in
  `/etc/pattern-guard/`.
- Its default config is [deploy/docker/gateway.toml](../deploy/docker/gateway.toml):
  detect mode, upstream `http://app:80`, decision log in the
  `/var/log/pattern-guard` volume, learned state (`[persistence]`) in
  `/var/lib/pattern-guard/state.json`. Mount your own config over it, and keep
  `/var/lib/pattern-guard` on a named volume: otherwise every new container starts with
  nothing learned (see [GATEWAY.md](GATEWAY.md#persistence)).
- Publish the admin port (9901) on a private address only.
- [deploy/docker/compose.yml](../deploy/docker/compose.yml) runs the gateway in front of a
  demo app: `docker compose -f deploy/docker/compose.yml up --build`, then replace `app`
  with your application.

## 1. Build from source

```bash
cargo build --release -p pattern-guard-gateway -p pattern-guard-cli
sudo install -m 0755 target/release/pattern-guard-gateway target/release/pattern-guard /usr/local/bin/
sudo mkdir -p /etc/pattern-guard /var/log/pattern-guard
sudo cp config/gateway.toml.example /etc/pattern-guard/gateway.toml
sudo cp config/guard.toml.example   /etc/pattern-guard/guard.toml      # optional, ML tuning
```

Edit `/etc/pattern-guard/gateway.toml`:

```toml
listen = "127.0.0.1:8080"
upstream = "http://127.0.0.1:3000"
mode = "detect"
guard_config = "guard.toml"
[client_ip]
trusted_proxies = ["127.0.0.1"]
[challenge]
secret = "<64 hex chars: openssl rand -hex 32>"
[log]
decisions = "/var/log/pattern-guard/decisions.jsonl"
```

```bash
pattern-guard-gateway --config /etc/pattern-guard/gateway.toml --check
```

## 2. TLS terminator in front

**Caddy** (adds `X-Forwarded-For` automatically):

```
shop.example.com {
    reverse_proxy 127.0.0.1:8080
}
```

**nginx**:

```nginx
server {
    listen 443 ssl http2;
    server_name shop.example.com;
    # ssl_certificate ...;
    client_max_body_size 10m;
    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

**Behind a CDN** (e.g. Cloudflare): add the CDN's published IP ranges to
`trusted_proxies`. If the CDN puts the client in its own header, set it in
`client_ip.header` (e.g. `cf-connecting-ip`). If your terminator can compute a JA4 TLS
fingerprint, pass it in a header and set `client_ip.fingerprint_header`.

## 3. systemd

A hardened unit is in [deploy/systemd/pattern-guard-gateway.service](../deploy/systemd/pattern-guard-gateway.service):
it validates the config before every start (`ExecStartPre=... --check`), reads secrets
from `/etc/pattern-guard/env`, and runs with no capabilities, a read-only system, a
system-call filter and write access to `/var/log/pattern-guard` only.

```bash
sudo cp deploy/systemd/pattern-guard-gateway.service /etc/systemd/system/
```

The essential part:

```ini
# /etc/systemd/system/pattern-guard-gateway.service
[Unit]
Description=Pattern-Guard Gateway
After=network-online.target
Wants=network-online.target

[Service]
User=pattern-guard
Group=pattern-guard
ExecStart=/usr/local/bin/pattern-guard-gateway --config /etc/pattern-guard/gateway.toml
Restart=always
RestartSec=1
TimeoutStopSec=20                             # > limits.shutdown_grace_secs (default 7)
StateDirectory=pattern-guard                  # /var/lib/pattern-guard for [persistence]
StateDirectoryMode=0700
# EnvironmentFile=/etc/pattern-guard/env      # CROWDSEC_BOUNCER_KEY=...
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/log/pattern-guard
PrivateTmp=true
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
```

```bash
sudo useradd --system --no-create-home pattern-guard
sudo chown pattern-guard: /var/log/pattern-guard
sudo systemctl daemon-reload && sudo systemctl enable --now pattern-guard-gateway
journalctl -u pattern-guard-gateway -f
```

`systemctl stop` and `systemctl restart` send SIGTERM: the gateway drains (see
[GATEWAY.md](GATEWAY.md#graceful-shutdown)) and exits within `limits.shutdown_grace_secs`
plus about a second. `TimeoutStopSec` must stay above that, or systemd kills it before
the decision log is written and the learned state is saved.

To keep learned state across restarts, set in `gateway.toml`:

```toml
[persistence]
path = "/var/lib/pattern-guard/state.json"
```

`StateDirectory=pattern-guard` makes systemd create `/var/lib/pattern-guard` (mode 0700,
owned by the service user) and keep it writable under `ProtectSystem=strict`.

To read Suricata or Wazuh alert files, add the service user to the group that owns them
(e.g. `sudo usermod -aG wazuh pattern-guard`) and add their directories to
`ReadOnlyPaths=`.

## 4. Integrations

**CrowdSec** (shared IP reputation):

```bash
# install CrowdSec per its docs, then:
sudo cscli bouncers add pattern-guard-gateway        # copy the key
echo 'CROWDSEC_BOUNCER_KEY=<key>' | sudo tee /etc/pattern-guard/env
```
```toml
[crowdsec]
enabled = true
url = "http://127.0.0.1:8080"      # CrowdSec LAPI. If it also uses 8080, move one of them.
api_key_env = "CROWDSEC_BOUNCER_KEY"
```

CrowdSec's LAPI defaults to `127.0.0.1:8080`. Either run the gateway on another port, or
change the LAPI's `listen_uri`.

**Suricata** (network IDS): enable the `eve-log` output with `alert` events, then:
```toml
[[feeds]]
kind = "suricata"
path = "/var/log/suricata/eve.json"
min_severity = 2
block_secs = 3600
```

**Wazuh** (host monitoring, SIEM):
- *Wazuh → gateway:* add a `[[feeds]] kind = "wazuh"` entry with
  `path = "/var/ossec/logs/alerts/alerts.json"`.
- *Gateway → Wazuh:* have the Wazuh agent read `/var/log/pattern-guard/decisions.jsonl`
  as JSON. A rule example is in [GATEWAY.md](GATEWAY.md#threat-intelligence).

**Prometheus**: scrape `http://127.0.0.1:9901/metrics`. Alert examples are in
[OPERATIONS.md](OPERATIONS.md#metrics-and-alerts).

## 5. Several instances

- Run N gateways behind your load balancer.
- Set the same `challenge.secret` on all of them, so a clearance from one is accepted by
  the others.
- Behavioural state is per instance. Use client-IP affinity (sticky by source IP) on the
  load balancer, so each client's behaviour is seen by one instance.
- Each instance pulls CrowdSec decisions itself.
- Give each instance its own `persistence.path`. Instances don't share or merge state
  files.

## 6. Sizing

- One instance did about 28,000 fully inspected req/s on 4 vCPU that it shared with the
  load generator and the upstream (`crates/gateway/examples/loadtest.rs`). Measure on your own
  hardware and traffic mix.
- Memory is bounded by the LRU caps (`max_actors`, `adaptive.max_routes`,
  `max_fingerprints`, `max_subnets`), plus request buffers up to `max_body_bytes` per
  in-flight request.
- The `[persistence]` files grow with the same caps: about 210 MB together when every
  table is full (100 000 actors, 100 000 bans, 500 000 CrowdSec entries). A save takes
  up to about 1 s of one core, the load at startup 1–2 s. Expect a few MB for a small
  site.

## 7. Upgrading

- Engine models are TOML files. Point `guard.toml`'s `model = "..."` at a new file and
  reload (`systemctl reload pattern-guard-gateway`, or `kill -HUP`): baselines are kept,
  and a reload doesn't switch to a model trained for another version's features. Most
  config changes reload the same way; the few that need a restart are listed in
  [GATEWAY.md](GATEWAY.md#reloading-the-config).
- The `[persistence]` state files carry format versions. A release that can't read the
  previous ones says so in one warning line at startup, keeps the unusable file as
  `<file>.bad` and starts with nothing learned for that part only: an engine with a new
  feature layout still gets the bans and the clearance key back.
- Read [CHANGELOG.md](../CHANGELOG.md) for breaking config changes.
- Run `--check` before restarting or reloading.
