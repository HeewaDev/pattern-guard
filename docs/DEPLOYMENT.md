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

## 1. Build

```bash
cargo build --release -p pattern-guard-gateway -p pattern-guard
sudo install -m 0755 target/release/pattern-guard-gateway target/release/pattern-guard /usr/local/bin/
sudo mkdir -p /etc/pattern-guard /var/log/pattern-guard
sudo cp gateway.toml.example /etc/pattern-guard/gateway.toml
sudo cp guard.toml.example   /etc/pattern-guard/guard.toml      # optional, ML tuning
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

## 6. Sizing

- One instance did about 32,000 fully inspected req/s on 4 vCPU that it shared with the
  load generator and the upstream (`gateway/examples/loadtest.rs`). Measure on your own
  hardware and traffic mix.
- Memory is bounded by the LRU caps (`max_actors`, `adaptive.max_routes`,
  `max_fingerprints`, `max_subnets`), plus request buffers up to `max_body_bytes` per
  in-flight request.

## 7. Upgrading

- Engine models are TOML files. Point `guard.toml`'s `model = "..."` at a new file and
  restart. Hot reload is planned.
- Read [CHANGELOG.md](../CHANGELOG.md) for breaking config changes.
- Run `--check` before restarting.
