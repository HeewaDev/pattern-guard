# Pattern-Guard Gateway

A reverse proxy that sits in front of any HTTP application and enforces its decisions:

```
client ─► [TLS terminator / CDN] ─► pattern-guard-gateway ─► your app
                                        │
   every request:  allow/deny/challenge lists
                   → IP reputation (CrowdSec community blocklist, Suricata & Wazuh alerts)
                   → WAF payload inspection (SQLi, XSS, traversal, RCE, SSRF, Log4Shell, XXE, SSTI, NoSQL)
                   → behavioural ML (bots, scraping, credential stuffing, L7 floods)
                   → one decision: allow · delay · proof-of-work challenge · block
```

## Quick start

```bash
cargo build --release -p pattern-guard-gateway
cp config/gateway.toml.example gateway.toml          # set `upstream` to your app
./target/release/pattern-guard-gateway --config gateway.toml --check
./target/release/pattern-guard-gateway --config gateway.toml
```

Start with `mode = "detect"`: everything is inspected and logged (`decisions.jsonl`,
`/metrics`), nothing is blocked. Review what *would* have been stopped, add exclusions,
then switch to `mode = "prevent"`.

The gateway speaks plain HTTP/1.1. Terminate TLS (and HTTP/2/3) in front of it — nginx,
Caddy, HAProxy, a cloud load balancer or a CDN — and list that hop in
`client_ip.trusted_proxies`.

## What each decision does (`mode = "prevent"`)

| Decision | Response | Fed back to the ML |
|---|---|---|
| Allow | proxied to your app; `x-pattern-guard-bot-score`, `-risk`, `-request-id` added | your app's status |
| Delay | proxied after up to `delay_max_secs` | your app's status |
| Challenge | 403 page that solves a SHA-256 proof-of-work in the browser (~0.1–0.5 s at difficulty 16), then sets an HttpOnly, IP-bound clearance cookie for `ttl_secs`. Non-HTML clients get `{"error":"challenge_required"}` | neutral (humans aren't punished for meeting a challenge) |
| Block | 403 page / JSON with a request id | 403 (repeated attempts escalate) |

A valid clearance cookie lifts Challenge and Delay, never Block.

Precedence: the most severe layer wins. `deny` list → Block; reputation `ban` → Block;
reputation `captcha` or `challenge` list → Challenge; WAF score ≥ `block_score` → Block;
behavioural ML → its own decision.

## Threat intelligence

**CrowdSec (shared IP reputation).** The gateway is a CrowdSec *bouncer*: it pulls the
decision stream (community blocklist + detections from your own CrowdSec agents) from the
local API.

```bash
cscli bouncers add pattern-guard-gateway      # prints an API key
export CROWDSEC_BOUNCER_KEY=...
```
```toml
[crowdsec]
enabled = true
url = "http://127.0.0.1:8080"
api_key_env = "CROWDSEC_BOUNCER_KEY"
```

`ban` decisions block, `captcha` decisions challenge; IPs and ranges are supported.

**Suricata (network layer).** Point a feed at `eve.json`. Alerts with severity ≤
`min_severity` block the attacking IP for `block_secs` (direction-aware: for `to_client`
alerts the attacker is `dest_ip`).

**Wazuh (host layer).** Point a feed at `alerts.json`. Alerts with `rule.level` ≥
`min_severity` and a `data.srcip` block that IP. An SSH brute-forcer flagged by Wazuh is
then also blocked from the web app.

**Sending gateway events to Wazuh / Elastic / Splunk.** `log.decisions` writes one JSON
object per mitigated (or WAF-flagged) request using EVE/ECS-style fields (`timestamp`,
`event_type`, `src_ip`, `srcip`, `http.url`, `http.http_user_agent`, `http.status`) plus a
`pattern_guard` object (`action`, `layer`, `enforced`, `risk`, `bot_score`, `reasons`, `waf`,
`reputation`). Wazuh can read it with
`<localfile><log_format>json</log_format><location>/path/decisions.jsonl</location></localfile>`
and a rule on `pattern_guard.action`. An example rule follows; it has not been tested
against a live Wazuh manager:

```xml
<group name="pattern-guard,web,">
  <rule id="100500" level="3">
    <decoded_as>json</decoded_as>
    <field name="pattern_guard.request_id">\.+</field>
    <description>Pattern-Guard: $(pattern_guard.action) $(srcip)</description>
  </rule>
  <rule id="100501" level="10">
    <if_sid>100500</if_sid>
    <field name="pattern_guard.action">^block$</field>
    <description>Pattern-Guard blocked $(srcip) ($(pattern_guard.layer))</description>
  </rule>
</group>
```

## WAF tuning

* `block_score` (default 7) / `log_score` (4): each attack class is scored 0–10.
* `exclude_paths`: path prefixes skipped entirely (health checks, webhooks you verify by signature).
* `exclude_params`: field names whose values are not inspected (rich-text editors, code snippets).
* Measured accuracy, including hold-out results and their limits: [FEATURES.md](FEATURES.md) §3.

## Connection-level protection

* `limits.max_connections_per_ip`: concurrent connections per client IP (trusted proxies exempt).
* `limits.header_read_timeout_secs`: clients that trickle headers (slowloris) are dropped.
* `max_body_bytes`: larger bodies get 413 before any work is done.

Volumetric L3/L4 floods must be absorbed upstream (ISP / CDN / cloud scrubbing). No
software on your server can absorb more traffic than its uplink carries.

## Admin endpoints (`admin_listen`, keep private)

| Path | |
|---|---|
| `/metrics` | Prometheus: requests by action, blocks by layer, WAF findings by class, challenges passed/failed, feed alerts, reputation entries, CrowdSec status, decision time |
| `/healthz` | `ok` |
| `/inventory` | API discovery: every route template seen (`GET /api/items/{n}`), with volume, block count, status codes, first/last seen |

## Performance

`cargo run --release -p pattern-guard-gateway --example loadtest` (`crates/gateway/examples/loadtest.rs`) (4 vCPU shared by load
generator, gateway and upstream; every request fully inspected and proxied in detect mode):
**~32 000 req/s, p50 ≈ 2 ms, p99 ≈ 3 ms**, against ~200 000 req/s for the bare upstream.
The behavioural engine runs behind a single lock today; sharding it is the next
performance step.

## Limits of this version

* HTTP/1.1 only towards clients and upstream; no WebSocket upgrade passthrough yet.
* Request bodies are buffered (up to `max_body_bytes`) for inspection; responses are streamed.
* CrowdSec local API over `http://` only (it normally runs on localhost).
* Single process: reputation, clearances and ML state are per instance (set `challenge.secret`
  so clearances work across instances behind a load balancer).
