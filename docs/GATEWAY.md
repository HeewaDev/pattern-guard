# Pattern-Guard Gateway

A reverse proxy that sits in front of any HTTP application and enforces its decisions:

```
client ─► [TLS terminator / CDN] ─► pattern-guard-gateway ─► your app
                                        │
   every request:  allow / deny / challenge lists · custom rules · country policy
                   → protocol enforcement · honeypot traps · rate limits
                   → business operations (per-account budgets, allowed sources, replay protection)
                     · login protection (distributed brute force, credential stuffing)
                   → IP reputation (automatic bans, CrowdSec community blocklist, Suricata & Wazuh alerts)
                   → WAF payload inspection (SQLi, XSS, traversal, RFI, RCE, SSRF, PHP/Java/Node code,
                     Log4Shell, XXE, SSTI, NoSQL, prototype pollution, session fixation,
                     malicious uploads)
                   → behavioural ML (bots, scraping, credential stuffing, L7 floods)
                   → one decision: allow · delay · proof-of-work challenge · block (403 / 429 / 4xx)
   every response: security headers · data-leak blocking
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

Precedence: an `allow` list entry or `allow` rule skips everything; otherwise the most
severe layer wins (Block > Challenge > Delay > Allow). The deciding layer appears as
`layer` in the decision log and in `pattern_guard_blocked_total{layer=...}`:
`deny_list`, `rule`, `geo`, `protocol`, `trap`, `rate_limit`, `operation`, `reputation`,
`waf`, `behaviour`, `data_leak`. Enforced blocks from any layer except `reputation` and `trap`
count towards automatic bans.

## Custom rules

`[[rules]]`, evaluated in file order. Every condition you set must match. The first
terminal action wins; `log` and `skip_waf` keep evaluating.

**How paths are matched (rules, rate limits, operations, logins, traps, restricted
extensions, `waf.exclude_paths`).** Your application decodes the path before routing it
(`/%61dmin` is `/admin`, `/a/../b` is `/b`, `//admin` is `/admin`, `/x/..;/admin` is `/admin`
on Tomcat and Spring, `\` is `/` on IIS). So the gateway matches against both the raw path
and a canonical one:
- a **protection** (block / challenge / delay / log rules, rate limits, operations, logins,
  traps, restricted extensions) applies when either form matches, ignoring upper and lower case;
- an **exemption** (`allow` and `skip_waf` rules, `waf.exclude_paths`) applies only when both
  forms match exactly. `/health/..;/app` is not exempted by `exclude_paths = ["/health"]`.

The request is forwarded with its original path. Prefixes are plain string prefixes:
`/health` also matches `/healthz`, so write `/health/` or use `path_regex` when that matters.

| Condition | Meaning |
|---|---|
| `path` / `path_regex` | Path prefix / regex (query string excluded) |
| `methods` | e.g. `["POST", "PUT"]` |
| `hosts` | Exact host, or `*.example.com` for subdomains |
| `ips` / `not_ips` | Client IP in / not in these CIDRs |
| `countries` | Client country (needs `[geo] database`) |
| `user_agent_regex`, `query_regex` | Regex on User-Agent / raw query string |
| `headers` | `[{ name, regex }]` present and matching, or `[{ name, absent = true }]` |

| Action | Effect |
|---|---|
| `allow` | Forward with no further inspection (terminal) |
| `block` / `challenge` / `delay` | As the decisions above (terminal) |
| `log` | Note the match in the decision log, continue |
| `skip_waf` | Skip payload inspection for this request, continue |

Typical uses:
- **Virtual patching:** block a vulnerable endpoint until the app is fixed.
- **Admin areas:** allow them only from the office network.
- **Known attack tools:** challenge them.
- **Signed webhooks:** turn off WAF inspection for them.

## Rate limits

`[[rate_limits]]` is a token bucket per route and key. Each rule sets `requests` per
`per_secs`, and bursts up to `requests` are allowed.

- **Route:** `path`, `path_regex`, `methods`.
- **Key:**
  - `ip` (the default);
  - `ip_route`: per IP and per route template (`/api/items/{n}`);
  - `header:<name>`: per header value, e.g. an API key; falls back to the IP if the header
    is missing.
- **Action:**
  - `block`: **429 Too Many Requests** with `Retry-After` (HTML or JSON);
  - `challenge`;
  - `delay`.

Every matching limit consumes a token. The most severe exceeded limit decides.

## Business operations

Rate limits per IP don't stop an attacker who spreads requests over many IPs, or who
replays one valid payment confirmation many times. `[[operations]]` protects the routes
that move money or data: checkout, transfers, payment callbacks.

```toml
[[operations]]
name = "checkout"
path = "/checkout"
methods = ["POST"]
account = "header:authorization"            # who performs the operation
limit = { requests = 5, per_secs = 3600 }   # budget per account, from any IP

[[operations]]
name = "payment callback"
path = "/payment/callback"
allowed_ips = ["203.0.113.0/24"]            # only the payment provider may call it
unique = "json:transaction_id"              # each transaction accepted once
```

| Setting | Effect | Answer when enforced |
|---|---|---|
| `account` | Identifies the account: `header:<name>`, `cookie:<name>`, `query:<name>`, `form:<name>` or `json:<dotted.path>`. Values are hashed (SHA-256); tokens and user names are never stored or logged | |
| `require_account` | Refuse requests without the identifier | 403 `account_missing` |
| `limit` | Token bucket per account (per IP if there is no account) | 429 + Retry-After `account_limit` |
| `allowed_ips` | Only these sources may call the route | 403 `source_not_allowed` |
| `unique` + `unique_ttl_secs` | A value that may be used once. It is held while its request is in flight, so concurrent duplicates (race-condition double spends) are refused, and kept as used only if your app answered 2xx, so a provider retrying after a failure still gets through | 409 `replay` |
| `action` | `block` (default), `challenge`, `delay` or `log` (record only) | |

The deciding layer is `operation`; the decision log reason names the operation, the
check and a short account hash, e.g. `operation:checkout:account_limit account=fa8c06dd`.

These checks are a safety net, not a replacement for verifying payments in your
application: confirm every payment server-to-server with your provider (amount,
currency, order) and store each transaction id once.

## Login protection

`[[logins]]` counts **failed** logins (your app's `failure_statuses`, default 401/403):

- **Per account, from any IP.** After `max_failures` within `window_secs` the account is
  protected with `action` (challenge by default, answer 429), however many IPs the
  attacker uses. A successful login resets the count.
- **Per IP, across accounts.** An IP that fails on more than `max_accounts_per_ip`
  different accounts is stuffing credentials and is refused for new accounts.

Only failures count, so an office behind one NAT where people log in normally is never
flagged.

```toml
[[logins]]
name = "login"
path = "/login"
account = "json:email"        # or "form:username"
max_failures = 5
max_accounts_per_ip = 10
window_secs = 900
```

## Bans and honeypot traps

- `[bans]` (on by default): `threshold` enforced blocks within `window_secs` ban the IP for
  `ban_secs`. Each repeat ban lasts `escalation`× longer, up to `max_ban_secs`.
- `[traps]`: path prefixes your site never serves, e.g. `/wp-login.php` on a
  non-WordPress site. One request to a trap bans the client for `traps.ban_secs`.
- Bans live in the reputation store as source `gateway:ban`, so they are enforced, expire
  on their own, and are logged like CrowdSec decisions.
- On the admin port: `GET /bans` lists bans and `POST /bans/unban?ip=…` lifts one.

## Protocol enforcement

`[protocol]` (on by default) applies the ideas of OWASP CRS 911/920. Each refusal uses
its proper status:

| Check | Status |
|---|---|
| Method not in `allowed_methods` | 405 |
| Request target over `max_url_bytes` | 414 |
| More than `max_headers` fields, or over `max_header_bytes` | 431 |
| More than `max_query_args` | 400 |
| NUL byte (raw or `%00`) in the target | 400 |
| Missing Host | 400 |
| Path ending in a `restricted_extensions` entry (e.g. `.bak`, `.sql`) | 403 |

## Security headers

`[response_headers]` (on by default). Added only where your app hasn't set them:
`X-Content-Type-Options: nosniff`, `X-Frame-Options: SAMEORIGIN` and `Referrer-Policy`.
HSTS, CSP, Permissions-Policy and COOP are opt-in. Fingerprinting headers (`Server`,
`X-Powered-By`, `X-AspNet-Version`, …) are removed. Set a value to `""` to disable it.

## Data-leak blocking

`[response_inspection]` (opt-in) scans uncompressed text responses for things that
should never reach a visitor:
- SQL errors (MySQL, PostgreSQL, Oracle, SQL Server, SQLite);
- PHP, Java, Python, .NET and Node error pages and stack traces;
- directory listings;
- private keys and AWS access keys.

In prevent mode with `action = "block"`, the response is replaced by a generic 500 page;
otherwise it is passed through and logged (layer `data_leak`). Responses larger than
`max_bytes` are inspected at the start and the rest is streamed unchanged.

## Country access control

`[geo]` loads an IP-to-country CSV in the format `start_ip,end_ip,country_code`, IPv4
and IPv6. The free DB-IP "IP to Country Lite" database uses this format (CC BY 4.0,
attribution required).

- `deny_countries`: blocked.
- `challenge_countries`: challenged.
- `allow_countries`: if set, every other known country is blocked. Private and unknown
  addresses are never blocked.
- Custom rules accept `countries = [...]`.
- The decision log records each request's `country`.

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
  Applies to query, form, JSON and multipart fields, and to upload file names (`filename:<field>`).
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
| `/bans` | Active automatic and trap bans: IP, reason, seconds left |
| `POST /bans/unban?ip=…` | Lift a ban |

## Performance

`cargo run --release -p pattern-guard-gateway --example loadtest` (`crates/gateway/examples/loadtest.rs`) (4 vCPU shared by load
generator, gateway and upstream; every request fully inspected and proxied in detect mode):
**~28 000 req/s, p50 ≈ 2.2 ms, p99 ≈ 3.4 ms**, against ~200 000 req/s for the bare upstream.
WAF inspection alone costs ~17 µs for a typical request and 0.35–0.5 ms for an 8 KiB
value (`cargo bench -p pattern-guard-waf`).
The behavioural engine runs behind a single lock today; sharding it is the next
performance step.

## Limits of this version

* HTTP/1.1 only towards clients and upstream; no WebSocket upgrade passthrough yet.
* Request bodies are buffered (up to `max_body_bytes`) for inspection; responses are streamed.
* CrowdSec local API over `http://` only (it normally runs on localhost).
* Single process: reputation, clearances and ML state are per instance (set `challenge.secret`
  so clearances work across instances behind a load balancer).
