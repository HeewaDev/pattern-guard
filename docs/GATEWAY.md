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
| Challenge | 403 page that solves a SHA-256 proof-of-work in the browser (~0.1–0.5 s at difficulty 16), then sets an HttpOnly, IP-bound clearance cookie for `ttl_secs`. A challenged form `POST` from your own pages (same-origin, URL-encoded) is sent again automatically once solved, so a login isn't lost; other browser POSTs return to the form page. Non-HTML clients get `{"error":"challenge_required"}` | neutral (humans aren't punished for meeting a challenge) |
| Block | 403 page / JSON with a request id | 403 (repeated attempts escalate) |

A valid clearance cookie lifts Challenge and Delay, never Block.

Precedence: an `allow` list entry or `allow` rule skips everything; otherwise the most
severe layer wins (Block > Challenge > Delay > Allow). The deciding layer appears as
`layer` in the decision log and in `pattern_guard_blocked_total{layer=...}`:
`deny_list`, `rule`, `geo`, `protocol`, `trap`, `rate_limit`, `operation`, `reputation`,
`waf`, `behaviour`, `data_leak`. Enforced blocks from any layer except `reputation` and `trap`
count towards automatic bans.

## Client IP

Every per-IP decision (access lists, rate limits, bans, reputation, the behavioural
engine, clearance cookies) uses the client IP, resolved before anything else:

- When the TCP peer is not in `client_ip.trusted_proxies`, the peer is the client.
  Whatever it writes in `X-Forwarded-For` or similar headers is ignored.
- When the peer is a trusted proxy, the client is the right-most address in
  `client_ip.header` (default `X-Forwarded-For`) that is not itself a trusted proxy.
  Every line of the header counts, in order, as if the lines were joined with commas.
  An entry that is not a bare IP address (`203.0.113.7:4711`, `unknown`) falls back to
  the peer.

List your own hops (load balancer, reverse proxy, CDN ranges) in `trusted_proxies`, and
nothing else.

Your application receives a client identity it can trust:

| Header | Value |
|---|---|
| `X-Forwarded-For` | The client, then the trusted proxies that relayed the request, ending with the gateway's peer: `203.0.113.7, 10.0.0.2, 10.0.0.1`. Entries left of the client, which the client wrote itself, are dropped. Without a trusted proxy in front, it is just the client |
| `X-Real-IP` | The client |
| `client_ip.header`, when it is not `X-Forwarded-For` (e.g. `CF-Connecting-IP`) | The client |

So the application can read the client from `X-Real-IP` or the left-most
`X-Forwarded-For` entry, as long as only the gateway can reach it. The RFC 7239
`Forwarded` header is passed on unchanged: don't let the application trust it.

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

**A `header:<name>` key is chosen by the client.** Each distinct value gets its own
bucket, and the gateway can't tell a real API key from an invented one, so a client
that sends a new value with every request is never limited. Such a limit throttles
honest clients (per-customer quotas), not attackers. Pair it with an `ip` limit on the
same route:

```toml
[[rate_limits]]
name = "API per key"
path = "/api/"
key = "header:x-api-key"
requests = 600
per_secs = 60

[[rate_limits]]
name = "API per IP"           # header values are chosen by the client
path = "/api/"
requests = 1200
per_secs = 60
```

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
| `limit` | Token bucket per account (per IP if there is no account). A token is reserved when the request arrives, so concurrent bursts are limited, and given back if the request is not forwarded (another layer stopped it) or your app answers 401 or 403 (the requester was not that account) | 429 + Retry-After `account_limit` |
| `allowed_ips` | Only these sources may call the route | 403 `source_not_allowed` |
| `unique` + `unique_ttl_secs` | A value that may be used once. It is held while its request is in flight, so concurrent duplicates (race-condition double spends) are refused, and kept as used only if your app answered 2xx, so a provider retrying after a failure still gets through | 409 `replay` |
| `action` | `block` (default), `challenge`, `delay` or `log` (record only) | |

The deciding layer is `operation`; the decision log reason names the operation, the
check and a short account hash, e.g. `operation:checkout:account_limit account=fa8c06dd`.

**Key budgets on what your application authenticates**: a session cookie or the
`Authorization` header, not a public identifier such as a user name, e-mail address or
account number in the query or body. Anyone who knows a public identifier can send
requests in that account's name. Their tokens come back only when your app answers 401
or 403, so requests it accepts, or refuses with another status (400, 422, …), still
spend the owner's budget and can lock the owner out.

**Identifiers in the body** (`form:` and `json:`, for operations and logins) are read
the way applications read them, not by the declared Content-Type alone, so an attacker
can't hide an account by switching it:
- the text is decoded first (byte-order mark, `charset`, UTF-16 / UTF-32);
- `multipart/*` bodies are read as form fields (file parts are skipped);
- URL-encoded bodies are read as form fields, then as JSON if they look like JSON;
- any other body is read as JSON when the Content-Type says JSON or the body starts
  with `{` or `[`, otherwise as form fields;
- `form:name` also matches a top-level JSON field `name`, and `json:name` (one segment)
  a form field `name`, since Laravel, Rails, Express and others merge both.

A repeated form field keeps its first value, a repeated JSON key its last. The whole
body is read, once per request and in one pass for every matching entry, without being
built in memory: only the values on the configured paths are kept.

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

`account` takes the same sources as for operations, and body fields are read the same
way, whatever the declared Content-Type (see [Business operations](#business-operations)).
User names are compared without regard to case.

**A lockout can be turned against your users.** Failures count per account from any
IP, so anyone who knows a user name can fail `max_failures` times on it and lock it
for the rest of `window_secs`. With `action = "block"`, the owner is refused too (429)
until the window ends. Keep the default `challenge` unless that is acceptable: the real
user's browser solves the proof-of-work and its login form is sent again automatically
(same-origin, URL-encoded forms), or it returns to the login page; a browser that already
holds a clearance cookie goes straight through. Scripts and API clients without a cookie
get 403 `challenge_required`.

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
  A name is excluded **wherever it appears and on every path**: in the query or body of
  any route, as a JSON key at any depth (`json.post.body` and `json.body[3]` count as
  `body`), and as a cookie or header of that name. An attacker can put a payload in a
  parameter with an excluded name on any route and the WAF won't look at it. Keep the
  list short and the names specific (`article_html`, not `text`). When only one route
  needs it, a `skip_waf` rule for that route's path confines the gap to that route,
  at the price of not inspecting its other parameters.
* Measured accuracy, including hold-out results and their limits: [FEATURES.md](FEATURES.md) §3.

## Connection-level protection

* `limits.max_connections_per_ip`: concurrent connections per client IP (trusted proxies exempt).
* `limits.max_requests_in_flight_per_ip` (default 256, 0 = unlimited): requests in
  progress (body upload, inspection, waiting for the upstream) per client IP *after*
  `client_ip.trusted_proxies` is applied; more get **429** with `Retry-After: 1`. Behind a
  CDN or load balancer every client arrives from a trusted peer, which the connection cap
  exempts, so this is the per-client bound there. Without a proxy it changes nothing: one
  HTTP/1.1 connection carries one request at a time, so 256 matches the connection cap.
  Raise it if many users share one address (an office NAT) *and* your app holds requests
  open for long (long polling). The allow list is exempt.
* `limits.header_read_timeout_secs`: clients that trickle headers (slowloris) are dropped.
* `max_body_bytes`: larger bodies get 413 before any work is done (a `Content-Length`
  over the limit is refused before the body is read).
* `limits.body_read_timeout_secs` (default 30) and `limits.body_min_bytes_per_sec`
  (default 1024): request bodies are buffered for inspection, so they must keep arriving.
  Within every 30-second period at least 30 KiB (or the rest of the body) must come in,
  otherwise the client gets **408** and the connection is closed. This stops bodies
  trickled a few bytes at a time and uploads that stop just before the last byte, each of
  which used to hold a buffer and a connection forever. The defaults never touch real
  clients: 1 KiB/s is well below a GPRS uplink, a 30-second gap is far longer than any
  live connection pauses, and a large upload over a slow link is fine as long as it keeps
  moving (the rule is per period, not a deadline for the whole body). Set
  `body_min_bytes_per_sec = 0` to cut off only stalls.
* `limits.max_buffered_body_bytes` (default 256 MiB, 0 = unlimited, never less than
  `max_body_bytes`): request-body bytes buffered at once by all requests together. Bytes
  are reserved as they arrive and released when the request ends, so a stalled upload
  holds only what it has sent. A request whose body would go over the budget gets **503**
  with `Retry-After: 1`. 256 MiB is 25 maximum-size (10 MiB) bodies arriving at the same
  moment, or tens of thousands of typical API bodies; raise it with `max_body_bytes` if
  your site takes many large uploads at once. `pattern_guard_buffered_body_bytes` shows the
  current use. Without it, 40 connections each withholding the last byte of a 10 MiB body
  held 405 MiB.

Refusals are counted in `pattern_guard_requests_rejected_total{reason="body_timeout" |
"body_budget" | "in_flight_per_ip"}` (and 413s in `pattern_guard_body_too_large_total`).
They happen before inspection, so they are not in the decision log.

Volumetric L3/L4 floods must be absorbed upstream (ISP / CDN / cloud scrubbing). No
software on your server can absorb more traffic than its uplink carries.

## Admin endpoints (`admin_listen`, keep private)

| Path | |
|---|---|
| `/metrics` | Prometheus: requests by action, blocks by layer, WAF findings by class, challenges passed/failed, feed alerts, reputation entries (and entries evicted at a cap), CrowdSec status, decision time, dropped decision-log lines |
| `/healthz` | `ok` |
| `/inventory` | API discovery: every route template seen (`GET /api/items/{n}`), with volume, block count, status codes, first/last seen. At most 10 000 routes; templates longer than 512 bytes are cut (ending in `…`); requests refused by `[protocol]` are not recorded |
| `/bans` | Active automatic and trap bans: IP (or `/64`, see below), reason, seconds left; soonest-expiring first |
| `POST /bans/unban?ip=…` | Lift a ban. A merged IPv6 ban is lifted as its `/64` (`?ip=2001:db8:1:2::/64`) |

Gateway bans are capped by `limits.max_bans` (default 100 000; the ban closest to expiry
is dropped first, counted in `pattern_guard_intel_evicted_total`). When 16 addresses of
one IPv6 `/64` are banned at the same time, they are merged into one `/64` ban that
lasts as long as the longest of them, and later bans inside it extend it: a client that
rotates through its `/64` costs one entry and is banned on addresses it hasn't used yet.
IPv4 bans are never merged (one address may be a whole carrier-grade NAT).

## Performance

`cargo run --release -p pattern-guard-gateway --example loadtest` (`crates/gateway/examples/loadtest.rs`) (4 vCPU shared by load
generator, gateway and upstream; every request fully inspected and proxied in detect mode):
**~28 000 req/s, p50 ≈ 2.2 ms, p99 ≈ 3.4 ms**, against ~200 000 req/s for the bare upstream.
WAF inspection alone costs ~17 µs for a typical request and 0.35–0.5 ms for an 8 KiB
value (`cargo bench -p pattern-guard-waf`).
The behavioural engine runs behind a single lock today; sharding it is the next
performance step.

### Memory bounds

Every table the gateway keeps per client, key or route is capped, and no entry stores an
attacker-sized value:

| Table | Cap | Per entry |
|---|---|---|
| Request bodies being buffered | `limits.max_buffered_body_bytes` in total (default 256 MiB), `max_body_bytes` each | the body bytes received so far |
| Rate-limit buckets | 200 000 (least recently used evicted) | fixed: keyed by a keyed 64-bit hash of the IP, route or header value, never the value itself |
| Reputation store: gateway bans (traps, repeat offenders) | `limits.max_bans` (default 100 000); the ban closest to expiry is dropped; IPv6 bans of one `/64` merged after 16 | ~350 bytes; 100 000 bans plus the offender history ≈ 50 MiB |
| Reputation store: each external source (every CrowdSec origin, Suricata, Wazuh) | `limits.max_intel_entries_per_source` (default 500 000); the source's entry closest to expiry is dropped, entries without expiry last | ~350 bytes (≈ 170 MiB for a full source) |
| API inventory | 10 000 routes (new routes are ignored once full) | method + template, cut at 512 bytes; `[protocol]` rejects are not recorded; `/inventory` copies the table under its lock and serialises it afterwards |
| Decision-log queue (lines waiting for the disk) | 10 000 lines and `limits.decision_log_queue_bytes` (default 16 MiB, minimum 64 KiB) | one line, a few KiB at most (see below) |

**Decision log under pressure.** The request path never waits for the disk: when the
writer is 10 000 lines or `decision_log_queue_bytes` behind (a slow, full or hung disk),
new lines are dropped and counted in `pattern_guard_decision_log_dropped_total`. Values a
client controls are truncated before they are logged, so a ~400 KB request head can't
turn into a ~400 KB line: `http.hostname` at 256 bytes, `http.url` at 8 KiB (the default
`protocol.max_url_bytes`, so URLs the defaults accept are logged whole),
`http.http_user_agent` at 1 KiB, each reason and reputation value at 512 bytes, WAF
`location` and `sample` at 256 bytes. A truncated value ends in `…`; field names don't
change. A line lists at most 16 WAF findings, the highest-scoring ones in their original
order; when more were found, `pattern_guard.waf_omitted` says how many were left out (all
of them still count in `pattern_guard_waf_findings_total`). Without this, a 31 KB cookie
of tiny XSS fragments made a 247 KB line; it now makes a 3.5 KB one.

**Reputation store under pressure.** Each source has its own cap and only ever evicts its
own entries, so a flood of trap bans from rotating addresses can't push out CrowdSec or
Suricata decisions, and the CrowdSec stream can't push out your bans. Evicting the entry
closest to expiry keeps the long, escalated bans of repeat offenders and drops the
short-lived ones first. The store keeps an expiry-ordered index per source: the
30-second sweep visits only expired entries (in batches, releasing its lock in between),
and the entry count behind `pattern_guard_intel_entries` is a counter, so a `/metrics`
scrape no longer walks the table. Ranges other than IPv6 `/64` are still matched by a
linear scan; keep CrowdSec range decisions to a few thousand.

## Limits of this version

* HTTP/1.1 only towards clients and upstream; no WebSocket upgrade passthrough yet.
* Request bodies are buffered (up to `max_body_bytes` each, `limits.max_buffered_body_bytes`
  in total) for inspection; responses are streamed.
* CrowdSec local API over `http://` only (it normally runs on localhost).
* Single process: reputation, clearances and ML state are per instance (set `challenge.secret`
  so clearances work across instances behind a load balancer).
