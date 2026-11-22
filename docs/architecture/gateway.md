# Gateway internals (`crates/gateway`)

The gateway is the only component that does I/O. It accepts connections, runs every
layer on each request, fuses the results into one action, enforces it (or only logs it,
in detect mode), forwards the request to the upstream, and feeds the outcome back to the
learning layers.

## Module map

| Path | Responsibility |
|---|---|
| `main.rs` | Arguments (`--config`, `--check`), loads the config, calls `run` |
| `lib.rs` | `build_state` (compiles everything once), `start_background` (tasks), `run`; re-exports `serve` |
| `server.rs` | `serve`: accept loop, per-IP connection cap (`ConnGuard`), header-read timeout, one task per connection |
| `admin.rs` | Admin server: `/metrics`, `/healthz`, `/inventory`, `/bans`, `POST /bans/unban` |
| `util.rs` | `now_secs`, `header_str`, `form_decode` (exact one-pass form decoding) |
| `state.rs` | `State`: everything shared between requests, behind one `Arc` |
| `config.rs` | `GatewayConfig` and every section (serde, `deny_unknown_fields`), defaults, `validate()` |
| `proxy/mod.rs` | `handle`: the request pipeline and enforcement |
| `proxy/verdict.rs` | Fusion: `Action`, `Layer` (the logged layer names), `Signal`, `Respond`, `Verdict` |
| `proxy/client_ip.rs` | Real client IP behind trusted proxies |
| `proxy/forward.rs` | Upstream request (header hygiene, timeout), response headers, response leak inspection |
| `proxy/verify.rs` | `/.pattern-guard/verify`: checks a proof-of-work solution, sets the clearance cookie |
| `proxy/responses.rs` | Block page, 429 with `Retry-After`, error responses, header helpers |
| `proxy/decision_log.rs` | Decision-log JSON line and the rate-limited console line |
| `policy/path.rs` | `PathView`: raw and canonical path; protections match either, exemptions need both |
| `policy/rules.rs` | `[[rules]]`: ordered custom rules (allow / block / challenge / delay / log / skip_waf) |
| `policy/rate_limit.rs` | `[[rate_limits]]`: token buckets per IP, IP + route, or header value |
| `policy/operations.rs` | `[[operations]]` and `[[logins]]`: per-account budgets, allowed sources, replay protection, login failure tracking |
| `policy/bans.rs` | `[bans]` escalating bans for repeat offenders, `[traps]` honeypot paths |
| `policy/protocol.rs` | `[protocol]`: methods, sizes, NUL bytes, `Host`, restricted extensions |
| `geo.rs` | IP-to-country CSV (`GeoDb`, binary search over ranges) and `[geo]` country policy |
| `challenge/` | `Challenger`: issues and verifies proof-of-work, signs and checks clearance cookies, renders `page.html` |
| `intel/store.rs` | `IntelStore`: ban / challenge entries per IP or CIDR from any source |
| `intel/crowdsec.rs` | CrowdSec LAPI stream bouncer |
| `intel/feeds.rs` | Tails Suricata EVE and Wazuh alert files |
| `hardening/headers.rs` | Security headers added to responses, fingerprinting headers removed |
| `hardening/leaks.rs` | Response signatures: SQL / PHP / Java / Python / .NET / Node errors, directory listings, private keys, AWS keys |
| `observability/metrics.rs` | Prometheus text exposition (atomics plus small mutex maps) |
| `observability/eventlog.rs` | Async JSON-lines writer (bounded channel → file) |
| `observability/inventory.rs` | API inventory: route templates with request, block and status counts |
| `ipnet.rs` | `Cidr` parsing and matching, IPv4-mapped IPv6 normalisation |

## Process and tasks

```
main ─► GatewayConfig::load ─► validate
     └► run ─► bind listen + admin_listen
            ├► build_state            compile rules / limits / operations, load guard.toml + model,
            │                         load GeoDb, build Inspector, Challenger, HTTP client
            ├► start_background
            │    ├─ crowdsec::run       every poll_secs: GET /v1/decisions/stream (startup=true first)
            │    ├─ feeds::run ×N       every 1 s: read new lines of each alert file (≤ 8 MiB per read)
            │    ├─ intel sweeper       every 30 s: drop expired entries
            │    └─ serve_admin         /metrics /healthz /inventory /bans /bans/unban
            ├► EventLog writer        (spawned by build_state when log.decisions is set)
            └► serve (accept loop) ──► one task per connection ──► hyper http1 ──► proxy::handle
     until Ctrl-C (no connection draining yet; see target.md)
```

`--check` runs `build_state` with the decision log disabled, so validating a config never
creates files. Every config error (bad regex, bad CIDR, missing GeoDb for country rules,
CrowdSec without a key) is found at startup, never at request time.

## Connection layer (`server.rs::serve`)

- **Per-IP connection cap** (`limits.max_connections_per_ip`, default 256) on the *peer*
  address. Trusted proxies are exempt, because every client arrives through them. The count is held by
  a `ConnGuard` (RAII) in `State.conns: Mutex<HashMap<IpAddr, u32>>`. Over the cap,
  the socket is dropped without a response.
- **Header read timeout** (`limits.header_read_timeout_secs`, default 10) against
  slowloris. Keep-alive is on.
- Accept errors are logged and retried after 50 ms. The loop never exits on its own.

## The request pipeline (`proxy/mod.rs::handle`)

The stages below are in code order.

| # | Stage | Detail |
|---|---|---|
| 1 | Request id | `hex(unix_secs)-hex(counter)`. Returned on block pages and forwarded as `x-pattern-guard-request-id` |
| 2 | Client IP | `client_ip`: the peer, or, when the peer is in `trusted_proxies`, the right-most entry in `client_ip.header` that is not itself trusted. An unparsable entry falls back to the peer |
| 3 | Verify path | A request to `/.pattern-guard/verify?...` (any method) goes to `verify` **before anything else**: no body read, no layers, not even the deny list. A clearance never lifts a Block, so a banned client gains nothing here |
| 4 | Body | Buffered up to `max_body_bytes` (default 10 MiB) with `http_body_util::Limited`. Over the limit → **413** |
| 5 | Allow list | `access.allow` → forward immediately: no ML, WAF, operations or logging |
| 6 | Rules | Country lookup (if a GeoDb is loaded), then `rules.evaluate`. The first terminal rule wins, `log` rules accumulate, `skip_waf` sets a flag. A terminal `allow` → forward immediately |
| 7 | Gatekeeper checks | `rate_limiter.check`, `operations.check` (returns a hit and a **ticket**), `protocol.check`, `bans.trap`. A trap hit calls `bans.ban_now` straight away |
| 8 | Behavioural ML | `guard.assess(event)` with actor `ip:<addr>`, method, path + query, server time, IP, UA and fingerprint header. **This runs on every request from here on**, including ones blocked below |
| 9 | WAF | Unless `waf.enabled = false`, a `skip_waf` rule, or an `exclude_paths` prefix: `waf.inspect` over path, query, headers, cookies and the first `inspect_body_bytes` (64 KiB) of the body. Findings below `log_score` (4) or on an `exclude_params` name are dropped |
| 10 | Reputation | `intel.lookup(ip)` (the strongest live entry) and `access.deny` |
| 11 | Fuse | See [Fusion](#fusion) |
| 12 | Adjust | Challenge with `challenge.enabled = false` → Block. A valid clearance cookie turns Challenge or Delay (never Block) into Allow |
| 13 | Account | Metrics (`requests`, per-action counters, `blocked_by{layer}`, `would_mitigate`). In prevent mode, a Block not caused by `reputation` or `trap` counts towards an escalating ban |
| 14 | Enforce | Prevent mode only. See [Enforcement](#enforcement) |
| 15 | Forward | `forward` (see [Forwarding](#forwarding)) |
| 16 | Settle | `op_ticket.complete(status)`, `guard.observe_response(status)`, `inventory.record`, decision log |

A request is logged when it was mitigated or would have been, had WAF findings, matched a
`log` rule, leaked data, or when `log.include_allowed` is on.

### Fusion

Fusion lives in `proxy/verdict.rs` (`Action`, `Layer`, `Signal`, `Respond`, `Verdict`, with
unit tests for every rule). Each layer that fires calls `verdict.raise(Signal::new(action, layer,
reason))`, optionally with `.respond(...)` to say how an enforced block answers. The highest action
wins. On a tie, the **first** layer raised keeps the attribution, because `raise` only replaces on a strictly
higher action. Every reason is kept in the log, whichever layer won. The raise order, which is
therefore the tie-break order, is:

| Order | Layer | Can raise | Reason format |
|---|---|---|---|
| 1 | `deny_list` | Block | `deny_list` |
| 2 | `protocol` | Block | `protocol:<reason>` |
| 3 | `trap` | Block | `trap:<prefix>` |
| 4 | `rule` (terminal) | Block, Challenge, Delay | `rule:<name>` |
| 5 | `geo` | Block, Challenge | `geo:<CC>` |
| 6 | `rate_limit` | Block, Challenge, Delay | `rate_limit:<name>` |
| 7 | `operation` | Block, Challenge, Delay, Allow (log) | `operation:<name>:<kind> account=<hash>` |
| 8 | `rule` (log) | Allow | `rule-log:<name>` |
| 9 | `challenge_list` | Challenge | `challenge_list` |
| 10 | `reputation` | Block (ban), Challenge | `<source>: <reason>` |
| 11 | `waf` | Block when top score ≥ `block_score` (7) | `waf:<class> at <location> (score N)` |
| 12 | `behaviour` | Block, Challenge, Delay | `ml:<reason>,<reason>,…` |

The engine's `Warn` maps to Allow. The `data_leak` layer is raised later, on the response.

### Enforcement

| Action | Prevent mode | ML feedback |
|---|---|---|
| **Block** | Status from the winning layer: `rate_limit` → **429** + `Retry-After`; `protocol` → 405 / 414 / 431 / 400 / 403; `operation` → its status (429 + `Retry-After`, 409 replay, 403 source / account); anything else → **403** block page (HTML or JSON by `Accept`) | `observe_response(status)` |
| **Challenge** | **403** with the proof-of-work page for `GET` with `Accept: text/html`, otherwise JSON `{"error":"challenge_required"}` | *none*: deliberately neutral |
| **Delay** | Sleep `min(engine delay or delay_max_secs, delay_max_secs)`, then forward | the upstream status |
| **Allow** | Forward | the upstream status |

**Detect mode** computes everything, logs `would-mitigate`, and forwards every request.
Side effects that remain in detect mode: trap hits still create ban entries (they appear
in `/bans` and as `reputation` reasons, but are not enforced). Repeat-offender bans and
leak blocking happen only in prevent mode.

### Forwarding (`proxy/forward.rs`)

Request to the upstream:
1. URI rebuilt from `upstream` + the original path and query. A bad target → 400.
2. Hop-by-hop headers removed (`Connection`, plus every header that `Connection` lists, `TE`, `Upgrade`, …).
3. Every incoming `x-pattern-guard-*` header removed, so clients can't forge scores.
4. `X-Forwarded-For` appended with the client IP. `X-Real-IP` set. `Host` rewritten
   to the upstream unless `preserve_host`.
5. With `forward_scores`: `x-pattern-guard-request-id`, `-bot-score`, `-risk`.
6. Pooled hyper client (idle timeout 60 s), `upstream_timeout_secs` (default 30). On timeout → **504**,
   on error → **502**, and `upstream_errors` is counted.

Response from the upstream:
1. Hop-by-hop headers removed. Security headers applied (`hardening/headers.rs`).
2. Leak inspection, if enabled and the response is uncompressed text of a configured content
   type. Up to `max_bytes` is buffered and scanned with a `RegexSet`. In prevent mode with
   `action = "block"`, the response is replaced by a neutral **500** page. Otherwise the buffered
   prefix is re-joined with the rest of the stream (`Rejoin`), so large responses still stream.

## Threat intelligence (`intel/`)

```
CrowdSec LAPI ──stream──┐
Suricata EVE  ──tail────┼──► IntelStore ◄── bans (source "gateway:ban")
Wazuh alerts  ──tail────┘     │
                              └── lookup(ip) per request: strongest live entry (Ban > Challenge)
```

- **Model.** Single IPs live in a `HashMap<IpAddr, Vec<IntelEntry>>`. Ranges live in a
  `Vec<(Cidr, IntelEntry)>`, which is **scanned linearly** on every lookup. Each entry has
  `source`, `reason`, `action` and an optional expiry. Adding an entry replaces the same
  source's entry for that IP or range, so sources never overwrite each other.
- **CrowdSec.** The first poll uses `startup=true` and replaces all `crowdsec*` entries. Later
  polls apply `new` and `deleted` decisions. `ban` → Ban, `captcha` → Challenge. Durations
  use Go syntax (`4h0m0s`), capped at a year. `crowdsec_ok` in metrics reflects the last poll.
- **Feeds.** The tailer starts at the end of the file (no history replay), copes with rotation and truncation,
  and keeps partial lines between reads. Suricata: `event_type = alert`, `severity ≤
  min_severity` (default 2), attacker = `dest_ip` for `to_client` traffic. Every hit becomes an
  entry expiring after `block_secs`.
- **Bans** are intel entries with source `gateway:ban`. `/bans` lists them and `POST
  /bans/unban?ip=` removes them. Escalation: `ban_secs × escalation^previous_bans`, capped at
  `max_ban_secs`. Offender history is kept in an LRU of 100 000 IPs.

## Proof-of-work challenge (`challenge/`)

```
gateway                                         browser
  │  403 page: nonce, expires(+300 s), difficulty, sig = HMAC(k, "c|ip|nonce|expires|difficulty")
  │ ─────────────────────────────────────────────►
  │                       find counter: SHA-256("nonce:counter") has ≥ difficulty leading zero bits
  │  GET /.pattern-guard/verify?n=&e=&d=&s=&c=&r=
  │ ◄─────────────────────────────────────────────
  │  check: not expired, d ≥ configured, sig valid for this IP, hash meets difficulty
  │  302 Location: safe_return(r)
  │  Set-Cookie: pg_clearance=<exp>.<HMAC(k, "k|ip|exp")>; HttpOnly; SameSite=Lax; Max-Age=ttl
  │ ─────────────────────────────────────────────►
```

- The key comes from `challenge.secret` (≥ 32 hex characters), or is random per process. With a random
  key, clearances don't survive a restart and aren't valid across instances.
- `safe_return` accepts only same-site relative paths (no `//`, `/\` or CR/LF). On the
  page, the path is a JSON string with `<`, `>` and `&` escaped.
- Stateless: nothing is stored per challenge. Replaying a solved challenge within its
  5-minute TTL just issues another cookie for the same IP.

## Business operations and logins (`policy/operations.rs`)

`operations.check` runs before the upstream is called and returns `(Option<OpHit>,
Ticket)`. The ticket carries what can only be settled once the upstream's status is known:

| Check | Kind | Status | Settled by the ticket |
|---|---|---|---|
| Source not in `allowed_ips` | `source_not_allowed` | 403 | — |
| `require_account` without the identifier | `account_missing` | 403 | — |
| Account token bucket empty | `account_limit` | 429 + Retry-After | — |
| `unique` value already used or in flight | `replay` | 409 | marked in flight now; **kept** after a 2xx, **released** otherwise; released on `Drop` if never forwarded |
| Account over `max_failures` | `account_locked` | 429 + Retry-After (rest of the window) | failure statuses count per account; a 2xx resets it |
| IP over `max_accounts_per_ip` failing accounts | `credential_stuffing` | 429 + Retry-After | failing accounts per IP within `window_secs`; an account already tried is still allowed |

Identifiers (`header:`, `cookie:`, `query:`, `form:`, `json:<dotted.path>`) are hashed
with SHA-256, keeping 64 bits. Caches hold at most 200 000 entries, and 256 accounts per IP.

## Shared state and concurrency

`State` is built once and shared as `Arc<State>`. Nothing in it is replaced while the
process runs. A request that reaches the fuse takes these locks:

| State | Type | Taken per request | Notes |
|---|---|---|---|
| `guard` (engine) | one `Mutex` inside `Guard` | 2× (`assess`, `observe_response`) | **the main serialisation point**; ~2 µs held |
| `rate_limiter.buckets` | `Mutex<LruCache>` (200 000) | 1× if any limit is configured | all limits are checked under one lock |
| `operations` caches | several `Mutex<LruCache>` | only on matching routes | settled again in `Ticket::complete` |
| `bans.offenders` | `Mutex<LruCache>` (100 000) | on a Block in prevent mode | |
| `intel` | `RwLock` | 1 read | the range list is a linear scan |
| `conns` | `Mutex<HashMap>` | per connection, not per request | |
| `inventory` | `Mutex<HashMap>` (≤ 10 000 routes) | 1× | |
| `metrics` | atomics + 3 small `Mutex<HashMap>` | WAF classes, `blocked_by`, feeds | |
| decision log | `mpsc` (10 000) | `try_send`, never blocks | lines are dropped if the writer falls behind |
| `waf` (`Inspector`) | immutable | none | the `RegexSet` lazy DFA cache is per thread |

Runtime: tokio multi-threaded, hyper 1 HTTP/1.1 server and pooled client. WAF inspection
costs ~17–20 µs per typical request. The whole gateway was measured at ~28 000 requests per second, p99 ≈ 3.4 ms,
on 4 vCPUs shared with the client and the upstream (`examples/loadtest.rs`).

## Observability

**Decision log** (`log.decisions`, JSON lines, EVE/ECS-like):

```json
{"timestamp":"…","event_type":"alert","src_ip":"…","srcip":"…","peer_ip":"…",
 "http":{"hostname":"…","url":"/login?…","http_method":"POST","http_user_agent":"…","status":403},
 "pattern_guard":{"request_id":"…","action":"block","layer":"waf","enforced":true,"mode":"prevent",
   "risk":0.12,"bot_score":87,"reasons":["waf:sqli at query:id (score 9.0)"],
   "waf":[{"class":"sqli","score":9.0,"location":"query:id","indicators":["…"],"sample":"…"}],
   "country":null,"reputation":null}}
```

`event_type` is `alert` when the request was mitigated or had findings, and `http` otherwise. `src_ip` and
`srcip` are both present for Suricata-style and Wazuh-style consumers. These fields are a
public contract.

**Metrics** (`/metrics`): per-action counters, `would_mitigate`, challenges passed and failed,
upstream errors, bodies too large, rejected connections, CrowdSec health, WAF hits per class, blocks per
layer, feed hits, intel entries, and the summed decision time.

**Inventory** (`/inventory`): one entry per `METHOD /template` (at most 10 000): first and last
seen, requests, blocked, up to 16 status codes.

**Console**: at most one mitigation line per second, followed by a count of suppressed lines.

## Admin server

`admin_listen` (default `127.0.0.1:9901`) serves `/metrics`, `/healthz`, `/inventory`, `/bans`
and `POST /bans/unban?ip=`. It has **no authentication**, so bind it to loopback or a private
network.

## Failure modes

| Failure | Behaviour |
|---|---|
| Upstream down or slow | 502 / 504, `upstream_errors`; the ML still sees the request |
| Gateway process dies | Traffic stops (fail-closed). Run it under a supervisor with `/healthz` checks |
| CrowdSec unreachable | Last known decisions stay until they expire; `crowdsec_ok = 0` |
| Feed file missing or rotated | Retried every second; restarts at offset 0 after a rotation |
| Decision-log disk full or slow | Lines dropped; requests unaffected |
| A lock poisoned by a panic | Recovered (`PoisonError::into_inner`); the request path keeps working |
| Memory pressure from many clients | Every table is capped; the oldest entries are evicted first |
| Restart | All learned state is lost: baselines, bans, rate buckets, clearances (with a random key) |
