# Architecture

## Components

| Component | Crate / path | What it is |
|---|---|---|
| Detection engine | `pattern-guard` (`src/`) | Library: behavioural ML (`features.rs`, `model.rs`, `guard.rs`), WAF (`waf.rs`), optional threshold rules (`tracker.rs`, `analyzer.rs`), log parsing (`logs.rs`) |
| CLI | `pattern-guard` binary (`src/main.rs`) | `replay` logs, `train` models, wrap commands |
| Gateway | `pattern-guard-gateway` (`gateway/`) | Reverse proxy that runs the engine on live traffic and enforces decisions |
| Evaluation | `examples/` | Traffic simulator, `realworld_eval`, `waf_eval`, `gen_traffic`; `gateway/examples/loadtest.rs` |

The engine has no network or async dependencies, so it can be embedded anywhere: an axum
middleware, a CLI, a log pipeline. The gateway is one consumer of it.

## Request lifecycle (gateway)

```
TCP accept ── per-IP connection cap ── header-read timeout (slowloris)
   │
   ▼
parse request ── /.pattern-guard/verify? ──► challenge verification ──► 302 + cookie
   │
   ▼
client IP  (peer, or right-most untrusted X-Forwarded-For entry if the peer is a trusted proxy)
   │
   ▼
buffer body (≤ max_body_bytes, else 413)
   │
   ├─ IP on allow list ─────────────────────────────────────────────► forward
   │
   ▼
1. behavioural ML    guard.assess(event)          → risk, bot score, Allow/Warn/Delay/Challenge/Block
2. WAF               waf.inspect(request)          → findings per location, score 0–10
3. reputation        intel.lookup(ip)              → CrowdSec / Suricata / Wazuh entry
4. IP lists          deny / challenge
   │
   ▼
fuse: most severe wins (Block > Challenge > Delay > Allow)
      challenge disabled → Block;  valid clearance cookie lifts Challenge/Delay
   │
   ├─ detect mode ──► log "would-mitigate", forward
   ├─ Block ────────► 403, observe_response(403)
   ├─ Challenge ────► proof-of-work page / JSON (neutral for the ML)
   ├─ Delay ────────► sleep ≤ delay_max_secs, forward
   ▼
forward to upstream (hop-by-hop headers stripped, X-Forwarded-For / X-Real-IP set,
                     x-pattern-guard-bot-score / -risk / -request-id added)
   │
   ▼
observe_response(status) → ML learns failures (401/403/404/429…)
inventory.record(route template, status) · metrics · decision log
```

The ML is assessed for **every** request, including those another layer blocks, so an
attacker's behavioural history builds up even while the WAF stops their payloads.

## Behavioural engine internals

```
Event ─► normalize path (/product/123 → /product/{n}, id=123)
      ─► FeatureEngine: update + read decayed state for
            actor   (LRU, max_actors)         burst, volume, failures, route mix, ids, pacing
            subnet  (LRU, max_subnets)        new-client churn, failures
            client  (LRU, max_fingerprints)   fingerprint/UA failures, new-IP share, route share
            route   (LRU, max_routes)         asymmetric baselines: rate, failure ratio, arrivals
      ─► 28 features ─► Model (logistic, TOML) ─► risk, contributions → reasons
      ─► optional rules (sliding window per actor, O(1) incremental counts)
      ─► cooldown after N blocks ─► Decision
```

* **Memory is bounded.** Every table is an LRU with a cap, and every counter is a
  16-byte exponentially decayed value. Nothing grows with traffic volume.
* **Time.** The library defaults to event time (monotonised), so logs replay exactly as
  they happened live. The gateway passes server time.
* **Explainability.** Each feature's contribution in log-odds is kept, and the top three
  are returned as reasons.
* **Training/serving parity.** Features never depend on the model's own decisions, so
  `pattern-guard train` sees exactly what production sees.

## WAF internals

```
value ─► decode ×≤4 (URL, %uXXXX, HTML entities, \uXXXX/\xHH) ─► lowercase, collapse whitespace
      ─► variants: SQL comments removed · comments → space · Log4j lookups resolved
      ─► RegexSet over ~70 weighted indicators (one pass per variant)
      ─► per attack class: sum of distinct indicator weights, capped at 10
      ─► strongest class ≥ min_score → Finding {class, score, location, indicators, sample}
```

Locations: path, query names and values, form fields, JSON keys and values (walked
recursively), XML/text/multipart bodies, cookies, `User-Agent`, `Referer`,
`X-Forwarded-Host`, `X-Original-URL`, and every other header for JNDI only.

## Concurrency and state (gateway)

| State | Type | Contention |
|---|---|---|
| Behavioural engine | `Guard` (one `Mutex` inside) | the main serialisation point, ~2 µs held per request; sharding is planned |
| WAF | `Inspector` (immutable, compiled once) | none |
| Reputation | `IntelStore` (`RwLock`) | reads on every request, writes from CrowdSec/feeds |
| Metrics | atomics + small mutex maps | negligible |
| Inventory | `Mutex<HashMap>` (≤ 10 000 routes) | short critical section |
| Decision log | bounded mpsc channel → writer task | never blocks requests; drops lines if the disk falls behind |

Runtime: tokio multi-threaded; hyper 1 HTTP/1.1 server and pooled client.

## Security model of the gateway itself

* **Fail behaviour:**
  - If the upstream fails, the gateway returns 502/504.
  - If the gateway process dies, traffic stops (fail-closed). Run it under a supervisor
    (systemd `Restart=always`), with load-balancer health checks on `/healthz`.
* **Trust boundaries:**
  - Only `client_ip.trusted_proxies` may set the client-IP header.
  - Incoming `x-pattern-guard-*` headers are stripped, so clients can't forge scores
    towards your app.
  - Challenge return paths only accept same-site relative paths, so they can't be used
    as open redirects. They are JSON-escaped with `<`, `>` and `&` encoded, so they can't
    break out of the page's script.
* **Secrets:**
  - The challenge HMAC key comes from config, or is random per process.
  - The CrowdSec key should come from an environment variable (`api_key_env`).
  - Clearance cookies are HttpOnly, SameSite=Lax, bound to the client IP and to an
    expiry.
* **Admin port:** `/metrics`, `/healthz` and `/inventory` are unauthenticated. Bind them
  to loopback or a private network.
* **Resource limits:**
  - Body size is limited.
  - Each WAF value is truncated (8 KiB), and only the first `inspect_body_bytes` of the
    body are inspected.
  - JSON walking stops at depth 32 and 1 000 items per level.
  - Every engine table has an LRU cap.
