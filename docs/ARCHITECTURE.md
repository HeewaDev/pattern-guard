# Architecture

This page is the overview. For module-level detail (the exact pipeline order, fusion
tie-breaks, locks, analysers), how-to recipes and the proposed target structure, see
[architecture/](architecture/README.md).

## Components

| Component | Crate / path | What it is |
|---|---|---|
| Behavioural engine | `pattern-guard` (`crates/engine`) | Library: `ml/` (features, model), `rules/` (optional thresholds), `util/` (route templating, decayed counters), `guard.rs`, `config.rs`, `logs.rs`; re-exports the WAF as `pattern_guard::waf` |
| WAF | `pattern-guard-waf` (`crates/waf`) | Payload inspection: `decode` (normalisation, base64), `indicators` (attack signatures), `lexicon` (OWASP CRS word lists), `sql` (SQL tokenizer), `shell` (shell-command analysis), `ssrf` (URL analysis), `multipart` (part parsing, upload checks), `inspect` (request walking, scoring) |
| CLI | `pattern-guard-cli` (`crates/cli`, binary `pattern-guard`) | `replay` logs, `train` models, wrap commands |
| Gateway | `pattern-guard-gateway` (`crates/gateway`) | Reverse proxy: `proxy/`, `challenge/`, `intel/`, `observability/`; runs the engines on live traffic and enforces decisions |
| Evaluation | `pattern-guard-eval` (`tools/eval`, unpublished) | Traffic simulator, `realworld_eval`, `gen_traffic`, `waf_eval`, `crs_eval`; plus `crates/gateway/examples/loadtest.rs` |

The engine and WAF have no network or async dependencies, so they can be embedded anywhere: an
axum middleware, a CLI, a log pipeline. The gateway is one consumer of them.

## Project layout

```
crates/
  engine/    pattern-guard          behavioural engine library
             src/ml/                  streaming features, explainable model, built-in model
             src/rules/               optional threshold rules
             src/util/                route templating, decayed counters
             src/{guard,config,event,logs}.rs
  waf/       pattern-guard-waf      payload inspection: decode · indicators · lexicon (CRS lists)
                                      · sql · shell · ssrf · multipart · inspect
  cli/       pattern-guard-cli      `pattern-guard` binary: replay · train · wrap
  gateway/   pattern-guard-gateway  reverse proxy
             src/proxy/               pipeline, client IP, forwarding, responses, verify, decision log
             src/policy/              custom rules, rate limits, business operations + logins,
                                      bans + traps, protocol enforcement
             src/hardening/           security headers, data-leak blocking
             src/geo.rs               IP → country lookup and country policy
             src/challenge/           proof-of-work challenge (+ page.html)
             src/intel/               reputation store, CrowdSec bouncer, Suricata/Wazuh feeds
             src/observability/       metrics, JSON decision log, API inventory
tools/
  eval/      pattern-guard-eval     simulator + realworld_eval, gen_traffic, waf_eval, crs_eval
config/      example configs (guard.toml, gateway.toml) and demo/ configs
deploy/      Dockerfile companions (docker/gateway.toml, docker/compose.yml), systemd unit
scripts/     extract_crs_tests.py (OWASP CRS regression tests → JSONL)
docs/        documentation
```

One crate per product area, feature folders inside each crate. Dependencies point one way:
`waf` ← `engine` ← `cli`, `gateway`, `tools/eval`.

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
   ├─ custom rule `allow` ──────────────────────────────────────────► forward
   │
   ▼
0. gatekeeper policy: custom rules · country policy · protocol enforcement ·
   honeypot traps (→ immediate ban) · rate limits (→ 429) ·
   business operations: account budget (→ 429), source (→ 403), replay (→ 409) ·
   logins: account locked / credential stuffing (→ 429)
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
operations ticket.complete(status) → unique values kept after 2xx (else released),
                                     login failures / successes counted
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
                   · base64 decodings (whole value and fragments, 4 alignments)
                   · UTF-7 decoding · look-alike brackets folded (＜ « ‹ ¼ → <)
      ─► RegexSet over ~110 weighted indicators (one pass per variant)
      ─► Aho-Corasick over OWASP CRS word lists (OS files, restricted files, shell,
         PHP functions, Java classes)
      ─► SQL tokenizer: strings, numbers, keywords, functions, operators, comments;
         string / numeric breakout, whole-value SQL expressions, database functions
      ─► shell analyser: undo quotes / ${IFS} / {a,b} / [x] / empty expansions, split into
         commands, score command words by position and arguments; Windows FOR / IF
      ─► URL analyser: normalise hosts (decimal / hex / octal IPv4, IPv4-mapped IPv6,
         Unicode look-alikes), classify internal / metadata / obfuscated targets, RFI
      ─► per attack class: sum of distinct indicator weights, capped at 10
      ─► strongest class ≥ min_score → Finding {class, score, location, indicators, sample}
request ─► session-id parameter names without a same-site Referer → session_fixation
multipart body ─► parts (RFC 7578): each field inspected as `body:<name>`, JSON parts
                  walked, file names checked (server scripts, double extensions, config
                  files, session files), binary files searched only for embedded code,
                  header evasions (parser-confusing quotes, charsets, invalid names)

The indicator RegexSet is built with a 16 MiB lazy-DFA cache per thread. With the regex
crate's default 2 MiB it thrashes and falls back to the PikeVM, about 60× slower;
`crates/waf/benches/inspect_bench.rs` guards against that.
```

Locations: path, query names and values, form fields, JSON keys and values (walked
recursively), XML/text/multipart bodies, cookies, `User-Agent`, `Referer`,
`X-Forwarded-Host`, `X-Original-URL`, and every other header for JNDI and Java payloads only.

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
