# Target architecture and file structure

> **Status: proposal (2026-11).** Nothing on this page is implemented yet. It records where
> the structure should go and in which order. Each step below is meant to be one
> behaviour-preserving commit.

## Verdict on the current structure

The foundations are right and should stay:

- **One crate per product area, with one-way dependencies.** The WAF and the engine are
  synchronous, I/O-free and embeddable, and the gateway is one consumer of them.
- **Feature folders** inside each crate (`ml/`, `rules/`, `policy/`, `intel/`, …).
- **Bounded state, explained decisions, measured detection.**

The pressure points are exactly where the roadmap adds the most code:

| Roadmap | Adds | Strains |
|---|---|---|
| M2 WAF 2.0 | paranoia levels, an anomaly score, exclusions per indicator × target, learned value types per parameter, HTML/JS context parsing | WAF internals: locations are strings, analysers are wired in by hand, a 684-line indicator table |
| M3 hardening | sharding, hot reload, persistence, `ext_authz` / `auth_request` endpoint, graceful shutdown | `State` (config and learned state mixed), the request function (decision and forwarding fused), the engine's single lock |
| M4 / M5 | schema enforcement, BOLA signals, verified bots, more layers | the request function: each new layer touches 3–5 places |
| M1 / M7 | fuzzing, CI gates, licence hygiene, security policy | repository infrastructure that doesn't exist yet |

The goal is to fix those pressure points before the milestones land, without
churning what works.

## Findings

| # | Finding | Why it matters |
|---|---|---|
| F1 | `proxy::handle` is one ~440-line function that collects evidence, fuses, enforces, forwards and logs | Adding a layer means edits in 3–5 places. The tie-break order is implicit in the order of `raise` calls. Fusion can only be tested end-to-end over TCP. `ext_authz` (M3) needs "decide without forwarding", which this shape doesn't allow |
| F2 | Stringly-typed identities. The layer is a `&'static str` compared by literal (`layer == "rate_limit"`, `matches!(layer, "reputation" \| "trap")`). WAF locations are `String`s that the gateway parses back (`param_name`). Analyser applicability is decided by string comparison (`location != "path"`, `"header:referer"`) | Typos compile. M2 exclusions ("indicator X off for parameter Y") and per-parameter learning need structured locations |
| F3 | `State` is a flat struct of 27 public fields. Config-derived, rebuildable data (compiled rules, limits, lists) is mixed with learned state (guard, buckets, bans, intel). `RateLimiter` and `Operations` each hold both their definitions and their caches | Hot reload has to rebuild the first kind and keep the second; persistence must snapshot only the second. Neither is possible without a split |
| F4 | `pattern-guard` (behaviour) depends on `pattern-guard-waf` only to re-export it | Embedders who only want behaviour compile regex, aho-corasick and the CRS lists, and two independent products are coupled |
| F5 | `config.rs` is 860 lines for every section. Validation is split between `validate()` and each module's `compile()` | It is hard to see a section's schema next to its rules |
| F6 | `lib.rs` mixes the public API with the accept loop, the connection cap and the admin server | It will grow with graceful shutdown (M3) and an admin UI (M6) |
| F7 | Helpers in odd places: two gateway percent-decoders (`operations::url_decode`, `verify::percent_decode_simple`); `now_secs` lives in `challenge` but is used by observability; `header_str` lives in `proxy::responses` but is used across modules | Small, but it invites a third copy. (The WAF's multi-pass decoder is intentionally different. Don't merge it with these) |
| F8 | `IntelStore::lookup` scans every CIDR range linearly, under an `RwLock`, on every request | Cost grows with CrowdSec range lists. M3 already plans lock-free reads |
| F9 | `tests/e2e.rs` is one 971-line file with the harness inside | Slower to navigate; the harness can't be reused by new test files |
| F10 | No fuzz targets, no dependency or licence audit, CI on the MSRV only, evaluation data not reproducible (no pinned fetch), no `SECURITY.md` | All four are expected of a security product, and M1 and M7 require them |
| F11 | Small drift: the gateway crate is `0.1.0` while the workspace is `0.3.0`; `tests/corpus.rs` says `--test waf_corpus` (the target is `corpus`); the doc comment on `Finding::location` says `json:user.name` (the code emits `json.user.name`) | Confusing for users and contributors |

## Target crate graph

```
   pattern-guard-waf        pattern-guard (engine)
        ▲     ▲                ▲      ▲
        │     └──────┐  ┌──────┘      │
        │        gateway             cli
        └──────── tools/eval ─────────┘
```

The engine keeps `pub use pattern_guard_waf as waf` behind a **default-on cargo feature
`waf`**, so existing code still compiles. The gateway and the eval tools depend on
`pattern-guard-waf` directly. **Don't split the gateway into more crates yet.** One
maintainer and one binary are served well by module boundaries. Revisit only if the decision
pipeline must ship without the proxy (for example, an `ext_authz` server as a separate binary).

## Target: gateway

### The pipeline as data

```rust
/// Today's log strings, unchanged: `as_str()` is a public contract.
pub enum Layer { DenyList, Protocol, Trap, Rule, Geo, RateLimit, Operation,
                 ChallengeList, Reputation, Waf, Behaviour, DataLeak }

pub enum Respond { Default, Status(StatusCode, String), TooMany { retry_after: u64 } }

pub struct Signal { pub action: Action, pub layer: Layer, pub reason: String, pub respond: Respond }

#[derive(Default)]
pub struct Verdict { signals: Vec<Signal>, winner: Option<usize> }

impl Verdict {
    /// Same rule as today: a strictly higher action replaces the winner, so on a tie
    /// the earlier signal keeps the attribution. Every reason is kept.
    pub fn raise(&mut self, s: Signal) { … }
    pub fn action(&self) -> Action { … }
}
```

`handle` becomes glue:

```
ctx      = RequestCtx::read(state, peer, req)        // id, client ip, parts, body, country, template
shortcut = verify path · 413 · allow list · allow rule    → respond early
verdict  = pipeline::decide(state, &ctx)              // every layer, in LAYER_ORDER → Verdict + Ticket + Assessment
verdict.finalise(challenge_enabled, clearance)
response = enforce(verdict)  or  forward(...)          // the status comes from the winning Signal's `respond`
settle(ticket, status) · observe_response · inventory · log
```

What this buys:
- **Fusion and tie-breaks become unit tests** (a table of signal combinations → action, layer, status),
  with no TCP involved.
- **A new layer is one function and one `Layer` variant.** Its status code travels in its
  `Signal`, so enforcement needs no new special cases.
- **`pipeline::decide` can serve an `ext_authz` / `auth_request` endpoint** (M3) as it is.
- A trait-object plugin system is *not* needed. The order of layers has meaning, and static
  functions are simpler and faster.

### State split

```rust
pub struct State {
    pub compiled: Swap<Compiled>,  // from config, rebuilt on reload: rules, limit and operation definitions,
                                   // protocol, geo policy, lists, security headers, leak signatures, upstream
    pub learned: Learned,          // kept across reloads, snapshotted for persistence: guard, intel, bans,
                                   // rate buckets, operation and login caches, inventory
    pub runtime: Runtime,          // process-wide: HTTP client, metrics, event log, connection counts,
                                   // request counter, challenger
}
```

`Swap` is either `arc_swap::ArcSwap` (lock-free, but a new dependency that needs a decision) or
`RwLock<Arc<Compiled>>` (clone the `Arc` once per request). `RateLimiter` splits into
`Limits` (compiled) and `Buckets` (learned). `Operations` splits the same way, with logins in their own file.

### File structure

```
crates/gateway/src/
  main.rs
  lib.rs                 public API only: build_state, run, module list
  server.rs              accept loop, per-IP connection cap, graceful shutdown (M3)
  admin.rs               admin endpoints
  state.rs               State { compiled, learned, runtime }
  util.rs                now_secs, header_str, gateway percent-decoding
  config/
    mod.rs               GatewayConfig, load (relative paths), validate (calls each section)
    core.rs              listen, upstream, mode, limits, client_ip, log
    waf.rs  policy.rs  intel.rs  hardening.rs  geo.rs  challenge.rs   (each section with its validation)
  pipeline/              decides; no sockets
    mod.rs               decide(state, ctx) -> (Verdict, Ticket, Assessment)
    context.rs           RequestCtx
    verdict.rs           Action, Layer, Signal, Respond, Verdict, LAYER_ORDER   + fusion tests
    layers.rs            one fn per layer: rules, geo, protocol, traps, rate limits, operations,
                         logins, behaviour, waf, reputation
  proxy/                 HTTP glue
    mod.rs               handle = context → decide → enforce / forward → settle
    enforce.rs           Verdict → Response
    forward.rs  client_ip.rs  verify.rs  responses.rs  decision_log.rs
  policy/
    rules.rs  rate_limit.rs  operations.rs  logins.rs  fields.rs (shared header / cookie / query / form / json extraction)
    bans.rs  protocol.rs  geo.rs (moved from src/)
  net/ipnet.rs           Cidr, normalisation (+ a prefix structure for intel ranges, F8)
  challenge/  intel/  hardening/  observability/    unchanged
tests/e2e/
  main.rs                mod common; mod waf; mod policy; …   (one test binary, fast to link)
  common/mod.rs          start_upstream, start_crowdsec, start_gateway, send
  waf.rs  policy.rs  challenge.rs  intel.rs  hardening.rs  admin.rs
```

## Target: WAF

### Structured locations

```rust
pub enum Location {
    Path, QueryName, Query(String), BodyName, Body(String), RawBody,
    Json(String), JsonKey(String), Cookie(String), Header(String),
    Filename(String), Multipart, ParamName(String),
}
impl Location {
    pub fn param(&self) -> Option<&str>;   // replaces the gateway's param_name()
    fn kind(&self) -> Kind;                // drives which analysers run (no string compares)
}
impl Display for Location { … }           // emits exactly today's strings, so logs don't change
```

`Finding.location` becomes a `Location`. That is an API change for direct users of
`pattern-guard-waf`: a minor bump while on 0.x, with a CHANGELOG entry. The log output stays
byte-identical. This is the foundation for M2 exclusions (indicator × location) and
per-parameter learning.

### File structure

```
crates/waf/src/
  lib.rs
  inspector.rs           Inspector, HttpRequest, Inspection, Finding (the public surface)
  location.rs            Location, Kind, where each analyser applies
  scoring.rs             per-class accumulation, caps, min_score   (→ paranoia levels, anomaly score: M2)
  normalize/
    decode.rs            URL / %u / entities / JS escapes
    variants.rs          comments, Log4j lookups, UTF-7, base64, look-alikes
  signatures/
    mod.rs               RegexSet build (16 MiB DFA cache), PATH_EXEMPT, the jndi_only map
    sqli.rs  xss.rs  traversal.rs  rce.rs  ssrf.rs  java.rs  php.rs  …   (today's table, split by class)
    lexicon.rs           CRS lists
  analyzers/
    sql.rs  shell.rs  url.rs (today's ssrf.rs)       (+ html_context.rs, libinjection adapter: M2)
  request/
    walk.rs              path, query, headers, cookies, body dispatch
    json.rs  multipart.rs (parser + upload checks)  session.rs
  data/crs/              unchanged
```

Splitting the 684-line indicator table by class maps it onto the CRS categories (930–944) and
keeps reviews of detection changes small.

## Target: engine

The structure stays. Two changes:
- The **`waf` feature** for the re-export (F4).
- **Lock scope**, before sharding: keep the shared tables (route, subnet, client) apart from the actor
  state, so the M3 sharding options in [engine.md](engine.md#concurrency) can be tried one by one.
  Measure every option with `realworld_eval` (detection) and `check_bench` / `loadtest`
  (throughput).

## Target: repository

```
.github/workflows/rust.yml    + job on stable  + cargo-deny  + cargo doc -D warnings
.github/workflows/fuzz.yml    scheduled fuzzing (and a short run on PRs that touch waf/ or logs.rs)
deny.toml                     licences: allow MIT / Apache-2.0 / BSD / ISC / Unicode, deny GPL / AGPL
                              (turns the licence policy into a check); advisories; crates.io sources only
fuzz/                         cargo-fuzz (outside the workspace): waf_inspect, waf_multipart,
                              waf_decode, engine_log_line, gateway_config
scripts/fetch_eval_data.sh    pinned commits + SHA-256 for the CRS tests and the payload / benign lists
tools/eval/data/README.md     what each dataset is, its licence, and whether it is hold-out or development data
SECURITY.md                   disclosure process (M7)
dashboard/                    React + Vite + shadcn management UI (see the dashboard section below)
CLAUDE.md, docs/architecture/ (present)
```

## Target: management dashboard (M6)

**Stack:** React + TypeScript + Vite + **shadcn/ui** (Radix primitives + Tailwind), TanStack
Query (API polling and caching), TanStack Table (decision log, inventory, bans), and shadcn
charts (Recharts) for metrics.

Why this stack:
- shadcn components are copied into the repository, not installed as a runtime UI kit. The project
  owns and reviews every line, and there's no upgrade treadmill. That suits a security product's
  stance on its supply chain.
- Radix gives accessible behaviour (focus, keyboard, ARIA) for free.
- Dense tables and dark mode fit an operator console.
- The build is static files, which can be compiled into the gateway binary, so it stays one binary.

```
browser ──► admin_listen (loopback / private network, or behind the TLS terminator)
             ├─ GET /                 embedded single-page app (index.html + hashed assets, inside the binary)
             └─ /api/v1/…             JSON management API, authenticated
                  GET   stats · decisions (recent) · decisions/stream (SSE) · inventory · bans · intel
                        · config (secrets redacted)
                  POST  bans/unban · exclusions · rules · config/reload            (audited)
/metrics, /healthz                    stay as they are for Prometheus and load balancers
```

Prerequisites, in order. **The dashboard must not become the weakest door into the gateway.**

1. **Authentication on the management API.** Today the admin port has none, which is only
   acceptable for read-only data on loopback. Needed: a token from an environment variable (`admin.token_env`)
   for API clients, and a login → session cookie for the UI (HttpOnly, SameSite=Strict, Secure
   behind TLS). Every `POST` gets CSRF protection: an `Origin` check plus a custom header. Logins are
   rate limited. **Every change goes into an audit log** (who, what, before → after, when).
2. **A recent-decisions buffer.** A bounded ring buffer (say 10 000 entries) in the gateway, plus a
   server-sent-events stream served by hyper directly. The UI never reads `decisions.jsonl`
   from disk.
3. **Writes need the state split (step 9).** An exclusion or rule change builds a new
   `Compiled`, validates it with the same code as `--check`, and swaps it in, while learned state
   is kept. Until step 9 lands, the dashboard is read-only, plus unban.
4. **TOML stays the source of truth.** A change made in the UI is written back to the config file atomically
   (temporary file + rename), so Git-managed configs keep working and the UI never holds
   hidden state.

**Embedding.** `npm run build` writes `dashboard/dist/`. A `build.rs` behind a cargo feature
`dashboard` turns it into an `include_bytes!` table, so no new Rust dependency is needed. Rust-only
builds and the MSRV CI job don't need Node. The Dockerfile gets a Node build stage. The UI ships
with a strict CSP (`default-src 'self'`, no inline scripts), which Vite's output satisfies.

```
dashboard/
  package.json  package-lock.json  vite.config.ts  tsconfig.json  components.json  index.html
  src/
    main.tsx  router.tsx
    api/                 typed client and types for /api/v1 (mirroring the Rust structs)
    components/ui/       shadcn components (owned code)
    features/
      overview/          requests by action, blocks by layer, top offenders, upstream and CrowdSec health
      decisions/         live table, filters (layer, action, IP, route), detail drawer: reasons + WAF findings
      inventory/         route templates, status mix, blocked share
      bans/              bans and reputation, unban
      rules/             rules and exclusions; one-click "exclude this indicator here" from a decision
      settings/          redacted config view, reload
    lib/
```

## Migration plan

Every step is one commit. It keeps `cargo test --workspace` green, keeps the e2e suite
unchanged, and keeps decision-log output byte-identical. The pipeline steps also run `loadtest`
before and after.

| Step | Change | Size | Fixes | Unblocks |
|---|---|---|---|---|
| 1 | Hygiene: `version.workspace = true` for the gateway, the stale comments, `util.rs` | S | F7, F11 | — |
| 2 | Repository: `deny.toml` + CI job, stable-toolchain job, `fuzz/` with five targets, the eval-data fetch script | S–M | F10 | M1 |
| 3 | `lib.rs` → `server.rs` + `admin.rs` | S | F6 | M3 shutdown |
| 4 | `Layer`, `Signal`, `Verdict` in `proxy/verdict.rs`, replacing the `raise` closure and the status special cases, with tie-break tests | M | F1, F2 | — |
| 5 | Move the layer evaluation out of `handle` into `pipeline/` | M | F1 | M3 `ext_authz`, M4 / M5 layers |
| 6 | WAF `Location` + applicability; the gateway uses `location.param()` | M | F2 | M2 exclusions |
| 7 | WAF folder restructure (pure moves, one commit) | M | — | M2 work without conflicts |
| 8 | `config/` folder, validation next to each section | S–M | F5 | — |
| 9 | `State { compiled, learned, runtime }`; split `RateLimiter` and `Operations` into definitions + caches | M | F3 | M3 reload and persistence |
| 10 | Engine `waf` feature; the gateway depends on the WAF directly | S | F4 | — |
| 11 | `tests/e2e/` with a shared harness | S | F9 | — |
| 12 | Prefix structure for intel ranges; measure with ~50 000 ranges in `loadtest` | M | F8 | M3 throughput |

Order: steps 1–3 are risk-free. Steps 4–7 should land **before** M2 and M3 feature work starts,
because those milestones would otherwise write new code into the shapes being replaced. Steps
8–12 can run in parallel with feature work.

Dashboard track (it can start after step 3; D5 waits for step 9):

| Step | Change | Size |
|---|---|---|
| D1 | Management API: authentication, CSRF, audit log, read endpoints (stats, inventory, bans, redacted config) | M |
| D2 | Recent-decisions ring buffer + SSE stream | S–M |
| D3 | `dashboard/` scaffold, embedded assets behind the `dashboard` feature, CI job (type check, lint, build), Docker stage | M |
| D4 | Read-only pages + unban | M |
| D5 | Writes: exclusions, rules, reload with validation, audited | M–L |

## What not to change

- The crate-per-area layout and the one-way dependencies.
- Signatures in Rust code rather than external rule files. They are tested and reviewed in diffs.
  Data files fit *exclusions* and *paranoia-level packages* (M2), not signatures.
- Hand-written argument parsing. It means fewer dependencies in a security binary.
- `Result<_, String>` in the gateway. That is fine for a binary. Revisit it only if the gateway is
  published as a library (M7).
- Measured detection before refactoring detection code. A structural WAF change must
  leave `waf_eval` and `crs_eval` numbers identical.
