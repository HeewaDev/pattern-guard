# Changelog

All notable changes to this project will be documented in this file.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- **Gateway library API: state split** (`pattern_guard_gateway::state`). `State` is now
  `{ compiled, learned, runtime }`: `State::compiled()` returns the config snapshot
  (`Compiled`: the `GatewayConfig`, rules, limit and operation definitions, lists, the
  `Challenger`, …), `learned` holds the `Guard`, `IntelStore`, rate buckets, operation and
  login caches, ban counts and the inventory, and `runtime` the HTTP client, metrics,
  decision log, connection counts and the WAF. `policy::rate_limit::RateLimiter` is split into
  `Limits` + `Buckets`, `Operations::check` takes an `OperationCaches`, `Bans` takes an
  `Offenders`, and `proxy::client_ip` / `proxy::handle` take the `Compiled` snapshot.
  Migration: `state.intel` → `state.learned.intel`, `state.metrics` →
  `state.runtime.metrics`, `state.cfg` → `state.compiled().cfg`. Behaviour and the decision
  log are unchanged.
- **Project layout**: a virtual workspace with one crate per product area and
  feature folders inside each: `crates/engine` (`pattern-guard`: `ml/`, `rules/`,
  `util/`), `crates/waf` (`pattern-guard-waf`, new crate, re-exported as
  `pattern_guard::waf`), `crates/cli` (`pattern-guard-cli`, binary `pattern-guard`),
  `crates/gateway` (`proxy/`, `challenge/`, `intel/`, `observability/`), `tools/eval`
  (simulator and benchmarks), `config/` (example and demo configs). Public Rust paths
  are unchanged; commands now take `-p <crate>` (see README).
- **WAF cost**: the extra analysis makes inspection ~17–20 µs per typical request (was
  ~9 µs); the gateway load test went from ~30 000 to ~26 000–28 000 req/s on the same 4 shared
  vCPUs. The indicator RegexSet now uses a 16 MiB lazy-DFA cache, without which it fell
  back to the regex crate's slow engine.

### Added

- **Business-operation protection** (`[[operations]]`): per-account budgets keyed by a
  header, cookie, query, form or JSON field (hashed, never stored), allowed source IPs
  (e.g. payment callbacks), and replay / race-condition protection for unique values
  such as transaction ids (held while in flight, kept only after a 2xx answer). New
  decision layer `operation`; answers 429 + Retry-After, 409 or 403.
- **Login protection** (`[[logins]]`): failed logins per account from any IP
  (distributed brute force) and distinct failing accounts per IP (credential stuffing).
- **Deployment**: `Dockerfile` (non-root, ~125 MB), `deploy/docker/compose.yml` demo,
  hardened `deploy/systemd/pattern-guard-gateway.service`.
- **WAF 2.0** (`crates/waf`), measured on the OWASP CRS regression tests (attack
  categories 930–944: 11.8 % → 53.4 % blocked) with 0 of 19 215 benign values blocked
  throughout:
  - OWASP CRS word lists (OS files, restricted files, Unix shell, PHP functions, Java
    classes) matched with Aho-Corasick (`lexicon.rs`, lists vendored under Apache-2.0);
  - PHP code injection, including PHP2Shell-style code in multipart fields;
  - Java attacks: serialized objects, gadget classes, Spring4Shell; base64-hidden
    payloads; Java payloads in any request header;
  - shell-command analyser for Unix and Windows command injection (`shell.rs`);
  - URL analyser for SSRF and remote file inclusion (`ssrf.rs`);
  - server-side JavaScript, Perl and expression-language injection, prototype
    pollution;
  - session fixation;
  - SQL tokenizer: string / numeric breakout, whole-value SQL expressions, database
    functions, PostgreSQL casts, JSON operators (`sql.rs`);
  - XSS evasions: look-alike brackets, HTML5 entities, split `javascript:`, JS globals,
    JSFuck, namespaced tags, UTF-7;
  - multipart bodies parsed part by part with upload checks and multipart-evasion
    detection (`multipart.rs`); `exclude_params` now covers multipart fields;
  - new attack classes: `remote_file_inclusion`, `code_injection`,
    `prototype_pollution`, `session_fixation`, `malicious_upload`, `protocol_violation`
    (17 in total);
  - `cargo bench -p pattern-guard-waf` inspection benchmark;
  - `crs_eval`: `SHOW_NEG=<category>` lists blocked negative tests, `DUMP=1` prints every
    test's score for build-to-build diffs.
- **Feature tracker**: enterprise protection target per threat (docs/FEATURES.md §4).
- **Gatekeeper features** in the gateway (new `policy/` and `hardening/` modules):
  - custom firewall rules (`[[rules]]`);
  - per-route rate limits with 429 and Retry-After (`[[rate_limits]]`);
  - escalating automatic bans and honeypot traps (`[bans]`, `[traps]`, plus `/bans` and
    `/bans/unban` admin endpoints);
  - HTTP protocol enforcement (`[protocol]`);
  - security headers (`[response_headers]`);
  - data-leak blocking on responses (`[response_inspection]`);
  - country access control from an IP-to-country CSV (`[geo]`).
- **`pattern-guard-gateway`** (new crate in `gateway/`): a reverse proxy that enforces
  Pattern-Guard decisions in front of any HTTP app.
  - Detect (shadow) and prevent modes.
  - Allow, deny and challenge IP lists, with client-IP resolution behind trusted proxies.
  - Proof-of-work bot challenge with an HMAC-signed, IP-bound clearance cookie.
  - CrowdSec bouncer (community blocklist + local decisions).
  - Suricata EVE and Wazuh alert feeds turned into temporary blocks.
  - Per-IP connection cap and header-read timeout.
  - Async EVE/ECS-style decision log, Prometheus `/metrics`, `/healthz`, and an
    `/inventory` API discovery endpoint.
  - `x-pattern-guard-bot-score`, `-risk` and `-request-id` headers forwarded to the app.
- **`waf` module**: payload inspection with server-like decoding and weighted indicators
  for 9 attack classes. Corpus test plus a `waf_eval` example for public payload lists.
- `normalize` module is now public (route templates).
- docs/FEATURES.md (gap tracker vs open-appsec and Imperva), docs/GATEWAY.md.
- The workspace now has two members. CI runs fmt, clippy, tests and bench compilation for
  both.

### Security

- **Dependencies** (found by the new `cargo-deny` CI job): `lru` 0.12.5 → 0.19.1
  (RUSTSEC-2026-0002, an unsound `IterMut`, and RUSTSEC-2026-0253, a use-after-free if a
  key's `Drop` panics during `pop()`; Pattern-Guard's keys are integers, strings and IP
  addresses, whose `Drop` never panics) and `crossbeam-epoch` 0.9.18 → 0.9.21
  (RUSTSEC-2026-0204; only used by the benchmark library).

WAF bypasses found in an internal security review (regression tests in
`crates/waf/tests/bypass_regressions.rs`):

- **Unknown content types**: a body with a content type outside form / JSON / multipart /
  XML / `text/*` was not inspected at all, so one header switched the WAF off for the
  body. It is now inspected (walked as JSON when it is JSON); binary bodies are searched
  for embedded server code.
- **Charsets**: UTF-16 / UTF-32 bodies (declared, with a byte-order mark, or detected by
  RFC 4627 null bytes) are transcoded before inspection; they used to be read as UTF-8
  garbage. A charset that hides content (EBCDIC such as `ibm037`, UTF-7, unknown labels)
  scores 7 (`body_charset`, class `protocol`).
- **SQL injection** from a numeric context into a comparison on a column (`1 OR
  username='admin'`, `0 OR id IN (SELECT …)`, `1 OR name IS NOT NULL`) scored 0; it now
  scores 7 (`sql_column_breakout`).
- **Overlong UTF-8** percent-encoding (`%c0%ae`, `%e0%80%af`) is folded to the ASCII it
  encodes, so `../` traversal hidden that way is seen.
- **Headers**: `X-Forwarded-For`, `X-Real-IP`, `True-Client-IP`, `X-Client-IP`,
  `Forwarded` and `Origin` get full inspection (they were checked for JNDI only). In these
  headers and in `Referer`, SSRF / RFI indicators no longer apply, so a development
  `http://localhost:3000` origin or referer is no longer logged as SSRF.
- **Uploads**: with both `filename` and `filename*`, both names are checked.
- **WAF CPU exhaustion** (critical): on random-looking values (e.g. 8 KiB of random
  punctuation) the combined indicator automaton fell back to a slow engine (~200 ms per
  value), and there was no limit on values per request: one ~430 KB request cost ~7 s of
  CPU and a few of them stalled the gateway. Long, diverse values (and the rest of a request
  that has spent 2 ms in the automaton) are now matched one regex at a time, with identical
  results; identical decoding variants are scanned once; at most 8 192 values are inspected
  per request, more is flagged `inspection_limit` (7). Worst case now ~35–45 ms; a typical
  request got faster (~15.5 µs).
- **Large and deep JSON**: the walk stopped silently after 1 000 items per level and at depth
  32, so a payload in item 1 001 or behind 1 000 keys was never seen. JSON is now walked to the
  request's value budget (a key or string inspected clean is not inspected again in that
  request, so bulk payloads stay cheap); deeper than 64 levels is flagged `json_too_deep` (7).
- **WAF panic**: a shell-like value with a multi-byte character after `-` (`;cat -é`, in a
  query, form field, cookie or User-Agent) panicked the connection's task.
- Multipart header parameters: an O(n²) scan on quoted values full of `;` is now linear.
- **Disguised path traversal**: look-alike dots and slashes (`%uff0e`, `%u2215`, `／`) and
  hex notation (`0x2e0x2e0x2f`) are folded to `../`, and a traversal that only appears once
  the dots are decoded (`%2e`, double encoding, overlong UTF-8, entities, look-alikes) scores
  `disguised_traversal` (5): browsers and HTTP libraries never encode `.`. Plain relative
  paths (`../img/logo.png`, a browser's `..%2Fimg`) are unchanged.
- **OS file paths as a whole value** (`/etc/passwd`, `.ssh/id_rsa`, `c:\boot.ini`,
  `file:///etc/hosts`): a parameter that is nothing but the path of a known OS file adds
  `lfi_path_value` (4) to the CRS file-list hit, enough to block. The same path inside a
  sentence is not affected. LFI hold-out (never tuned on): 34.7 % → 84.0 %.
- **SQL injection**: fragments that are attacks as a whole value (`OR x=x`, `AND deleted = 0)`,
  `ORDER BY 3--`, `HAVING 1=1`), time-based probes without a call (`select pg_sleep`,
  `WAITFOR DELAY '`), MySQL scientific-notation evasion (`1.e(ascii)`), a value that is a
  system catalog name, and look-alike quotes (`’`, `′`, `ʼ`, folded to `'`). Development SQLi
  90.7 → 95.0 %, CRS 942 42.8 → 45.7 %, hold-out SQLi 72.9 → 75.0 %; benign unchanged.
- **PHP filter chains** (`convert.iconv.UTF8.CSISO2022KR|convert.base64-decode…`, the
  2022 RCE technique) score 7 (`php_filter_chain`).
- **RFI parameter names** are compared case-insensitively (`_CONF[path]=https://…`,
  `mosConfig_absolute_path=…`).
- **Command substitution in a header** (``User-Agent: Mozilla/5.0`id` ``) adds
  `header_command_substitution` (4): it used to score 4 in total.
- **False positives found by the pinned benign corpus** (`scripts/fetch_eval_data.sh`):
  real User-Agents with the Indonesian locale (`(Linux; U; Android 4.4.2; id; …)`, UC Browser,
  BlackBerry) looked like a chained `id` command and were blocked; language tags alone in a
  User-Agent comment are now ignored (`$(id)` and other attacks still block). A single-quoted
  `charset='utf-8'` was flagged as an unknown charset.
- Cost of the bypass fixes above: a typical request took ~19 µs instead of ~17.5 µs before
  the CPU fix brought it to ~15.5 µs (`inspect_bench`).

Gateway issues found in the same review:

- **Behavioural engine: shared evidence can challenge, not block.** Evidence innocent
  clients share (a network's or user agent's failures and new arrivals) or that every first
  contact has (`actor_new`, `cold_write`) no longer blocks on its own: such a request gets
  `Challenge` (reason `shared_evidence_only`), and a cooldown earned that way challenges
  too. An attacker copying a popular browser's user agent no longer gets its users blocked
  and banned, and a password manager's or app's first login is challenged, not blocked.
  `realworld_eval` (seeds 7–9): legitimate requests blocked 0.13–0.17 % → 0.03–0.06 %;
  stopped, detection and every attack's blocked-or-challenged rate unchanged.
  `Decision::Challenge` can now appear without `challenge_below`.
- **Engine and log replay** (behaviour unchanged, `realworld_eval` identical):
  - `pattern-guard replay` / `train` no longer panic on hostile access-log lines (out-of-range,
    NaN or huge timestamps, non-ASCII time zones are parse errors); in the combined format
    the Basic-auth user name can no longer set the event time, nor an escaped `\"` the
    status; `logs::ReplayOrder` skips unconfirmed far-future and badly out-of-order
    records, so one injected line can no longer freeze the replay clock (3 580 of 7 201
    benign requests were stopped after one).
  - The client and actor tables are keyed by 64-bit hashes: 300 KB user agents could take
    ~14 GiB, now ~43 MiB for 50 000 clients.
  - Request preparation runs before the engine's lock, now held ~0.8 µs per call whatever
    the request size: one client sending 400 KB user agents used to cut other traffic from
    ~197 000 to 23 requests/s (3 threads); now ~655 000.
- **Challenged form POSTs**: a browser that met a challenge on a `POST` (e.g. a login form
  under `[[logins]]` with the default `challenge`) got a JSON 403 and was stuck. It now gets
  the proof-of-work page; a same-origin URL-encoded form is sent again once solved
  (`verify?…&j=1` returns 204 + the cookie), other browser POSTs return to their form page.
  Cross-site POSTs are never re-sent, which would defeat SameSite cookies and Origin-based
  CSRF checks. API clients still get JSON.
- **Client identity**: the `X-Forwarded-For` sent upstream is rebuilt from the resolved
  client (`<client>` for a direct client, `<client>, <trusted hops>, <peer>` behind trusted
  proxies), so entries a client forged no longer reach the application; a non-XFF
  `client_ip.header` (e.g. `CF-Connecting-IP`) is set to the client. The client IP is
  resolved from every line of `client_ip.header`, not only the first.
- **Operations and logins**: `form:` / `json:` identifiers are read whatever the declared
  Content-Type (charsets and UTF-16, multipart forms, JSON sniffing, form/JSON
  cross-matching), so switching the Content-Type no longer evades login lockout, budgets or
  replay protection. The body is read once per request in one streaming pass without
  building a JSON tree (a 10 MiB body cost ~160 MiB per field).
- **Budgets spent for a victim**: a per-account token is given back when the request is not
  forwarded or the application answers 401 / 403, so anyone who knows a public identifier can
  no longer exhaust another account's budget with requests that are blocked or refused.
- **Encoded paths walked around policies**: rules, rate limits, operations, logins, traps,
  restricted extensions and `waf.exclude_paths` matched the raw path, while applications
  decode it. `/%61dmin`, `/ADMIN`, `//admin`, `/x/../admin`, `/dump%2Esql` and
  `/health/..;/app` evaded a rule or reached an exemption. Paths are now matched raw and
  canonical (`policy/path.rs`): protections apply when either form matches (ignoring
  case), exemptions only when both match. Query-string rules match the raw and the decoded
  query the same way.

### Changed

- **Gateway limits** (security review H5, H1, H2, M4):
  - new `[limits]` keys: `body_read_timeout_secs` (30) and `body_min_bytes_per_sec` (1024):
    a body that stops keeping up gets 408; `max_buffered_body_bytes` (256 MiB): a global
    budget for buffered bodies, over it 503 + `Retry-After`; `max_requests_in_flight_per_ip`
    (256, per resolved client IP, also behind trusted proxies): over it 429; `max_bans`
    (100 000) and `max_intel_entries_per_source` (500 000): the reputation store is capped
    per source and evicts the entry closest to expiry; IPv6 bans sharing a /64 are merged;
    `decision_log_queue_bytes` (16 MiB).
  - a `Content-Length` over `max_body_bytes` is refused before reading; broken or abandoned
    bodies get 400 instead of 413; all gateway refusals send `Connection: close`.
  - decision-log values a client controls are truncated (field names unchanged); at most 16
    WAF findings per line, `pattern_guard.waf_omitted` counts the rest.
  - rate-limit buckets are keyed by a keyed 64-bit hash; requests refused by `[protocol]` are
    not recorded in the inventory, templates are cut at 512 bytes, `/inventory` is serialised
    outside its lock; `/bans` lists merged bans as `prefix/64`, soonest-expiring first.
  - metrics: `pattern_guard_requests_rejected_total{reason}`,
    `pattern_guard_buffered_body_bytes`, `pattern_guard_decision_log_dropped_total`,
    `pattern_guard_intel_evicted_total`.
  - measured: 40 stalled 10 MiB uploads +405 MiB growing → capped by the budget; 2 M bans
    +937 MiB → 100 000 entries (+47 MiB); 1 000 huge API keys +297 → +6 MiB; a 300 KB Host
    with a stalled log writer +301 → +11 MiB; a 31 KB cookie's log line 247 KB → 3.5 KB.
- `pattern_guard::features::Prepared` gains `actor`, `client`, `ip`, `write`, `read` and
  `Prepared::new`; `FeatureEngine::observe_request` / `observe_response` take `&Prepared`
  instead of `&Event`. `normalize::is_probe_path` scans the first 2 KiB of a path. Log
  timestamps must lie between 1970 and 9999.

### Fixed

- **Gateway**: a request to `/.pattern-guard/verify` whose `r=` value had a non-ASCII byte
  right after `%` made the connection's task panic (the decoder sliced a string inside a
  UTF-8 character). The gateway's two percent-decoders are now one byte-based
  `util::form_decode`.
- `pattern-guard-gateway` now takes the workspace version (was `0.1.0`).

## [0.3.0] - Unreleased

The engine is rebuilt around an adaptive, explainable ML model. Tested against
realistic mixed traffic (`examples/realworld_eval.rs`): legitimate requests stopped
went from 11.9% to ~0.3%, attack requests stopped from 52% to ~98.5%. See docs/ML.md.

### Breaking

- New `Decision::Challenge` variant (only produced when `challenge_below` is set);
  exhaustive `match`es need an extra arm.
- `Event` has new public fields `ip`, `user_agent`, `fingerprint` (use the builders
  `with_ip` / `with_user_agent` / `with_fingerprint`). Struct-literal construction breaks.
- Rule thresholds (`burst_max_events`, `repetition_max_count`, `hopping_max_targets`,
  `weight_max_total`) are now `Option`s and **opt-in**: unset means the rule is off
  instead of using defaults. Configs that set them explicitly behave as before.
- Default `mode = "hybrid"`: the adaptive engine runs in addition to your rules. Set
  `mode = "rules"` for the 0.2 behaviour.
- Default `time_source = "event"`: windows use `Event::timestamp` (monotonised) instead
  of the process clock, so logs can be replayed. Set `time_source = "system"` for 0.2
  behaviour.
- `max_actors` now defaults to 100 000 (was unbounded).
- `risk_combine = "weighted_sum"` is now a probabilistic OR (`1 − Π(1 − r)`), so extra
  evidence can only raise risk (0.2 averaged, which could lower it).
- `repetition_max_count` counts the *current* (action, target) instead of the maximum
  over all targets.
- Config bands and thresholds are validated at load (`Error::ConfigInvalid`).
- `Tracker` is no longer constructible from outside the crate.

### Added

- Adaptive engine (`features.rs`): streaming, constant-memory features per actor,
  subnet, client fingerprint and route; learned per-route baselines with asymmetric
  adaptation against baseline poisoning; route surges only count together with
  actor/client evidence.
- Explainable model (`model.rs`): logistic regression stored as TOML; built-in model;
  `Guard::with_model`, `[guard].model`.
- `Guard::assess` → `Assessment { decision, risk, bot_score (1–99), model_risk,
  rules_risk, reasons, features }`.
- `Guard::observe_response(&event, status)` — failure ratios feed the model.
- `Guard::new(Config)`, `Guard::from_toml_str`, `Config::from_toml_str`, `Config::default`.
- Cooldown after repeated blocks (`cooldown_secs`, `cooldown_after_blocks`), trusted
  actors (`trusted = true`), `challenge_below`, `[guard.adaptive]` settings.
- Route templating (`/product/123?x` → `/product/{n}`) and scanner probe-path list.
- CLI: `pattern-guard replay` (JSONL / nginx combined, accuracy report with labels) and
  `pattern-guard train` (scenario balancing, mimicry augmentation).
- `logs` module for parsing JSONL and combined access logs.
- Traffic simulator, `examples/gen_traffic.rs`, `examples/realworld_eval.rs`.
- docs/ML.md.

### Fixed

- Two requests ~`interval_secs` apart were blocked (interval rule now needs ≥ 5 gaps).
- Replaying logs collapsed all events into one instant and blocked light users.
- Each check copied and scanned the whole window: 156 µs per check after 1 000 flood
  events, 5.6 ms after 20 000. Now O(1) amortised and memory per actor is bounded.
- Unbounded memory growth by default.

## [0.2.0] - Unreleased

### Breaking

- `GuardConfig::actors` is now `HashMap<String, ActorOverride>` instead of
  `HashMap<String, GuardConfig>`. Per-actor entries no longer pull in serde
  defaults for unset fields; they inherit from `[guard]` correctly.
- `GuardConfig::risk_combine` and `EffectiveConfig::risk_combine` are now the
  typed enum `RiskCombine { Max, WeightedSum }` instead of `String`. Invalid
  values in TOML are rejected at parse time. The existing `"max"` and
  `"weighted_sum"` literals continue to deserialize.
- `Tracker::new` now takes `(max_window_secs: u64, max_actors: Option<NonZeroUsize>)`.
  Library callers who constructed `Tracker` directly will need to update.
- CLI: unknown flags now error instead of being silently skipped.

### Added

- `[guard].max_actors` (optional `NonZeroUsize`): caps the number of distinct
  actors retained in memory with LRU eviction. Omit for unbounded behaviour
  (the 0.1.0 default).
- CLI accepts the command after flags without requiring `--`, e.g.
  `pattern-guard --config guard.toml my_script.sh`.
- New tests covering interval-risk regularity vs irregularity, weighted-sum
  averaging, per-actor inheritance, invalid `risk_combine` rejection,
  `max_actors` parsing, LRU eviction, CLI argument parsing.
- Compile-time `Send + Sync` assertion on `Guard`, `Event`, `Decision`.
- Criterion benchmark (`benches/check_bench.rs`).
- Integration test for the CLI binary (`tests/cli_integration.rs`).

### Changed

- Tracker windowing now uses a monotonic `Instant` stamped at `record()` time
  instead of the caller-supplied `Event::timestamp` (`SystemTime`). Wall-clock
  jumps (NTP, leap seconds) no longer affect eviction. `Event::timestamp`
  remains `SystemTime` on the public API.
- Per-actor LRU insert path reduced from three hashmap lookups to one
  (`get_or_insert_mut`).
- `EffectiveConfig` is now `Copy`.

### Removed

- `unsafe impl Send for Guard` / `unsafe impl Sync for Guard`. The compiler's
  auto-trait derivation already provides both; the manual `unsafe impl` was
  redundant and unsafe-by-name without justification.
- `anyhow` dependency (was unused).

### Fixed

- Per-actor overrides correctly inherit unset fields from `[guard]`. In 0.1.0,
  the `unwrap_or(self)` pattern only applied when an actor had no entry at all;
  any defined entry silently filled missing fields with `serde` defaults
  (e.g. `window_secs = 300`) instead of the parent values.

### Migration notes

For users upgrading from 0.1.0:

- **Library users:** if you constructed `GuardConfig` or `Tracker` by hand,
  the type signatures changed; see the Breaking section. The recommended path
  (`Guard::from_config_path(...)` → `guard.check_with_risk(&event)`) is
  unchanged.
- **TOML config files:** no changes required. Existing `risk_combine = "max"`
  and `risk_combine = "weighted_sum"` continue to work. Per-actor overrides
  may now produce slightly different effective configs because unset fields
  inherit from `[guard]` rather than serde defaults — this is the bug fix
  above.
- **CLI users:** if any wrapper scripts passed unknown flags expecting them to
  be silently skipped, those now exit with an error message.

## [0.1.0] - 2026-02-01

Initial public release.
