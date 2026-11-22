# Changelog

All notable changes to this project will be documented in this file.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

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
- Cost: a typical request takes ~19 µs instead of ~17.5 µs (`inspect_bench`).

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
