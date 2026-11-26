# Extending Pattern-Guard: recipes

Each recipe lists every place a change touches, in order. Following them keeps the
public contracts (log fields, layer names, metric names, config keys) stable and keeps
detection measured. General rules for every change:

- One commit per feature, `area: summary`, with a `Tested:` paragraph. Every commit builds and passes CI.
- In the same commit: the `docs/FEATURES.md` row, `CHANGELOG.md` `[Unreleased]`, the relevant
  `docs/*.md`, and `config/*.example` for new keys.
- Detection changes report before and after numbers (`waf_eval`, `crs_eval`, `realworld_eval`).

---

## 1. Add a WAF indicator (a regex)

1. **`crates/waf/src/indicators.rs`**, inside `indicators()`:
   `i(AttackClass::X, "unique_name", weight, r"pattern")`.
   - The pattern sees **decoded, lower-cased, whitespace-collapsed** values (and the other
     variants), so write it in lower case and don't decode in the regex. `(?s)` is added for you.
   - **Names must be unique across all indicators.** Scoring de-duplicates by name within a
     class, so a clash silently drops weight (commit `56a426e` fixed one).
   - Weight: **≥ 7** blocks alone, so use it only for patterns that never appear in
     benign text. **4–6** is strong but needs one more signal. **2–3** is context.
2. If the indicator must not fire in the URL path (JS names in page slugs), add its name to
   `PATH_EXEMPT` in `inspect.rs`. If it is safe in arbitrary headers, its class must be
   JNDI or Java (`jndi_only`).
3. Tests: an attack that now scores ≥ 7 **and** a benign look-alike that stays below 7, in the
   module's tests or in `tests/corpus.rs`.
4. `cargo bench -p pattern-guard-waf --bench inspect_bench`. A new alternation can add many DFA states.
5. Measure with `waf_eval` and `crs_eval`, and paste the numbers into the commit message.

## 2. Add an attack class

1. Add a variant to `AttackClass` and its name to `as_str()` (`indicators.rs`). **The name is a public
   contract**: it appears in the decision log and as a metric label. Choose it once.
2. Indicators for it (recipe 1), or an analyser (recipe 3).
3. Is the class safe to inspect in every header (like JNDI)? Then extend the `jndi_only`
   mapping in `Inspector::new`.
4. Docs: the class list in `README.md`, `docs/GATEWAY.md` and `docs/FEATURES.md`. CHANGELOG "Added".

## 3. Add a WAF analyser (structural detection)

Follow the shape of `sql.rs`, `shell.rs` and `ssrf.rs`:

```rust
pub(crate) struct Xyz { /* compiled tables, built once */ }
impl Xyz {
    pub(crate) fn new() -> Self { … }
    /// Indicator names and weights hit by `value` (already decoded).
    pub(crate) fn scan(&self, value: &str) -> Vec<(&'static str, f64)> { … }
}
```

1. New module in `crates/waf/src/`, `mod xyz;` in `lib.rs`.
2. A field on `Inspector`, built in `Inspector::new()`.
3. Call it in `inspect_value_filtered`, inside `if !jndi_only`. Choose the input (`decoded`, or
   `kept_case` when case or newlines matter) and the locations where it applies (see how SSRF
   skips `path` and `header:referer`). Feed the results to `add(class, name, weight)`.
4. Tests in the module: `*_score_high` and `*_stay_low` pairs. Run the benchmark and the evaluations.

## 4. Add a gateway policy layer

Take `policy/rate_limit.rs` or `policy/protocol.rs` as the template.

1. **Config** (`config.rs`): `XyzConfig` with `#[serde(deny_unknown_fields)]` and defaults
   (`fn d_*()`), plus a field in `GatewayConfig` with `#[serde(default)]`.
2. **Module** (`policy/xyz.rs`, `pub mod xyz;` in `policy/mod.rs`):
   - `compile(&cfg) -> Result<Self, String>` validates everything (regexes, CIDRs, ranges) at
     startup, with messages that name the section.
   - `check(...) -> Option<XyzHit>` plus `check_at(..., now)` for tests.
   - All state is bounded: `Mutex<LruCache<…>>` with a `MAX_*` constant.
3. **State** (`state.rs`): the definitions are a field of `Compiled`, built in
   **`Compiled::compile`** with `Xyz::compile(&cfg.xyz)?`. State the layer learns from traffic
   (buckets, counters) is a separate type in `Learned`, keyed by the definition's name
   (`policy::definition_ids`), so it survives a reload.
4. **Pipeline** (`proxy/mod.rs::handle`):
   - Compute the hit with the other gatekeeper checks (after the allow list and rules, before the fuse).
   - Add a `Layer::Xyz` variant in `proxy/verdict.rs` (and to `Layer::ALL` and `as_str`;
     the contract test lists every name).
   - `verdict.raise(Signal::new(action, Layer::Xyz, format!("xyz:{name}")))`. **The position
     of this call is the tie-break order** (see [gateway.md](gateway.md#fusion)). Put it where
     its attribution should win against equally severe layers.
   - If an enforced Block needs a status other than the 403 block page, attach it to the signal:
     `.respond(Respond::TooManyRequests { retry_after })` or `.respond(Respond::Status { status, reason })`.
   - If the layer needs the upstream's answer (like `[[operations]]`), return a ticket and
     settle it next to `op_ticket.complete(status)`.
5. **The new layer name `xyz` is a public value.** It shows up in `pattern_guard.layer`,
   `blocked_by{layer}` and the console. Document it in `docs/GATEWAY.md` (decisions) and
   `docs/OPERATIONS.md` (log queries).
6. Tests: unit tests in the module and one end-to-end test in `tests/e2e.rs` (block, the status
   code, and detect mode). Add the example config.

[target.md](target.md) proposes a `Signal` / `Verdict` refactor that reduces steps 4 and 5 to
returning a value.

## 5. Add a config key

| | Gateway (`crates/gateway/src/config.rs`) | Engine (`crates/engine/src/config.rs`) |
|---|---|---|
| Field | `#[serde(default = "d_name")]` on the section struct | `#[serde(default = "default_name")]` on `GuardConfig` / `AdaptiveConfig` |
| Per actor? | — | also add it to `ActorOverride` and `EffectiveConfig` / `for_actor` |
| Validate | `GatewayConfig::validate`, or the module's `compile` | `EffectiveConfig::validate` / `Config::validate` |
| Document | `docs/GATEWAY.md`, `config/gateway.toml.example` | `docs/CONFIG.md`, `config/guard.toml.example` |

Gateway sections use `deny_unknown_fields`. Older binaries therefore reject configs that use a new
key, so mention the minimum version in the CHANGELOG. A rename is a breaking change.

## 6. Add a behavioural feature

1. **`ml/features.rs`**: compute it in `observe_request` (or update it in
   `observe_response`) from bounded state. Use `Decay`, `TopCounts` with a cap, or `RecentIds`, never
   an unbounded collection.
2. **Append** its name to `FEATURE_NAMES` and raise `N_FEATURES`. Never reorder: the order
   is the vector layout.
3. Can an attacker fake it cheaply (user agent, network, timing)? Then add it to
   `MIMICABLE_FEATURES` in `ml/model.rs`.
4. It must not depend on the model's own decisions (training and serving parity).
5. Retrain the built-in model the way it was made, then replace
   `ml/default_model.toml`:
   ```bash
   cargo run --release -p pattern-guard-eval --bin gen_traffic -- --seed 101 --hours 3 > train.jsonl
   cargo run --release -p pattern-guard-cli -- train -o crates/engine/src/ml/default_model.toml train.jsonl
   ```
6. `realworld_eval` before and after, including the `[unseen]` rows. Update `docs/ML.md` (the
   features table and the results).

## 7. Add a threat-intelligence feed

1. Add a `FeedKind` variant (`config.rs`) and a branch in `intel/feeds.rs::parse_alert` that
   returns `(attacker IP, reason)`. Decide which field holds the attacker (see Suricata's
   `to_client` handling).
2. Pick the source name: it prefixes entries in `IntelStore` and appears in reasons and metrics
   (`inc_feed`).
3. Tests with real sample lines (positive, filtered by severity, malformed). Document it in
   `docs/GATEWAY.md#threat-intelligence`.

Pull-based sources (like CrowdSec) get their own module and task in `start_background`.

## 8. Add a metric

1. An `AtomicU64` field (or a small labelled `Mutex<HashMap>`) on `Metrics`.
2. A `# HELP` / `# TYPE` block and the value in `Metrics::render`. Names start with
   `pattern_guard_` and counters end in `_total`.
3. Metric names are a public contract (alert rules and dashboards). Add an alert example to
   `docs/OPERATIONS.md` if it matters during an incident.

## 9. Add an admin endpoint

Add a match arm in `admin.rs::serve_admin`. The admin server has **no authentication**:
- read-only endpoints only, unless state changes need `POST` (like `/bans/unban`);
- never return secrets (challenge key, CrowdSec key) or raw identifiers;
- bound the size of what you return (the inventory stops at 10 000 routes).

Document it in `docs/GATEWAY.md#admin-endpoints-admin_listen-keep-private`.
