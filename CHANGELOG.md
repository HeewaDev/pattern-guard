# Changelog

All notable changes to this project will be documented in this file.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
