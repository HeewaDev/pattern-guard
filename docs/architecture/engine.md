# Behavioural engine internals (`crates/engine`, crate `pattern-guard`)

The engine answers one question per request: *does this client behave like a person
using the site, or like a tool abusing it?* It is a synchronous library: event in,
`Assessment` out. The caller enforces the decision and reports the response status back.

What each feature means, how the model was trained, and the measured results are in
[../ML.md](../ML.md). Every configuration key is in [../CONFIG.md](../CONFIG.md). This page covers
the structure and the data flow.

## Public API

| Item | Purpose |
|---|---|
| `Guard::new(Config)`, `from_config_path`, `from_toml_str`, `with_model` | Build a guard. Without `model = …` it uses the built-in model (`ml/default_model.toml`, embedded with `include_str!`) |
| `Guard::assess(&Event) -> Assessment` | Score a request and record it. Call it **once per request, before handling it** |
| `Guard::observe_response(&Event, status)` | Report the status your handler returned, for the same event |
| `Guard::check`, `check_with_risk` | Shorthands that return only the decision, or the decision and the risk |
| `Guard::snapshot() -> Snapshot`, `Guard::restore(Snapshot)`, `restore_at(…, now)` | Copy out / put back what the guard has learned, to survive a restart (see [Snapshots](#snapshots)). `Snapshot` is serde; `to_json` / `from_json` |
| `Event::new(actor, action, target, time)` + `with_ip`, `with_user_agent`, `with_fingerprint`, `with_weight`, `with_metadata` | The request as the engine sees it |
| `Assessment { decision, risk, bot_score, model_risk, rules_risk, reasons, features }` | The result. `bot_score` = `1 + round((1 − risk) × 98)` |
| `Decision` | `Allow < Warn < Delay(d) < Challenge < Block`. `Challenge` appears only when `challenge_below` is set |
| `Model`, `model::train`, `TrainOptions`, `model::mimicry_copy` | Load, save, train and augment the logistic model |
| `logs::{parse_line, LogFormat, LogRecord}` | Parse nginx/Apache combined or JSONL access logs (used by the CLI); timestamps validated (1970–9999), the combined-format time anchored on the request's opening quote |
| `logs::{ReplayOrder, Ordered}` | Replay ordering for `replay` / `train`: skips a record more than 60 s ahead unless the next records confirm the jump, and records more than 1 h older than the newest |
| `normalize::normalize_path` | Route templating, also used by the gateway for rate-limit keys and the inventory |
| `pattern_guard::waf` | Re-export of the `pattern-guard-waf` crate |

`Guard`, `Event` and `Decision` are `Send + Sync`, checked at compile time in `guard.rs`.

## Module map

| Path | Responsibility |
|---|---|
| `guard.rs` | `Guard`: the clock, request preparation, model and rules orchestration, cooldowns, reasons, decision |
| `config.rs` | `Config` / `GuardConfig` / `AdaptiveConfig` / per-actor overrides, `validate`, `EffectiveConfig::risk_to_decision` |
| `event.rs` | `Event` and its builder; the client key (fingerprint, else user agent) |
| `decision.rs` | `Decision` |
| `error.rs` | `Error` (thiserror): config I/O, parse, validation, model and snapshot errors |
| `snapshot.rs` | `Snapshot` (format version, layout fingerprint, the learned state), floats as bits, chunked table copies |
| `ml/features.rs` | `FeatureEngine`: four LRU tables of decayed state → 28 features |
| `ml/model.rs` | Standardised logistic regression: `predict` with per-feature contributions, `train` (Adam), TOML format |
| `rules/tracker.rs` | Sliding window per actor (event time, O(1) incremental counts) for the optional threshold rules |
| `rules/analyzer.rs` | Turns window statistics into a rules risk (`max` or probabilistic OR) |
| `util/normalize.rs` | Route templates: `{n}` numbers (the last one becomes the event's object id), `{uuid}`, `{hex}` (≥ 16 hex digits), `{token}` (≥ 24 characters with a digit), digit runs inside words; `hash_str`; scanner probe paths |
| `util/stats.rs` | `Decay` (exponentially decayed counter), `GapStats`, `TopCounts`, `RecentIds`, `smoothed_ratio` |
| `logs.rs` | Access-log parsing (hostile lines are errors, never panics); CLF dates converted without a date crate; `ReplayOrder` |

## `assess` step by step

```
Event
 │ 1. effective config for the actor  ([guard] merged with [guard.actors."<id>"])
 │ 2. prepare (no lock): template = normalize_path(target); route = hash(method, template);
 │             id = numeric/uuid id from the path; probe = scanner path (first 2 KiB)?;
 │             actor and client keys = 64-bit hashes
 │ 3. lock state (one Mutex for the whole guard); now = clock.now(event)
 │ 5. mode ≠ rules     → features = FeatureEngine.observe_request(...)   (updates state)
 │                       (model_risk, contributions) = Model.predict(features)
 │ 6. mode ≠ adaptive  → rules_risk = analyzer(Tracker.record(...))     (only if a rule is set)
 │ 7. risk = max(model_risk, rules_risk)
 │ 8. trusted actor    → risk = 0, reason "trusted"
 │    else cooldown    → risk raised to the block threshold, reason "cooldown"
 │         reasons     = rule name (if it dominates) + top 3 contributions > 0.25 log-odds
 │    a block from shared evidence only → Challenge, reason "shared_evidence_only"
 │         (see "Shared evidence" below)
 │ 9. decision = risk_to_decision(risk), or Challenge after the cap above
 │10. if risk ≥ block threshold: add a strike; enough strikes in cooldown_secs → cooldown
 ▼
Assessment
```

`observe_response` locks the same state and updates the failure and response counters of the
actor, subnet, client and route that the request touched. It uses `peek_mut`, so a response never
creates or refreshes an LRU entry.

### Clock

| `time_source` | `now` | Use |
|---|---|---|
| `event` (default) | the event's timestamp, made monotonic (`max` of all timestamps seen) | log replay gives exactly the live results; the gateway passes server time |
| `system` | seconds since the guard was created (`Instant`), plus where a restored snapshot's clock left off | embedders whose event times are unreliable |

Never pass a client-supplied timestamp: with `event` time, it would drive every window.

### Risk → decision

| Risk | Decision (defaults) |
|---|---|
| `< allow_below` (0.3) | Allow |
| `< warn_below` (0.6) | Warn |
| `< delay_below` (0.85) | Delay(`delay_secs`, 5 s) |
| `< challenge_below` (unset) | Challenge |
| otherwise | Block |

**Cooldown.** Each request whose own risk reaches the block threshold adds a strike to a
decayed counter. When the counter reaches `cooldown_after_blocks` (3), the actor is held at
the block threshold for `cooldown_secs` (60 s). A single borderline block never locks anyone out.

## Feature engine (`ml/features.rs`)

Four LRU tables, each entry a handful of 16-byte decayed counters:

| Table | Key | Cap (default) | Holds |
|---|---|---|---|
| actors | 64-bit hash of the actor id | `max_actors` (100 000) | burst, volume, failures, route mix (top 16), recent ids, request gaps, read count |
| subnets | (/24 or /56 prefix) | `max_subnets` (50 000) | new actors appearing, failures |
| clients | 64-bit hash of the fingerprint, else of the user agent | `max_fingerprints` (50 000) | volume, new actors, failures, route mix (top 32), recent ids |
| routes | hash(method, template) | `max_routes` (10 000) | short-window rate, failures, new-actor arrivals, and their **baselines** |

Time constants: burst 10 s; volume 300 s; outcomes and objects 600 s; client 300 s;
route short window 60 s; route failures 120 s.

**Route baselines are asymmetric.** A baseline follows a drop in traffic within ~10 minutes
(`TAU_BASE_DOWN` = 600 s), but a rise only over ~4 hours (`TAU_BASE_UP`). An attack therefore can't
quickly teach the route that a flood is normal, while a quiet period is learned fast. Baselines
are trusted only after `warmup_secs` (300 s).

**Surges count only together with client evidence.** Route surge features are products,
such as `surge × actor_route_share` and `fail_surge × client_fail_ratio`. A flash sale
(a surge spread over many normal clients) stays low; a surge concentrated on one actor or tool
scores high.

The 28 features, in vector order, are `FEATURE_NAMES`. **The order is the model's input
layout**: new features go at the end, `N_FEATURES` is raised, and the built-in model is
retrained. Model files are keyed by feature name, so older model files still load.

## Model (`ml/model.rs`)

```
z = bias + Σ wᵢ · (xᵢ − meanᵢ) / scaleᵢ        risk = sigmoid(z)
contributionᵢ = wᵢ · (xᵢ − meanᵢ) / scaleᵢ     (log-odds; the top three become reasons)
```

- TOML on disk: `format`, `description`, `bias`, and per feature `{name, weight, mean, scale}`.
- `train`: weighted logistic regression, full-batch Adam on standardised features (600
  epochs, learning rate 0.05, L2 1e-3 by default).
- **Mimicry augmentation** (`mimicry_copy`): copies of attack rows with the features an
  attacker can fake cheaply (`MIMICABLE_FEATURES`: fingerprint and user-agent signals, IP
  network, timing regularity, a page view before a write) replaced by legitimate means.
  What the attack *does* (failing logins, enumerating ids, hammering a route, volume) is never
  replaced. The model learns behaviour, not disguises.
- **Training and serving parity:** features never depend on the model's decisions, so `pattern-guard
  train` computes exactly what production computes.

## Optional threshold rules (`rules/`)

Opt-in hard limits from the 0.2 releases (`burst_max_events`, `repetition_max_count`,
`hopping_max_targets`, `weight_max_total`, `interval_secs`). `Tracker` keeps a sliding
window per actor on event time, with O(1) incremental counts and a memory cap per actor.
`analyzer` maps each statistic to a risk, combined by `risk_combine` (`max`, or
`weighted_sum` = 1 − Π(1 − r)). In `hybrid` mode (the default) the final risk is
`max(model, rules)`. With no rule configured, the rules path is skipped entirely.

## Shared evidence

Some inputs describe what *other* clients did, or what every legitimate first contact
looks like (`SHARED_EVIDENCE` in `guard.rs`): `actor_new`, `cold_write`, the network's and
the client key's failure and new-arrival signals (`subnet_*`, `client_fail_ratio`,
`client_new_actor_share` and their surge interactions). They raise the risk, but a request
that would block **only because of them** is challenged instead:

- the model's risk is recomputed without their positive contributions; if that "own" risk
  (or the rules' risk) is below the block threshold, the decision is `Challenge`;
- cooldown strikes still count, but a cooldown remembers whether the actor's own behaviour
  reached the block threshold: if not, it challenges instead of blocking.

Why: with no TLS fingerprint the client key is the user agent, so an attacker using a
popular browser's user agent made that browser's users score as abusive (blocked, then
banned by the gateway), and a password manager's or app's first login (a cold write) was
blocked. Route concentration and surges (`client_route_share`, `surge_x_*`) are not in the
set: they are how distributed floods are caught, and innocent users don't share them.

Measured with `realworld_eval` (seeds 7, 8, 9, built-in model): legitimate requests
**blocked** 0.13 / 0.16 / 0.17 % → 0.03 / 0.06 / 0.04 % (now challenged); stopped,
detection and every attack's blocked-or-challenged rate unchanged.

## Concurrency

The config and the model sit behind an `RwLock<Arc<Settings>>`. Each `assess` and
`observe_response` clones the `Arc` once, so `Guard::reload` can swap both while calls are
running, and a call never mixes two settings. `Guard::config()` and `Guard::model()` return
`Arc`s for the same reason.

One `Mutex<State>` guards the clock, the feature engine, the rules tracker and the cooldowns.
Everything that doesn't need shared state (path template, route and target keys, probe scan
of the first 2 KiB, actor and client hashes) is prepared before locking, so the lock is held
~0.8 µs per call whatever the request's size; reasons and the decision are built after
unlocking. It is held once for `assess` and again for `observe_response`. It is the gateway's main
serialisation point.

Sharding it (milestone M3) is not a pure refactor. Actor state shards cleanly by actor hash,
but **route, subnet and client state is shared across actors**. Splitting it per shard
would give every shard 1/N of the traffic and shift every baseline. The options, in
increasing complexity:

1. Shard only the actor table and keep the shared tables under their own lock (two locks per call).
2. Shard everything and scale route rates by N (approximate; skewed when traffic is uneven).
3. Keep the shared tables in lock-free structures (atomic decayed counters) and shard the actors.

Whichever option is chosen, the result must be checked against `realworld_eval` before and after.

## Snapshots

`Guard::snapshot()` copies the learned state: the clock, the four feature tables, the rule
windows and the cooldowns, each table least recently used first. `Guard::restore` builds a
fresh state from it outside the lock and swaps it in. The engine does no I/O; the caller
serialises the `Snapshot` (any serde format) and stores it. The gateway does this in
`persistence.rs`.

- **Copy without stalling requests.** A table is copied 1 024 entries per hold of the
  state lock, with a 50 µs pause in between (std's `Mutex` isn't fair: without the pause
  the copying thread takes the lock straight back and waiting requests starve). One hold
  per table lists its keys in LRU order. At the default caps, the slowest `assess` during
  a snapshot took 5–20 ms (75–320 ms when copied in one hold).
- **Versioned.** `format` (`FORMAT_VERSION`) and `layout` (a `hash_str` of `N_FEATURES` and
  `FEATURE_NAMES`, which also changes if the key hash changes) come first. A mismatch
  skips the state without parsing it and is refused with `Error::SnapshotVersion` /
  `SnapshotLayout`. Another `time_source` is `SnapshotIncompatible`. The fingerprint
  doesn't cover the shape of the state structs: `golden_snapshot_keeps_its_shape` does.
  It parses a frozen format-1 file (`crates/engine/tests/data/snapshot-v1.json`) and
  requires it to serialise back unchanged, so a change to `ActorState`, `ClientState`,
  `RouteState`, `Strikes`, a tracker `Entry` or a container fails the test until
  `FORMAT_VERSION` is bumped and the file regenerated (`PG_BLESS=1`).
- **Bounded.** `restore` keeps the most recent entries that fit `max_actors` and
  `adaptive.max_*`, and cuts every per-entry list to its size (16 / 8 / 32 per actor,
  32 / 64 per client, rule windows to the largest window any actor's config allows). A
  ring position outside its buffer is brought inside on load.
- **Range-checked.** Values are checked for range as well as shape (a crafted file): no
  stored time may be later than the snapshot's clock (a later one is set to it), a
  cooldown ends at most `cooldown_secs` after it, counters and baselines are not
  negative (their logarithms would be NaN), the system-mode clock is at most 10¹⁰ s and
  the gap added to it at most ten years.
- **Exact.** Floats are stored as their IEEE-754 bits, because serde_json's default float
  parsing can be off by one unit in the last place. A restored guard gives bit-identical
  assessments on the same events (unit-tested). NaN and infinities are refused.
- **Compact.** States are tuples without field names. JSON size at the default caps:
  ~160 MB when actors send a few requests each, ~540 MB when every actor and client list
  is full, ~900 MB with 40-entry rule windows on top. Serialising takes 0.15–0.8 s,
  parsing 0.3–1.7 s, `restore` 40–500 ms.
- **Keys, not identities.** Every table is keyed by the 64-bit hashes the engine already
  uses (actor id, client fingerprint / user agent, route, subnet prefix, rule targets).
  No raw id, user agent or path is stored. The hash is unkeyed, so `ip:<address>` is quick
  to recover by brute force; treat a snapshot like an access log.

**Time across a restart.** Every counter stores absolute times, so nothing has to be
shifted. With `time_source = "event"` the clock resumes at the newest event the snapshot
saw, and the first event after the restart moves it to the present: every counter decays
by the real gap, as if the process had kept running and seen no traffic. Large gaps
(days, years) only drive the decays to zero (`exp` of a large negative number), and
cooldowns and windows expire. A snapshot whose clock is more than 60 s ahead of the
system clock is refused: the event clock never goes backwards, so the counters would not
decay until real time caught up. With `time_source = "system"` the restored clock resumes
at its saved reading plus the wall-clock time between snapshot and restore (0 if the wall
clock went backwards).

## Error handling and validation

`Config::validate` runs at construction time, for `[guard]` and for every per-actor override after
merging. It requires risk bands in [0, 1] with `allow_below ≤ warn_below ≤ delay_below ≤
challenge_below`, non-negative delays, rule limits ≥ 1 (omit a rule to disable it), and
valid prefix lengths. Errors are `pattern_guard::Error`
(thiserror). `assess` and `observe_response` cannot fail.
