# Config

TOML. Values under `[guard]` apply to every actor unless that actor has an entry under
`[guard.actors."id"]`. **An empty file is valid**: adaptive engine, built-in model, no hard rules.
Invalid values (unknown enum, bands out of order, zero thresholds) are rejected at load time.

```toml
[guard]
# ...

[guard.adaptive]
# ...

[guard.actors."entity_id"]
# only keys you set here override [guard]
```

---

## Engine (`[guard]`)

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `mode` | string | `"hybrid"` | `adaptive` = ML engine only, `rules` = explicit thresholds only, `hybrid` = both (final risk = max). |
| `time_source` | string | `"event"` | `event`: windows use `Event::timestamp`, monotonised (never moves backwards) — needed for log replay; pass server time, never client time. `system`: process clock at check time. |
| `normalize_targets` | bool | `true` | Collapse ids in paths (`/product/123?x` → `/product/{n}`) for rules. The adaptive engine always templates routes. |
| `model` | path | built-in | Trained model TOML (from `pattern-guard train`). Relative to the config file. |
| `max_actors` | integer ≥ 1 | `100000` | Distinct actors kept in memory (LRU). |

## Decisions

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `allow_below` | f64 | 0.3 | Risk < this → `Allow`. |
| `warn_below` | f64 | 0.6 | Risk < this → `Warn`. |
| `delay_below` | f64 | 0.85 | Risk < this → `Delay(delay_secs)`. |
| `challenge_below` | f64 | — | If set, risk < this → `Challenge`, else `Block`. Must be ≥ `delay_below`. |
| `delay_secs` | f64 | 5.0 | Suggested delay. |
| `cooldown_secs` | f64 | 60.0 | Once cooldown starts, the actor gets `Block` for this long. 0 = off. |
| `cooldown_after_blocks` | u32 | 3 | Blocks within ~`cooldown_secs` before cooldown starts (one borderline block never locks anyone out). |

**Bands:** `[0, allow)` allow · `[allow, warn)` warn · `[warn, delay)` delay · `[delay, challenge)` challenge (if set) · rest block.

## Explicit rules (opt-in hard limits)

Unset = rule disabled. Use as safety nets sized well above normal traffic.

| Key | Type | Description |
|-----|------|-------------|
| `window_secs` | u64 (default 300) | Sliding window for the rules. |
| `burst_max_events` | u32 | Max events per actor in the window. |
| `repetition_max_count` | u32 | Max occurrences of the current (action, target) in the window. |
| `hopping_max_targets` | u32 | Max distinct targets in the window. |
| `weight_max_total` | f64 | Max sum of `Event::weight` in the window. |
| `interval_secs` | f64 | Flag timer-like pacing at this period (needs ≥ 5 gaps). |
| `interval_tolerance_ratio` | f64 (0.2) | ± tolerance for `interval_secs`. |
| `risk_combine` | `"max"` / `"weighted_sum"` | `weighted_sum` = probabilistic OR, `1 − Π(1 − rᵢ)`. |

Each rule's risk is 0 up to its limit and rises linearly to 1 at 2× the limit.

## Adaptive engine (`[guard.adaptive]`)

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `warmup_secs` | f64 | 300 | A route's learned baseline is used only after this long. |
| `ipv4_prefix` | u8 | 24 | IPv4 network grouping. |
| `ipv6_prefix` | u8 | 56 | IPv6 network grouping. |
| `max_routes` | int | 10000 | Route templates tracked (LRU). |
| `max_fingerprints` | int | 50000 | Client fingerprints / user agents tracked (LRU). |
| `max_subnets` | int | 50000 | Networks tracked (LRU). |
| `probe_paths` | [string] | `[]` | Extra path substrings treated as scanner probes (case-insensitive). |

## Per-actor overrides

Same keys as the rules and decision sections, plus:

| Key | Type | Description |
|-----|------|-------------|
| `trusted` | bool | Always `Allow` (still observed so baselines stay accurate). Monitors, partners, internal jobs. |

Omitted keys inherit from `[guard]`.

```toml
[guard.actors."ip:198.51.100.50"]
trusted = true

[guard.actors."service:cron"]
burst_max_events = 5
window_secs = 60
```

Full example: [config/guard.toml.example](../config/guard.toml.example)
