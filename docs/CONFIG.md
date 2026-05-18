# Config

TOML. Values under `[guard]` apply to every actor unless that actor has an entry under `[guard.actors."id"]`.

```toml
[guard]
# ...

[guard.actors."entity_id"]
# only keys you set here override [guard]; omitted keys inherit from [guard]
```

---

## Guard section (`[guard]`)

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `window_secs` | u64 | 300 | Default sliding window (seconds). |
| `burst_max_events` | u32 | 100 | Burst: max events in window before risk. |
| `repetition_max_count` | u32 | 10 | Repetition: max same (action, target) in window. |
| `hopping_max_targets` | u32 | 50 | Target hopping: max distinct targets in window. |
| `weight_max_total` | f64 | 1000.0 | Weighted overuse: max sum of weights in window. |
| `interval_secs` | f64 | — | Fixed interval: expected period (sec). Omit to disable. |
| `interval_tolerance_ratio` | f64 | 0.2 | Fixed interval: ±20% = 0.2. |
| `risk_combine` | string | `"max"` | How to combine pattern risks: `max` or `weighted_sum`. Invalid values are rejected at parse time. |
| `allow_below` | f64 | 0.3 | Risk < this → allow. |
| `warn_below` | f64 | 0.6 | Risk < this → warn (else allow). |
| `delay_below` | f64 | 0.85 | Risk < this → delay (else block). Above → block. |
| `delay_secs` | f64 | 5.0 | Suggested delay duration (seconds). |
| `max_actors` | integer (≥ 1) | — | When set, at most this many distinct actors are kept; least-recently-used actors are dropped. Omit for unbounded. |

**Risk bands:** `[0, allow_below)` = allow; `[allow_below, warn_below)` = warn; `[warn_below, delay_below)` = delay; `[delay_below, 1.0]` = block.

---

## Per-actor overrides

Use the same key names as `[guard]`. **Omitted keys inherit from `[guard]`,** not from the global schema defaults (unless `[guard]` also omits them, in which case schema defaults apply).

Setting `interval_secs` under an actor replaces the parent value for that actor. There is no TOML `null` to “clear” a parent `interval_secs`; omit the key on the actor to keep inheriting the parent setting.

Example:

```toml
[guard.actors."service:cron"]
burst_max_events = 5
window_secs = 60
```

---

## Minimal

```toml
[guard]
window_secs = 300
burst_max_events = 100
allow_below = 0.3
warn_below = 0.6
delay_below = 0.85
```

Full: guard.toml.example
