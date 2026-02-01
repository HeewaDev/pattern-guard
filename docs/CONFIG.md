# Config

TOML. Global defaults; override per actor under `[guard.actors."id"]`.

```toml
[guard]
# ...

[guard.actors."entity_id"]
# override any key
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
| `risk_combine` | string | "max" | How to combine pattern risks: "max" or "weighted_sum". |
| `allow_below` | f64 | 0.3 | Risk < this → allow. |
| `warn_below` | f64 | 0.6 | Risk < this → warn (else allow). |
| `delay_below` | f64 | 0.85 | Risk < this → delay (else block). Above → block. |
| `delay_secs` | f64 | 5.0 | Suggested delay duration (seconds). |

**Risk bands:** `[0, allow_below)` = allow; `[allow_below, warn_below)` = warn; `[warn_below, delay_below)` = delay; `[delay_below, 1.0]` = block.

---

## Per-actor overrides

Same keys as `[guard]`. Example:

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
