# Architecture in depth

[../ARCHITECTURE.md](../ARCHITECTURE.md) is the one-page overview. This folder goes a
level deeper, down to modules, data structures, locks and the exact order of operations.
It is written for contributors, and for anyone who has to decide whether Pattern-Guard can be trusted
in front of their application.

| Document | Read it to… |
|---|---|
| [gateway.md](gateway.md) | follow one request through the gateway, stage by stage, and see every lock and background task |
| [engine.md](engine.md) | understand how the behavioural engine turns events into a risk, a decision and reasons |
| [waf.md](waf.md) | understand how a request is decoded, walked and scored by the WAF |
| [tooling.md](tooling.md) | use the CLI, the evaluation tools, the tests, the benchmarks and CI |
| [extending.md](extending.md) | add an indicator, an attack class, a policy layer, a config key, an ML feature or a feed |
| [target.md](target.md) | see where the structure should go next, and the order in which to get there |

## System context

```
                 ┌──────────────── threat intelligence ────────────────┐
                 │ CrowdSec LAPI (stream)   Suricata EVE   Wazuh alerts │
                 └───────────────┬─────────────────────────────────────┘
                                 │ IntelStore (bans / challenges per IP or CIDR)
client ─► [TLS terminator / CDN] ─► pattern-guard-gateway ─► upstream app (http://)
                                 │        │
                  admin (private) ◄┘        └─► decisions.jsonl ─► SIEM (Wazuh / Elastic)
         /metrics /healthz /inventory /bans
```

- TLS ends **in front of** the gateway (Caddy, nginx, a CDN). The gateway only speaks
  HTTP/1.1 to clients and to the upstream (`upstream` must be `http://`).
- The gateway is stateless across restarts. Learned baselines, bans and clearances live
  in memory only. Persistence is milestone M3 in [../ROADMAP.md](../ROADMAP.md).

## Crates

```
                 ┌──────────────────────┐
                 │ pattern-guard-waf    │  payload inspection, no async, no I/O
                 └──────────▲───────────┘
                            │ (re-export: pattern_guard::waf)
                 ┌──────────┴───────────┐
                 │ pattern-guard        │  behavioural engine, no async, no I/O
                 │ (crates/engine)      │  (config files and log parsing only)
                 └──▲────────▲───────▲──┘
                    │        │       │
   ┌────────────────┴┐ ┌─────┴─────┐ ┌┴──────────────────┐
   │ gateway (tokio, │ │ cli       │ │ tools/eval        │
   │ hyper 1)        │ │ replay,   │ │ simulator, WAF /  │
   │ lib + binary    │ │ train,    │ │ CRS / ML benches  │
   └─────────────────┘ │ wrap      │ └───────────────────┘
                       └───────────┘
```

| Crate | `src/` lines (with tests, benches) | Biggest modules |
|---|---|---|
| `crates/waf` | 3 900 (4 222) | `sql.rs` 781 · `indicators.rs` 684 · `inspect.rs` 655 · `multipart.rs` 444 · `ssrf.rs` 441 |
| `crates/gateway` | 5 954 (7 041) | `config.rs` 860 · `policy/operations.rs` 763 · `proxy/mod.rs` 531 |
| `crates/engine` | 3 024 (3 248) | `ml/features.rs` 553 · `config.rs` 488 · `guard.rs` 400 · `ml/model.rs` 347 |
| `crates/cli` | 699 (891) | `replay.rs`, `train.rs`, `wrap.rs` |
| `tools/eval` | 1 411 | `sim.rs` 965 |
| `tools/redteam` | 6 610 with unit tests | `app/sql.rs` 1 187 · `app/shell.rs` 840 · `attack/mutate.rs` 822 · `attack/adaptive.rs` 775 |

## Design principles

Each principle explains a choice you will see in the code. A change that breaks one
needs an explicit decision.

1. **One decision per request, with reasons.** Every layer produces evidence. The gateway
   fuses it into one action and logs *which layer decided and why* (`layer`, `reasons`).
   An unexplained block is a support ticket nobody can resolve.
2. **Libraries recommend, the gateway enforces.** `Guard::assess` returns a `Decision`
   and `Inspector::inspect` returns `Finding`s. Neither blocks anything. That is what
   makes them embeddable in an axum middleware, a CLI or a log pipeline.
3. **No async or network in the core.** The engine and the WAF are synchronous, `Send +
   Sync` and allocation-light. All I/O (sockets, CrowdSec, feeds, log files) lives in the
   gateway.
4. **Bounded everything.** Memory caps on every table, truncation on every input, timeouts on
   every socket. An attacker controls the input size, so the cost per request must not depend on it.
5. **Learn from outcomes.** The upstream's status code is fed back into the behavioural
   engine (`observe_response`). Failure ratios are among the strongest abuse signals,
   and only the application knows whether a login failed.
6. **Detect before prevent.** Detect mode computes everything and enforces nothing, so a
   deployment can be validated on real traffic before it can hurt anyone.
7. **Integrate, don't rebuild.** Packet inspection (Suricata), host monitoring (Wazuh) and
   a global reputation network (CrowdSec) are consumed, not reimplemented.
8. **Measured, not claimed.** Detection numbers come from runnable tools (`tools/eval`),
   with hold-out data kept separate from tuning data.

## Glossary

| Term | Meaning |
|---|---|
| **Actor** | Who the engine tracks behaviour for. The gateway uses `ip:<addr>`; embedders may use a user id or API key |
| **Client** | A client fingerprint (`fingerprint_header`, e.g. JA4) or, without one, the user agent: groups actors that share a tool |
| **Subnet** | The actor's network, /24 for IPv4 and /56 for IPv6 by default: catches IP rotation inside one network |
| **Route / template** | `METHOD + path` with ids collapsed: `/product/123` → `/product/{n}` (`util::normalize`) |
| **Event** | One request as the engine sees it: actor, action (method), target (path), time, optional UA / IP / fingerprint |
| **Assessment** | The engine's output: `Decision`, risk 0–1, bot score 1–99, reasons, feature vector |
| **Indicator** | One named WAF signal with a weight (a regex, a word-list hit, an analyser result) |
| **Attack class** | A WAF category (`sqli`, `xss`, …). A value's score is the sum of its distinct indicator weights in one class, capped at 10 |
| **Finding** | The strongest attack class for one inspected value: class, score, location, indicators, sample |
| **Location** | Where a value came from: `path`, `query:id`, `body:comment`, `json.user.name`, `cookie:sid`, `header:user-agent`, `filename:file` |
| **Layer** | A gateway component that can raise an action (`waf`, `behaviour`, `rate_limit`, …). It is logged as `pattern_guard.layer` |
| **Action** | The gateway's enforced outcome: Allow < Delay < Challenge < Block. (The engine's `Decision` also has `Warn`, which maps to Allow) |
| **Clearance** | The `pg_clearance` cookie set after a solved proof-of-work. It lifts Challenge and Delay for that IP until expiry |
| **Intel entry** | A reputation record (ban or challenge) for an IP or CIDR from a source: `crowdsec:*`, `suricata`, `wazuh`, `gateway:ban` |
| **Ticket** | State from `[[operations]]` / `[[logins]]` that is settled once the upstream's status is known |
| **Detect / prevent** | Gateway `mode`: log what would happen, or enforce it |
