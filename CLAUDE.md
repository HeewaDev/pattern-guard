# CLAUDE.md

Pattern-Guard is self-hosted web application and API protection written in Rust. A
reverse-proxy gateway fuses a WAF, a behavioural ML engine, proof-of-work challenges, rate
limits, business-operation protection and threat intelligence into **one explained
decision per request**. The engine and the WAF are also embeddable libraries.

This is a security product. A change can let attacks through (false negative) or lock
real users out (false positive). Treat both as bugs, and measure detection changes.

## Workspace

| Crate | Path | Package (binary) | Depends on |
|---|---|---|---|
| WAF | `crates/waf` | `pattern-guard-waf` | regex, aho-corasick, serde_json |
| Behavioural engine | `crates/engine` | `pattern-guard` (lib `pattern_guard`) | waf (re-exported as `pattern_guard::waf`) |
| CLI | `crates/cli` | `pattern-guard-cli` (`pattern-guard`) | engine |
| Gateway | `crates/gateway` | `pattern-guard-gateway` (lib + bin) | engine, tokio, hyper 1 |
| Evaluation | `tools/eval` | `pattern-guard-eval` (unpublished) | engine |

Dependencies point one way: `waf ← engine ← cli, gateway, eval`. The engine and the WAF
must stay free of async and network dependencies, because they are embedded elsewhere.

Read before structural work:
- `docs/architecture/`: deep architecture. Start with its `README.md`. It covers the gateway pipeline,
  engine, WAF, tooling, how-to recipes in `extending.md`, and the target structure in `target.md`.
- `docs/ARCHITECTURE.md`: a one-page overview.
- `docs/FEATURES.md` (status of every feature) and `docs/ROADMAP.md` (milestones, KPIs).

## Commands

CI (`.github/workflows/rust.yml`, toolchain 1.85 = MSRV) runs exactly:

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo bench --workspace --no-run
```

Also in CI: rustdoc on stable (`RUSTDOCFLAGS=-D warnings cargo doc --workspace --no-deps`),
`cargo deny check` (licences, advisories, sources; `deny.toml`), and nightly fuzzing
(`.github/workflows/fuzz.yml`, targets in `fuzz/`, a separate workspace: `cargo +nightly fuzz run <target>`).

Focused:

```bash
cargo test -p pattern-guard-waf                                  # WAF units + benign/attack corpus
cargo test -p pattern-guard-waf --test corpus -- --nocapture     # print corpus misses
cargo test -p pattern-guard-gateway --test e2e                   # gateway over real TCP
cargo bench -p pattern-guard-waf --bench inspect_bench           # WAF speed guard (DFA cache)
cargo run --release -p pattern-guard-gateway -- --config gateway.toml --check
cargo run --release -p pattern-guard-eval --bin realworld_eval   # behavioural ML on simulated traffic
cargo run --release -p pattern-guard-eval --bin waf_eval -- --attack sqli.txt --benign words.txt
cargo run --release -p pattern-guard-eval --bin crs_eval -- crs_tests.jsonl [--pl 1]
```

The local toolchain may be newer than the 1.85 MSRV. Clippy reads `rust-version` from
`Cargo.toml` (`incompatible_msrv`), so `-D warnings` locally catches most uses of newer
std APIs. CI on 1.85 is the final check.

Evaluation data is not vendored. `crs_tests.jsonl` comes from
`python3 -I scripts/extract_crs_tests.py <coreruleset checkout> crs_tests.jsonl` (needs
PyYAML). The payload and benign lists for `waf_eval` are external files.

## Code graph (optional: graphify)

If `graphify-out/` exists (it's git-ignored; build it with `graphify update .`, ~5 s, no
LLM), use it to orient:

```bash
graphify query "how are bans stored"        # subgraph for a question
graphify explain "IntelStore"               # a node and its neighbours
graphify path "Bans" "IntelStore"           # how two things connect
```

Treat it as **a map of files, types and free-function calls, not a call graph.** Tree-sitter
has no type information, so method calls through struct fields are missing. For example,
`proxy::handle` → `state.guard.assess(..)`, `state.waf.inspect(..)` and every
`state.<policy>.check(..)` aren't in the graph, so "who calls X" answers are incomplete. Confirm
call chains with grep or by reading the code. Run `graphify update .` again after structural changes.

## Invariants (do not break without an explicit decision)

- **Bounded memory.** Every table keyed by actor, IP, route, account or value is an LRU
  with a cap. Inputs are truncated: WAF values at 8 KiB, JSON depth 32 × 1 000 items, 256 multipart
  parts, and inspected bodies at `inspect_body_bytes`. New state must be bounded too.
- **The request path never waits on slow I/O it doesn't need.** The decision log uses
  `try_send` and drops lines under pressure. Console output is limited to one line per second.
- **Client identity.** Only `client_ip.trusted_proxies` may set the client-IP header,
  and the right-most untrusted entry wins. Never take identity from any other client header.
- Incoming `x-pattern-guard-*` headers are stripped before forwarding.
- The challenge return path goes through `challenge::safe_return`. Clearance cookies are
  HMAC-bound to client IP and expiry.
- `[[operations]]` / `[[logins]]` store SHA-256 hashes (64 bits) of identifiers, never
  the raw tokens or user names. Never log the raw values.
- **The behavioural engine learns from outcomes.** `guard.assess` runs for every request
  that reaches the fuse, including requests that another layer blocks, and `observe_response` gets the final
  status. A challenge is deliberately *not* reported, so a human who meets one doesn't
  look like a failing client. Keep both when touching `proxy/mod.rs`.
- ML features never depend on the model's own decisions. This keeps training and serving identical.
- The WAF `RegexSet` uses a 16 MiB lazy-DFA cache. With less, it falls back to the PikeVM and runs ~60×
  slower. `inspect_bench` guards this.
- No `unsafe`. A poisoned lock is recovered (`unwrap_or_else(PoisonError::into_inner)`),
  never unwrapped into a panic on the request path.

## Public contracts (changing them breaks users)

- Decision-log JSON fields and the `pattern_guard.layer` values: `deny_list`, `protocol`,
  `trap`, `rule`, `geo`, `rate_limit`, `operation`, `challenge_list`, `reputation`,
  `waf`, `behaviour`, `data_leak`. SIEM rules, Wazuh decoders and dashboards key on them.
- Prometheus metric names and labels (`observability/metrics.rs`).
- Config keys. Gateway sections use `deny_unknown_fields`, so a rename breaks existing
  files. Rename only with a CHANGELOG "Changed" entry and a migration note.
- `AttackClass::as_str` names: logged, and used as metric labels.
- Model TOML is keyed by feature name. `FEATURE_NAMES` order (`N_FEATURES = 28`) is the
  vector layout: append new features at the end and update `ml/default_model.toml`.

## Gotchas

- If `mode` is omitted from the gateway config, the code defaults to **`prevent`**. The example configs set `detect`.
- The engine defaults to `time_source = "event"`. Never feed it client-supplied timestamps.
- **Fusion:** the most severe action wins (Block > Challenge > Delay > Allow). On ties, the
  layer raised *first* keeps the attribution, and the enforced status depends on it:
  `rate_limit` → 429, `protocol` → its own status, `operation` → its own status, everything else → 403 (each
  `Signal` carries its `Respond`). The raise order is the sequence of `verdict.raise(...)` calls in
  `proxy/mod.rs::handle`; the rules are unit-tested in `proxy/verdict.rs`.
- The allow list and an `allow` rule return before the ML engine, WAF and operations run.
- WAF location strings (`query:id`, `body:x`, `cookie:sid`, `json.user.name`,
  `header:user-agent`) are part of the log. The gateway also parses them back for `exclude_params`
  (`proxy::param_name`), so keep both sides in sync.
- `Inspector::new()` is expensive because it compiles the patterns. Build it once and share it.
- A trap hit records a ban even in detect mode. It is only enforced in prevent mode.

## Changing detection

- Measure before and after: `waf_eval` and `crs_eval` for the WAF, `realworld_eval` for the ML. Put
  the numbers in the commit message or PR.
- False positives weigh as much as misses. The benign corpus in `crates/waf/tests/corpus.rs`
  must stay at 0 blocks.
- Never tune on hold-out data (SecLists / fuzzdb lists). When hold-out data is used to
  measure, say so. The CRS regression tests are development data now.
- Licences: borrow code only from permissive projects (MIT / Apache-2.0). From GPL / AGPL
  projects, take ideas only. No JA4+ (FoxIO licence); plain JA4 is fine. Vendored CRS lists
  live in `crates/waf/data/crs/` (Apache-2.0, pinned commit in its README).

## Conventions

- British spelling in docs and comments (behaviour, normalise, licence).
- Commits: `area: summary` (areas: `waf`, `gateway`, `engine`, `cli`, `eval`, `deploy`,
  `docs`). The body has bullets and ends with a `Tested:` paragraph. One commit per feature or
  self-contained change, and every commit builds and passes tests (keeps history bisectable).
- In the same commit, update the `docs/FEATURES.md` row, `CHANGELOG.md` `[Unreleased]`
  (Keep a Changelog), the relevant `docs/*.md`, and `config/*.example` for new keys.
- Errors: the engine uses its `thiserror` `Error`. The gateway uses `Result<_, String>` with
  messages that name the config section or key.
- Tests sit next to the code (`#[cfg(test)] mod tests`). Time-dependent logic takes `now`
  (`check_at`, `record_block_at`) so tests never sleep. Every gateway feature gets an
  end-to-end test in `crates/gateway/tests/e2e.rs`. WAF changes get an attack test *and*
  a benign test ("O'Brien", prose, code in docs).
- New config key: a field with `#[serde(default = ...)]`, validated in `validate()` or the
  module's `compile()`, and documented in `docs/GATEWAY.md` or `docs/CONFIG.md` and the example config.
