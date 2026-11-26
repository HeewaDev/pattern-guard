# Product plan

Per-feature status lives in [FEATURES.md](FEATURES.md). This document sets **direction,
order and the bar for "done"**.

## 1. Vision

A self-hosted, open-source application-protection platform that a small team can run in
an afternoon. It should match the protection of commercial WAAP products (Imperva,
Cloudflare, open-appsec Enterprise) at the HTTP layer, and **explain every decision it
makes**.

Pattern-Guard does natively what belongs at the HTTP layer and integrates proven
open-source tools for layers that must run elsewhere:

| Layer | Owner |
|---|---|
| WAF, behavioural ML, bot challenge, L7 DDoS, API discovery & schema, enforcement | **Pattern-Guard** |
| Shared IP reputation | CrowdSec community network (consumed, and later fed) |
| Packet / network IDS | Suricata (its alerts are enforced by the gateway) |
| Host monitoring / SIEM | Wazuh or Elastic (ingest our events; Wazuh alerts are enforced) |
| Volumetric L3/L4 DDoS, CDN | Upstream provider |

What sets it apart: per-request behavioural ML with learned, poisoning-resistant
baselines; reasons on every decision; models you can retrain on your own logs; a single
Rust binary.

## 2. Where we are (0.3, measured)

| Area | State |
|---|---|
| Behavioural ML | ~0.3 % legit stopped / ~98.5 % attacks stopped on synthetic traffic incl. unseen attacks |
| WAF | 82.4 % on the pinned PayloadsAllTheThings lists (traversal 99.9 %, SQLi 95 %, LFI 66 %), 1 / 17 719 benign blocked; hold-out 96.2 %: command injection 99 %, XSS 89 %, LFI 84 %, SQLi 75 %; **OWASP CRS regression tests: 54.3 % blocked** (11.8 % before WAF 2.0). Datasets: `scripts/fetch_eval_data.sh` |
| Gateway | proxy, detect/prevent, PoW challenge (real browser verified), CrowdSec, Suricata/Wazuh feeds, metrics, decision log, API inventory |
| Performance | ~28k req/s, p99 ≈ 3.4 ms (4 vCPU shared) |
| Real-world proof | **none yet** |

## 3. KPIs (tracked every release)

| KPI | Now | Target for 1.0 |
|---|---|---|
| Legit requests **blocked**, real shadow traffic | unknown | ≤ 0.05 % |
| Legit requests challenged, real shadow traffic | unknown | ≤ 0.5 % |
| WAF hold-out detection (SecLists/fuzzdb, never tuned on), per class | 75–99 % | ≥ 85 % every class |
| WAF on OWASP CRS PL1 attack tests (930–944) | 64.5 % | ≥ 80 % |
| WAF benign false blocks (pinned 17.7k benign corpus + real logs) | 0.006 % (corpus) | ≤ 0.01 % |
| Behaviour ML detection on unseen simulated attacks (avg per type) | ~93 % | ≥ 95 % |
| Throughput per 8 vCPU, full inspection | ~28k (4 vCPU shared) | ≥ 100k req/s, p99 ≤ 5 ms |
| Time from `git clone` to protected app | one `docker compose up` (build ~5 min) | ≤ 10 min (Docker) |

## 4. Milestones

Effort: S ≈ days, M ≈ 1–2 weeks, L ≈ 3–5 weeks, for one experienced developer.

### M1 — Prove it on real traffic · *highest priority* · L
**Goal:** replace synthetic evidence with real evidence.
- [ ] Shadow deployment on at least one real site for 2+ weeks (`mode = "detect"`); weekly false-positive review.
- [ ] Labelled real dataset: CSIC-2010-style HTTP dataset for the WAF; public nginx logs (e.g. Zaker 2019, check licence) for behaviour.
- [ ] `pattern-guard replay` report includes per-layer breakdown and exportable false-positive list.
- [x] CI gates (`eval.yml`, `tools/eval/gates.toml`): `waf_eval` development sets and benign corpus,
      `crs_eval` (per category, PL1) and `realworld_eval` must not regress beyond tolerance. The
      hold-out numbers are reported there but deliberately not gated, so a red gate never invites
      tuning on hold-out data.
- [ ] `cargo-fuzz` targets: log parsing, WAF decoding, gateway request path.

**Done when:** real-traffic KPIs above are measured and published in FEATURES.md §3, CI
gates are live, and fuzzers have run 24 h without crashes.

### M2 — WAF accuracy 2.0 and zero-day RCE protection · L
**Goal:** close the CRS benchmark gap without raising false positives, and block
code-execution attempts without CVE-specific signatures. Uses the techniques from
open-appsec's engine (Apache-2.0) and OWASP CRS. The full list, with source paths, is in
[RESEARCH.md](RESEARCH.md) §4.

- [ ] **Measure first.** `crs_eval` (CRS regression tests) and a quantitative
      false-positive corpus (100k English sentences, CRS-style) run in CI; every change
      reports before/after numbers.
- [ ] **Full-request decoding.** [x] Multipart parsed part by part, keeping each field name.
      Base64, JSON-in-string and delimiter splitting, with a depth limit. Evasion re-scan
      loop: decode only when a trigger is present, and keep the result only if new
      indicators appear.
- [ ] **Indicator library.**
  - [ ] libinjection SQLi/XSS (`libinjectionrs`): needs a decision on adding the
        third-party crate.
  - [x] CRS word lists via Aho-Corasick: OS files, restricted files, Unix shell, PHP
        functions, Java classes. [ ] Windows, SQL functions.
  - [x] PHP code tags, superglobals and stream wrappers; Java deserialization magic
        bytes, including base64.
  - [x] Shell-command analyser (evasions, command position, Windows FOR/IF).
  - [x] URL analyser (obfuscated IPs, internal and metadata targets, RFI).
  - [x] Node.js / Perl / expression-language injection, prototype pollution, session
        fixation.
  - [x] SQL tokenizer (own; libinjection still needs a decision on the dependency).
  - [x] XSS evasions: look-alike brackets, HTML5 entities, JS globals, JSFuck,
        namespaced tags. [ ] Full HTML/attribute/JS context parsing.
  - [ ] Protocol anomalies.
- [ ] **Scoring.** One anomaly score per request, with per-class sub-scores.
      Keyword-pair scores with a saturating combiner, learned from labelled data.
      Paranoia levels 1–4, with separate detection and blocking levels.
- [ ] **Context, the zero-day part.**
  - Per-parameter learned value types (open-appsec "unsupervised model"): code or URLs in
    a parameter that never carries them raise the score.
  - The client's behavioural bot score and IP reputation scale the payload score
    (open-appsec's final-score formula).
- [ ] **Exclusions** per indicator × target, packaged per application.

**Done when:**
- CRS PL1 attack tests (categories 930–944) are ≥ 80 % blocked.
- Our hold-out lists are ≥ 85 % per class.
- Benign false blocks are ≤ 0.01 % on the 100k-sentence corpus plus the existing 19k
  benign corpus.
- A request carrying PHP code tags plus an OS command in a multipart field (the shape of
  PHP2Shell-style exploits) is blocked in prevent mode with no CVE-specific rule, and the
  log explains why (location, indicators, reputation).

### M3 — Production hardening · L
**Goal:** safe to run as the front door of a busy site.
- [ ] Shard the behavioural engine by actor hash; lock-free reputation reads.
- [x] Hot reload of config and model on SIGHUP. [ ] Persist baselines, reputation and clearances (snapshot + load).
- [ ] WebSocket passthrough; HTTP/2 to upstream; stream bodies beyond the inspection window.
- [x] Graceful shutdown and connection draining (`limits.shutdown_grace_secs`). [ ] Configurable fail-open/fail-closed.
- [x] Dockerfile (Debian slim, non-root), docker-compose demo, hardened systemd unit in `deploy/`. [ ] CrowdSec in the compose demo, Helm chart.
- [ ] `ext_authz` (Envoy) / `auth_request` (nginx) decision endpoint for users who keep their proxy.

**Done when:** ≥ 100k req/s at p99 ≤ 5 ms on 8 vCPU; restart keeps learned state; config
reload drops no connections; `docker compose up` protects a demo app in ≤ 10 minutes.

### M4 — API security · M
**Goal:** Imperva / open-appsec Premium API protection.
- [ ] OpenAPI schema enforcement per route template: method, params, types, body schema; detect then enforce.
- [ ] Schema *learning* from the inventory: generate a draft OpenAPI from observed traffic.
- [ ] Broken-object-level-authorization signals: an authenticated actor touching many other users' object ids.
- [ ] Response inspection: data leakage (card numbers, API keys, stack traces), with masking in logs.
- [x] Business operations (`[[operations]]`): per-account budgets, allowed sources, replay and
      race protection on unique values. [ ] Learned per-operation baselines, spend / volume alerts.

**Done when:** a request violating the schema is detected in tests for each rule type,
and the generated schema covers ≥ 95 % of observed routes in the simulator.

### M5 — Bot management 2.0 · M
**Goal:** Cloudflare-style bot management depth.
- [ ] Verified good bots: reverse-DNS + forward-confirm for search engines; known-bot UA lists (isbot, crawler-user-agents).
- [ ] JA4 from the TLS terminator as a first-class signal, and per-fingerprint signals (UA diversity, path diversity, unique IPs, browser ratio).
- [ ] Challenge page collects passive client signals (`navigator.webdriver`, timing). A passed challenge becomes a strong "human" feature for the ML.
- [ ] Tor exit, anonymiser and hosting-ASN lists as model features (not hard blocks).
- [x] Account-takeover: per-account failure tracking across IPs and credential stuffing per IP (`[[logins]]`). [ ] Breached-password check via k-anonymity range queries.

**Done when:** headless-browser and residential-proxy scenarios are added to the
simulator and detected at ≥ 90 % with no KPI regression; stealth stuffing ≥ 75 %.

### M6 — Ecosystem and visibility · M
- [ ] Push decisions to CrowdSec (`POST /v1/alerts`) so CrowdSec bouncers enforce them network-wide.
- [ ] Grafana dashboard JSON and Prometheus alert rules in `deploy/`.
- [ ] Wazuh decoder + rules package, tested against a live manager.
- [ ] Local web UI on the admin port: live decisions, top offenders, inventory, one-click exclusions.
- [ ] Attack analytics: group decisions into incidents (actor × fingerprint × time).

**Done when:** each integration has an end-to-end test or a recorded manual test, and the
UI can resolve a false positive without editing TOML by hand.

### M7 — Release 1.0 · S–M
- [ ] Publish crates (`pattern-guard`, `pattern-guard-gateway`); semantic versioning; MSRV policy.
- [ ] `SECURITY.md`, vulnerability disclosure process, signed release binaries.
- [ ] Documentation site (mdBook) built from `docs/`.
- [ ] Independent security review of the gateway.

**Done when:** all 1.0 KPIs above are met and published.

## 5. Order and dependencies

```
M1 Prove ──► M2 WAF 2.0 ──┐
   │                      ├──► M7 1.0
   └──► M3 Hardening ──► M4 API ──┤
              └──► M5 Bots ───────┤
                   M6 Ecosystem ──┘   (can run in parallel once M3's persistence lands)
```

M1 comes first because every later decision (weights, thresholds, which features matter)
should be made on real data, not on our own simulator.

## 6. Risks

| Risk | Mitigation |
|---|---|
| Overfitting to our own simulator and payload lists | Hold-out sets are never used for tuning; real shadow traffic in M1; numbers reported as measured |
| False positives hurt real users | Detect mode first; challenge before block; per-layer exclusions; reasons on every decision |
| Gateway becomes a single point of failure | systemd restart, multiple instances behind a load balancer, `/healthz`; fail-open option (M3) |
| Performance under floods | Bounded state, O(1) per request, connection caps; sharding (M3) |
| Licence contamination | Only permissive code borrowed (MIT/Apache); ideas only from GPL/AGPL projects; JA4+ avoided |
| One maintainer | Small, well-tested modules; FEATURES.md as the shared source of truth; good first issues per milestone |

## 7. How we work

- One branch per feature. **One commit per feature or self-contained change**. Every
  commit builds and passes tests, so history stays bisectable.
- Update the feature's row in FEATURES.md in the same commit.
- Before merging, run `cargo fmt --all --check`, `cargo clippy --workspace --all-targets
  -- -D warnings`, `cargo test --workspace`, plus `realworld_eval` and `waf_eval` when
  detection changes. Paste the before/after numbers into the PR.
- Never tune against hold-out data; when it's used to measure, say so.

## 8. Deliberately not building

- Packet inspection, host monitoring, a global threat-intel network, a CDN: integrate
  instead.
- A copy of the OWASP CRS: we keep our own scoring engine; CRS is an optional second
  opinion.
- JA4+ variants (FoxIO licence restrictions). Plain JA4 (BSD-3-Clause) is fine as an input.
