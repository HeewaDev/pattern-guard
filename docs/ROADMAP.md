# Roadmap

Direction, order and the bar for "done". Why we build what we build is in
[STRATEGY.md](STRATEGY.md); per-feature status lives in [FEATURES.md](FEATURES.md).

---

## 1. Vision

**A self-hosted, open-source protection platform for everything after the edge:** the
web application and its APIs, the business logic behind them, and the servers they run
on. Small teams can run it in an afternoon, and it explains every decision it makes.

| Layer | Owner |
|---|---|
| Volumetric DDoS, CDN, global edge reputation | Edge provider (Cloudflare or similar), or ISP / upstream scrubbing |
| **Application:** WAF, behavioural ML, bots, accounts, business operations, API security | **Pattern-Guard Gateway** (built) |
| **Host and network:** service logins (SSH, mail, DB), bans on every port, file integrity, outbound traffic, scans | **Pattern-Guard Agent** (planned) |
| **Visibility and response:** one timeline, banned everywhere, UI, alerts | **Pattern-Guard Console** (planned) |
| Deep packet signatures, full SIEM, community reputation | Optional integrations: Suricata, Wazuh, CrowdSec |

What sets it apart: business-logic defences built in, behaviour learned per application,
explainable decisions, one Rust binary, no paywalled detection. Details in
[STRATEGY.md §3](STRATEGY.md#3-what-makes-it-stand-out).

## 2. Where we are (0.3, measured)

| Area | State |
|---|---|
| Gateway | Reverse proxy, detect / prevent, proof-of-work challenge (real browser verified), custom rules, rate limits, bans and traps, protocol checks, country policy, security headers, data-leak blocking, CrowdSec bouncer, Suricata / Wazuh feeds, metrics, decision log, API inventory |
| Business logic | `[[operations]]` (per-account budgets, allowed sources, replay / race protection), `[[logins]]` (lockout across IPs, credential stuffing) |
| WAF | 17 attack classes; OWASP CRS attack tests **53.4 %** blocked (paranoia level 1: **63.5 %**); PayloadsAllTheThings 92.5 %; hold-out lists: command injection 100 %, XSS 87–97 %, SQLi 59 %, file inclusion 35 %; **0 / 19 215** benign values blocked |
| Behavioural ML | ~0.3 % legitimate requests stopped, ~98.5 % attack requests stopped, on synthetic traffic including unseen attacks |
| Performance | ~28 000 req/s, p99 ≈ 3.4 ms through the gateway (4 shared vCPUs); WAF ~17 µs per typical request |
| Deployment | Docker image (non-root), compose demo, hardened systemd unit |
| Tests | 137 workspace tests incl. 18 end-to-end gateway tests over real HTTP |
| **Real-world proof** | **None yet.** Every number comes from synthetic traffic or public payload lists |

## 3. Evaluation of the plan so far (November 2026)

| Aspect | Grade | Notes |
|---|---|---|
| Structure, measurability, honesty | A | Milestones with acceptance bars, measured numbers, hold-out discipline |
| Execution | B+ | WAF 2.0 largely delivered; business operations, logins and Docker shipped beyond plan |
| Prioritisation | C | The old plan put real-traffic proof first, yet none of it is done |
| Production readiness | C | No persistence, hot reload, graceful shutdown or engine sharding |
| Quality safety net | C− | GitHub Actions has no runners on the account, so CI doesn't run; checks are manual |
| Vision alignment | fixed here | The old plan excluded host / network protection; the standalone direction is now the plan |
| Business plan | fixed here | Positioning, segments and revenue paths are in STRATEGY.md |

Lessons applied to the order below:
1. **Proof and production-readiness before breadth.** One real deployment with measured
   false positives beats another detection class.
2. **Standalone in steps, each useful alone.** Gateway → Agent → Console.
3. **Guard against scope creep.** At most two phases in progress at once; a phase is done
   only when its acceptance bar is met.

## 4. KPIs (tracked every release)

| KPI | Now | Target for 1.0 |
|---|---|---|
| Legitimate requests **blocked**, real traffic (detect-mode review) | unknown | ≤ 0.05 % |
| Legitimate requests challenged, real traffic | unknown | ≤ 0.5 % |
| Real deployments running ≥ 2 weeks | 0 | ≥ 3 |
| WAF on OWASP CRS paranoia-level-1 attack tests (930–944) | 63.5 % | ≥ 80 % |
| WAF hold-out detection (never tuned on), per class | 35–100 % | ≥ 85 % every class |
| WAF on CSIC-2010 (labelled real HTTP) | not measured | ≥ 95 % detection, ≤ 1 % false positives |
| Benign false blocks (19k corpus + 100k-sentence corpus + real logs) | 0 % (19k corpus) | ≤ 0.01 % |
| Behavioural ML detection on unseen simulated attacks (avg per type) | ~93 % | ≥ 95 % |
| Throughput per 8 vCPU, full inspection | ~28k (4 shared vCPUs) | ≥ 100k req/s, p99 ≤ 5 ms |
| Restart keeps learned state and bans | no | yes |
| Time from nothing to a protected app | one `docker compose up` | ≤ 10 minutes, documented |
| Agent: SSH brute force detected and banned on all ports | n/a | within 10 s, 0 false bans in tests |
| Console: time to resolve a false positive | edit TOML + restart | ≤ 1 minute, from the UI |
| CI | not running | every PR: fmt, clippy, tests, benchmarks, accuracy gates |

## 5. Phases

Effort: **S** ≈ days, **M** ≈ 1–2 weeks, **L** ≈ 3–5 weeks, for one experienced developer.
Each phase lists its goal, work items and the acceptance bar ("done when").

### Phase 1: Trust and proof · M · *start now*

**Goal:** real evidence and a trustworthy project.

- [ ] Release **0.4.0**: align crate versions (workspace 0.3.0 vs gateway 0.1.0), tag,
      changelog section, GitHub release with binaries.
- [ ] `SECURITY.md`: how to report vulnerabilities, supported versions.
- [ ] **CI running**: fix the account's GitHub Actions availability (settings / billing)
      or use another runner; fmt, clippy, tests, benchmarks on every PR.
- [ ] **Accuracy gates in CI**: `crs_eval`, `waf_eval` (hold-out + benign) and
      `realworld_eval` must not regress beyond tolerance.
- [ ] **Fuzzing** (`cargo-fuzz`): WAF decoding, SQL / shell / URL / multipart parsers,
      log parsing, gateway request path. 24 h without crashes.
- [ ] **CSIC-2010** labelled HTTP dataset benchmark (`tools/eval`).
- [ ] **100k-sentence false-positive corpus** (natural language in several languages,
      including Arabic and Kurdish), CRS-style.
- [ ] `pattern-guard replay` report: per-layer breakdown, exportable false-positive list.
- [ ] **First real deployment** in detect mode (a digital-goods shop), weekly
      false-positive review, findings published in FEATURES.md §3.

**Done when:** 0.4.0 is released, CI and accuracy gates run on every PR, fuzzers have run
24 h, CSIC-2010 and the 100k corpus are measured, and one site has run ≥ 2 weeks in
detect mode with a published false-positive rate.

### Phase 2: Edge integration (Cloudflare first) · S

**Goal:** Pattern-Guard behind an edge provider, with no way around it.

- [ ] **Reject untrusted peers**: optionally refuse connections that don't come from a
      trusted proxy (edge ranges or the local tunnel).
- [ ] **Origin secret header**: refuse requests without the zone's secret (env var,
      constant-time compare); closes "attacker's own Cloudflare account" bypasses.
- [ ] **Built-in edge ranges**: `trusted_proxies = ["cloudflare"]`, with a refresh command.
- [ ] Use `cf-ipcountry` as the country source (no geo database needed), `cf-ray` in the
      decision log.
- [ ] **Push bans to the edge**: Pattern-Guard bans (credential stuffing, replay, traps)
      are added to a Cloudflare IP list through the API and expire with the ban.
- [ ] Guide: "Behind Cloudflare": tunnel setup, firewall, Transform Rule, ready config.

**Done when:** an e2e test proves direct-to-origin and foreign-zone requests are refused;
a ban reaches a (mocked) Cloudflare list and is removed on expiry; the guide is complete.

### Phase 3: Production core · M–L

**Goal:** safe to run as the front door of a busy site.

- [ ] **Persistence**: snapshot and reload of baselines, bans, budgets, replay keys and
      clearances; restart keeps learned state.
- [ ] **Hot reload** of config and model (SIGHUP / admin endpoint) without dropping
      connections; `--check` runs first.
- [ ] Graceful shutdown and connection draining; configurable fail-open / fail-closed.
- [ ] **Shard the behavioural engine** by actor hash; lock-free reputation reads.
- [ ] HTTP/2 to the upstream; WebSocket passthrough; stream bodies beyond the inspection
      window.
- [ ] Body-read timeouts, global connection budget, shedding under memory / FD pressure.
- [ ] **Cluster state** (optional): bans, budgets and replay keys shared between gateway
      instances (embedded gossip or Redis).

**Done when:** ≥ 100k req/s at p99 ≤ 5 ms on 8 vCPU; restart and reload lose no learned
state or connections; two instances share bans and replay keys in an e2e test.

### Phase 4: WAF completion and zero-day protection · L

**Goal:** CRS-grade coverage without false positives, and protection that doesn't depend
on knowing the attack. Techniques: [RESEARCH.md §4](RESEARCH.md).

- [ ] **Per-parameter learning** (open-appsec's "unsupervised model"): learned value
      types and lengths per route parameter; code or URLs in a parameter that never
      carries them raise the score. This is the zero-day layer.
- [ ] **One anomaly score per request** with per-class sub-scores; **paranoia levels 1–4**
      with separate detection and blocking levels.
- [ ] Reputation-weighted scoring: the behavioural bot score and IP reputation scale the
      payload score.
- [ ] **Exclusions per indicator × location**, and packages for common apps (WordPress,
      WooCommerce, Laravel, Django, Magento).
- [ ] Evasion re-scan loop; JSON-in-string and delimiter decoding.
- [ ] Close the gaps: file inclusion (hold-out 35 %), SQLi (59 %), RFI, PHP, RCE;
      keyword-pair scores; Windows and SQL-function word lists.
- [ ] Protocol attacks (CRS 920/921): request smuggling (CL/TE), CRLF and header
      injection, parameter pollution, double encoding.
- [ ] Decide on libinjection (third-party crate) or keep our own tokenizer.

**Done when:** CRS paranoia level 1 ≥ 80 %; every hold-out class ≥ 85 %; benign false
blocks ≤ 0.01 % on the 19k + 100k corpora; a novel payload in a learned numeric parameter
is flagged with no signature.

### Phase 5: Digital-goods and fraud pack · M

**Goal:** the strongest protection for shops that sell instantly delivered goods
(gift cards, eSIM, top-ups, game credit, software keys). See
[STRATEGY.md §6](STRATEGY.md#6-vertical-playbook-digital-goods-and-esim).

- [ ] **Failure-counted operations**: count declined payments per account, IP and card
      fingerprint (card testing), like failed logins.
- [ ] **BOLA / IDOR detection**: one account touching many other customers' object IDs
      (orders, QR codes, activation codes).
- [ ] **Custom leak patterns** in response inspection (e.g. `LPA:1$…` activation strings,
      gift-card code formats), with bulk-leak thresholds.
- [ ] **Issuance reconciliation alert**: goods issued vs payments confirmed, per window.
- [ ] Signup, OTP and coupon velocity per device / network; CAPTCHA providers
      (Turnstile, hCaptcha) as challenge options.
- [ ] Payment-callback signature verification helper (HMAC header check per provider).
- [ ] Ready configs: `config/examples/esim-shop.toml`, `gift-card-shop.toml`,
      `topup-api.toml`.

**Done when:** each threat in the playbook has an e2e test; the example configs pass
`--check`; a simulated card-testing run and a BOLA crawl are stopped with no false
positives on normal shopping traffic.

### Phase 6: Agent v1, server protection · M

**Goal:** protect the whole server, not only the website. First standalone step; makes
CrowdSec-style tools optional.

- [ ] `pattern-guard agent`: log sources (journald, auth.log / SSH, nginx / Apache, mail,
      databases), parsers with tests.
- [ ] The behavioural engine on non-HTTP events: learned login baselines per service.
- [ ] Enforcement on every port: nftables (iptables fallback) sets with expiry.
- [ ] Public blocklists: Spamhaus DROP, FireHOL level 1, abuse.ch, Tor exits; scheduled
      refresh.
- [ ] Shared bans with the gateway on the same host (and through the Console later).
- [ ] Packaging: same binary, systemd unit, Docker host-network mode.

**Done when:** an SSH brute force is banned on all ports within 10 s in an e2e test with
zero false bans on normal admin logins; blocklists load and refresh; a web attacker
banned by the gateway is refused on SSH too.

### Phase 7: Console and UI · L

**Goal:** one place to see and control everything; the feature paying users ask for first.

- [ ] Central event store for gateways and agents (embedded database; retention policy).
- [ ] Correlation into incidents (actor × fingerprint × time, across layers).
- [ ] **Seen anywhere → banned everywhere**: gateways, agents, edge.
- [ ] Web UI: live decisions, top offenders, incidents, inventory, bans, one-click
      exclusions, config editing with validation and hot reload.
- [ ] Alerts: Telegram, email, Slack, webhooks; daily summary report.
- [ ] Authentication, roles, audit log; multi-tenant mode for service providers.

**Done when:** a false positive is resolved from the UI in under a minute; an attacker
seen by one gateway is banned on every connected gateway and agent within 5 s; alerts
reach Telegram and email in tests.

### Phase 8: API security · M

- [ ] OpenAPI schema enforcement per route template (method, params, types, body
      schema); detect, then enforce.
- [ ] Schema learning: a draft OpenAPI generated from the inventory.
- [ ] Response DLP: card numbers, API keys, personal data, with masking in logs.
- [ ] Learned per-operation baselines and spend / volume alerts.

**Done when:** each schema rule type is detected in tests; the generated schema covers
≥ 95 % of observed routes in the simulator.

### Phase 9: Bot management 2.0 · M

- [ ] Verified good bots: reverse DNS + forward confirm; known-bot lists.
- [ ] JA4 from the TLS terminator or edge as a first-class signal; per-fingerprint
      features.
- [ ] Challenge page collects passive client signals; a passed challenge becomes a strong
      "human" feature.
- [ ] Tor, anonymiser and hosting-ASN lists as model features.
- [ ] Breached-password check (k-anonymity range queries).

**Done when:** headless-browser and residential-proxy scenarios are added to the
simulator and detected at ≥ 90 % with no KPI regression; stealth stuffing ≥ 75 %.

### Phase 10: Agent v2 and network lite · L

- [ ] File integrity for web roots, configs and binaries; **web-shell detection** (new
      script files in upload directories, known shell signatures).
- [ ] **Exposed-secret scan**: `.env`, `.git`, backups reachable from the web root.
- [ ] New users, processes and listening ports; unexpected outbound connections from the
      web server's user (reverse shells, data theft).
- [ ] Network lite (conntrack / eBPF): port scans, floods, direct-to-origin attempts,
      outbound connections to known-bad IPs.
- [ ] Suricata and Wazuh stay supported as optional depth.

**Done when:** a web shell dropped in an upload directory, an exposed `.env`, a reverse
shell and a port scan are each detected in tests with no false alarms on a normal
deployment cycle.

### Phase 11: Ecosystem · M

- [ ] Kubernetes: Helm chart, ingress mode; `ext_authz` (Envoy) / `auth_request`
      (nginx) decision endpoint for teams that keep their proxy.
- [ ] Push decisions to CrowdSec; Grafana dashboards and Prometheus alert rules in
      `deploy/`.
- [ ] Wazuh decoder and rules tested against a live manager; SIEM exports (Elastic,
      Splunk, OpenSearch).

**Done when:** each integration has an e2e test or a recorded manual test.

### Phase 12: Release 1.0 · S–M

- [ ] Publish crates; semantic versioning; MSRV and support policy.
- [ ] Signed release binaries and images, SBOM.
- [ ] Documentation site (mdBook) built from `docs/`.
- [ ] **Independent security review** of gateway, agent and console.

**Done when:** every 1.0 KPI in §4 is met and published.

## 6. Timeline (indicative, one developer)

| Months | Phases | Outcome |
|---|---|---|
| 1 | 1 Trust and proof · 2 Edge integration | Released, tested, first real site, airtight behind Cloudflare |
| 2–3 | 3 Production core · 5 Digital-goods pack | Safe front door; strongest for digital goods |
| 3–4 | 4 WAF completion and zero-day | CRS-grade coverage, zero-day layer |
| 5 | 6 Agent v1 | Whole-server protection |
| 6–7 | 7 Console and UI | One screen, banned everywhere: sellable |
| 8–9 | 8 API · 9 Bots | Enterprise depth |
| 10–11 | 10 Agent v2 · 11 Ecosystem | Standalone platform complete |
| 12 | 12 Release 1.0 | Audited 1.0 |

With more contributors, phases 4, 5 and 6 can run in parallel once phase 3's
persistence lands.

## 7. Dependencies

```
1 Trust & proof ──┬──► 3 Production core ──┬──► 6 Agent v1 ──► 7 Console ──┬──► 10 Agent v2
2 Edge ───────────┘                        ├──► 4 WAF completion ──────────┤
                                           ├──► 5 Digital-goods pack ──────┼──► 12 Release 1.0
                                           ├──► 8 API · 9 Bots ────────────┤
                                           └──► 11 Ecosystem ──────────────┘
```

## 8. Risks

| Risk | Mitigation |
|---|---|
| **No real-world proof** | Phase 1 first; numbers labelled synthetic until real deployments report |
| **Scope creep** (gateway + agent + console + network) | Max two phases in progress; acceptance bars; standalone in steps, each useful alone |
| Overfitting to our simulator and benchmarks (CRS tests are now a development set) | Hold-out lists never tuned on; CSIC-2010 and 100k corpus added; real traffic |
| False positives hurt real users | Detect mode first; challenge before block; exclusions; reasons on every decision |
| No running CI | Phase 1 makes CI and accuracy gates mandatory |
| Pattern-Guard itself is attacked (parser bugs, DoS) | Fuzzing, bounded state, value and body limits, independent security review |
| Gateway is a single point of failure | Restart supervision, multiple instances, cluster state, fail-open option |
| One maintainer | Small, well-tested modules; FEATURES.md as the source of truth; good first issues per phase |
| Licence contamination | Only MIT / Apache / BSD code borrowed; ideas only from GPL / AGPL projects; JA4+ avoided |
| Vendor dependence on one edge | Edge integration behind an interface; works alone without any edge |

## 9. How we work

- One branch per feature; **one commit per feature or self-contained change**; every
  commit builds and passes tests.
- Update the feature's row in FEATURES.md in the same commit.
- Before merging: `cargo fmt --all --check`, `cargo clippy --workspace --all-targets --
  -D warnings`, `cargo test --workspace`, benchmarks compile; detection changes also
  report `crs_eval`, `waf_eval` (hold-out + benign) and `realworld_eval` before/after.
- Never tune on hold-out data; say so whenever a set was used for development.

## 10. Deliberately not building

- A CDN or volumetric DDoS scrubbing.
- A global threat-intelligence network of our own (we consume and feed CrowdSec and
  public feeds).
- A full packet-signature IDS or a full SIEM (Suricata and Wazuh stay optional depth).
- A copy of the OWASP CRS rule language; CRS stays an optional second opinion.
- Paywalled detection in the open-source core.
- JA4+ variants (FoxIO licence); plain JA4 (BSD-3-Clause) is fine as an input.
