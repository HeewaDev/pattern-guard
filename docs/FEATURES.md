# Feature tracker: Pattern-Guard vs open-appsec and Imperva

This file is the single list of what to build and where the gaps are. Update the status
column in the same commit that changes a feature.

**Status key**

| | Meaning |
|---|---|
| ✅ | Built and tested |
| 🧪 | Built, but tested only on synthetic data / small corpus — needs real-world validation |
| 🚧 | In progress |
| ⬜ | Planned, not started |
| 🔌 | Provided by integrating another open-source tool (not re-implemented) |
| ❌ | Out of scope for self-hosted software (explained in the row) |

**Sources.** The open-appsec columns come from its GitHub README (Apache-2.0 code and
basic model; advanced model under a separate ML licence) and from search-result
snippets of openappsec.io/pricing and its docs. The pricing page itself could not be
fetched from the build environment, which blocked openappsec.io, so editions and prices
may be out of date; re-check them at https://www.openappsec.io/pricing. The Imperva
column reflects its publicly marketed product areas from general knowledge and was not
re-verified line by line.

---

## 1. open-appsec features, by edition

| # | Feature | open-appsec edition | Pattern-Guard | Where / next step |
|---|---|---|---|---|
| 1.1 | ML-based WAF for web apps & APIs (OWASP Top 10, zero-day) | Community | 🧪 behavioural ML (`crates/engine/src/ml/`) · 🧪 payload scoring engine (`crates/waf`, see §3) | Raise SQLi, XSS and file-inclusion detection; validate on a labelled real dataset |
| 1.2 | Supervised model trained offline on malicious/benign requests | Community (basic) / Production (advanced) | 🧪 behaviour model trained via `pattern-guard train` · ⬜ supervised *payload* model | Train a payload classifier on top of `waf.rs` indicators |
| 1.3 | Unsupervised model learned in the protected environment | Community | 🧪 per-route learned baselines (rate, failures, new clients) · ⬜ per-parameter value profiles (length, charset, type) | Add per-route/param profiles to `waf.rs` |
| 1.4 | Two-phase evaluation: attack indicators → contextual scoring | Community | ✅ WAF indicators + behavioural risk + reputation fused into one decision (`crates/gateway/src/proxy/`) | |
| 1.5 | Request decoding, JSON/XML extraction | Community | ✅ multi-pass URL/`%u`/HTML/JS decoding (overlong UTF-8 folded), SQL comments, base64 (whole values and fragments), shell evasions, JSON walk (to the value budget, depth ≤ 64), form, XML/text, multipart per part; bodies decoded by charset (UTF-16 / UTF-32 incl. BOM and RFC 4627 detection; EBCDIC / UTF-7 flagged); unknown content types still inspected (`crates/waf`) | Duplicate JSON keys (first-wins parsers) |
| 1.6 | IPS engine (Snort 3.0 signatures) | Community | 🔌✅ Suricata alongside; gateway tails `eve.json` and blocks alerting IPs (`crates/gateway/src/intel/feeds.rs`, e2e-tested) | |
| 1.7 | Automatic IPS signature updates | Premium | 🔌 via Suricata-update / ET Open | Document |
| 1.8 | Behavioural anti-bot | Premium | 🧪 behaviour ML + bot score 1–99 · ✅ proof-of-work challenge with IP-bound HMAC cookie (verified in real headless Chromium: solved in 142 ms; curl stays blocked) | Verified good bots (2.4) |
| 1.9 | API schema enforcement (OpenAPI) | Premium | ⬜ | Load OpenAPI spec; validate method/path/params/body types per route template |
| 1.10 | Block malicious IPs (ThreatCloud reputation) | Enterprise | 🔌✅ CrowdSec bouncer: community blocklist + local decisions, ban → block, captcha → challenge (`crates/gateway/src/intel/crowdsec.rs`, tested against a mock LAPI) | Test against a live CrowdSec |
| 1.11 | Block anonymizers & Tor | Enterprise | ⬜ | Load Tor exit list + VPN/hosting ASN lists as features/blocks |
| 1.12 | IP-level access control on every request | Community | ✅ allow / deny / challenge CIDR lists, custom rules on IP / not-IP, country policy, trusted-proxy client-IP resolution | |
| 1.13 | CrowdSec integration | Community | ✅ (as bouncer) · ⬜ push our decisions to CrowdSec (`POST /v1/alerts`) | |
| 1.14 | Rate limiting | (docs; edition unverified) | ✅ per-route token buckets keyed by IP, IP+route or API-key header (`[[rate_limits]]`, 429 + Retry-After) · adaptive surge detection · per-IP connection cap | |
| 1.15 | File upload security | Enterprise (third-party listings; unverified) | 🧪 multipart parsed per part; server scripts, double extensions, config / session / restricted files, NUL and traversal in names, PHP hidden in binary files (`crates/waf/src/multipart.rs`) · ⬜ magic-byte vs extension check, per-path size limits, ClamAV hook | |
| 1.16 | Deploy as NGINX / Kong / APISIX / Envoy / Istio attachment | Community | ✅ standalone reverse proxy (`gateway/`) · ⬜ nginx `auth_request` / Envoy `ext_authz` decision endpoint · ⬜ WebSocket passthrough · ⬜ HTTP/2 | |
| 1.17 | Kubernetes ingress / Helm | Community | ⬜ | Container image + Helm chart |
| 1.18 | Docker / Linux installer | Community | ✅ `Dockerfile` (non-root, ~125 MB), `deploy/docker/compose.yml`, hardened `deploy/systemd/` unit | |
| 1.19 | Gateway VM for AWS / Azure / VMware | Enterprise | ⬜ | Later: image build scripts |
| 1.20 | Declarative config files | Community | ✅ `guard.toml`, `gateway.toml` (validated, `--check`) | |
| 1.21 | Web management UI (SaaS) | Community (3 agents) | ⬜ | Local dashboard on the admin port first |
| 1.22 | Log storage / event viewer | Community 10K/mo · Premium 1M/mo | ✅ async JSON decision log (EVE/ECS-like, `srcip` for Wazuh) · ⬜ local viewer | |
| 1.23 | Monitor-only (detect) vs prevent mode | Community | ✅ `mode = "detect" \| "prevent"`, `would_mitigate` metric | |
| 1.24 | Playgrounds / virtual labs | Community | 🧪 traffic simulator + `realworld_eval` · ✅ docker-compose demo (`deploy/docker/compose.yml`) | |
| 1.25 | Independent security audit | Done for open-appsec (2022) | ⬜ | After 1.0 |
| 1.26 | Enterprise 24×7 support | Enterprise | ❌ (project, not a company) | |

## 2. Imperva capability areas

| # | Capability | Pattern-Guard | Notes |
|---|---|---|---|
| 2.1 | WAF with managed signatures | 🧪 `crates/waf` scoring engine, 17 attack classes, ~110 indicators + OWASP CRS word lists + SQL / shell / URL / multipart analysers · ⬜ optional Coraza + OWASP CRS second opinion | |
| 2.2 | Custom security rules | ✅ `[[rules]]`: path, method, host, IP, country, UA, query, header conditions; allow / block / challenge / delay / log / skip_waf. Paths matched raw and canonical (`%61dmin`, `..;`, `//`, case): protections fire on either, exemptions need both | |
| 2.3 | Virtual patching | ✅ via `[[rules]]` (block a vulnerable route / parameter pattern until patched) | |
| 2.4 | Advanced bot protection | 🧪 behaviour ML, fingerprints · 🚧 challenge · ⬜ verified good bots (reverse DNS), headless-browser signals | |
| 2.5 | Account takeover protection | 🧪 credential stuffing detection (failure ratios, route failure surge) · ✅ `[[logins]]`: failures per account from any IP, failing accounts per IP · ⬜ breached-password check (k-anonymity) |
| 2.6 | Application-layer DDoS protection | 🧪 surge detection + blocking · ✅ rate limits, escalating bans, per-IP connection cap, header-read timeout (slowloris), body size limit | |
| 2.7 | Network-layer (L3/L4) volumetric DDoS scrubbing | ❌ | Needs upstream bandwidth/scrubbing centres. Self-hosted: put behind a CDN/ISP scrubbing service |
| 2.8 | API discovery & inventory | ✅ `/inventory` on the admin port: route templates, volume, blocks, status codes | |
| 2.9 | API schema protection | ⬜ | Same as 1.9 |
| 2.10 | Sensitive data exposure detection (responses) | ✅ `[response_inspection]`: SQL/stack-trace/error pages, directory listings, private keys, AWS keys → generic 500 or log | Card numbers / PII masking |
| 2.11 | Client-side protection (third-party JS, CSP) | 🧪 CSP and other security headers injected (`[response_headers]`) · ⬜ CSP report collection, script inventory | |
| 2.12 | RASP (in-app runtime protection) | 🧪 library mode is in-process · ⬜ sink-level hooks | Long-term |
| 2.13 | Threat intelligence / IP reputation | 🔌✅ CrowdSec | |
| 2.14 | Attack analytics (grouping incidents) | ⬜ | Cluster decision log by actor/fingerprint/time |
| 2.15 | SIEM export | ✅ EVE/ECS-like JSON log · 🔌 Wazuh/Elastic (example rule in GATEWAY.md, untested against live Wazuh) | |
| 2.16 | CDN / caching | ❌ | Different product category |
| 2.17 | Host security monitoring | 🔌✅ Wazuh alongside; gateway tails `alerts.json` and blocks `data.srcip` | |
| 2.18 | Network IDS | 🔌✅ Suricata (see 1.6) | |

## 2b. Gaps found by studying OWASP CRS and open-appsec ([RESEARCH.md](RESEARCH.md))

| # | Capability | Pattern-Guard | Source of the technique |
|---|---|---|---|
| 2b.1 | libinjection SQLi/XSS detection | 🧪 replaced by our own SQL tokenizer (2b.20) and XSS evasion handling (2b.21); adding the `barbacane-libinjection` crate is still open (needs a decision on the dependency) | CRS 942100 / 941100 (`libinjectionrs`, BSD-3) |
| 2b.2 | Evasion re-scan loop (decode only on trigger, keep if new indicators) | ⬜ | open-appsec `WaapAssetState::apply` |
| 2b.3 | Large attack word lists (OS files, shell, Windows, SQL/PHP functions, Java classes, SSRF) | 🧪 OS files, restricted files, Unix shell + builtins, PHP functions, Java classes (`crates/waf/src/lexicon.rs`, `shell.rs`) · ⬜ Windows, SQL functions | CRS `rules/*.data` (Apache-2.0) |
| 2b.4 | One anomaly score per request, per-class sub-scores | ⬜ | CRS 901/949 |
| 2b.5 | Paranoia levels 1–4, separate detection/blocking level | ⬜ | CRS |
| 2b.6 | Keyword-pair scores + saturating combiner | ⬜ | open-appsec `WaapScores.cc` |
| 2b.7 | Recursive parsing: multipart per part, base64, JSON-in-string, delimiters | 🧪 multipart per part (2b.22), base64 (whole values and fragments), UTF-7 · ⬜ JSON-in-string, delimiters | open-appsec `DeepParser.cc` |
| 2b.8 | Per-parameter learned value types and keyword-confidence filtering | ⬜ | open-appsec `TypeIndicatorsFilter.cc`, `KeywordIndicatorFilter.cc` |
| 2b.9 | PHP code injection (tags, functions, superglobals, wrappers, serialized objects) | 🧪 CRS 933: 1.8 % → 26.6 % blocked (57.5 % logged) | CRS 933, `php-function-names` |
| 2b.10 | Java attacks (deserialization magic bytes incl. base64, class names) | 🧪 CRS 944: 6.6 % → 75.7 % | CRS 944, `java-classes.data` |
| 2b.16 | Shell-command analysis (evasion undoing, command words by position, Windows FOR/IF) | 🧪 CRS 932: 9.1 % → 34.8 %; commix hold-out 24 % → 100 % (`crates/waf/src/shell.rs`) | CRS 932, `unix-shell*.data` |
| 2b.17 | URL analysis: obfuscated IPs, internal / metadata targets, parser confusion, RFI | 🧪 CRS 934 SSRF rules, CRS 931: 10.8 % → 18.9 % (`crates/waf/src/ssrf.rs`) | CRS 931 / 934 |
| 2b.18 | Server-side JavaScript, Perl, expression-language injection; prototype pollution | 🧪 CRS 934: 7.5 % → 68.8 % (with 2b.17) | CRS 934 |
| 2b.19 | Session fixation (session-id parameters without a same-site Referer) | 🧪 CRS 943: 4.7 % → 95.3 % | CRS 943 |
| 2b.20 | SQL tokenizer: string / numeric breakout (also into a column comparison: `1 or username='admin'`), whole-value SQL expressions, database functions, casts, JSON operators | 🧪 CRS 942: 20.1 % → 42.8 % (PL1 27.5 % → 68.8 %); fuzzdb SQLi hold-out 50 % → 59 % (`crates/waf/src/sql.rs`) | libinjection idea, CRS 942 |
| 2b.21 | XSS evasions: look-alike brackets, HTML5 entities, split schemes, JS globals, JSFuck, namespaced tags | 🧪 CRS 941: 36.8 % → 60.8 % | CRS 941 |
| 2b.22 | Multipart per part, upload checks, multipart evasions | 🧪 CRS 922: 14.8 % → 100 % (`crates/waf/src/multipart.rs`) | CRS 922 / 920120 / 933110 |
| 2b.11 | Protocol enforcement (null/non-printable bytes, double encoding, CL+TE, CRLF, parameter pollution, restricted extensions) | 🧪 `[protocol]`: methods, URL / header / argument limits, NUL bytes, Host, restricted extensions · ⬜ double encoding, CRLF, parameter pollution | CRS 920 / 921 |
| 2b.12 | Reputation-weighted WAF score (behavioural bot score scales payload score) | ⬜ | open-appsec `D2Main.cc` |
| 2b.13 | Quantitative false-positive gate in CI (100k English sentences) | ⬜ | CRS `quantitative.yaml` |
| 2b.14 | Response inspection (SQL/PHP/Java errors, web shells) | ✅ errors, stack traces, listings, keys · ⬜ web-shell signatures | CRS 95x, open-appsec `resp_body_*` |
| 2b.15 | Exclusions per indicator × target, packaged per app (WordPress, Drupal…) | 🧪 `skip_waf` rules, `exclude_params`, `exclude_paths` · ⬜ per-indicator exclusions, app packages | CRS exclusion plugins, open-appsec `WaapOverride.h` |

## 2c. Gatekeeper parity with other open-source tools

| # | Behaviour | Found in | Pattern-Guard |
|---|---|---|---|
| 2c.1 | Custom rules, virtual patching | Coraza / ModSecurity, Cloudflare, BunkerWeb | ✅ `[[rules]]` |
| 2c.2 | Rate limiting per route / key | nginx `limit_req`, BunkerWeb, open-appsec | ✅ `[[rate_limits]]` |
| 2c.3 | Escalating automatic bans | fail2ban, CrowdSec | ✅ `[bans]` |
| 2c.4 | Honeypot / bad-behaviour bans | BunkerWeb | ✅ `[traps]` |
| 2c.5 | Proof-of-work / JS challenge | Anubis, BunkerWeb antibot, CrowdSec AppSec | ✅ PoW · ⬜ CAPTCHA providers (Turnstile, hCaptcha) |
| 2c.6 | Country blocking | BunkerWeb, SafeLine, Cloudflare | ✅ `[geo]` |
| 2c.7 | Security headers | BunkerWeb | ✅ `[response_headers]` |
| 2c.8 | Error-disclosure / data-leak blocking | open-appsec, CRS 95x | ✅ `[response_inspection]` |
| 2c.9 | Protocol enforcement | CRS 911/920 | 🧪 `[protocol]` (partial, see 2b.11) |
| 2c.10 | Consume shared IP reputation | CrowdSec bouncers | ✅ CrowdSec bouncer |
| 2c.11 | Push decisions to CrowdSec / host firewall (nftables) | CrowdSec, fail2ban | ⬜ |
| 2c.19 | Business-operation protection: per-account budgets, allowed sources, replay / race protection | Imperva (API & business logic), Cloudflare (rate limiting by session) | ✅ `[[operations]]` |
| 2c.20 | Login protection: per-account lockout across IPs, credential stuffing per IP | Cloudflare, Imperva ATO, fail2ban (per IP only) | ✅ `[[logins]]` |
| 2c.12 | Verified good bots (reverse DNS) | Cloudflare, BunkerWeb | ⬜ |
| 2c.13 | Tor / anonymiser / DNSBL blocking | open-appsec Enterprise, BunkerWeb | ⬜ |
| 2c.14 | Path-level authentication (basic auth / OIDC) | BunkerWeb, SafeLine | ⬜ |
| 2c.15 | Per-path body limits, upload filtering | SafeLine, open-appsec | 🧪 global `max_body_bytes` · ⬜ per path, file-type checks |
| 2c.16 | WebSocket, HTTP/2, TLS termination, caching, compression | BunkerWeb, SafeLine (nginx-based) | ⬜ (TLS via a front proxy today) |
| 2c.17 | Hot reload of config without dropping connections | all of the above | ✅ `SIGHUP` / `systemctl reload`: the whole config and the engine model are validated before the swap, a request is judged on the config current when its body has arrived, learned state is kept; restart-only keys in GATEWAY.md |
| 2c.18 | Web UI for decisions, bans and tuning | BunkerWeb, SafeLine, open-appsec | ⬜ |

## 3. Proof

| # | Item | Status |
|---|---|---|
| 3.1 | Behaviour ML on synthetic mixed traffic (incl. unseen attacks) | 🧪 0.44–0.54 % stopped (0.03–0.06 % blocked) / 98.4–98.7 % detection, incl. unseen first-contact clients (`tools/eval/src/bin/realworld_eval.rs`) |
| 3.2a | WAF, own corpus (`crates/waf/tests/corpus.rs`, tuned against) | 🧪 76/77 attacks blocked, 0/62 tricky benign blocked |
| 3.2b | WAF, PayloadsAllTheThings payload lists (MIT, 4 437 values, development; `{FILE}` templates given a target) + benign: 4 000 names, 10 000 English words, 1 989 user agents, 1 730 code lines from the Rust book; pinned by `scripts/fetch_eval_data.sh` | 🧪 82.4 % of attacks blocked (traversal 99.9 %, SQLi 95 %, SSTI 94 %, LFI 66 %, XSS 58 %, NoSQL 58 %, command injection 55 %) · **1 of 17 719** benign blocked (a `curl … \| sh` command line). Earlier figures (92.5 % / 0 of 19 215) used lists that were not recorded |
| 3.2c | WAF hold-out, never tuned on: SecLists / fuzzdb, 10 173 values (`scripts/eval_waf.sh`) | 🧪 96.2 %: commix command injection 99.2 % (the list is many variants of a few templates), XSS 89.3 %, LFI 84.0 % (34.7 % before the whole-value OS path rule), SQLi 75.0 % (72.9 % before the 2026-11 SQL rules) — **SQLi is the gap** |
| 3.2d | **WAF on the OWASP CRS regression tests** (3 730 attack requests; `tools/eval/src/bin/crs_eval.rs`) | 🧪 **54.3 % blocked overall** (11.8 % before WAF 2.0), 64.5 % for rules at paranoia level 1: multipart 100 %, session fixation 95 %, Java 76 %, generic/SSRF/Node 70 %, LFI 61 %, XSS 61 %, SQLi 46 %, RCE 35 %, PHP 30 %, RFI 27 %. Since WAF 2.0 these tests are used for development, so they are no longer a hold-out. See [RESEARCH.md](RESEARCH.md) |
| 3.2e | Zero-day-style PHP code execution (PHP tags + OS command in a multipart field such as `PHP_SESSION_UPLOAD_PROGRESS`) | ✅ blocked as `php_injection` (acceptance test in `crates/waf/tests/corpus.rs`) |
| 3.2f | Internal security review (2026-11): gateway trust boundaries, WAF bypass classes, resource exhaustion and behavioural-engine abuse | 🧪 findings fixed with regression tests (`crates/waf/tests/bypass_regressions.rs`, e2e `encoded_paths_cannot_walk_around_policies`, unit tests); see CHANGELOG `[Unreleased]` → Security. Fuzzing targets in `fuzz/` (CI: nightly, plus a weekly 24 h run with a cached corpus) |
| 3.3 | Real production traffic (shadow mode) | ⬜ needs a site; run gateway in `detect` mode or `pattern-guard replay` on access logs |
| 3.4 | Performance under load | 🧪 ~28 000 req/s, p99 ≈ 3.4 ms through the gateway (4 vCPU shared with client and upstream, `crates/gateway/examples/loadtest.rs`; measured before the 2026-11 fixes) · WAF ~15.5 µs per typical request, worst hostile request ~35–45 ms (was ~7 s) (`crates/waf/benches/inspect_bench.rs`) · ⬜ shard the engine lock |
| 3.5 | End-to-end gateway tests | ✅ 19 tests over real TCP: encoded paths vs policies, WAF, multipart uploads, business operations + logins, deny list via trusted proxy, PoW round trip + IP binding, CrowdSec mock, Suricata feed, detect mode + log, body limit, admin endpoints, custom rules, rate limits, bans + traps + unban, protocol statuses, security headers, data-leak blocking (incl. streaming past the inspection window), country policy |

## 4. Enterprise protection target: what "protect them at best" requires

An enterprise application needs protection across several attack surfaces. This table
is the bar each row must reach; the *Next step* column links it to the work above and
to [ROADMAP.md](ROADMAP.md).

| # | Threat | Pattern-Guard today | Target | Next step |
|---|---|---|---|---|
| 4.1 | SQL injection | WAF indicators + SQL tokenizer (CRS 942: 42.8 %, PL1 68.8 %) | OWASP CRS-grade coverage | Keyword-pair scores (2b.6), libinjection if the dependency is approved (2b.1), CRS 942 regression tests in CI |
| 4.2 | XSS | WAF indicators + evasion handling (CRS 941: 60.8 %) | Context-aware detection and evasion testing | HTML/attribute/JS context parsing, evasion corpus |
| 4.3 | LFI / RFI | WAF indicators, CRS file lists, URL analysis (CRS 930: 47.8 %, 931: 18.9 %) | Extensive regression corpus | CRS 930/931 + SecLists/fuzzdb hold-out as a CI gate |
| 4.4 | Command injection | WAF indicators, shell-command analyser (CRS 932: 34.8 %, commix hold-out 100 %) | Multiple encoding and evasion tests | Evasion re-scan loop (2b.2), commix hold-out as a CI gate |
| 4.5 | Credential stuffing | Behavioural ML + `[[logins]]` (failures per account across IPs, failing accounts per IP) | Account-level correlation | Breached-password check (2.5); per-account signals into the ML |
| 4.6 | Distributed bot attacks | Actor / subnet / client features | Cross-instance detection | Shared state between gateway instances (e.g. Redis or gossip), push decisions to CrowdSec (2c.11) |
| 4.7 | API abuse | Rate limits + ML + `[[operations]]` (per-account budgets, allowed sources, replay protection) | Endpoint and business-operation awareness | OpenAPI enforcement (1.9), learned per-operation baselines, spend / volume alerts |
| 4.8 | L7 DDoS | Connection caps, rate limits, bans | Adaptive distributed mitigation | Load-adaptive thresholds, cluster-wide rate limits and bans |
| 4.9 | Slowloris | Header timeout + connection cap | Resource-aware connection management | Body-read timeouts, global connection budget, shedding under memory / FD pressure |
| 4.10 | Data exfiltration | Response inspection | Sensitive-data policies and response controls | Card numbers / PII rules, masking, per-route response size and rate policies (2.10) |
| 4.11 | Zero-day attacks | Behavioural ML + WAF | Anomaly detection and application context | Per-parameter learned profiles (1.3, 2b.8), reputation-weighted scoring (2b.12) |
