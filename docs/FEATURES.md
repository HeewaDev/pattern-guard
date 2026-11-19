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
| 1.1 | ML-based WAF for web apps & APIs (OWASP Top 10, zero-day) | Community | 🧪 behavioural ML (`crates/engine/src/ml/`) · 🧪 payload scoring engine (`crates/waf`, see §3) | Raise hold-out SQLi / LFI / command-injection detection; validate on a labelled real dataset |
| 1.2 | Supervised model trained offline on malicious/benign requests | Community (basic) / Production (advanced) | 🧪 behaviour model trained via `pattern-guard train` · ⬜ supervised *payload* model | Train a payload classifier on top of `waf.rs` indicators |
| 1.3 | Unsupervised model learned in the protected environment | Community | 🧪 per-route learned baselines (rate, failures, new clients) · ⬜ per-parameter value profiles (length, charset, type) | Add per-route/param profiles to `waf.rs` |
| 1.4 | Two-phase evaluation: attack indicators → contextual scoring | Community | ✅ WAF indicators + behavioural risk + reputation fused into one decision (`crates/gateway/src/proxy/`) | |
| 1.5 | Request decoding, JSON/XML extraction | Community | ✅ multi-pass URL/`%u`/HTML/JS decoding, SQL comments, JSON walk, form, XML/text (`crates/waf`) | Add multipart part-by-part parsing |
| 1.6 | IPS engine (Snort 3.0 signatures) | Community | 🔌✅ Suricata alongside; gateway tails `eve.json` and blocks alerting IPs (`crates/gateway/src/intel/feeds.rs`, e2e-tested) | |
| 1.7 | Automatic IPS signature updates | Premium | 🔌 via Suricata-update / ET Open | Document |
| 1.8 | Behavioural anti-bot | Premium | 🧪 behaviour ML + bot score 1–99 · ✅ proof-of-work challenge with IP-bound HMAC cookie (verified in real headless Chromium: solved in 142 ms; curl stays blocked) | Verified good bots (2.4) |
| 1.9 | API schema enforcement (OpenAPI) | Premium | ⬜ | Load OpenAPI spec; validate method/path/params/body types per route template |
| 1.10 | Block malicious IPs (ThreatCloud reputation) | Enterprise | 🔌✅ CrowdSec bouncer: community blocklist + local decisions, ban → block, captcha → challenge (`crates/gateway/src/intel/crowdsec.rs`, tested against a mock LAPI) | Test against a live CrowdSec |
| 1.11 | Block anonymizers & Tor | Enterprise | ⬜ | Load Tor exit list + VPN/hosting ASN lists as features/blocks |
| 1.12 | IP-level access control on every request | Community | ✅ allow / deny / challenge CIDR lists, custom rules on IP / not-IP, country policy, trusted-proxy client-IP resolution | |
| 1.13 | CrowdSec integration | Community | ✅ (as bouncer) · ⬜ push our decisions to CrowdSec (`POST /v1/alerts`) | |
| 1.14 | Rate limiting | (docs; edition unverified) | ✅ per-route token buckets keyed by IP, IP+route or API-key header (`[[rate_limits]]`, 429 + Retry-After) · adaptive surge detection · per-IP connection cap | |
| 1.15 | File upload security | Enterprise (third-party listings; unverified) | ⬜ | Multipart: type/extension/magic-byte checks, size limits, optional ClamAV hook |
| 1.16 | Deploy as NGINX / Kong / APISIX / Envoy / Istio attachment | Community | ✅ standalone reverse proxy (`gateway/`) · ⬜ nginx `auth_request` / Envoy `ext_authz` decision endpoint · ⬜ WebSocket passthrough · ⬜ HTTP/2 | |
| 1.17 | Kubernetes ingress / Helm | Community | ⬜ | Container image + Helm chart |
| 1.18 | Docker / Linux installer | Community | ⬜ | Dockerfile, systemd unit |
| 1.19 | Gateway VM for AWS / Azure / VMware | Enterprise | ⬜ | Later: image build scripts |
| 1.20 | Declarative config files | Community | ✅ `guard.toml`, `gateway.toml` (validated, `--check`) | |
| 1.21 | Web management UI (SaaS) | Community (3 agents) | ⬜ | Local dashboard on the admin port first |
| 1.22 | Log storage / event viewer | Community 10K/mo · Premium 1M/mo | ✅ async JSON decision log (EVE/ECS-like, `srcip` for Wazuh) · ⬜ local viewer | |
| 1.23 | Monitor-only (detect) vs prevent mode | Community | ✅ `mode = "detect" \| "prevent"`, `would_mitigate` metric | |
| 1.24 | Playgrounds / virtual labs | Community | 🧪 traffic simulator + `realworld_eval` | Publish a demo docker-compose |
| 1.25 | Independent security audit | Done for open-appsec (2022) | ⬜ | After 1.0 |
| 1.26 | Enterprise 24×7 support | Enterprise | ❌ (project, not a company) | |

## 2. Imperva capability areas

| # | Capability | Pattern-Guard | Notes |
|---|---|---|---|
| 2.1 | WAF with managed signatures | 🧪 `crates/waf` scoring engine, 9 attack classes · ⬜ optional Coraza + OWASP CRS second opinion | |
| 2.2 | Custom security rules | ✅ `[[rules]]`: path, method, host, IP, country, UA, query, header conditions; allow / block / challenge / delay / log / skip_waf | |
| 2.3 | Virtual patching | ✅ via `[[rules]]` (block a vulnerable route / parameter pattern until patched) | |
| 2.4 | Advanced bot protection | 🧪 behaviour ML, fingerprints · 🚧 challenge · ⬜ verified good bots (reverse DNS), headless-browser signals | |
| 2.5 | Account takeover protection | 🧪 credential stuffing detection (failure ratios, route failure surge) · ⬜ breached-password check (k-anonymity), per-username tracking | |
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
| 2b.1 | libinjection SQLi/XSS detection | ⬜ | CRS 942100 / 941100 (`libinjectionrs`, BSD-3) |
| 2b.2 | Evasion re-scan loop (decode only on trigger, keep if new indicators) | ⬜ | open-appsec `WaapAssetState::apply` |
| 2b.3 | Large attack word lists (OS files, shell, Windows, SQL/PHP functions, Java classes, SSRF) | ⬜ | CRS `rules/*.data` (Apache-2.0) |
| 2b.4 | One anomaly score per request, per-class sub-scores | ⬜ | CRS 901/949 |
| 2b.5 | Paranoia levels 1–4, separate detection/blocking level | ⬜ | CRS |
| 2b.6 | Keyword-pair scores + saturating combiner | ⬜ | open-appsec `WaapScores.cc` |
| 2b.7 | Recursive parsing: multipart per part, base64, JSON-in-string, delimiters | ⬜ | open-appsec `DeepParser.cc` |
| 2b.8 | Per-parameter learned value types and keyword-confidence filtering | ⬜ | open-appsec `TypeIndicatorsFilter.cc`, `KeywordIndicatorFilter.cc` |
| 2b.9 | PHP code injection (tags, functions, superglobals, wrappers, serialized objects) | ⬜ (CRS 933: 1.8 %) | CRS 933, `php-function-names` |
| 2b.10 | Java attacks (deserialization magic bytes incl. base64, class names) | ⬜ (CRS 944: 6.6 %) | CRS 944, `java-classes.data` |
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
| 2c.12 | Verified good bots (reverse DNS) | Cloudflare, BunkerWeb | ⬜ |
| 2c.13 | Tor / anonymiser / DNSBL blocking | open-appsec Enterprise, BunkerWeb | ⬜ |
| 2c.14 | Path-level authentication (basic auth / OIDC) | BunkerWeb, SafeLine | ⬜ |
| 2c.15 | Per-path body limits, upload filtering | SafeLine, open-appsec | 🧪 global `max_body_bytes` · ⬜ per path, file-type checks |
| 2c.16 | WebSocket, HTTP/2, TLS termination, caching, compression | BunkerWeb, SafeLine (nginx-based) | ⬜ (TLS via a front proxy today) |
| 2c.17 | Hot reload of config without dropping connections | all of the above | ⬜ |
| 2c.18 | Web UI for decisions, bans and tuning | BunkerWeb, SafeLine, open-appsec | ⬜ |

## 3. Proof

| # | Item | Status |
|---|---|---|
| 3.1 | Behaviour ML on synthetic mixed traffic (incl. unseen attacks) | 🧪 ~0.3% FP / ~98.5% detection (`tools/eval/src/bin/realworld_eval.rs`) |
| 3.2a | WAF, own corpus (`crates/waf/tests/corpus.rs`, tuned against) | 🧪 75/77 attacks blocked, 0/62 tricky benign blocked |
| 3.2b | WAF, PayloadsAllTheThings (MIT) + benign: 4.9k names, 10k words, 2.1k doc lines with code, 2.1k user agents (used to fix *categories*) | 🧪 85.4% of 1 380 attacks blocked · **0 of 19 215** benign blocked |
| 3.2c | WAF hold-out, never tuned on: SecLists / fuzzdb (`waf_eval` tool) | 🧪 XSS 83–94%, SQLi 50%, LFI 29%, commix command injection 24% — **the real gap** |
| 3.2d | **WAF on the OWASP CRS regression tests** (3 730 attack requests, never tuned on; `tools/eval/src/bin/crs_eval.rs`) | 🧪 **11.8 % blocked overall**: XSS 35 %, SQLi 20 %, LFI 24 %, RCE 9 %, PHP 1.8 %, Java 6.6 %. The main gap; see [RESEARCH.md](RESEARCH.md) |
| 3.2e | Zero-day-style PHP code execution (PHP tags + OS command in a multipart field such as `PHP_SESSION_UPLOAD_PROGRESS`) | ⬜ only logged (score 4), not blocked |
| 3.3 | Real production traffic (shadow mode) | ⬜ needs a site; run gateway in `detect` mode or `pattern-guard replay` on access logs |
| 3.4 | Performance under load | 🧪 ~32 000 req/s, p99 ≈ 3 ms through the gateway (4 vCPU shared with client and upstream, `crates/gateway/examples/loadtest.rs`) · ⬜ shard the engine lock |
| 3.5 | End-to-end gateway tests | ✅ 16 tests over real TCP: WAF, deny list via trusted proxy, PoW round trip + IP binding, CrowdSec mock, Suricata feed, detect mode + log, body limit, admin endpoints, custom rules, rate limits, bans + traps + unban, protocol statuses, security headers, data-leak blocking (incl. streaming past the inspection window), country policy |

## 4. Enterprise protection target: what "protect them at best" requires

An enterprise application needs protection across several attack surfaces. This table
is the bar each row must reach; the *Next step* column links it to the work above and
to [ROADMAP.md](ROADMAP.md).

| # | Threat | Pattern-Guard today | Target | Next step |
|---|---|---|---|---|
| 4.1 | SQL injection | WAF indicators | OWASP CRS-grade coverage | libinjection (2b.1), SQL tokenizer / keyword pairs (2b.6), CRS 942 regression tests in CI |
| 4.2 | XSS | WAF indicators | Context-aware detection and evasion testing | HTML/attribute/JS context parsing, libinjection XSS, evasion corpus |
| 4.3 | LFI / RFI | WAF indicators, CRS file lists, URL analysis | Extensive regression corpus | CRS 930/931 + SecLists/fuzzdb hold-out as a CI gate |
| 4.4 | Command injection | WAF indicators, shell-command analyser | Multiple encoding and evasion tests | Evasion re-scan loop (2b.2), commix hold-out as a CI gate |
| 4.5 | Credential stuffing | Behavioural ML | Account-level correlation | Per-username / per-account failure tracking, breached-password check (2.5) |
| 4.6 | Distributed bot attacks | Actor / subnet / client features | Cross-instance detection | Shared state between gateway instances (e.g. Redis or gossip), push decisions to CrowdSec (2c.11) |
| 4.7 | API abuse | Rate limits + ML | Endpoint and business-operation awareness | OpenAPI enforcement (1.9), per-operation limits and baselines (login, checkout, search) |
| 4.8 | L7 DDoS | Connection caps, rate limits, bans | Adaptive distributed mitigation | Load-adaptive thresholds, cluster-wide rate limits and bans |
| 4.9 | Slowloris | Header timeout + connection cap | Resource-aware connection management | Body-read timeouts, global connection budget, shedding under memory / FD pressure |
| 4.10 | Data exfiltration | Response inspection | Sensitive-data policies and response controls | Card numbers / PII rules, masking, per-route response size and rate policies (2.10) |
| 4.11 | Zero-day attacks | Behavioural ML + WAF | Anomaly detection and application context | Per-parameter learned profiles (1.3, 2b.8), reputation-weighted scoring (2b.12) |
