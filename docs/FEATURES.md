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
| 1.1 | ML-based WAF for web apps & APIs (OWASP Top 10, zero-day) | Community | 🧪 behavioural ML (`src/features.rs`, `src/model.rs`) · 🧪 payload scoring engine (`src/waf.rs`, see §3) | Raise hold-out SQLi / LFI / command-injection detection; validate on a labelled real dataset |
| 1.2 | Supervised model trained offline on malicious/benign requests | Community (basic) / Production (advanced) | 🧪 behaviour model trained via `pattern-guard train` · ⬜ supervised *payload* model | Train a payload classifier on top of `waf.rs` indicators |
| 1.3 | Unsupervised model learned in the protected environment | Community | 🧪 per-route learned baselines (rate, failures, new clients) · ⬜ per-parameter value profiles (length, charset, type) | Add per-route/param profiles to `waf.rs` |
| 1.4 | Two-phase evaluation: attack indicators → contextual scoring | Community | ✅ WAF indicators + behavioural risk + reputation fused into one decision (`gateway/src/proxy.rs`) | |
| 1.5 | Request decoding, JSON/XML extraction | Community | ✅ multi-pass URL/`%u`/HTML/JS decoding, SQL comments, JSON walk, form, XML/text (`src/waf.rs`) | Add multipart part-by-part parsing |
| 1.6 | IPS engine (Snort 3.0 signatures) | Community | 🔌✅ Suricata alongside; gateway tails `eve.json` and blocks alerting IPs (`gateway/src/feeds.rs`, e2e-tested) | |
| 1.7 | Automatic IPS signature updates | Premium | 🔌 via Suricata-update / ET Open | Document |
| 1.8 | Behavioural anti-bot | Premium | 🧪 behaviour ML + bot score 1–99 · ✅ proof-of-work challenge with IP-bound HMAC cookie (verified in real headless Chromium: solved in 142 ms; curl stays blocked) | Verified good bots (2.4) |
| 1.9 | API schema enforcement (OpenAPI) | Premium | ⬜ | Load OpenAPI spec; validate method/path/params/body types per route template |
| 1.10 | Block malicious IPs (ThreatCloud reputation) | Enterprise | 🔌✅ CrowdSec bouncer: community blocklist + local decisions, ban → block, captcha → challenge (`gateway/src/crowdsec.rs`, tested against a mock LAPI) | Test against a live CrowdSec |
| 1.11 | Block anonymizers & Tor | Enterprise | ⬜ | Load Tor exit list + VPN/hosting ASN lists as features/blocks |
| 1.12 | IP-level access control on every request | Community | ✅ allow / deny / challenge CIDR lists, trusted-proxy client-IP resolution | |
| 1.13 | CrowdSec integration | Community | ✅ (as bouncer) · ⬜ push our decisions to CrowdSec (`POST /v1/alerts`) | |
| 1.14 | Rate limiting | (docs; edition unverified) | ✅ explicit rules + adaptive surge detection, enforced by the gateway; per-IP connection cap | |
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
| 2.1 | WAF with managed signatures | 🧪 `src/waf.rs` scoring engine, 9 attack classes · ⬜ optional Coraza + OWASP CRS second opinion | |
| 2.2 | Custom security rules | ✅ rule thresholds, WAF path/param exclusions, IP lists · ⬜ per-route custom match rules | |
| 2.3 | Virtual patching | ⬜ | Custom rules per route template |
| 2.4 | Advanced bot protection | 🧪 behaviour ML, fingerprints · 🚧 challenge · ⬜ verified good bots (reverse DNS), headless-browser signals | |
| 2.5 | Account takeover protection | 🧪 credential stuffing detection (failure ratios, route failure surge) · ⬜ breached-password check (k-anonymity), per-username tracking | |
| 2.6 | Application-layer DDoS protection | 🧪 surge detection + blocking · ✅ per-IP connection cap, header-read timeout (slowloris), body size limit | |
| 2.7 | Network-layer (L3/L4) volumetric DDoS scrubbing | ❌ | Needs upstream bandwidth/scrubbing centres. Self-hosted: put behind a CDN/ISP scrubbing service |
| 2.8 | API discovery & inventory | ✅ `/inventory` on the admin port: route templates, volume, blocks, status codes | |
| 2.9 | API schema protection | ⬜ | Same as 1.9 |
| 2.10 | Sensitive data exposure detection (responses) | ⬜ | Scan responses for card numbers, keys, stack traces |
| 2.11 | Client-side protection (third-party JS, CSP) | ⬜ | Inject CSP headers + collect reports |
| 2.12 | RASP (in-app runtime protection) | 🧪 library mode is in-process · ⬜ sink-level hooks | Long-term |
| 2.13 | Threat intelligence / IP reputation | 🔌✅ CrowdSec | |
| 2.14 | Attack analytics (grouping incidents) | ⬜ | Cluster decision log by actor/fingerprint/time |
| 2.15 | SIEM export | ✅ EVE/ECS-like JSON log · 🔌 Wazuh/Elastic (example rule in GATEWAY.md, untested against live Wazuh) | |
| 2.16 | CDN / caching | ❌ | Different product category |
| 2.17 | Host security monitoring | 🔌✅ Wazuh alongside; gateway tails `alerts.json` and blocks `data.srcip` | |
| 2.18 | Network IDS | 🔌✅ Suricata (see 1.6) | |

## 3. Proof

| # | Item | Status |
|---|---|---|
| 3.1 | Behaviour ML on synthetic mixed traffic (incl. unseen attacks) | 🧪 ~0.3% FP / ~98.5% detection (`examples/realworld_eval.rs`) |
| 3.2a | WAF, own corpus (`tests/waf_corpus.rs`, tuned against) | 🧪 75/77 attacks blocked, 0/62 tricky benign blocked |
| 3.2b | WAF, PayloadsAllTheThings (MIT) + benign: 4.9k names, 10k words, 2.1k doc lines with code, 2.1k user agents (used to fix *categories*) | 🧪 85.4% of 1 380 attacks blocked · **0 of 19 215** benign blocked |
| 3.2c | WAF hold-out, never tuned on: SecLists / fuzzdb (`waf_eval` example) | 🧪 XSS 83–94%, SQLi 50%, LFI 29%, commix command injection 24% — **the real gap** |
| 3.3 | Real production traffic (shadow mode) | ⬜ needs a site; run gateway in `detect` mode or `pattern-guard replay` on access logs |
| 3.4 | Performance under load | 🧪 ~32 000 req/s, p99 ≈ 3 ms through the gateway (4 vCPU shared with client and upstream, `gateway/examples/loadtest.rs`) · ⬜ shard the engine lock |
| 3.5 | End-to-end gateway tests | ✅ 9 tests over real TCP: WAF, deny list via trusted proxy, PoW round trip + IP binding, CrowdSec mock, Suricata feed, detect mode + log, body limit, admin endpoints |
