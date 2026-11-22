# Pattern-Guard

**Open-source, self-hosted web application and API protection, written in Rust.**

Pattern-Guard puts a WAF, behavioural machine learning, bot challenges and shared threat
intelligence in front of your application, in one gateway and one decision per request.
The detection engine is also a Rust library you can embed directly.

```
client ─► [TLS / CDN] ─► pattern-guard-gateway ─► your app
                           │
  allow/deny/challenge lists · custom rules · country policy · protocol checks
  → honeypot traps · rate limits · business operations (per-account budgets, replay
    protection, allowed sources) · login protection
  → IP reputation (bans · CrowdSec · Suricata · Wazuh)
  → WAF (SQLi, XSS, traversal, RFI, RCE, SSRF, PHP/Java/Node code, Log4Shell, XXE,
         SSTI, NoSQL, prototype pollution, session fixation, malicious uploads)
  → behavioural ML (bots, scraping, credential stuffing, L7 floods)
  → allow · delay · proof-of-work challenge · block      (or log only: detect mode)
  responses: security headers · data-leak blocking
```

- **Repository:** `pattern-guard`

---

## Status

| Capability | Status |
|---|---|
| Runs as a reverse proxy in front of your app | ✅ `pattern-guard-gateway` |
| Blocks, challenges and delays by itself | ✅ prevent mode, or detect (shadow) mode |
| Web-attack inspection (WAF) | ✅ 17 attack classes, file-upload checks · see accuracy below |
| Working bot challenge (proof-of-work) | ✅ verified in a real headless browser |
| Behavioural bot / abuse detection (ML) | ✅ explainable model, bot score 1–99, trainable on your logs |
| Shared IP reputation | ✅ via the CrowdSec community blocklist (gateway is a CrowdSec bouncer) |
| Network-layer detections (packets) | ✅ via Suricata: its alerts are enforced at the gateway |
| Host-layer detections | ✅ via Wazuh: its alerts are enforced at the gateway; our events export to Wazuh |
| API discovery | ✅ `/inventory` of every route template seen |
| Custom firewall rules (virtual patching, admin-only areas, tool blocking) | ✅ `[[rules]]` |
| Rate limiting per route / IP / API key | ✅ `[[rate_limits]]`, 429 + Retry-After |
| Business-operation protection (checkout, transfers, payment callbacks) | ✅ `[[operations]]`: budgets per account across IPs, allowed sources, replay and race protection on transaction ids |
| Account takeover: distributed brute force, credential stuffing | ✅ `[[logins]]`: failures per account from any IP, failing accounts per IP |
| Automatic escalating bans, honeypot traps | ✅ `[bans]`, `[traps]`, `/bans` admin API |
| HTTP protocol enforcement | ✅ methods, sizes, NUL bytes, restricted extensions |
| Security headers, data-leak blocking on responses | ✅ `[response_headers]`, `[response_inspection]` |
| Country access control | ✅ `[geo]` with an IP-to-country CSV |
| Proven on real production traffic | ⬜ **not yet.** Every number below comes from synthetic traffic or public payload lists |

The full feature list, compared against open-appsec and Imperva, is in
[docs/FEATURES.md](docs/FEATURES.md).

## Measured results

| Test | Result |
|---|---|
| Behavioural ML, 1 h simulated mixed traffic, including attacks it never trained on | ~0.3 % of legitimate requests stopped, ~98.5 % of attack requests stopped |
| WAF, PayloadsAllTheThings payload lists (4 437) vs 17 719 benign values (names, English words, user agents, code lines from docs) | 81.3 % of attacks blocked: traversal 99.9 %, SSTI 94 %, SQLi 91 %, file inclusion 66 %, XSS 58 %, NoSQL 58 %, command injection 55 % · **1** benign value blocked (a `curl … \| sh` command line) |
| WAF hold-out lists never tuned on (SecLists / fuzzdb, 10 173 payloads) | 96.1 % blocked: command injection (commix) 99 %, XSS 89 %, file inclusion 84 %, SQLi 73 %. SQLi is the gap to close |
| WAF on the OWASP CRS regression tests (3 730 attack requests) | **53.6 % blocked** (rules at paranoia level 1: 64.0 %), up from 11.8 %. RFI (27 %), PHP (30 %) and RCE (35 %) are the weakest classes; see [RESEARCH.md](docs/RESEARCH.md). These tests are now used for development, so they are no longer a hold-out |
| Proof-of-work challenge in real Chromium | solved in 142 ms, clearance cookie set; curl without JS stays blocked |
| Gateway throughput, full inspection | ~28 000 req/s, p99 ≈ 3.4 ms (4 vCPU shared with client and upstream) |

WAF figures are reproducible: `scripts/fetch_eval_data.sh` downloads the datasets at pinned
commits (checksummed) and `scripts/eval_waf.sh` runs every evaluation. Earlier figures (92.5 %
of attacks, 0 of 19 215 benign values) came from lists that were not recorded.

Treat these as evidence that the mechanisms work, not as real-world accuracy guarantees.
Run detect mode on your own traffic before enforcing.

---

## Quick start: gateway

With Docker (gateway in front of a demo app):

```bash
docker compose -f deploy/docker/compose.yml up --build
curl "http://localhost:8080/?id=1%27%20OR%201=1"    # logged as SQL injection (detect mode)
```

From source:

```bash
cargo build --release -p pattern-guard-gateway
cp config/gateway.toml.example gateway.toml        # set `upstream = "http://127.0.0.1:3000"`
./target/release/pattern-guard-gateway --config gateway.toml --check
./target/release/pattern-guard-gateway --config gateway.toml
```

It starts in `mode = "detect"`. Watch `decisions.jsonl` and `http://127.0.0.1:9901/metrics`,
add exclusions, then switch to `mode = "prevent"`. Full guide: [docs/GATEWAY.md](docs/GATEWAY.md).

## Quick start: library

```rust
use pattern_guard::{Decision, Event, Guard};
use std::time::SystemTime;

let guard = Guard::from_config_path("guard.toml")?;      // an empty file works
let event = Event::new("ip:203.0.113.7", "POST", "/login", SystemTime::now())
    .with_user_agent(user_agent);
let a = guard.assess(&event);        // a.decision, a.bot_score (1–99), a.reasons
let status = handle(request);
guard.observe_response(&event, status);
```

Payload inspection on its own: the `pattern-guard-waf` crate (`Inspector::new().inspect(&request)`), also re-exported as `pattern_guard::waf`.

## Test on your own logs

```bash
cargo build --release
./target/release/pattern-guard replay /var/log/nginx/access.log      # nginx/Apache combined or JSONL
./target/release/pattern-guard train -o model.toml labelled.jsonl    # train the ML on your traffic
```

---

## How it works

**WAF** ([crates/waf](crates/waf/src)). Each value (path, query, form, JSON keys and values, XML,
cookies, user agent, referer, and every header for Log4Shell and Java payloads) is decoded the way servers
and browsers would decode it: repeated URL-decoding, `%uXXXX`, HTML entities, JS escapes,
SQL comments and Log4j lookups; base64, UTF-7 and look-alike brackets are tried too.
It is then scored per attack class from about 110 weighted indicators, OWASP CRS word
lists (OS files, shell commands, PHP functions, Java classes), a SQL tokenizer, a
shell-command analyser that undoes shell evasions, and a URL analyser that sees through
obfuscated IP addresses. Multipart bodies are parsed part by part: each field is
inspected under its name and uploads are checked for web shells and disguised file
names. One weak signal (the apostrophe
in "O'Brien", a sentence starting with "rm -rf") stays low; attack-only combinations
score high.

**Behavioural ML** ([docs/ML.md](docs/ML.md)). Streaming, constant-memory features per
client, network (/24, /56), client fingerprint and route. Routes learn baselines that an
attack can't poison quickly. Route surges count only together with client evidence, so
flash sales aren't punished. Scoring is an explainable logistic model stored as TOML,
trainable on your own labelled logs, with mimicry augmentation so it learns behaviour
rather than spoofable disguises.

**Gateway** ([docs/GATEWAY.md](docs/GATEWAY.md)):
- Fuses every layer into one decision.
- Proof-of-work challenge with an HMAC-signed, IP-bound clearance cookie.
- CrowdSec bouncer, plus Suricata and Wazuh alert feeds.
- Per-IP connection cap and slowloris timeouts.
- Async decision log with EVE/ECS-style fields, Prometheus metrics, API inventory.

## What it does not do

| | Why / alternative |
|---|---|
| Absorb volumetric L3/L4 DDoS | Needs upstream bandwidth: use your ISP, CDN or cloud scrubbing |
| Inspect raw packets itself | Suricata does; the gateway enforces Suricata's alerts |
| Monitor hosts itself | Wazuh does; the gateway enforces Wazuh's alerts |
| Run a global threat-intel network of its own | Uses CrowdSec's community network |
| CDN / caching | Different product category |

## Layout

```
crates/
  engine/    pattern-guard          behavioural engine library
             src/ml/                  streaming features, explainable model, built-in model
             src/rules/               optional threshold rules
             src/util/                route templating, decayed counters
             src/{guard,config,event,logs}.rs
  waf/       pattern-guard-waf      payload inspection: decode · indicators · lexicon (CRS lists)
                                      · sql · shell · ssrf · multipart · inspect
  cli/       pattern-guard-cli      `pattern-guard` binary: replay · train · wrap
  gateway/   pattern-guard-gateway  reverse proxy
             src/proxy/               pipeline, client IP, forwarding, responses, verify, decision log
             src/policy/              custom rules, rate limits, business operations + logins,
                                      bans + traps, protocol enforcement
             src/hardening/           security headers, data-leak blocking
             src/geo.rs               IP → country lookup and country policy
             src/challenge/           proof-of-work challenge (+ page.html)
             src/intel/               reputation store, CrowdSec bouncer, Suricata/Wazuh feeds
             src/observability/       metrics, JSON decision log, API inventory
tools/
  eval/      pattern-guard-eval     simulator + realworld_eval, gen_traffic, waf_eval, crs_eval
config/      example configs (guard.toml, gateway.toml) and demo/ configs
deploy/      Dockerfile companions (docker/gateway.toml, docker/compose.yml), systemd unit
scripts/     extract_crs_tests.py (OWASP CRS regression tests → JSONL)
docs/        documentation
```

| Docs | |
|---|---|
| `docs/` | [index](docs/README.md) · [RESEARCH](docs/RESEARCH.md) · [GATEWAY](docs/GATEWAY.md) · [DEPLOYMENT](docs/DEPLOYMENT.md) · [OPERATIONS](docs/OPERATIONS.md) · [ARCHITECTURE](docs/ARCHITECTURE.md) · [ML](docs/ML.md) · [CONFIG](docs/CONFIG.md) · [USE-CASES](docs/USE-CASES.md) · [FEATURES](docs/FEATURES.md) · [ROADMAP (product plan)](docs/ROADMAP.md) |

## Why this project

Modern backends are protected mostly by rate limiters and static rules. Those fail when
abuse stays under the limits, spreads across thousands of IPs, or mimics real browsers.
Commercial edge networks solve this with behavioural ML, but there was no reusable,
self-hosted equivalent in the Rust ecosystem.

**There isn’t a general, reusable behavior-level guard in the Rust ecosystem yet. I built this as a small contribution, hoping it might help someone or spark further ideas. If even one person finds it useful, I’d consider that a success.**

## License

MIT OR Apache-2.0.
