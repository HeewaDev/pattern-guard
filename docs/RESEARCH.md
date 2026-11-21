# Research notes: OWASP CRS and open-appsec

What two mature open-source WAFs do, what our WAF does differently, and what we will adopt.
These notes come from reading the source:

- **OWASP CRS**: github.com/coreruleset/coreruleset, 4.31.0-dev (commit 2de4afc, Nov 2026), Apache-2.0.
- **open-appsec**: github.com/openappsec/openappsec, Apache-2.0 code and basic model.

Paths below refer to those repositories. Items marked *unverified* were not confirmed in code.

---

## 1. Where we stand: CRS regression benchmark

`tools/eval/src/bin/crs_eval.rs` runs CRS's own regression tests through our WAF
(`scripts/extract_crs_tests.py` extracts them; 5 247 tests, of which 3 730 are attack
requests in categories 930–944).

| CRS category | Attack tests | Blocked before WAF 2.0 | Blocked now (score ≥ 7) |
|---|---|---|---|
| 930 local file inclusion | 67 | 23.9 % | 50.7 % |
| 931 remote file inclusion | 37 | 10.8 % | 18.9 % |
| 932 remote code execution | 793 | 9.1 % | 34.9 % |
| 933 PHP injection | 327 | 1.8 % | 30.0 % |
| 934 generic (SSRF, SSTI, Node, prototype pollution) | 240 | 7.5 % | 69.6 % |
| 941 XSS | 209 | 34.9 % | 60.8 % |
| 942 SQL injection | 871 | 20.0 % | 42.8 % |
| 943 session fixation | 43 | 4.7 % | 95.3 % |
| 944 Java (deserialisation, Log4Shell, class names) | 1 143 | 6.6 % | 75.8 % |
| **All attack categories** | **3 730** | **11.8 %** | **53.4 %** |

Rules at paranoia level 1, the CRS default: 63.5 % of 2 082 attack tests blocked.
Multipart attacks (922): 100 % of 27; protocol enforcement (920): 16 %.

**Since WAF 2.0 these tests are a development set.** The detectors added in WAF 2.0 (CRS
word lists, base64 / UTF-7 decoding, Java, SQL tokenizer, XSS evasions, shell and URL
analysis, multipart parsing, Node / Perl / expression language, prototype pollution,
session fixation) were built by studying the missed
tests, so the numbers above are no longer a blind measurement. The blind checks are the
SecLists / fuzzdb hold-out lists (FEATURES.md §3.2c) and the 19 215-value benign corpus,
which stayed at 0 false blocks through every step. Each WAF 2.0 commit message records
its before/after numbers.

How to read the original (11.8 %) measurement:

* **The gap is real.** There are clear misses:
  - namespaced script tags (`<x:script src="data:,alert(1)">`)
  - UTF-7 `+ADw-script+AD4-`
  - JSFuck-style `[].map.call`${eval}``
  - `' + sleep(20) + '`
  - `select 1 FROM(select count(*),concat((select … user(` scored only 5
  - whole families we don't model at all: PHP, Java deserialisation, protocol attacks
* **Some of it is a design difference.** CRS runs these tests at paranoia level 4, where
  single keywords such as `substr(`, `SCHEMA_NAME` or `sysdate(` are expected to fire. Our
  engine deliberately doesn't block a lone keyword. That is why it blocked 0 of 19 215
  benign values, but it caps the score on this benchmark.
* **CRS negatives are not guaranteed benign.** A negative test only says that one specific
  rule must stay silent. We block 4.3 % of them; read that as a rough signal, not as a
  false-positive rate.

This benchmark replaces our own payload lists as the main WAF yardstick from now on.

---

## 2. OWASP CRS: how it works

**Anomaly scoring** (`rules/REQUEST-901-INITIALIZATION.conf`, `REQUEST-949-BLOCKING-EVALUATION.conf`)
- Rule severity maps to points: CRITICAL 5, ERROR 4, WARNING 3, NOTICE 2.
- Points are **summed over the whole request**, across all locations and rules. The
  inbound threshold is 5, so one critical rule blocks.
- Per-class sub-scores are kept for logging.

**Paranoia levels 1–4** (`crs-setup.conf.example`)
- Every rule has a level: PL1 215 rules, PL2 89, PL3 34, PL4 9.
- Detection and blocking levels are separate: you can log PL3 while blocking only PL1.
- Higher levels add keyword lists and character-count rules. For example 942430–942432
  count SQL special characters and fire at ≥ 12 (PL2), ≥ 6 (PL3) or ≥ 2 (PL4).

**Rule families**

| ID | Detects |
|---|---|
| 911 | HTTP methods outside the allow list |
| 913 | Scanner user agents |
| 920 | Protocol enforcement (68 rules): malformed request line, CL+TE, null and non-printable bytes, UTF-8 and full-width abuse, multiple URL encoding, argument count and length limits, content-type and charset allow lists, restricted extensions and headers |
| 921 | Request smuggling, response splitting, CRLF header injection, LDAP injection, HTTP parameter pollution |
| 930 | LFI |
| 931 | RFI |
| 932 | Unix, Windows and PowerShell RCE, shellshock |
| 933 | PHP |
| 934 | Node.js, prototype pollution, SSTI, SSRF and cloud metadata |
| 941 | XSS (libinjection plus patterns, JSFuck, AngularJS, UTF-7) |
| 942 | SQLi (68 rules) |
| 943 | Session fixation |
| 944 | Java (deserialisation magic bytes, Log4Shell, class names) |
| 950–956 | Response leakage: SQL, PHP, Java, IIS and Ruby errors, directory listings, web shells |

**Transformations** (usage counts across all rules):

| Transformation | Uses |
|---|---|
| urlDecodeUni | 141 |
| jsDecode | 38 |
| htmlEntityDecode | 35 |
| utf8toUnicode | 32 |
| removeNulls | 27 |
| cssDecode | 23 |
| cmdLine | 16 |
| removeWhitespace | 12 |
| replaceComments | 9 |
| normalizePath / normalizePathWin | 8 + 4 |
| escapeSeqDecode | 7 |
| base64Decode | 4 |

Unlike us, CRS decodes **once** and treats double encoding as its own signal (920230).
Quote and backslash evasion in shell commands (`c'a't`, `c\at`) is handled inside the
regexes: the build tool inserts `[\\'"]*` between characters.

**libinjection.** 942100 (`@detectSQLi`) and 941100 (`@detectXSS`) are PL1 CRITICAL, so
each blocks on its own. Pure-Rust ports exist on crates.io: `libinjectionrs` and
`barbacane-libinjection` (BSD-3). Their fidelity is *unverified*.

**Data files** (`rules/*.data`, `regex-assembly/include/*.ra`; Apache-2.0)

| File | Entries |
|---|---|
| lfi-os-files.data | 1 096 |
| unix-shell.data | 758 |
| restricted-files.data | 639 |
| php-function-names | 233 |
| ssrf.data (incl. decimal, octal and hex IP forms) | 103 |
| java-classes | 68 |
| windows-commands.ra | 301 |
| sql-injection-function-names.ra | 279 |
| url-schemes.ra | ≈120 |
| sql-errors.data (response) | 172 |
| php-errors.data (response) | 1 801 |

`regex-assembly/exclude/*.ra` lists, per paranoia level, the words that cause false
positives.

**Test and false-positive infrastructure**
- `tests/regression/tests/**.yaml` holds the go-ftw tests (5 247), described in §1.
- `.github/workflows/quantitative.yaml` is a false-positive gate that runs on every PR. It
  sends 100 000 English news sentences (Leipzig `eng_news_2023_100K`) as a query parameter
  and counts false positives per rule and per paranoia level.

**Exclusions** (WordPress, Drupal and Nextcloud plugins)
- Exclusions are mostly *(rule or tag) × target*, applied when a path matches. Example: on
  `/wp-login.php`, all rules are removed from `ARGS:pwd`.
- Conditions on one parameter are guarded against parameter pollution (the parameter must
  appear exactly once).
- Each exclusion package has its own enable flag.

---

## 3. open-appsec: how its WAAP engine works

Paths are under `components/security_apps/waap/waap_clib/` unless noted.

**Pipeline.** `Waf2Engine.cc` passes each value through `DeepParser.cc` to
`WaapScanner.cc`, then `WaapAssetState::apply`.

**Recursive parsers** (`DeepParser.cc`, depth ≤ 7):
- URL-encoded, JSON, XML, HTML, multipart, GraphQL, PHP-serialized, gzip, PDF, binary files.
- Delimiter splitting (`| ; * , &`) and percent-encoding.
- Base64 detection; decoded values get a `#base64` key marker.
- Values are typed (free text, HTML, file path, URL, random token) via
  `format_types_regex_list`.

**Normalisation** (`WaapAssetState.cc` `unescape`):
1. UTF-7 decode
2. `unquote_plus`
3. HTML entities
4. C escapes
5. `unquote_plus` again
6. `\u` decode
7. lowercase

**Indicators**
- An Aho-Corasick precondition stage picks which regexes need to run.
- The regex lists are words (1 177), accuracy keywords (306) and patterns (93), from
  `resources/1.data`.
- Named groups become keywords.

**Evasion re-scan loop** (`WaapAssetState::apply`). Each trigger decodes the value,
re-scans it, and keeps the evasion keyword only if new keywords appear. The triggers:
- `[aa]` command collapse
- quote removal and comment removal
- broken or overlong UTF-8 (`%c0%ae`)
- hex `0x…`, `2f` → `/`
- tabs, the Windows `^` caret, `\u` and `\x`
- bash backslash (`/\b\i\n/\s\h`)
- a second URL decode

Split values are also re-scanned with a `;` or `|` prefix, for command-injection context.

**Synthetic indicators.** `repetition` (more than 100 repeated characters) and `probing`
(the value is almost entirely keywords: keyword count + 2 > word count).

**Scoring** (`WaapScanner.cc`, `WaapScores.cc`, `resources/2.data`):
- Every keyword and every **sorted pair of keywords** has a learned score: 720 singles
  and 2 994 pairs.
- Scores combine with a saturating function: start at 1, then for each score x,
  `s = 10 − (10 − s)·10/(x/3 + 10)`.
- An optional sparse logistic model exists, but the open-source data ships without its
  coefficients.

**Final score** (`D2Main.cc`)
- `min(2·score·(10 − 0.8·relRep)/10 · fpMitigation/10, 10)`, where `relRep` is the source's
  learned reputation.
- Threat levels: < 1 info, < 3 low, < 6 medium, ≥ 6 high. The default policy blocks high.

**Unsupervised learning**
- `BehaviorAnalysis.cc` keeps IP, UA and IP+UA reputation.
- `FpMitigation.cc` labels events as true or false positives by reputation.
- `ScoreBuilder.cc` re-weights keywords from those labels.
- `KeywordIndicatorFilter.cc` stops counting a keyword for a parameter once ≥ 3 sources
  have sent it over ≥ 5 two-hour windows (ratio ≥ 0.8).
- `TypeIndicatorsFilter.cc` learns each parameter's value type.
- A file-path parameter that suddenly receives a URL scores 10.

**Other modules**
- CSRF (`Csrf.cc`).
- Open redirect (`WaapOpenRedirect.cc`): URLs seen in the request are compared with the
  `Location` header.
- Error disclosure (`resp_body_*` lists).
- User limits (`UserLimitsPolicy.h`): URL 32 KiB, header 100 KiB, object depth 40.
- Rate and error limiting.
- Overrides with an "ignore indicator" behaviour (`WaapOverride.h`).
- IPS: Snort 3 rules converted to a native keyword language
  (`components/security_apps/ips`, `components/utils/keywords`).
- CrowdSec via its intelligence service (`components/security_apps/layer_7_access_control`).
- The nginx attachment uses shared-memory ring queues and fails open on a 50 ms timeout
  (`core/shmem_ipc`, `components/attachment-intakers/nginx_attachment`).

**Licence.** The code and basic model (`resources/1.data`, `2.data`, `8.data`) are Apache-2.0.
The advanced model is under a separate ML licence and is not in the repo, so we don't
touch it. The regexes use lookbehind, atomic groups and possessive quantifiers, which
Rust's `regex` crate can't compile; they would need `fancy-regex` or rewriting.

*Unverified:* the anti-bot JavaScript (not in the repo), an OpenAPI validator (only the
policy plumbing is present), ThreatCloud internals, and the Envoy, Kong and APISIX
filters (they live in other repos).

---

## 4. What we adopt (feeds ROADMAP milestone M2)

Ordered by expected impact on the CRS benchmark and on our own hold-out lists.

| # | Technique | From | Rust sketch |
|---|---|---|---|
| 1 | **libinjection SQLi/XSS** as a standalone blocking indicator | CRS 942100 / 941100 | `libinjectionrs` (BSD-3) behind a feature flag, after a fidelity check against the CRS tests |
| 2 | **Evasion re-scan loop**: decode only when a trigger is present, keep only if new indicators appear | open-appsec `WaapAssetState::apply` | `for d in DECODERS { if d.triggers(v) { let u = d.decode(v); if scan(&u).new_over(&base) { merge } } }` |
| 3 | **CRS word lists** (OS files, Unix shell, Windows commands, SQL functions, PHP functions, Java classes, SSRF) with CRS exclude lists | CRS `rules/*.data`, `regex-assembly/include` | `aho_corasick` automata built at startup from vendored lists with attribution |
| 4 | **One anomaly score per request**, with per-class sub-scores and severity points | CRS 901/949 | sum the findings across locations; block at a threshold |
| 5 | **Paranoia levels**: tag every indicator PL1–4; separate detection and blocking levels | CRS | `Indicator { pl }`, `waf.blocking_pl`, `waf.detection_pl` |
| 6 | **Keyword-pair scores and the saturating combiner** instead of plain weight sums | open-appsec `WaapScores.cc` | learn pair scores from the CRS tests + benign corpus with `pattern-guard train`; `s = 10 − (10−s)·10/(x/3+10)` |
| 7 | **Recursive parsing**: base64, JSON-in-string, delimiter split, depth limit | open-appsec `DeepParser.cc` | parser stack emitting `(key_path, value)` |
| 8 | **Per-parameter learned value types** and keyword-confidence filters, so thresholds can drop without more false positives | open-appsec `TypeIndicatorsFilter.cc`, `KeywordIndicatorFilter.cc` | per `(route, param)`: type counts, plus decayed per-keyword source counts in the existing feature engine |
| 9 | **Protocol enforcement** (null and non-printable bytes, double encoding, CL+TE, CRLF, parameter pollution, restricted extensions) | CRS 920/921 | low-point indicators in the gateway |
| 10 | **Quantitative false-positive gate** in CI: 100 000 English sentences as a parameter, per paranoia level | CRS `quantitative.yaml` | an example over a sentence corpus, plus a CI threshold |
| 11 | **Reputation-weighted final score**: our behavioural bot score scales the WAF score | open-appsec `D2Main.cc` | `final = waf × f(bot_score)` |
| 12 | **Response inspection** (error disclosure, web shells) and "ignore indicator" exceptions | CRS 95x, open-appsec `resp_body_*`, `WaapOverride.h` | response RegexSet in the gateway; exclusions per indicator × target |

Rules for this work:
- Vendored lists keep their Apache-2.0 notices.
- Nothing is copied from the open-appsec advanced model.
- Every change is measured on the CRS benchmark **and** on the benign corpora, and the
  before/after numbers go in the commit message.
