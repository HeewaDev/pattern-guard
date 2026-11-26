# Red-team harness (`pattern-guard-redteam`, unpublished)

An attacker against a deliberately vulnerable demo shop, run twice per scenario: through
the gateway (in process, prevent mode, [`gateway.toml`](gateway.toml)) and directly
against the shop. It measures what the gateway changes:

- **requests and time until the first bypass**: a vulnerability confirmed through the
  gateway, judged from the response the attacker received;
- **requests and time until the first ban** (from `/bans` on the admin port);
- **vulnerabilities found with the gateway vs. without it**, plus BOLA records leaked,
  blocks per layer (`/metrics`), challenges, 429s, delayed responses and proof-of-work
  solves.

Everything runs on 127.0.0.1, offline and deterministic for a seed (two runs give the same
JSON apart from timings). No LLM, no browser, no real shell, database or file.

```bash
cargo run --release -p pattern-guard-redteam                    # all scenarios, Markdown on stdout
cargo run --release -p pattern-guard-redteam -- --json redteam.json --markdown redteam.md
cargo run --release -p pattern-guard-redteam -- --scenario rotating --vuln bola --verbose
```

Options: `--seed N` (7), `--pace-ms N` (50), `--budget N` requests per run (400),
`--max-wait-secs N` / `--wait-budget-secs N` for `Retry-After` (10 / 30), `--scenario NAME`
and `--vuln NAME` (repeatable), `--config FILE` (another gateway config, with
`{{UPSTREAM}}`), `--attacker-cmd CMD` (an external attacker), `--verbose` (one line per
request on stderr). The exit status is 0 whatever the results: this measures, it does not
gate.

## The demo shop (`src/app/`)

| Endpoint | Vulnerability (simulated) | Confirmed when the response shows |
|---|---|---|
| `GET /products?id=1` | SQL injection, numeric context (a small MySQL-flavoured engine) | the hidden product or the admin's password hash |
| `GET /search?q=` | reflected XSS in the page body and a quoted attribute | markup a browser would run (`src/browser.rs`), delivered by a link or a cross-site form |
| `GET /download?file=` | path traversal: `readfile("/srv/app/files/" . $file)` on a fake file system | the fake `/etc/passwd` or `/proc/self/environ` |
| `POST /tools/ping` `host=` | command injection: `shell_exec("ping -c 1 $host 2>&1")` in a small dash-like `sh` | output of `id`, `whoami`, `uname -a` or `/etc/passwd` |
| `GET /api/orders/{id}` | BOLA / IDOR: any order for any logged-in customer | another customer's order |
| `POST /login` | brute force: the admin's password is the 12th of the attacker's list | an admin session |

Parameters are read like PHP's `$_REQUEST` with cookies (body, then query, then cookie;
JSON recognised by its first character whatever the Content-Type), percent-decoded once.
The simulators accept only what they model; anything else is an error, so the harness
errs towards "not exploited".

## Scenarios

| Name | Attacker |
|---|---|
| `targeted` | one client IP, knows the endpoints, mutates payloads when blocked |
| `scanner` | one client IP, probes common paths (`/.env`, `/.git/config`, …) first |
| `rotating` | residential-proxy rotation: a new client IP per request from 256 addresses in different /16s (sent as `X-Forwarded-For` from the trusted peer 127.0.0.1) |
| `pow-solver` | one client IP that solves proof-of-work challenges like a bot can |

The built-in attacker (`src/attack/adaptive.rs`) browses `/`, then attacks in a fixed
order: SQLi, XSS, traversal, command injection (each from hand-written base payloads,
none taken from the WAF hold-out lists and none equal to one of their lines, checked
against the pinned lists), BOLA (reads up to 20 foreign orders), brute
force. When blocked it retries with mutations: percent-encoding, case, comments and
whitespace, versioned comments, `||`/`&&`, other tautologies, `/` instead of a space,
entities, JavaScript obfuscation, quotes and `${IFS}` in commands, globbing, absolute
paths, other separators, parameter pollution, form / JSON / JSON-as-text / multipart /
cookie. A small bandit prefers mutations that got through before. It paces its requests
(±25 %), waits for `Retry-After` within its budget, retries a challenge from a new address
when it rotates, and a single-address attacker stops once a plain `GET /` is blocked
("locked out": banned, or blocked by the behavioural engine). Because of the fixed order, a single-IP attacker that is banned during SQLi
never tries the rest; use `--vuln` to measure one vulnerability alone.

## Plugging in another attacker

- In Rust: implement `attack::Strategy` (`next() -> Option<Probe>`, `observe(&Probe,
  &Observation)`).
- Any program: `--attacker-cmd CMD` runs it with `sh -c` and talks JSON lines on its stdin
  / stdout (`src/attack/external.rs` documents the messages: `start` with the targets and
  client IPs, then a `response` for every `request` it sends, until `done`). This is where
  an LLM agent or a Playwright-driven browser plugs in; the harness still judges the
  responses with the same oracle and measures the same numbers.

## Reading the numbers

The demo shop is deliberately weak and the gateway config is one plausible deployment.
Numbers depend on the pace (bans count 10 blocks in 60 s), the request budget, the
campaign order and the seed. Compare runs with the same settings. Hold-out payload lists
are not used, and red-team results are not a reason to tune detection on these payloads
without the usual before/after measurements (`waf_eval`, `crs_eval`, benign corpus).
