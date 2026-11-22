# How the adaptive engine works (and how to train it on your traffic)

```
request ──► features (28 numbers) ──► model ──► risk 0–1 ──► decision + reasons
   ▲              ▲                                         
   │       streaming state: actor · subnet · fingerprint · route baseline
response status ──┘  (observe_response)
```

## 1. Features

Every request updates constant-size, exponentially decaying state for four entities and
produces one feature vector (`pattern_guard::FEATURE_NAMES`):

| Entity | What it catches | Examples |
|---|---|---|
| **actor** (IP or user) | single-source abuse | burst & burst beyond a page load, volume, failure ratio (overall and on this route), route concentration, low route diversity, novel objects, sequential id enumeration, timer-like pacing, POST without any prior GET, known scanner paths |
| **subnet** (/24, /56) | attacks spread across one network | new-client churn, failure ratio |
| **client fingerprint** (JA3/JA4 or header hash; else user agent) | botnets that rotate IPs but run one tool | failure ratio, share of brand-new IPs, route concentration, enumeration |
| **route** (`METHOD /template`) | distributed floods & stuffing invisible per IP | learned baseline of rate, failure ratio and new-client arrivals; current surge above it |

Two design rules came out of testing:

* **Route surges are context, never evidence on their own.** A flash sale, a viral link or
  Monday-morning logins are surges too. Surge features only exist multiplied by actor or
  client evidence ("this route is surging *and* this fingerprint sends almost all its
  traffic to it"). Before this, a legitimate flash sale had 20% of its requests blocked;
  after, 0%.
* **Baselines are asymmetric.** They follow quiet periods within ~10 minutes but spikes
  only over ~4 hours, so one attack wave cannot redefine "normal" for the next one
  (baseline poisoning).

## 2. Model

Standardised logistic regression: `p = σ(b + Σ wᵢ·(xᵢ − μᵢ)/sᵢ)`. Each term is that
signal's contribution in log-odds; the top ones are returned as `Assessment::reasons`
(e.g. `actor_fail_ratio`, `low actor_route_diversity`). Models are TOML files you can read,
diff and version. Inference is a 28-term dot product (whole `assess` ≈ 2 µs).

The **built-in model** is trained on 3 hours of synthetic traffic from
`tools/eval/src/sim.rs` (`cargo run -p pattern-guard-eval --bin gen_traffic -- --seed 101 --hours 3`). It is a reasonable starting
point, not a substitute for your own data.

## 3. Train on your own traffic

`pattern-guard replay` and `train` skip lines they can't trust instead of letting them
distort the replay clock: invalid dates, a record more than 60 s ahead of the replay clock
that the following records don't confirm (one injected far-future line used to freeze the
clock), and records more than 1 h older than the newest one. The summary counts them.

1. **Export logs as JSONL** (one request per line):
   ```json
   {"ts": 1700000000.25, "ip": "203.0.113.7", "method": "POST", "path": "/login",
    "status": 401, "ua": "Mozilla/5.0 ...", "fp": "t13d1516h2_...", "label": 1, "scenario": "stuffing"}
   ```
   `actor` (e.g. `"user:42"`) defaults to `ip:<ip>`. `fp` is optional but valuable.
   Keep *all* traffic in time order — unlabelled lines still build context.
2. **Label** (`1` abusive, `0` legitimate, omit if unknown). Practical sources:
   * legitimate: authenticated paying users, successful checkouts, your own monitors;
   * abusive: IPs your CDN/WAF already blocked, honeypot-path hits, accounts confirmed as
     takeover attempts, requests from known-bad lists, traffic during a confirmed incident;
   * `scenario` names the attack/traffic type so training can balance them.
3. **Train**:
   ```bash
   pattern-guard train -o model.toml labelled.jsonl
   ```
   * Classes get equal total weight, and within a class every `scenario` gets an equal
     share — a 45-request scan matters as much as a 75 000-request flood.
   * **Mimicry augmentation** (default, `--augment-weight 0.3`; `--no-augment` to disable)
     adds copies of attack samples whose attacker-controlled features (fingerprint, IP
     network, timing jitter, page view before POST — see `model::MIMICABLE_FEATURES`) are
     set to legitimate averages, so the model learns *behaviour*, not disguises. Pick the
     largest weight that keeps false positives on your training data acceptable.
4. **Evaluate on a different time period** (never on the training log):
   ```bash
   pattern-guard replay --model model.toml next_week.jsonl
   ```
5. Deploy: `model = "model.toml"` in `guard.toml`.

Without labels you can still replay plain nginx/Apache logs to see what *would* be
flagged and why: `pattern-guard replay access.log`.

## Shared evidence can challenge, not block

Inputs that innocent clients share (a network's or a user agent's failures and new
arrivals) or that every first contact has (`actor_new`, `cold_write`) raise the risk, but a
request that would block only because of them is challenged instead; see
[architecture/engine.md](architecture/engine.md#shared-evidence). A cold login by a password
manager, or a phone whose browser shares its user agent with an attacker, gets a challenge it
can pass, not a block and a ban.

Retraining with cold-write clients in the training data was tried and rejected
(2026-11): with the current features the model then traded those clients for false positives
on viral-link crowds (seed 8: 0.54 % → 1.23 % of legitimate requests stopped; more training
hours made it worse). Telling a flash crowd from distributed stuffing needs a new feature.

## 4. Results on synthetic traffic (`cargo run --release -p pattern-guard-eval --bin realworld_eval`)

One simulated site, 60 minutes: shoppers, an office NAT, casual visitors, a 2-second
polling dashboard, a partner API, a mobile app, uptime monitors, a viral spike and a login
rush, plus staggered attacks. Scenarios marked `[unseen]` were never part of training:
attacks, a flash sale, and (since 2026-11) clients whose **first request is a write**:
password-manager logins, app logins, an API client's token exchange, an SSO callback.
Evaluated on seeds not used for training (7, 8, 9):

| | 0.2 fixed rules | 0.3 adaptive (built-in model) |
|---|---|---|
| legitimate requests stopped | ~11 % | **0.44 – 0.54 %** |
| legitimate requests blocked | ~10.5 % | **0.03 – 0.06 %** (the rest of the stopped ones are delayed or challenged) |
| attack requests stopped | 52 % | **98.4 – 98.7 %** |
| attack requests blocked or challenged | — | 91.7 – 93.2 % |
| unseen: flash-sale spike (legit) | 2.6 % stopped | 0.0 % |
| unseen: L7 flood with browser fingerprints | 95 % | 99.8 % |
| unseen: different vulnerability scanner | 0 % | 100 % |
| unseen: random-order scraper, Chrome fingerprint | 92 % | 99.8 % |
| unseen: stealth credential stuffing (Chrome fp, residential IPs, page view first, 1 try / 2–4 min / IP) | 1 % | ~45 % |

**Honest caveats**

* This is synthetic traffic written by the same people who wrote the detector. It shows
  the mechanisms work and generalise to *some* unseen variants; it does not prove
  real-world accuracy. Replay your own logs before enforcing — start in `Warn`-only mode.
* Stealth credential stuffing is the hardest case: the first attempt from each IP looks
  exactly like a user's typo. Pair the guard with breached-password checks and a
  challenge on repeated login failures.
* The first request from a brand-new client is judged mostly on fingerprint, network and
  route context; behaviour-based signals need a few requests.
* There is no shared threat intelligence (IP reputation across sites) — the single largest
  advantage a network like Cloudflare has. See the roadmap in the README.
