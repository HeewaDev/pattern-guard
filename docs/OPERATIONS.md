# Operations runbook

## Rollout: detect → challenge → prevent

| Week | Mode | What to do |
|---|---|---|
| 0 | — | Replay last week's access log: `pattern-guard replay access.log`. Look at the top flagged clients and their reasons. |
| 1–2 | `mode = "detect"` | Gateway live and logging only. Review the decision log daily (queries below). Add exclusions and trusted actors. |
| 3 | `mode = "prevent"` with ML challenges | In `guard.toml` set `challenge_below = 0.95`, so most behavioural detections become challenges rather than blocks. WAF, deny-list and reputation blocks still block. |
| 4+ | `mode = "prevent"` | Watch `pattern_guard_requests_total` and support tickets. Tighten once false positives are rare. |

A challenge costs a real user a fraction of a second once per `challenge.ttl_secs`. A false
block costs a customer, so prefer challenges while you build confidence.

## Reading the decision log

Each line is JSON. The useful fields are `pattern_guard.action` / `layer` / `reasons` /
`waf` / `reputation`, plus `src_ip` and `http.url`.

```bash
L=/var/log/pattern-guard/decisions.jsonl
# what is being stopped, by layer
jq -r '.pattern_guard | "\(.action) \(.layer)"' $L | sort | uniq -c | sort -rn
# top clients mitigated
jq -r 'select(.pattern_guard.action != "allow") | .src_ip' $L | sort | uniq -c | sort -rn | head
# WAF hits by class and parameter
jq -r '.pattern_guard.waf[]? | "\(.class) \(.location)"' $L | sort | uniq -c | sort -rn | head -20
# everything about one request id (the id shown on the block page)
grep '"request_id":"6afea734-3"' $L | jq .
# would-be mitigations while in detect mode
jq -c 'select(.pattern_guard.enforced == false and .pattern_guard.action != "allow")' $L | head
```

## Fixing a false positive

Find the request (by the block page reference, or by IP and time) and look at `layer`:

| `layer` | Typical cause | Fix |
|---|---|---|
| `waf` | A field legitimately contains code/HTML/SQL-like text (CMS editor, code paste) | `waf.exclude_params = ["field"]`, or `waf.exclude_paths` for whole endpoints. Raise `block_score` only as a last resort. |
| `behaviour` | Legit automation (monitor, partner, mobile app sync) or an unusual but valid usage pattern | In `guard.toml`: `[guard.actors."ip:x.x.x.x"] trusted = true`. For many such cases, label your logs and retrain (`pattern-guard train`). |
| `reputation` | Shared IP (carrier NAT, VPN) on a community blocklist | `access.allow`, or switch that source to challenge. |
| `deny_list` / `challenge_list` | Your own lists | Edit `[access]`. |

After the change: `pattern-guard-gateway --check`, then restart.

## Metrics and alerts

Scrape `admin_listen` `/metrics`. Example Prometheus rules:

```yaml
groups:
- name: pattern-guard
  rules:
  - alert: PatternGuardBlockSpike
    expr: sum(rate(pattern_guard_requests_total{action="block"}[5m])) > 5 * sum(rate(pattern_guard_requests_total{action="block"}[1h] offset 1d))
    for: 10m
    annotations: {summary: "Blocks 5× above yesterday: attack or false-positive wave — check decisions.jsonl"}
  - alert: PatternGuardUpstreamErrors
    expr: rate(pattern_guard_upstream_errors_total[5m]) > 1
    for: 5m
  - alert: PatternGuardCrowdSecDown
    expr: pattern_guard_crowdsec_up == 0
    for: 10m
  - alert: PatternGuardChallengeFailures
    expr: rate(pattern_guard_challenges_failed_total[10m]) > rate(pattern_guard_challenges_passed_total[10m])
    for: 15m
    annotations: {summary: "More failed than passed challenges — bots attacking the challenge, or a broken client"}
```

Useful dashboard panels:
- requests by action (stacked);
- blocks by layer;
- WAF findings by class;
- challenge pass rate;
- reputation entries;
- decision time (`rate(pattern_guard_decision_seconds_sum[5m]) / rate(pattern_guard_decision_seconds_count[5m])`).

## During an attack

1. Check `/metrics` for which layer is firing (`pattern_guard_blocked_total{layer=...}`).
2. If it's a distributed flood that is still getting through, add the source ranges to
   `access.challenge` (or `deny`) and restart. CrowdSec will usually have the IPs within
   minutes if it's a known campaign.
3. If it's credential stuffing on `/login`, lower `challenge_below` in `guard.toml` so more
   behavioural detections are challenged.
4. Volumetric traffic that saturates your uplink can't be fixed on the server. Enable your
   CDN's or provider's DDoS protection.

## Troubleshooting

| Symptom | Likely cause |
|---|---|
| Every request comes from the same IP (your proxy's) | `client_ip.trusted_proxies` is missing the proxy, or `client_ip.header` is wrong |
| Users solve the challenge but get it again | Their IP changed (mobile networks), several gateway instances with different `challenge.secret`, or cookies blocked |
| Rich-text or code fields are blocked | `waf.exclude_params` |
| 413 errors | Uploads larger than `max_body_bytes` |
| 502 / 504 | Upstream down or slower than `upstream_timeout_secs` |
| CrowdSec decisions not applied | `pattern_guard_crowdsec_up 0`: wrong `url`, wrong API key, or a port clash with the gateway |
| Feeds do nothing | The service user can't read the alert file, or `min_severity` filters everything out |

## Maintenance

- **Models:** retrain each quarter, or after big traffic changes. Evaluate on a different
  week (`pattern-guard replay --model new.toml next_week.jsonl`) before switching.
- **Logs:** `decisions.jsonl` is append-only, so rotate it with logrotate (`copytruncate`).
- **Upgrades:** read the CHANGELOG, run `--check`, roll instances one at a time.
