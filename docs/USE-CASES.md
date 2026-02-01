# Use cases

## When to use it

Pattern-Guard is not a rate limiter. It answers *"Is this pattern of behavior normal?"* instead of *"Are we under N requests per second?"*

| Situation | Rate limiter | Pattern-Guard |
|-----------|--------------|---------------|
| Abuse under the limit | Allows (e.g. 10 req/s, attacker stays at 9) | Flags bursts, repetition, bot-like pacing |
| Bot mimics human rate | Allows (same req/min as a user) | Flags fixed intervals, repeated (action, target) |
| Runaway script | Often no visibility | One event per run; burst/repetition can delay or block |
| Scanning / hopping | May allow (one request per endpoint) | Many distinct targets in a window → risk |
| Cost spike (weighted) | Doesn’t see cost | Sum of weights in window → weighted overuse |

Use it alongside rate limiting: after "how many?", add "is this behavior normal?"

**Fit:** Backends/APIs (after auth, one event per request). CLI/cron (one event per run). Service-to-service (one event per call). It does not replace auth, authorization, rate limiters, or WAF/payload inspection.

---

## Event model

Everything you guard is an **event**. One event = one observation (one request, one run, one call).

```
Event {
  actor:   who or what (user, IP, service, script)
  action:  what happened (GET, POST, run, query)
  target:  what was hit (/api/foo, command, resource)
  timestamp: when
  weight:  optional cost/impact
  metadata: optional tags (non-sensitive)
}
```

You choose what goes in actor/action/target; Pattern-Guard groups and scores by them.

---

## Examples

### HTTP API

One HTTP request → one event. Actor = user id or IP, action = method, target = path. One event per request in your middleware; call `guard.check(event)` then allow, warn, delay, or block.

### CLI / script

One invocation → one event. Actor = `"cli"` or script name, action = `"run"`, target = command string. The CLI emits one event per run; `--repeat N` runs the child N times in one process so burst accumulates.

### Cron / scheduled jobs

One job run → one event. Actor = job or service name, action = `"run"`, target = job name. If a bug triggers the job every second, burst and repetition risk rise; Pattern-Guard can delay or block.

### Service-to-service

One call → one event. Actor = caller service, action = operation, target = endpoint. Burst, repetition, or target hopping (many distinct targets in a window) drive risk.

---

## Summary

| Context | One request = | Actor | Action | Target |
|---------|----------------|--------|--------|--------|
| HTTP API | One HTTP request | user id / IP | method | path or resource |
| CLI | One run of command | `cli` or script name | `run` | command string |
| Cron | One job execution | job/service name | `run` | job name |
| Service call | One RPC/HTTP call | caller service | operation | endpoint/resource |

Pattern-Guard uses only actor, action, target, timestamp (and optional weight, metadata). No headers or body. You map your traffic into events; pattern of behavior drives the decision, not just rate.
