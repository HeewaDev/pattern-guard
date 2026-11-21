# Product strategy notes

Why Pattern-Guard exists, where it fits, what makes it stand out, and the principles
that decide what we build. [ROADMAP.md](ROADMAP.md) turns this into ordered work;
[FEATURES.md](FEATURES.md) tracks each feature's status.

---

## 1. The promise

> **Every request that gets past the edge is understood:** who sent it, what it does,
> whether it is normal *for this application*, and whether it hurts *this business*,
> and every decision is explained.

Pattern-Guard is a self-hosted, open-source protection platform for web applications,
APIs and the servers behind them. It runs next to your application, so it sees what an
edge network can't: your accounts, your payment flow, your normal traffic, and the
server itself.

## 2. Positioning: behind the edge, or alone

We don't compete with Cloudflare, Akamai or Imperva at the edge. They own global
bandwidth and internet-wide visibility. **Pattern-Guard owns everything after the edge.**

| Threat | Edge (Cloudflare or similar) | Pattern-Guard |
|---|---|---|
| Volumetric DDoS (L3/L4, huge L7 floods) | **owns it** | n/a |
| Internet-wide bad IPs and botnets | **owns it** | adds local, CrowdSec, Suricata and Wazuh signals |
| TLS, HTTP/2/3, caching | **owns it** | n/a |
| Generic web attacks (SQLi, XSS, RCE, Log4Shell) | first filter | **second, deeper filter** tuned to the app (multipart parts, uploads, decoding) |
| Business-logic abuse (replayed payment callbacks, purchase floods per account, race conditions) | can't see app semantics | **owns it** (`[[operations]]`) |
| Account takeover (brute force over many IPs, credential stuffing) | partial, plan-dependent | **owns it** (`[[logins]]` + behavioural ML) |
| Abuse that looks clean per request (scraping, slow bots, mimicry) | bot scoring on higher plans | **owns it** (behaviour learned per route and actor) |
| Data leaks in responses | higher plans | **owns it** (`[response_inspection]`) |
| Evidence and forensics | in their dashboard | **owns it** (decision log with reasons, on your server) |
| SSH, mail, databases, other ports; outbound and internal traffic; the host itself | can't see them | **planned: Agent** (§5) |
| Data residency | traffic decrypted abroad | **stays on your servers** |

Without an edge provider (on-premises, internal apps, countries where foreign services
are unreliable or not allowed), Pattern-Guard runs alone and an upstream provider or ISP
handles volumetric DDoS.

### The non-negotiable rule for "after the edge"

Nothing may reach the application without passing Pattern-Guard. Attackers find origin
IPs (old DNS records, certificate logs, email headers) and go around the edge.

- **Best:** a tunnel (Cloudflare Tunnel or similar). The origin opens no inbound ports.
- **Otherwise:** a firewall that only accepts the edge's ranges, a secret header that
  only your zone adds (edge ranges are shared by all customers of that edge), and the
  app bound to localhost.
- Pattern-Guard is fail-closed: if the gateway stops, traffic stops; it never skips
  inspection.

## 3. What makes it stand out

1. **Business-logic defence built in.** Per-account budgets, allowed sources, replay
   and race protection on transaction IDs, account lockout across IPs. Generic WAFs
   (OWASP CRS, ModSecurity, Coraza, BunkerWeb, SafeLine) don't do this, and edge
   networks can't, because they don't know the application.
2. **Behaviour learned per application.** Streaming features per actor, network,
   fingerprint and route, with baselines an attacker can't poison quickly. The engine
   works on *events*, not just HTTP, so the same engine will learn SSH, mail and
   database logins (the Agent).
3. **Every decision explained.** Layer, indicators, location, score and reasons, in a
   log the operator owns. Explainability is a feature, not a debug mode.
4. **One platform, one binary.** Gateway today; Agent and Console next. It replaces a
   WAF, a bot tool, a rate limiter, fail2ban and CrowdSec-style banning with one
   self-hosted product. Integrations (CrowdSec, Suricata, Wazuh) stay optional for
   teams that already run them.
5. **Open source, no paywalled detection.** MIT OR Apache-2.0. The ML and all detections
   are in the open code; no separate model licence and no "Premium" tier for bot or API
   protection.
6. **Fast and safe.** Rust: ~17 µs of WAF inspection for a typical request, ~28 000 req/s
   through the gateway on 4 shared vCPUs, bounded memory, no garbage collector.
7. **Measured claims.** Every detection change reports before/after numbers on public
   benchmarks and a benign corpus, and the docs say what has *not* been proven yet.

## 4. Who it is for

| Segment | Why Pattern-Guard fits |
|---|---|
| **Digital goods and instant delivery** (gift cards, eSIM, game credit, top-ups, software keys) | Highest fraud pressure: goods resell instantly. Business-logic and account-level defences matter most |
| **Payments, fintech, wallets** | Replay and race protection, per-account budgets, evidence for every decision |
| **E-commerce and marketplaces** | Bots, credential stuffing, scraping, coupon abuse, checkout abuse |
| **Regional markets with data-residency needs** (e.g. Iraq and the wider MENA region) | Self-hosted; traffic and logs stay in the country |
| **Banks, government, internal applications** | Can't route traffic through a foreign edge |
| **SaaS and public APIs** | Per-key budgets, API inventory, OpenAPI enforcement (planned) |
| **Managed security providers (MSSPs)** | One platform to run for many clients (multi-tenant Console, planned) |

### A real case that shapes the roadmap

A digital gift-card shop (shared with the project, anonymised) lost a significant amount
of money. Cards were bought from its supplier, but **no orders appeared in the shop's
dashboard**, and the payment provider reported the purchases as already paid. The
likely causes are a replayed or forged payment confirmation, a leaked supplier API key,
or fulfilment that runs before the order is saved. None of these look like a classic
"attack" to a WAF.

What it taught us:
- **Business-logic protection is the core product**, not an extra. Built:
  `[[operations]]` (allowed callback sources, one-time transaction IDs, per-account
  budgets).
- **Reconciliation matters.** Alert when goods issued ≠ payments confirmed (planned).
- **Secrets and the host matter.** A leaked key bypasses every web defence. The Agent
  will watch for exposed `.env` files and unexpected outbound traffic (planned).

## 5. Target platform

```
                 Edge (Cloudflare or similar): volume, DDoS, global reputation
                                     │
         ┌───────────────────────────┼─────────────────────────────┐
         ▼                           ▼                             ▼
 Pattern-Guard GATEWAY          Pattern-Guard AGENT             (every server)
 application layer              host + network layer
 • WAF (decoding, analysers)    • SSH / mail / DB / web log detection
 • behavioural ML, bot score    • bans on every port (nftables)
 • operations, logins,          • file integrity, web shells, exposed secrets
   replay, reconciliation       • processes, listening ports, outbound traffic
 • challenge, response leaks    • scans, floods, edge-bypass attempts
         │                           │
         └─────────────┬─────────────┘
                       ▼
            Pattern-Guard CONSOLE (the brain)
            • every event from every gateway and agent, one timeline
            • seen anywhere → banned everywhere (gateways, agents, edge)
            • web UI, incidents, one-click exclusions, alerts (Telegram, email, webhook)
            • threat feeds, multi-tenant for service providers
```

All three ship as one Rust binary: `pattern-guard gateway | agent | console`.

**Scope honesty.** Suricata (tens of thousands of packet signatures) and Wazuh (a full
SIEM) are each many years of work by large teams. We build the part that protects a
typical company's servers (log-based detection, enforcement, file integrity, outbound
monitoring, scan and flood detection) and keep the integrations for organisations that
already run those tools.

## 6. Vertical playbook: digital goods and eSIM

| Threat | Today | Planned |
|---|---|---|
| Forged or replayed payment callbacks | ✅ `allowed_ips` + `unique` | callback signature verification helper |
| Purchase floods per account, race-condition double spends | ✅ per-account `limit`, in-flight replay lock | learned per-operation baselines |
| Login brute force, credential stuffing, OTP brute force | ✅ `[[logins]]` + ML | breached-password check |
| Card testing (many small declined payments) | partial (limits) | **failure-counted operations**: declines per account, IP and card fingerprint |
| Viewing other customers' orders, QR codes or activation codes (BOLA / IDOR) | — | **BOLA detection**: one account touching many other customers' object IDs |
| Bulk leak of activation codes or keys in responses | partial (leak patterns for errors and keys) | **custom leak patterns** (e.g. `LPA:1$…` activation strings) |
| Goods issued without payment | — | **issuance reconciliation alert** |
| Fake signups, promo and coupon farming | partial (rate limits, ML, challenge) | signup and coupon velocity per device and network, CAPTCHA providers |
| Leaked supplier or provider API keys | WAF blocks `.env` / `.git` probes, traps | Agent: exposed-secret scan, outbound-traffic watch |

Always required in the application itself, whatever protects it:
1. Verify every payment server-to-server: amount, currency, order.
2. Deliver only after verified payment, exactly once per order.
3. Show activation codes only to their owner; require re-authentication before
   re-download.
4. Two-factor authentication for accounts.
5. Provider keys in a vault, with IP allow-lists and spend limits at the provider.
6. Card data never touches the server (the provider's hosted page or fields).

## 7. How it pays

| Path | What | When |
|---|---|---|
| **Open-source reputation** | Strong, well-measured project; community, contributors, talks | Now |
| **Services** | Deployment, tuning and monitoring for local companies; monthly support | After the first real deployments |
| **Open core** | Free gateway and agent; paid Console features (multi-tenant, RBAC, SSO, long retention, managed rules and model updates) | After the Console exists |
| **Managed service** | Regional protection service run for clients (data stays in the region) | When the platform is proven on several sites |

The order matters: **proof first**. One real deployment with measured false positives
and real attacks caught is worth more than any new detection.

## 8. Principles

1. **Explain every decision.** No silent blocks.
2. **Detect before prevent.** Every rollout starts in detect mode.
3. **False positives are bugs.** The benign corpus must stay at zero false blocks; every
   change reports its effect.
4. **Measured claims only.** Report numbers as measured, name the dataset, and say
   when a test set was used for tuning.
5. **Privacy by default.** Account identifiers are hashed; tokens, passwords and card
   data are never stored or logged.
6. **Proof and production-readiness before breadth.** A feature isn't done until it is
   tested, documented and safe to run at the front door.
7. **Standalone in steps, each useful alone.** Gateway, then Agent, then Console; every
   step ships value on its own.
8. **Permissive licences only.** Borrow code only under MIT / Apache / BSD; ideas only
   from GPL projects.
9. **One commit per feature,** every commit builds and passes tests.

## 9. What we won't do

- A CDN or volumetric DDoS scrubbing: an edge provider's job.
- A global threat-intelligence network of our own: we consume and feed CrowdSec and
  public feeds, and share between a customer's own instances.
- A full packet-signature IDS or a full SIEM: integrate Suricata and Wazuh for that
  depth.
- A copy of the OWASP CRS rule language: we keep our own scoring engine.
- Paywalled detection in the open-source core.
