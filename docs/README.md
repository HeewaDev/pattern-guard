# Pattern-Guard documentation

## Start here

| If you want to… | Read |
|---|---|
| Understand what Pattern-Guard is and what it can do today | [../README.md](../README.md) |
| Put the gateway in front of an app | [GATEWAY.md](GATEWAY.md) → [DEPLOYMENT.md](DEPLOYMENT.md) |
| Roll it out safely and run it day to day | [OPERATIONS.md](OPERATIONS.md) |
| Embed the engine in your Rust service | [USE-CASES.md](USE-CASES.md) → [CONFIG.md](CONFIG.md) |
| Understand or retrain the ML | [ML.md](ML.md) |
| Know how it's built | [ARCHITECTURE.md](ARCHITECTURE.md) |
| See every feature, its status and the gaps | [FEATURES.md](FEATURES.md) |
| See where the product is going and what "done" means | [ROADMAP.md](ROADMAP.md) |
| Learn what OWASP CRS and open-appsec do and what we adopt | [RESEARCH.md](RESEARCH.md) |

## Reference

| Document | Contents |
|---|---|
| [GATEWAY.md](GATEWAY.md) | Gateway config, decisions, threat intel (CrowdSec, Suricata, Wazuh), WAF tuning, admin endpoints, limits |
| [DEPLOYMENT.md](DEPLOYMENT.md) | Topology, build, TLS terminator (Caddy/nginx/CDN), systemd, integrations, multiple instances, sizing |
| [OPERATIONS.md](OPERATIONS.md) | Rollout plan, decision-log queries, fixing false positives, Prometheus alerts, attack playbook, troubleshooting |
| [CONFIG.md](CONFIG.md) | Every `guard.toml` key (behavioural engine) |
| [ML.md](ML.md) | Features, model, training on your logs, results and caveats |
| [ARCHITECTURE.md](ARCHITECTURE.md) | Components, request lifecycle, engine and WAF internals, concurrency, security model |
| [USE-CASES.md](USE-CASES.md) | Library integration patterns (HTTP middleware, CLI, cron, service-to-service) |
| [FEATURES.md](FEATURES.md) | Feature tracker vs open-appsec and Imperva; measured results |
| [ROADMAP.md](ROADMAP.md) | Vision, KPIs, milestones with acceptance criteria, risks, workflow |
| [RESEARCH.md](RESEARCH.md) | OWASP CRS and open-appsec internals, CRS benchmark results, techniques to adopt |
| [../CHANGELOG.md](../CHANGELOG.md) | Release notes and breaking changes |

## Example configs

[`config/gateway.toml.example`](../config/gateway.toml.example) · [`config/guard.toml.example`](../config/guard.toml.example)
