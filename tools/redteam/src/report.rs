//! The results as a Markdown report (for people and CI job summaries) and as JSON (for
//! tracking per release).

use std::fmt::Write as _;

use crate::Vuln;
use crate::harness::{At, RunResult, ScenarioResult, Settings};

fn at(a: &At) -> String {
    format!("{} ({:.1} s)", a.request, a.secs)
}

fn found_count(r: &RunResult) -> usize {
    r.found.len()
}

fn stopped(r: &RunResult) -> usize {
    r.verdicts
        .iter()
        .filter(|(k, _)| !matches!(**k, "confirmed" | "passed"))
        .map(|(_, n)| n)
        .sum()
}

/// The whole report: the summary table, then per-vulnerability and per-layer detail.
pub fn markdown(results: &[ScenarioResult], set: &Settings) -> String {
    let mut s = String::new();
    let vulns: Vec<Vuln> = if set.vulns.is_empty() {
        Vuln::ALL.to_vec()
    } else {
        Vuln::ALL
            .into_iter()
            .filter(|v| set.vulns.contains(v))
            .collect()
    };
    let strategy = results
        .first()
        .map(|r| r.gateway.strategy.clone())
        .unwrap_or_default();
    let _ = writeln!(
        s,
        "## Red team: {strategy} vs. the demo shop\n\nSeed {}, pace {} ms, at most {} requests per run, Retry-After waited up to {} s (total {} s). \"Direct\" is the same attacker against the app without the gateway. A vulnerability is found when the response proves it (oracle).\n",
        set.seed,
        set.pace.as_millis(),
        set.budget,
        set.max_wait.as_secs(),
        set.wait_budget.as_secs()
    );
    let _ = writeln!(
        s,
        "| scenario | vulnerabilities found (gateway / direct) | requests to first bypass | requests to first ban | requests sent | stopped by the gateway | run ended |"
    );
    let _ = writeln!(s, "|---|---|---|---|---|---|---|");
    for r in results {
        let g = &r.gateway;
        let bypass = g
            .first_bypass()
            .map(|(v, f)| format!("{} ({})", at(&f.at), v.as_str()))
            .unwrap_or_else(|| "none".into());
        let ban = g
            .first_ban
            .as_ref()
            .map(|b| {
                format!(
                    "{}{}",
                    at(&b.at),
                    if g.banned_ips > 1 {
                        format!(", {} IPs banned", g.banned_ips)
                    } else {
                        String::new()
                    }
                )
            })
            .unwrap_or_else(|| "never".into());
        let _ = writeln!(
            s,
            "| **{}**: {} | {} / {} of {} | {bypass} | {ban} | {} in {:.1} s | {} ({:.0} %) | {} |",
            r.scenario.name,
            r.scenario.about,
            found_count(g),
            found_count(&r.direct),
            vulns.len(),
            g.requests,
            g.secs,
            stopped(g),
            100.0 * stopped(g) as f64 / g.requests.max(1) as f64,
            g.stop
        );
    }

    let _ = writeln!(
        s,
        "\n### Requests until each vulnerability was confirmed (gateway · direct)\n\n\"–\" is not found; the number in brackets is how many requests went to it.\n"
    );
    let mut head = String::from("| scenario |");
    let mut rule = String::from("|---|");
    for v in &vulns {
        let _ = write!(head, " {} |", v.as_str());
        rule.push_str("---|");
    }
    let _ = writeln!(
        s,
        "{head} other customers' orders read (gateway · direct) |\n{rule}---|"
    );
    for r in results {
        let mut row = format!("| {} |", r.scenario.name);
        for v in &vulns {
            let cell = |run: &RunResult| match run.found.get(v) {
                Some(f) => format!("{}", f.at.request),
                None => format!("– ({})", run.attempts.get(v).copied().unwrap_or(0)),
            };
            let _ = write!(row, " {} · {} |", cell(&r.gateway), cell(&r.direct));
        }
        let _ = writeln!(
            s,
            "{row} {} · {} |",
            r.gateway.records_leaked, r.direct.records_leaked
        );
    }

    let _ = writeln!(
        s,
        "\n### What the gateway did\n\n| scenario | blocked, by layer | challenges | 429 responses | responses delayed ≥ 1 s | proof-of-work solved | first ban |\n|---|---|---|---|---|---|---|"
    );
    for r in results {
        let g = &r.gateway;
        let layers = if g.blocked_by_layer.is_empty() {
            "none".to_string()
        } else {
            g.blocked_by_layer
                .iter()
                .map(|(k, v)| format!("{k} {v}"))
                .collect::<Vec<_>>()
                .join(", ")
        };
        let ban = g
            .first_ban
            .as_ref()
            .map(|b| format!("{} after {:.1} s: {}", b.ip, b.at.secs, b.reason))
            .unwrap_or_else(|| "none".into());
        let _ = writeln!(
            s,
            "| {} | {layers} | {} | {} | {} | {} | {ban} |",
            r.scenario.name,
            g.challenges,
            g.verdicts.get("rate_limited").copied().unwrap_or(0),
            g.slow_responses,
            g.pow_solved
        );
    }
    s
}

fn run_json(r: &RunResult) -> serde_json::Value {
    let found: serde_json::Map<String, serde_json::Value> = r
        .found
        .iter()
        .map(|(v, f)| {
            (
                v.as_str().to_string(),
                serde_json::json!({ "request": f.at.request, "secs": f.at.secs, "evidence": f.evidence }),
            )
        })
        .collect();
    let attempts: serde_json::Map<String, serde_json::Value> = r
        .attempts
        .iter()
        .map(|(v, n)| (v.as_str().to_string(), (*n).into()))
        .collect();
    serde_json::json!({
        "via": if r.via_gateway { "gateway" } else { "direct" },
        "strategy": r.strategy,
        "requests": r.requests,
        "secs": r.secs,
        "stop": r.stop,
        "verdicts": r.verdicts,
        "vulnerabilities_found": r.found.len(),
        "found": found,
        "attempts": attempts,
        "first_bypass": r.first_bypass().map(|(v, f)| serde_json::json!({
            "vuln": v.as_str(), "request": f.at.request, "secs": f.at.secs,
        })),
        "first_ban": r.first_ban.as_ref().map(|b| serde_json::json!({
            "request": b.at.request, "secs": b.at.secs, "ip": b.ip, "reason": b.reason,
        })),
        "banned_ips": r.banned_ips,
        "blocked_by_layer": r.blocked_by_layer,
        "challenges": r.challenges,
        "pow_solved": r.pow_solved,
        "slow_responses": r.slow_responses,
        "records_leaked": r.records_leaked,
    })
}

/// JSON for tracking per release.
pub fn json(results: &[ScenarioResult], set: &Settings) -> serde_json::Value {
    serde_json::json!({
        "tool": "pattern-guard-redteam",
        "version": env!("CARGO_PKG_VERSION"),
        "commit": std::env::var("GITHUB_SHA").ok(),
        "settings": {
            "seed": set.seed,
            "pace_ms": set.pace.as_millis() as u64,
            "budget": set.budget,
            "max_wait_secs": set.max_wait.as_secs(),
            "wait_budget_secs": set.wait_budget.as_secs(),
            "custom_gateway_config": set.gateway_config != crate::harness::DEFAULT_CONFIG,
            "attacker_cmd": set.attacker_cmd,
            "vulns": set.vulns.iter().map(|v| v.as_str()).collect::<Vec<_>>(),
        },
        "scenarios": results.iter().map(|r| serde_json::json!({
            "name": r.scenario.name,
            "about": r.scenario.about,
            "gateway": run_json(&r.gateway),
            "direct": run_json(&r.direct),
        })).collect::<Vec<_>>(),
    })
}
