//! `redteam`: runs the red-team scenarios and prints a Markdown report.
//!
//! ```text
//! cargo run --release -p pattern-guard-redteam -- [--seed N] [--pace-ms N] [--budget N]
//!     [--max-wait-secs N] [--wait-budget-secs N] [--scenario NAME]… [--vuln NAME]…
//!     [--config gateway.toml] [--attacker-cmd CMD]
//!     [--json FILE] [--markdown FILE] [--verbose]
//! ```
//!
//! Exit status 0 whatever the results (this is a measurement, not a gate); 2 on bad
//! arguments or when a run fails to start.

use std::time::Duration;

use pattern_guard_redteam::Vuln;
use pattern_guard_redteam::harness::{self, ScenarioResult, Settings};
use pattern_guard_redteam::report;

const USAGE: &str = "usage: redteam [--seed N] [--pace-ms N] [--budget N] [--max-wait-secs N] [--wait-budget-secs N] [--scenario NAME]… [--vuln sqli|xss|traversal|cmdi|bola|bruteforce]… [--config FILE] [--attacker-cmd CMD] [--json FILE] [--markdown FILE] [--verbose]";

fn fail(msg: &str) -> ! {
    eprintln!("redteam: {msg}\n{USAGE}");
    std::process::exit(2);
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut set = Settings::default();
    let mut only: Vec<String> = Vec::new();
    let mut json_path = None;
    let mut md_path = None;
    let mut i = 0;
    while i < args.len() {
        let flag = args[i].as_str();
        if flag == "--verbose" {
            set.verbose = true;
            i += 1;
            continue;
        }
        if flag == "--help" || flag == "-h" {
            println!("{USAGE}");
            return;
        }
        let Some(value) = args.get(i + 1) else {
            fail(&format!("{flag} needs a value"));
        };
        let num = || {
            value
                .parse::<u64>()
                .unwrap_or_else(|_| fail(&format!("{flag}: not a number: {value}")))
        };
        match flag {
            "--seed" => set.seed = num(),
            "--pace-ms" => set.pace = Duration::from_millis(num()),
            "--budget" => set.budget = num() as usize,
            "--max-wait-secs" => set.max_wait = Duration::from_secs(num()),
            "--wait-budget-secs" => set.wait_budget = Duration::from_secs(num()),
            "--scenario" => only.push(value.clone()),
            "--vuln" => set.vulns.push(
                Vuln::parse(value)
                    .unwrap_or_else(|| fail(&format!("unknown vulnerability {value}"))),
            ),
            "--config" => {
                set.gateway_config = std::fs::read_to_string(value)
                    .unwrap_or_else(|e| fail(&format!("cannot read {value}: {e}")));
            }
            "--attacker-cmd" => set.attacker_cmd = Some(value.clone()),
            "--json" => json_path = Some(value.clone()),
            "--markdown" => md_path = Some(value.clone()),
            _ => fail(&format!("unknown option {flag}")),
        }
        i += 2;
    }
    let all = harness::scenarios(set.seed);
    for name in &only {
        if !all.iter().any(|s| s.name == name) {
            let names: Vec<_> = all.iter().map(|s| s.name).collect();
            fail(&format!(
                "unknown scenario {name} (have: {})",
                names.join(", ")
            ));
        }
    }
    let chosen: Vec<_> = all
        .into_iter()
        .filter(|s| only.is_empty() || only.iter().any(|n| n == s.name))
        .collect();

    let mut results = Vec::new();
    for sc in chosen {
        let mut runs = Vec::new();
        for via_gateway in [true, false] {
            // a fresh runtime per run: the app, the gateway and their state go away with it
            let rt = tokio::runtime::Builder::new_multi_thread()
                .worker_threads(4)
                .enable_all()
                .build()
                .unwrap_or_else(|e| fail(&format!("runtime: {e}")));
            let r = rt
                .block_on(harness::run(&sc, &set, via_gateway))
                .unwrap_or_else(|e| fail(&format!("scenario {}: {e}", sc.name)));
            rt.shutdown_timeout(Duration::from_secs(1));
            eprintln!(
                "redteam: {} via {}: {} of 6 found in {} requests ({:.1} s), stopped: {}",
                sc.name,
                if via_gateway { "gateway" } else { "direct" },
                r.found.len(),
                r.requests,
                r.secs,
                r.stop
            );
            runs.push(r);
        }
        let direct = runs.pop().expect("direct run");
        let gateway = runs.pop().expect("gateway run");
        results.push(ScenarioResult {
            scenario: sc,
            gateway,
            direct,
        });
    }
    let md = report::markdown(&results, &set);
    print!("{md}");
    if let Some(p) = md_path {
        std::fs::write(&p, &md).unwrap_or_else(|e| fail(&format!("cannot write {p}: {e}")));
    }
    if let Some(p) = json_path {
        let j = serde_json::to_string_pretty(&report::json(&results, &set)).unwrap_or_default();
        std::fs::write(&p, j + "\n").unwrap_or_else(|e| fail(&format!("cannot write {p}: {e}")));
    }
}
