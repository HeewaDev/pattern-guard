//! Real-world evaluation: one site, one hour, legitimate background traffic plus
//! staggered attacks — including attack variants and a legitimate traffic spike that
//! the built-in model never saw during training (marked `[unseen]`).
//!
//! `cargo run --release -p pattern-guard-eval --bin realworld_eval [-- --model path/to/model.toml] [--seed N]`
//!
//! Runs the same traffic through:
//!  1. the 0.2-style rules (thresholds from the 0.2 guard.toml.example), and
//!  2. the adaptive engine with the built-in (or given) model.

use pattern_guard_eval::sim;

use std::collections::{BTreeMap, HashSet};
use std::time::Instant;

use pattern_guard::{Decision, Guard, Model};

const LEGACY_RULES: &str = r#"
[guard]
mode = "rules"
normalize_targets = false
cooldown_secs = 0
window_secs = 300
burst_max_events = 100
repetition_max_count = 10
hopping_max_targets = 50
weight_max_total = 1000.0
interval_secs = 2.0
"#;

#[derive(Default)]
struct Row {
    label: bool,
    total: usize,
    stopped: usize,
    blocked: usize,
    challenged: usize,
    actors: HashSet<String>,
    actors_stopped: HashSet<String>,
}

fn run(name: &str, guard: &Guard, recs: &[sim::Rec]) {
    let mut rows: BTreeMap<&str, Row> = BTreeMap::new();
    let start = Instant::now();
    for r in recs {
        let ev = sim::to_event(r);
        let a = guard.assess(&ev);
        guard.observe_response(&ev, r.status);
        let row = rows.entry(r.scenario).or_default();
        row.label = r.label;
        row.total += 1;
        row.actors.insert(r.actor.clone());
        if a.decision.is_mitigation() {
            row.stopped += 1;
            row.actors_stopped.insert(r.actor.clone());
        }
        if a.decision == Decision::Block {
            row.blocked += 1;
        }
        if a.decision == Decision::Challenge {
            row.challenged += 1;
        }
    }
    let us = start.elapsed().as_secs_f64() * 1e6 / recs.len() as f64;

    println!(
        "\n=== {name} ===   ({:.2} µs per request incl. response feedback)",
        us
    );
    println!(
        "{:<48} {:>8} {:>9} {:>9} {:>11} {:>15}",
        "scenario", "requests", "stopped%", "blocked%", "challenged%", "actors stopped"
    );
    println!("{}", "-".repeat(105));
    let mut sorted: Vec<_> = rows.iter().collect();
    sorted.sort_by_key(|(n, r)| (r.label, n.contains("[unseen]"), *n));
    let (mut lt, mut ls, mut at, mut ast, mut lb) = (0, 0, 0, 0, 0);
    let (mut lc, mut ahard) = (0, 0);
    let mut per_attack = Vec::new();
    for (n, r) in &sorted {
        println!(
            "{:<48} {:>8} {:>9.1} {:>9.1} {:>11.1} {:>8}/{:<6}",
            n,
            r.total,
            100.0 * r.stopped as f64 / r.total as f64,
            100.0 * r.blocked as f64 / r.total as f64,
            100.0 * r.challenged as f64 / r.total as f64,
            r.actors_stopped.len(),
            r.actors.len()
        );
        if r.label {
            at += r.total;
            ast += r.stopped;
            ahard += r.blocked + r.challenged;
            per_attack.push(r.stopped as f64 / r.total as f64);
        } else {
            lt += r.total;
            ls += r.stopped;
            lb += r.blocked;
            lc += r.challenged;
        }
    }
    println!(
        "\nFalse positives: {:.2}% of legitimate requests stopped ({:.2}% blocked, {:.2}% challenged)  |  detection: {:.1}% of attack requests (avg per attack type {:.1}%; {:.1}% blocked or challenged)",
        100.0 * ls as f64 / lt as f64,
        100.0 * lb as f64 / lt as f64,
        100.0 * lc as f64 / lt as f64,
        100.0 * ast as f64 / at as f64,
        100.0 * per_attack.iter().sum::<f64>() / per_attack.len() as f64,
        100.0 * ahard as f64 / at as f64
    );
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let flag = |f: &str| {
        args.iter()
            .position(|a| a == f)
            .and_then(|i| args.get(i + 1))
            .cloned()
    };
    let seed: u64 = flag("--seed").map(|s| s.parse().unwrap()).unwrap_or(7);
    let recs = sim::generate(seed, 1, true);
    println!(
        "Evaluation traffic: {} requests, 60 simulated minutes, seed {seed} (training used different seeds)",
        recs.len()
    );

    let legacy = Guard::from_toml_str(LEGACY_RULES).unwrap();
    run(
        "0.2-style fixed rules (0.2 guard.toml.example thresholds)",
        &legacy,
        &recs,
    );

    let mut adaptive = Guard::from_toml_str("").unwrap();
    if let Some(p) = flag("--model") {
        adaptive = adaptive.with_model(Model::load(p).unwrap());
    }
    let desc = adaptive.model().description.clone();
    run(
        &format!("0.3 adaptive engine (model: {desc})"),
        &adaptive,
        &recs,
    );
}
