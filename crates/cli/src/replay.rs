//! `pattern-guard replay`: run an access log through the guard and report.

use std::collections::HashMap;

use pattern_guard::{Decision, Guard, Model};

use crate::BoxErr;
use crate::args::{for_each_record, format_flag, load_config, parse_flags, pct};

#[derive(Default)]
struct Bucket {
    label: Option<bool>,
    total: usize,
    stopped: usize,
    blocked: usize,
    actors: HashMap<String, bool>,
}

#[derive(Default)]
struct ActorAgg {
    total: usize,
    stopped: usize,
    reasons: HashMap<String, usize>,
}

pub(crate) fn replay(args: &[String]) -> Result<(), BoxErr> {
    let f = parse_flags(args, &["--config", "--model", "--format", "--top"], &[])?;
    let [log] = f.positional.as_slice() else {
        return Err("replay: expected exactly one LOG argument (use '-' for stdin)".into());
    };
    let mut guard = Guard::new(load_config(f.values.get("--config"))?)?;
    if let Some(m) = f.values.get("--model") {
        guard = guard.with_model(Model::load(m)?);
    }
    let top: usize = f
        .values
        .get("--top")
        .map(|s| s.parse())
        .transpose()?
        .unwrap_or(10);

    let mut decisions: HashMap<&'static str, usize> = HashMap::new();
    let mut buckets: HashMap<String, Bucket> = HashMap::new();
    let mut actors: HashMap<String, ActorAgg> = HashMap::new();
    let (mut total, mut first, mut last) = (0usize, f64::INFINITY, f64::NEG_INFINITY);
    let mut labelled = false;

    for_each_record(log, format_flag(&f)?, |r| {
        let a = guard.assess(&r.event);
        if let Some(s) = r.status {
            guard.observe_response(&r.event, s);
        }
        total += 1;
        let ts = r.event.unix_secs();
        first = first.min(ts);
        last = last.max(ts);
        *decisions.entry(a.decision.label()).or_default() += 1;
        let stopped = a.decision.is_mitigation();
        let blocked = matches!(a.decision, Decision::Block);

        let agg = actors.entry(r.event.actor.clone()).or_default();
        agg.total += 1;
        if stopped {
            agg.stopped += 1;
            for reason in a.reasons.iter().take(2) {
                *agg.reasons.entry(reason.to_string()).or_default() += 1;
            }
        }

        if r.label.is_some() || r.scenario.is_some() {
            labelled |= r.label.is_some();
            let key = r.scenario.clone().unwrap_or_else(|| match r.label {
                Some(true) => "labelled abusive".into(),
                Some(false) => "labelled legitimate".into(),
                None => "unlabelled".into(),
            });
            let b = buckets.entry(key).or_default();
            b.label = r.label.or(b.label);
            b.total += 1;
            b.stopped += stopped as usize;
            b.blocked += blocked as usize;
            let e = b.actors.entry(r.event.actor.clone()).or_default();
            *e |= stopped;
        }
    })?;

    if total == 0 {
        return Err("no records".into());
    }
    println!(
        "Replayed {} requests from {} actors over {:.1} min  (model: {})",
        total,
        actors.len(),
        (last - first) / 60.0,
        guard.model().description
    );
    print!("Decisions:");
    for d in ["allow", "warn", "delay", "challenge", "block"] {
        let n = decisions.get(d).copied().unwrap_or(0);
        if n > 0 || d != "challenge" {
            print!("  {d} {:.1}%", pct(n, total));
        }
    }
    println!("\n");

    if !buckets.is_empty() {
        let mut rows: Vec<_> = buckets.iter().collect();
        rows.sort_by(|a, b| a.1.label.cmp(&b.1.label).then(a.0.cmp(b.0)));
        println!(
            "{:<44} {:>6} {:>9} {:>9} {:>9} {:>16}",
            "scenario", "label", "requests", "stopped%", "blocked%", "actors stopped"
        );
        println!("{}", "-".repeat(98));
        let (mut lt, mut ls, mut at, mut ast) = (0, 0, 0, 0);
        for (name, b) in &rows {
            let label = match b.label {
                Some(true) => "attack",
                Some(false) => "legit",
                None => "?",
            };
            println!(
                "{:<44} {:>6} {:>9} {:>9.1} {:>9.1} {:>9}/{:<6}",
                truncate(name, 44),
                label,
                b.total,
                pct(b.stopped, b.total),
                pct(b.blocked, b.total),
                b.actors.values().filter(|s| **s).count(),
                b.actors.len()
            );
            match b.label {
                Some(true) => {
                    at += b.total;
                    ast += b.stopped;
                }
                Some(false) => {
                    lt += b.total;
                    ls += b.stopped;
                }
                None => {}
            }
        }
        if labelled {
            println!();
            println!(
                "False positives: {:.2}% of legitimate requests stopped ({ls} of {lt})",
                pct(ls, lt)
            );
            println!(
                "Detection:       {:.1}% of abusive requests stopped ({ast} of {at})",
                pct(ast, at)
            );
            if ls + ast > 0 {
                println!(
                    "Precision:       {:.2}% of stopped requests were abusive",
                    pct(ast, ls + ast)
                );
            }
        }
        println!();
    }

    let mut flagged: Vec<_> = actors.iter().filter(|(_, a)| a.stopped > 0).collect();
    flagged.sort_by_key(|(_, a)| std::cmp::Reverse(a.stopped));
    if !flagged.is_empty() && top > 0 {
        println!("Top flagged actors ({} flagged in total):", flagged.len());
        for (actor, a) in flagged.into_iter().take(top) {
            let mut rs: Vec<_> = a.reasons.iter().collect();
            rs.sort_by(|x, y| y.1.cmp(x.1));
            let rs: Vec<&str> = rs.into_iter().take(3).map(|(k, _)| k.as_str()).collect();
            println!(
                "  {:<28} {:>7} reqs  {:>5.1}% stopped   {}",
                truncate(actor, 28),
                a.total,
                pct(a.stopped, a.total),
                rs.join(", ")
            );
        }
    }
    Ok(())
}

fn truncate(s: &str, n: usize) -> String {
    if s.chars().count() <= n {
        s.to_string()
    } else {
        let mut t: String = s.chars().take(n - 1).collect();
        t.push('…');
        t
    }
}
