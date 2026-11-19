//! CLI.
//!
//! ```text
//! pattern-guard replay [--config F] [--model M] [--format auto|jsonl|combined] [--top N] LOG
//! pattern-guard train  [--config F] [--epochs N] [--l2 X] [--lr X] [--no-balance] [--no-augment] [--augment-weight W] -o OUT LOG
//! pattern-guard --config F [--repeat N] [--] cmd [args]      (wrap a command)
//! ```

use std::collections::HashMap;
use std::io::{BufRead, BufReader};
use std::path::PathBuf;
use std::process::Command;
use std::time::SystemTime;

use pattern_guard::logs::{LogFormat, LogRecord, parse_line};
use pattern_guard::{Config, Decision, Guard, Mode, Model, TrainOptions};

type ParsedArgs = (Option<PathBuf>, Option<u32>, Vec<String>);
type BoxErr = Box<dyn std::error::Error>;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let result = match args.get(1).map(String::as_str) {
        Some("replay") => replay(&args[2..]),
        Some("train") => train(&args[2..]),
        Some("-h") | Some("--help") | Some("help") => {
            print!("{}", USAGE);
            Ok(())
        }
        _ => wrap(&args),
    };
    if let Err(e) = result {
        eprintln!("pattern-guard: {e}");
        std::process::exit(1);
    }
}

const USAGE: &str = "\
pattern-guard — adaptive request-abuse detection

USAGE:
  pattern-guard replay [--config F] [--model M] [--format auto|jsonl|combined] [--top N] LOG
      Replay an access log (JSONL or nginx/Apache combined, '-' for stdin) through the
      guard and report decisions. With labelled JSONL, also reports false positives and
      detection per scenario.

  pattern-guard train [--config F] [--epochs N] [--l2 X] [--lr X] [--no-balance] [--no-augment] [--augment-weight W] -o OUT LOG
      Train a model on labelled JSONL (`label`: 1 = abusive, 0 = legitimate) and write
      it as TOML. Use it with `model = \"OUT\"` in guard.toml or `replay --model OUT`.

  pattern-guard --config F [--repeat N] [--] CMD [ARGS...]
      Run CMD under the guard (one event per run).
";

// ---------------------------------------------------------------- arg helpers

struct Flags {
    values: HashMap<String, String>,
    switches: Vec<String>,
    positional: Vec<String>,
}

fn parse_flags(args: &[String], with_value: &[&str], switches: &[&str]) -> Result<Flags, BoxErr> {
    let mut f = Flags {
        values: HashMap::new(),
        switches: Vec::new(),
        positional: Vec::new(),
    };
    let mut i = 0;
    while i < args.len() {
        let a = args[i].as_str();
        if with_value.contains(&a) {
            let v = args
                .get(i + 1)
                .ok_or_else(|| format!("{a} requires a value"))?;
            f.values.insert(a.to_string(), v.clone());
            i += 2;
        } else if switches.contains(&a) {
            f.switches.push(a.to_string());
            i += 1;
        } else if a.starts_with("--") || (a.starts_with('-') && a.len() > 1) {
            return Err(format!("unknown flag: {a}").into());
        } else {
            f.positional.push(a.to_string());
            i += 1;
        }
    }
    Ok(f)
}

fn load_config(path: Option<&String>) -> Result<Config, BoxErr> {
    Ok(match path {
        Some(p) => Config::load(p)?,
        None => Config::default(),
    })
}

fn open_log(path: &str) -> Result<Box<dyn BufRead>, BoxErr> {
    Ok(if path == "-" {
        Box::new(BufReader::new(std::io::stdin()))
    } else {
        Box::new(BufReader::new(
            std::fs::File::open(path).map_err(|e| format!("cannot open {path}: {e}"))?,
        ))
    })
}

/// Streams records, auto-detecting the format from the first data line.
fn for_each_record(
    path: &str,
    format: Option<LogFormat>,
    mut f: impl FnMut(LogRecord),
) -> Result<usize, BoxErr> {
    let mut format = format;
    let mut bad = 0usize;
    for (n, line) in open_log(path)?.lines().enumerate() {
        let line = line?;
        let fmt = *format.get_or_insert_with(|| LogFormat::detect(&line));
        match parse_line(&line, fmt) {
            Ok(Some(r)) => f(r),
            Ok(None) => {}
            Err(e) => {
                bad += 1;
                if bad <= 5 {
                    eprintln!("pattern-guard: line {}: {e} (skipped)", n + 1);
                }
            }
        }
    }
    if bad > 5 {
        eprintln!("pattern-guard: {bad} unparseable lines skipped in total");
    }
    Ok(bad)
}

fn format_flag(f: &Flags) -> Result<Option<LogFormat>, BoxErr> {
    match f.values.get("--format").map(String::as_str) {
        None | Some("auto") => Ok(None),
        Some(s) => Ok(Some(
            LogFormat::parse(s).ok_or_else(|| format!("unknown --format {s}"))?,
        )),
    }
}

fn pct(n: usize, d: usize) -> f64 {
    if d == 0 {
        0.0
    } else {
        100.0 * n as f64 / d as f64
    }
}

// ---------------------------------------------------------------- replay

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

fn replay(args: &[String]) -> Result<(), BoxErr> {
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

// ---------------------------------------------------------------- train

fn train(args: &[String]) -> Result<(), BoxErr> {
    let f = parse_flags(
        args,
        &[
            "--config",
            "--format",
            "--epochs",
            "--l2",
            "--lr",
            "--augment-weight",
            "-o",
            "--out",
        ],
        &["--no-balance", "--no-augment"],
    )?;
    let [log] = f.positional.as_slice() else {
        return Err("train: expected exactly one labelled LOG argument".into());
    };
    let out = f
        .values
        .get("-o")
        .or(f.values.get("--out"))
        .ok_or("train: -o OUT is required")?;
    let config = load_config(f.values.get("--config"))?;
    if config.guard.mode == Mode::Rules {
        return Err("train: config has mode = \"rules\"; features are only computed in adaptive/hybrid mode".into());
    }
    let mut opts = TrainOptions::default();
    if let Some(v) = f.values.get("--epochs") {
        opts.epochs = v.parse()?;
    }
    if let Some(v) = f.values.get("--l2") {
        opts.l2 = v.parse()?;
    }
    if let Some(v) = f.values.get("--lr") {
        opts.learning_rate = v.parse()?;
    }
    let guard = Guard::new(config)?;

    let mut x = Vec::new();
    let mut y = Vec::new();
    let mut groups: Vec<String> = Vec::new();
    let mut unlabelled = 0usize;
    for_each_record(log, format_flag(&f)?, |r| {
        let a = guard.assess(&r.event);
        if let Some(s) = r.status {
            guard.observe_response(&r.event, s);
        }
        match r.label {
            Some(l) => {
                x.push(a.features);
                y.push(l);
                groups.push(
                    r.scenario
                        .unwrap_or_else(|| if l { "abusive" } else { "legitimate" }.into()),
                );
            }
            None => unlabelled += 1,
        }
    })?;
    let pos = y.iter().filter(|l| **l).count();
    let neg = y.len() - pos;
    let n_original = y.len();
    if pos == 0 || neg == 0 {
        return Err(format!(
            "train: need both abusive (label 1) and legitimate (label 0) samples; got {pos} abusive, {neg} legitimate"
        )
        .into());
    }
    if unlabelled > 0 {
        eprintln!("pattern-guard: {unlabelled} unlabelled records used for context only");
    }

    // Mimicry augmentation (see model::MIMICABLE_FEATURES): teach the model that an
    // attacker who spoofs a browser fingerprint, rotates residential IPs and adds a page
    // view is still an attacker if its behaviour is abusive.
    let augment_weight: f64 = f
        .values
        .get("--augment-weight")
        .map(|v| v.parse())
        .transpose()?
        .unwrap_or(0.3);
    if !f.switches.iter().any(|s| s == "--no-augment") && augment_weight > 0.0 {
        let mut legit_mean = [0.0; pattern_guard::N_FEATURES];
        for (xi, _) in x.iter().zip(&y).filter(|(_, l)| !**l) {
            for j in 0..legit_mean.len() {
                legit_mean[j] += xi[j] / neg as f64;
            }
        }
        for i in 0..n_original {
            if y[i] {
                x.push(pattern_guard::model::mimicry_copy(&x[i], &legit_mean));
                y.push(true);
                groups.push(format!("{} (mimicry)", groups[i]));
            }
        }
    }

    // Balance: each class gets half the total weight; within a class, each scenario
    // gets an equal share (so a huge flood does not drown out a 45-request scan).
    let weights: Vec<f64> = if f.switches.iter().any(|s| s == "--no-balance") {
        vec![1.0; y.len()]
    } else {
        let mut count: HashMap<(&str, bool), usize> = HashMap::new();
        for (g, l) in groups.iter().zip(&y) {
            *count.entry((g.as_str(), *l)).or_default() += 1;
        }
        let groups_per_class = |l: bool| count.keys().filter(|(_, c)| *c == l).count() as f64;
        let (gp, gn) = (groups_per_class(true), groups_per_class(false));
        groups
            .iter()
            .zip(&y)
            .map(|(g, l)| {
                let n = count[&(g.as_str(), *l)] as f64;
                let gc = if *l { gp } else { gn };
                let factor = if g.ends_with(" (mimicry)") {
                    augment_weight
                } else {
                    1.0
                };
                factor * y.len() as f64 * 0.5 / (gc * n)
            })
            .collect()
    };

    eprintln!(
        "pattern-guard: training on {} samples ({} abusive, {} legitimate, {} groups)...",
        y.len(),
        pos,
        neg,
        groups
            .iter()
            .collect::<std::collections::HashSet<_>>()
            .len()
    );
    let description = format!(
        "trained by `pattern-guard train` on {} samples ({} abusive / {} legitimate)",
        y.len(),
        pos,
        neg
    );
    let model = pattern_guard::model::train(&x, &y, &weights, &opts, description);

    let warn_below = guard.config().guard.warn_below;
    let (mut fp, mut tp) = (0usize, 0usize);
    for (xi, &l) in x.iter().zip(&y).take(n_original) {
        let stopped = model.predict(xi).0 >= warn_below;
        if stopped {
            if l {
                tp += 1;
            } else {
                fp += 1;
            }
        }
    }
    std::fs::write(out, model.to_toml_string())?;
    println!("Wrote {out}");
    println!(
        "On the training data at risk ≥ {warn_below}: false positives {:.2}%, detection {:.1}%",
        pct(fp, neg),
        pct(tp, pos)
    );
    println!("(Evaluate on a different log with `pattern-guard replay --model {out} LOG`.)");
    let mut w: Vec<_> = model.weights().collect();
    w.sort_by(|a, b| b.1.abs().total_cmp(&a.1.abs()));
    println!("Strongest signals:");
    for (name, wt) in w.into_iter().take(8) {
        println!("  {name:<28} {wt:+.3}");
    }
    Ok(())
}

// ---------------------------------------------------------------- wrap a command

fn wrap(args: &[String]) -> Result<(), BoxErr> {
    let (config_path, repeat_n, rest) = parse_args(args)?;

    let guard = if let Some(p) = config_path {
        Guard::from_config_path(p)?
    } else {
        eprintln!("pattern-guard: no --config given; running without guard");
        if rest.is_empty() {
            return Err(format!("no command given\n\n{USAGE}").into());
        }
        let code = run_child(&rest)?;
        std::process::exit(code);
    };

    if rest.is_empty() {
        return Err("no command given (use `-- cmd` or put the command after flags)".into());
    }

    let target = rest.join(" ");
    let runs = repeat_n.unwrap_or(1);
    let mut last_code = 0i32;

    for _ in 1..=runs {
        let event = pattern_guard::Event::new("cli", "run", target.clone(), SystemTime::now());
        let (decision, risk) = guard.check_with_risk(&event);

        match decision {
            Decision::Block => {
                let msg = format!("pattern-guard: block (risk {:.2})", risk);
                eprintln!("{}", msg);
                log::warn!("{}", msg);
                std::process::exit(2);
            }
            Decision::Challenge => {
                let msg = format!(
                    "pattern-guard: challenge (risk {:.2}) — refusing to run unattended",
                    risk
                );
                eprintln!("{}", msg);
                log::warn!("{}", msg);
                std::process::exit(2);
            }
            Decision::Delay(d) => {
                let msg = format!("pattern-guard: delay {:?} (risk {:.2})", d, risk);
                eprintln!("{}", msg);
                log::info!("{}", msg);
                std::thread::sleep(d);
            }
            Decision::Warn => {
                let msg = format!("pattern-guard: warn (risk {:.2}) — proceeding", risk);
                eprintln!("{}", msg);
                log::info!("{}", msg);
            }
            Decision::Allow => {}
        }

        last_code = run_child(&rest)?;
    }

    std::process::exit(last_code);
}

/// Parses argv[0] = program name. Supports `--config`, `--repeat`, optional `--`, then command args.
fn parse_args(args: &[String]) -> Result<ParsedArgs, String> {
    let mut config_path = None;
    let mut repeat_n = None;
    let mut i = 1usize;

    while i < args.len() {
        match args[i].as_str() {
            "--" => {
                i += 1;
                break;
            }
            "--config" => {
                let Some(path) = args.get(i + 1) else {
                    return Err("--config requires a path".into());
                };
                config_path = Some(PathBuf::from(path));
                i += 2;
            }
            "--repeat" => {
                let Some(n) = args.get(i + 1) else {
                    return Err("--repeat requires a number".into());
                };
                repeat_n = Some(
                    n.parse::<u32>()
                        .map_err(|_| format!("invalid --repeat value: {}", n))?,
                );
                i += 2;
            }
            s if s.starts_with("--") => {
                return Err(format!(
                    "unknown flag: {} (expected --config, --repeat, or --)",
                    s
                ));
            }
            _ => break,
        }
    }

    let rest: Vec<String> = args[i..].to_vec();
    Ok((config_path, repeat_n, rest))
}

fn run_child(argv: &[String]) -> Result<i32, BoxErr> {
    let (prog, rest) = (&argv[0], &argv[1..]);
    let status = Command::new(prog).args(rest).status()?;
    Ok(status.code().unwrap_or(1))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(s: &[&str]) -> Vec<String> {
        s.iter().map(|x| (*x).to_string()).collect()
    }

    #[test]
    fn parse_positional_command_without_double_dash() {
        let a = args(&["pg", "--config", "f.toml", "true"]);
        let (c, r, rest) = parse_args(&a).unwrap();
        assert_eq!(c, Some(PathBuf::from("f.toml")));
        assert_eq!(r, None);
        assert_eq!(rest, vec!["true"]);
    }

    #[test]
    fn parse_double_dash_still_works() {
        let a = args(&["pg", "--config", "f.toml", "--", "sh", "-c", "true"]);
        let (_, _, rest) = parse_args(&a).unwrap();
        assert_eq!(rest, vec!["sh", "-c", "true"]);
    }

    #[test]
    fn parse_unknown_flag_errors() {
        let a = args(&["pg", "--config", "f.toml", "--weird", "x"]);
        assert!(parse_args(&a).is_err());
    }

    #[test]
    fn subcommand_flags() {
        let f = parse_flags(&args(&["--top", "3", "access.log"]), &["--top"], &[]).unwrap();
        assert_eq!(f.values["--top"], "3");
        assert_eq!(f.positional, vec!["access.log"]);
        assert!(parse_flags(&args(&["--nope"]), &[], &[]).is_err());
        assert!(parse_flags(&args(&["-"]), &[], &[]).unwrap().positional == vec!["-"]);
    }
}
