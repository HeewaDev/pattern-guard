//! `pattern-guard train`: fit a model on labelled logs.

use std::collections::HashMap;

use pattern_guard::{Guard, Mode, TrainOptions};

use crate::BoxErr;
use crate::args::{for_each_record, format_flag, load_config, parse_flags, pct};

pub(crate) fn train(args: &[String]) -> Result<(), BoxErr> {
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
