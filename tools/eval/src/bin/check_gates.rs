//! Checks evaluation metrics against the CI gates.
//!
//! `check_gates tools/eval/gates.toml waf_dev=out/waf_dev.json crs=out/crs.json …`
//!
//! Each `SET=FILE` names the metrics file (written by an evaluation binary with
//! `--metrics FILE`) for one table of the gates file. Prints a Markdown table and exits
//! with 1 if a gate fails or a gated set is missing, 2 on bad input.

use std::collections::BTreeMap;

use pattern_guard_eval::gates::{Metrics, check, parse_gates};

fn fail(msg: String) -> ! {
    eprintln!("check_gates: {msg}");
    std::process::exit(2);
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let Some((gates_path, sets)) = args.split_first() else {
        fail("usage: check_gates GATES.toml SET=METRICS.json…".into());
    };
    let text = std::fs::read_to_string(gates_path)
        .unwrap_or_else(|e| fail(format!("cannot read {gates_path}: {e}")));
    let gates = parse_gates(&text).unwrap_or_else(|e| fail(e));
    let mut given = BTreeMap::new();
    for a in sets {
        let Some((set, path)) = a.split_once('=') else {
            fail(format!("expected SET=FILE, got {a}"));
        };
        let text = std::fs::read_to_string(path)
            .unwrap_or_else(|e| fail(format!("cannot read {path}: {e}")));
        let m = Metrics::from_json(&text).unwrap_or_else(|e| fail(format!("{path}: {e}")));
        given.insert(set.to_string(), m);
    }
    let report = check(&gates, &given);
    print!("{}", report.to_markdown());
    if !report.passed() {
        std::process::exit(1);
    }
}
