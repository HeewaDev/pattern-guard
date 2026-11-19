//! Writes labelled synthetic traffic as JSONL to stdout (for `pattern-guard train/replay`).
//!
//! `cargo run --release -p pattern-guard-eval --bin gen_traffic -- [--seed N] [--hours H] [--unseen] > traffic.jsonl`

use pattern_guard_eval::sim;

use std::io::{BufWriter, Write};

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let get = |flag: &str| {
        args.iter()
            .position(|a| a == flag)
            .and_then(|i| args.get(i + 1))
            .map(|v| v.parse::<u64>().expect("numeric flag value"))
    };
    let seed = get("--seed").unwrap_or(1);
    let hours = get("--hours").unwrap_or(1) as u32;
    let unseen = args.iter().any(|a| a == "--unseen");
    let recs = sim::generate(seed, hours, unseen);
    let mut out = BufWriter::new(std::io::stdout().lock());
    for r in &recs {
        writeln!(out, "{}", sim::to_json(r)).unwrap();
    }
    eprintln!(
        "wrote {} requests ({} hours, seed {seed}, unseen={unseen})",
        recs.len(),
        hours
    );
}
