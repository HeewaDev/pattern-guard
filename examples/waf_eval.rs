//! WAF accuracy on payload/benign files (one value per line).
//!
//! `cargo run --release --example waf_eval -- --attack sqli.txt --attack xss.txt --benign words.txt`
use pattern_guard::waf::Inspector;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let w = Inspector::new();
    let (mut at, mut ab, mut bt, mut bb) = (0usize, 0usize, 0usize, 0usize);
    let mut false_blocks = Vec::new();
    let mut misses = Vec::new();
    for pair in args.chunks(2) {
        let (kind, path) = (&pair[0], &pair[1]);
        let text = std::fs::read_to_string(path).expect("read file");
        let lines: Vec<&str> = text
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty() && !l.starts_with("```"))
            .collect();
        let mut blocked = 0;
        for l in &lines {
            let s = w
                .inspect_value("eval", l, true)
                .map(|f| f.score)
                .unwrap_or(0.0);
            if s >= 7.0 {
                blocked += 1;
                if kind == "--benign" {
                    false_blocks.push(format!("{s:4.1} {l}"));
                }
            } else if kind == "--attack" {
                misses.push(format!("{s:4.1} {l}"));
            }
        }
        let name = std::path::Path::new(path)
            .file_name()
            .unwrap()
            .to_string_lossy();
        println!(
            "{:<8} {:<20} {:>6} values  {:>6.1}% blocked",
            &kind[2..],
            name,
            lines.len(),
            100.0 * blocked as f64 / lines.len().max(1) as f64
        );
        if kind == "--attack" {
            at += lines.len();
            ab += blocked;
        } else {
            bt += lines.len();
            bb += blocked;
        }
    }
    println!(
        "\nattacks blocked: {ab}/{at} ({:.1}%)   benign blocked: {bb}/{bt} ({:.2}%)",
        100.0 * ab as f64 / at.max(1) as f64,
        100.0 * bb as f64 / bt.max(1) as f64
    );
    if std::env::var("SHOW").is_ok() {
        for f in false_blocks.iter().take(40) {
            println!("FALSE BLOCK {f}");
        }
        for m in misses.iter().take(60) {
            println!("miss {m}");
        }
    }
}
