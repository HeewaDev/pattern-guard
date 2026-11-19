//! Benchmarks the WAF against the OWASP Core Rule Set regression tests.
//!
//! The CRS tests (Apache-2.0, github.com/coreruleset/coreruleset, tests/regression/tests)
//! are not vendored. Extract them to JSONL with `scripts/extract_crs_tests.py`, then:
//!
//! `cargo run --release -p pattern-guard-eval --bin crs_eval -- crs_tests.jsonl [--pl 1]`
//!
//! Each CRS test asserts that *one CRS rule* does (positive) or does not (negative) fire,
//! run at paranoia level 4. So:
//! * positives are real attack requests → we report how many our WAF blocks (score ≥ 7);
//! * negatives are not guaranteed benign (another rule may legitimately fire) → we report
//!   how many we block, as a rough false-positive indicator only.

use std::collections::BTreeMap;

use pattern_guard::waf::{HttpRequest, Inspector};
use serde_json::Value;

const BLOCK: f64 = 7.0;

#[derive(Default)]
struct Row {
    pos: usize,
    pos_blocked: usize,
    pos_logged: usize,
    neg: usize,
    neg_blocked: usize,
}

fn category_name(c: u64) -> &'static str {
    match c {
        913 => "913 scanner detection",
        920 => "920 protocol enforcement",
        921 => "921 protocol attack",
        922 => "922 multipart attack",
        930 => "930 local file inclusion",
        931 => "931 remote file inclusion",
        932 => "932 remote code execution",
        933 => "933 PHP injection",
        934 => "934 generic (SSRF/SSTI/Node)",
        941 => "941 XSS",
        942 => "942 SQL injection",
        943 => "943 session fixation",
        944 => "944 Java attacks",
        _ => "other",
    }
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let path = args
        .first()
        .expect("usage: crs_eval crs_tests.jsonl [--pl N]");
    let max_pl: u64 = args
        .iter()
        .position(|a| a == "--pl")
        .and_then(|i| args.get(i + 1))
        .and_then(|v| v.parse().ok())
        .unwrap_or(4);
    // SHOW=<category> prints missed attacks; SHOW_NEG=<category> prints blocked negatives.
    let show_misses = std::env::var("SHOW").ok();
    let show_blocked_negatives = std::env::var("SHOW_NEG").ok();
    let waf = Inspector::new();
    let text = std::fs::read_to_string(path).expect("read JSONL");
    let mut by_cat: BTreeMap<u64, Row> = BTreeMap::new();
    let mut by_pl: BTreeMap<u64, Row> = BTreeMap::new();

    for line in text.lines() {
        let v: Value = match serde_json::from_str(line) {
            Ok(v) => v,
            Err(_) => continue,
        };
        let Some(expect) = v["expect_trigger"].as_bool() else {
            continue;
        };
        let cat = v["category"].as_u64().unwrap_or(0);
        if !(913..=944).contains(&cat) {
            continue; // response-side (95x) and evaluation rules are out of scope
        }
        let pl = v["rule_pl"].as_u64().unwrap_or(1);
        if pl > max_pl {
            continue;
        }
        let uri = v["uri"].as_str().unwrap_or("/");
        let mut headers: Vec<(String, String)> = v["headers"]
            .as_object()
            .map(|m| {
                m.iter()
                    .filter_map(|(k, x)| x.as_str().map(|s| (k.clone(), s.to_string())))
                    .collect()
            })
            .unwrap_or_default();
        let body = v["body"].as_str().unwrap_or("");
        let has_ct = headers
            .iter()
            .any(|(k, _)| k.eq_ignore_ascii_case("content-type"));
        // go-ftw autocompletes Content-Type for request bodies unless told not to.
        if !body.is_empty() && !has_ct && v["autocomplete_headers"].as_bool() != Some(false) {
            headers.push((
                "Content-Type".into(),
                "application/x-www-form-urlencoded".into(),
            ));
        }
        let ct = headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("content-type"))
            .map(|(_, v)| v.clone());
        let r = waf.inspect(&HttpRequest {
            path_and_query: uri,
            headers: &headers,
            content_type: ct.as_deref(),
            body: body.as_bytes(),
        });
        let score = r.max_score();
        for row in [by_cat.entry(cat).or_default(), by_pl.entry(pl).or_default()] {
            if expect {
                row.pos += 1;
                row.pos_blocked += (score >= BLOCK) as usize;
                row.pos_logged += (score >= 4.0) as usize;
            } else {
                row.neg += 1;
                row.neg_blocked += (score >= BLOCK) as usize;
            }
        }
        if !expect && score >= BLOCK && show_blocked_negatives.as_deref() == Some(&cat.to_string())
        {
            let top = r
                .top()
                .map(|f| format!("{} {:?}", f.location, f.indicators))
                .unwrap_or_default();
            println!(
                "blocked-negative {score:4.1} {} {:.60} | {top}",
                v["id"].as_str().unwrap_or(""),
                v["desc"].as_str().unwrap_or("")
            );
        }
        if expect && score < BLOCK && show_misses.as_deref() == Some(&cat.to_string()) {
            println!(
                "miss {score:4.1} {} {uri} body={body:.120}",
                v["id"].as_str().unwrap_or("")
            );
        }
    }

    let pct = |a: usize, b: usize| {
        if b == 0 {
            0.0
        } else {
            100.0 * a as f64 / b as f64
        }
    };
    println!(
        "CRS regression tests, rules up to paranoia level {max_pl} (block = score ≥ {BLOCK})\n"
    );
    println!(
        "{:<32} {:>9} {:>9} {:>9}   {:>9} {:>11}",
        "category", "attacks", "blocked%", "logged%", "negatives", "blocked%*"
    );
    println!("{}", "-".repeat(88));
    let (mut tp, mut tpb, mut tn, mut tnb) = (0, 0, 0, 0);
    for (c, r) in &by_cat {
        println!(
            "{:<32} {:>9} {:>9.1} {:>9.1}   {:>9} {:>11.1}",
            category_name(*c),
            r.pos,
            pct(r.pos_blocked, r.pos),
            pct(r.pos_logged, r.pos),
            r.neg,
            pct(r.neg_blocked, r.neg)
        );
        if (930..=944).contains(c) {
            tp += r.pos;
            tpb += r.pos_blocked;
            tn += r.neg;
            tnb += r.neg_blocked;
        }
    }
    println!("{}", "-".repeat(88));
    println!(
        "{:<32} {:>9} {:>9.1} {:>9}   {:>9} {:>11.1}",
        "attack categories 930–944",
        tp,
        pct(tpb, tp),
        "",
        tn,
        pct(tnb, tn)
    );
    println!("\nBy CRS paranoia level of the tested rule (attack categories and protocol rules):");
    for (pl, r) in &by_pl {
        println!(
            "  PL{pl}: {:>5} attacks, {:>5.1}% blocked   |   {:>4} negatives, {:>5.1}% blocked*",
            r.pos,
            pct(r.pos_blocked, r.pos),
            r.neg,
            pct(r.neg_blocked, r.neg)
        );
    }
    println!(
        "\n* CRS negatives only assert that one specific rule stays silent; they are not guaranteed-benign requests."
    );
}
