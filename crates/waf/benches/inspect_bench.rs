//! WAF inspection cost: a typical request, short values and worst-case 8 KiB values.
//!
//! `cargo bench -p pattern-guard-waf`. A typical request should stay in the tens of
//! microseconds; a jump to milliseconds means the indicator RegexSet fell back to the
//! regex crate's slow engine (see the `dfa_size_limit` note in `inspect.rs`).

use criterion::{Criterion, criterion_group, criterion_main};
use pattern_guard_waf::{HttpRequest, Inspector};
use std::hint::black_box;

fn bench(c: &mut Criterion) {
    let w = Inspector::new();
    let headers = vec![
        ("host".to_string(), "shop.example.com".to_string()),
        (
            "user-agent".to_string(),
            "Mozilla/5.0 (X11; Linux x86_64) Chrome/130.0".to_string(),
        ),
        ("accept".to_string(), "text/html".to_string()),
    ];
    c.bench_function("typical GET request", |b| {
        b.iter(|| {
            w.inspect(black_box(&HttpRequest {
                path_and_query: "/api/products/123?page=2&q=red+shoes",
                headers: &headers,
                content_type: None,
                body: b"",
            }))
        })
    });
    let form = b"user=alice&comment=Great+product%2C+would+buy+again%21&rating=5";
    c.bench_function("form POST", |b| {
        b.iter(|| {
            w.inspect(black_box(&HttpRequest {
                path_and_query: "/reviews",
                headers: &headers,
                content_type: Some("application/x-www-form-urlencoded"),
                body: form,
            }))
        })
    });
    c.bench_function("attack value", |b| {
        b.iter(|| {
            w.inspect_value(
                "query:id",
                black_box("1' UNION SELECT user,pass FROM users--"),
                true,
            )
        })
    });
    let prose = "lorem ipsum dolor sit amet, consectetur adipiscing elit. ".repeat(140);
    let soup = "a;b|c&d(e)f{g}h http://x@y/ ${ifs} [s] 0x7f.1 ".repeat(200);
    let b64 = "QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo=".repeat(220);
    for (name, v) in [
        ("8 KiB prose", &prose),
        ("8 KiB shell/url-like", &soup),
        ("8 KiB base64", &b64),
    ] {
        c.bench_function(name, |b| {
            b.iter(|| w.inspect_value("body:x", black_box(v), true))
        });
    }
}

/// Random printable values, a fresh one per iteration: the lazy DFA can't reuse states
/// across values, which is how an attacker would send them. With one combined automaton
/// this cost ~8 ms per 8 KiB value; the adaptive matcher keeps it near 2–3 ms.
fn bench_random(c: &mut Criterion) {
    let w = Inspector::new();
    let mut x: u64 = 0x9E37_79B9_7F4A_7C15;
    let mut random = |len: usize| -> String {
        (0..len)
            .map(|_| {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                (b' ' + (x % 95) as u8) as char
            })
            .collect()
    };
    for len in [256usize, 8192] {
        let values: Vec<String> = (0..64).map(|_| random(len)).collect();
        let mut i = 0;
        c.bench_function(&format!("{len} B random printable, fresh"), |b| {
            b.iter(|| {
                i = (i + 1) % values.len();
                black_box(w.inspect_value("query:q", &values[i], true))
            })
        });
    }
}

criterion_group!(benches, bench, bench_random);
criterion_main!(benches);
