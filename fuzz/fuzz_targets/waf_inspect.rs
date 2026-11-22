//! Whole-request WAF inspection: request target, header values and body, with the
//! content type picked by the first byte. Must never panic; scores stay in 0–10.
#![no_main]

use std::sync::LazyLock;

use libfuzzer_sys::fuzz_target;
use pattern_guard_waf::{HttpRequest, Inspector};

static WAF: LazyLock<Inspector> = LazyLock::new(Inspector::new);

const CONTENT_TYPES: &[&str] = &[
    "application/x-www-form-urlencoded",
    "application/json",
    "multipart/form-data; boundary=b",
    "text/xml",
    "text/plain",
    "",
];

fuzz_target!(|data: &[u8]| {
    let Some((&pick, rest)) = data.split_first() else {
        return;
    };
    // `0xFF` never occurs in UTF-8, so it splits target / header value / body.
    let mut parts = rest.splitn(3, |&b| b == 0xFF);
    let target = String::from_utf8_lossy(parts.next().unwrap_or_default());
    let header = String::from_utf8_lossy(parts.next().unwrap_or_default()).into_owned();
    let body = parts.next().unwrap_or_default();
    let ct = CONTENT_TYPES[pick as usize % CONTENT_TYPES.len()];
    let headers = vec![
        ("user-agent".to_string(), header.clone()),
        ("referer".to_string(), header.clone()),
        ("cookie".to_string(), header.clone()),
        ("x-anything".to_string(), header),
        ("content-type".to_string(), ct.to_string()),
    ];
    let inspection = WAF.inspect(&HttpRequest {
        path_and_query: &target,
        headers: &headers,
        content_type: (!ct.is_empty()).then_some(ct),
        body,
    });
    for f in &inspection.findings {
        assert!(
            (0.0..=10.0).contains(&f.score),
            "score {} out of range",
            f.score
        );
    }
});
