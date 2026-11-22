//! The multipart parser and upload checks, fed raw bodies with a fixed boundary `b`.
#![no_main]

use std::sync::LazyLock;

use libfuzzer_sys::fuzz_target;
use pattern_guard_waf::{HttpRequest, Inspector};

static WAF: LazyLock<Inspector> = LazyLock::new(Inspector::new);

const CT: &str = "multipart/form-data; boundary=b";

fuzz_target!(|data: &[u8]| {
    let headers = vec![("content-type".to_string(), CT.to_string())];
    let inspection = WAF.inspect(&HttpRequest {
        path_and_query: "/upload",
        headers: &headers,
        content_type: Some(CT),
        body: data,
    });
    for f in &inspection.findings {
        assert!(
            (0.0..=10.0).contains(&f.score),
            "score {} out of range",
            f.score
        );
    }
});
