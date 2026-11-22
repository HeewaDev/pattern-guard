//! One value through the decoder, every variant and every analyser, at a location
//! picked by the first byte (the high bit selects form decoding).
#![no_main]

use std::sync::LazyLock;

use libfuzzer_sys::fuzz_target;
use pattern_guard_waf::Inspector;

static WAF: LazyLock<Inspector> = LazyLock::new(Inspector::new);

const LOCATIONS: &[&str] = &[
    "path",
    "query:q",
    "body:comment",
    "json.user.name",
    "header:user-agent",
    "header:referer",
    "cookie:sid",
    "filename:file",
];

fuzz_target!(|data: &[u8]| {
    let Some((&pick, rest)) = data.split_first() else {
        return;
    };
    let value = String::from_utf8_lossy(rest);
    let location = LOCATIONS[pick as usize % LOCATIONS.len()];
    let _ = pattern_guard_waf::decode(&value, pick & 0x80 != 0);
    if let Some(f) = WAF.inspect_value(location, &value, pick & 0x80 != 0) {
        assert!(
            (0.0..=10.0).contains(&f.score),
            "score {} out of range",
            f.score
        );
        assert!(f.sample.len() <= 160, "sample of {} bytes", f.sample.len());
    }
});
