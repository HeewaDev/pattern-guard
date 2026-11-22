//! Access-log parsing (`pattern-guard replay` / `train` read attacker-influenced logs).
#![no_main]

use libfuzzer_sys::fuzz_target;
use pattern_guard::logs::{LogFormat, parse_line};

fuzz_target!(|data: &[u8]| {
    let line = String::from_utf8_lossy(data);
    let _ = LogFormat::detect(&line);
    for format in [LogFormat::Combined, LogFormat::Jsonl] {
        let _ = parse_line(&line, format);
    }
});
