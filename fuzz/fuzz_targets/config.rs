//! Config and model parsing: gateway config (validated and compiled whole, as a reload
//! does: rules, rate limits, operations, lists, headers), engine config, model files.
//! Errors are fine; panics are not.
#![no_main]

use libfuzzer_sys::fuzz_target;
use pattern_guard_gateway::config::GatewayConfig;
use pattern_guard_gateway::state::Compiled;

fuzz_target!(|data: &[u8]| {
    let Ok(s) = std::str::from_utf8(data) else {
        return;
    };
    if let Ok(mut cfg) = GatewayConfig::from_toml_str(s) {
        cfg.geo.database = None; // no file reads while fuzzing
        let _ = Compiled::compile(cfg);
    }
    let _ = pattern_guard::Config::from_toml_str(s);
    let _ = pattern_guard::Model::from_toml_str(s);
});
