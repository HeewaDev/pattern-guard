//! Config and model parsing: gateway config (and compiling its rules, rate limits and
//! operations), engine config, model files. Errors are fine; panics are not.
#![no_main]

use libfuzzer_sys::fuzz_target;
use pattern_guard_gateway::config::GatewayConfig;
use pattern_guard_gateway::policy::{
    operations::Operations, rate_limit::RateLimiter, rules::RuleSet,
};

fuzz_target!(|data: &[u8]| {
    let Ok(s) = std::str::from_utf8(data) else {
        return;
    };
    if let Ok(cfg) = GatewayConfig::from_toml_str(s) {
        let _ = RuleSet::compile(&cfg.rules);
        let _ = RateLimiter::compile(&cfg.rate_limits);
        let _ = Operations::compile(&cfg.operations, &cfg.logins);
    }
    let _ = pattern_guard::Config::from_toml_str(s);
    let _ = pattern_guard::Model::from_toml_str(s);
});
