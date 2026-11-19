//! Gatekeeper policy evaluated before inspection: custom rules (and, in later modules,
//! rate limits, bans, honeypot traps and protocol enforcement).

pub mod rate_limit;
pub mod rules;
