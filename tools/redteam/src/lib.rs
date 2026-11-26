//! Red-team harness for Pattern-Guard (not published).
//!
//! An attacker ([`attack`]) works against a deliberately vulnerable demo shop ([`app`]),
//! once through the gateway (in process, prevent mode, `gateway.toml`) and once directly.
//! The [`harness`] measures per scenario: requests and time until the first bypass (a
//! vulnerability confirmed through the gateway, judged by the [`oracle`] from the
//! response), requests and time until the first ban, and the vulnerabilities found with
//! and without the gateway. [`report`] prints a Markdown table and writes JSON for tracking
//! per release.
//!
//! Everything is offline and deterministic for a seed: localhost only, simulated
//! vulnerabilities, no LLM, no browser. An LLM- or browser-driven attacker plugs in
//! through the [`attack::Strategy`] trait or the JSON-lines protocol of
//! [`attack::external`].

pub mod app;
pub mod attack;
pub mod browser;
pub mod harness;
pub mod oracle;
pub mod report;
pub mod rng;

/// The demo shop's vulnerabilities.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Vuln {
    Sqli,
    Xss,
    Traversal,
    Cmdi,
    Bola,
    BruteForce,
}

impl Vuln {
    pub const ALL: [Vuln; 6] = [
        Vuln::Sqli,
        Vuln::Xss,
        Vuln::Traversal,
        Vuln::Cmdi,
        Vuln::Bola,
        Vuln::BruteForce,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Vuln::Sqli => "sqli",
            Vuln::Xss => "xss",
            Vuln::Traversal => "traversal",
            Vuln::Cmdi => "cmdi",
            Vuln::Bola => "bola",
            Vuln::BruteForce => "bruteforce",
        }
    }

    pub fn parse(s: &str) -> Option<Vuln> {
        Vuln::ALL.into_iter().find(|v| v.as_str() == s)
    }
}
