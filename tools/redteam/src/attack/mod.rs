//! The attacker side: what a strategy sends ([`Probe`]), what it gets back
//! ([`Observation`]), the [`Strategy`] trait, and how a response reads from the outside
//! ([`Verdict`]).
//!
//! Two strategies ship: [`adaptive::Adaptive`], a deterministic attacker that mutates
//! payloads when blocked, and [`external::External`], which drives any program over JSON
//! lines (an LLM agent, a browser automation script).

pub mod adaptive;
pub mod encode;
pub mod external;
pub mod mutate;
pub mod pow;

use std::net::IpAddr;
use std::time::Duration;

use crate::Vuln;
use crate::oracle::Confirmation;

/// One request the attacker wants sent.
#[derive(Debug, Clone, Default)]
pub struct Probe {
    pub method: String,
    /// Path and query, already encoded.
    pub target: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
    /// The client address the request appears to come from (the harness sends it as
    /// `X-Forwarded-For` from a trusted peer). `None`: the scenario's first address.
    pub client_ip: Option<IpAddr>,
    /// Pause before sending (pacing, `Retry-After`).
    pub wait: Duration,
    /// What the attacker is after with this request, for the log.
    pub goal: Option<Vuln>,
    /// A short description: payload and mutations.
    pub label: String,
}

/// The response, as the attacker sees it, plus the harness's verdict.
#[derive(Debug, Clone, Default)]
pub struct Observation {
    /// 0 when the request failed (connection refused, timeout, invalid request).
    pub status: u16,
    /// Lower-case names.
    pub headers: Vec<(String, String)>,
    pub body: String,
    pub elapsed: Duration,
    /// Set by the harness's oracle.
    pub confirmed: Option<Confirmation>,
}

impl Observation {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
    }
}

/// An attacker. The harness calls `next`, sends the probe, then `observe`s the result.
pub trait Strategy: Send {
    fn name(&self) -> String;
    /// The next request, or `None` when the attacker stops.
    fn next(&mut self) -> Option<Probe>;
    fn observe(&mut self, probe: &Probe, obs: &Observation);
    /// Why it stopped (`"done"`, `"banned"`, …), once `next` returned `None`.
    fn stop_reason(&self) -> String {
        "done".into()
    }
}

/// How a response reads from outside the gateway.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Verdict {
    /// The oracle confirmed the vulnerability.
    Confirmed,
    /// The application answered; the payload did nothing visible.
    Passed,
    /// The gateway's block page.
    Blocked,
    /// A proof-of-work challenge.
    Challenged,
    /// 429; wait this long (`Retry-After`).
    RateLimited(Duration),
    /// Another refusal by the gateway (protocol limits, replay, 503, …).
    Refused,
    /// The request failed.
    Error,
}

impl Verdict {
    pub fn as_str(self) -> &'static str {
        match self {
            Verdict::Confirmed => "confirmed",
            Verdict::Passed => "passed",
            Verdict::Blocked => "blocked",
            Verdict::Challenged => "challenged",
            Verdict::RateLimited(_) => "rate_limited",
            Verdict::Refused => "refused",
            Verdict::Error => "error",
        }
    }

    /// Stopped by the gateway (or failed), as opposed to answered by the application.
    pub fn stopped(self) -> bool {
        !matches!(self, Verdict::Confirmed | Verdict::Passed)
    }
}

/// Reads a response the way an attacker can: the gateway's own pages carry a request id
/// (`{"error":"blocked","request_id":…}` for API clients).
pub fn classify(obs: &Observation) -> Verdict {
    if obs.status == 0 {
        return Verdict::Error;
    }
    if obs.confirmed.is_some() {
        return Verdict::Confirmed;
    }
    let gateway_json = obs.body.contains("\"request_id\"");
    if obs.status == 429 {
        let secs = obs
            .header("retry-after")
            .and_then(|v| v.trim().parse::<u64>().ok())
            .unwrap_or(1);
        return Verdict::RateLimited(Duration::from_secs(secs));
    }
    if obs.status == 403
        && (obs.body.contains("challenge_required") || obs.body.contains("var N=\""))
    {
        return Verdict::Challenged;
    }
    if obs.status == 403
        && (obs.body.contains("\"error\":\"blocked\"") || obs.body.contains("Access denied"))
    {
        return Verdict::Blocked;
    }
    if gateway_json
        || (obs.status >= 400
            && obs.header("connection") == Some("close")
            && obs.header("content-type") == Some("text/plain"))
    {
        return Verdict::Refused;
    }
    Verdict::Passed
}

/// A vulnerable endpoint, as the attacker knows it from browsing the shop.
#[derive(Debug, Clone, Copy)]
pub struct Target {
    pub vuln: Vuln,
    pub method: &'static str,
    pub path: &'static str,
    pub param: &'static str,
    /// A value the endpoint expects (for parameter pollution, benign traffic).
    pub benign: &'static str,
}

pub const TARGETS: &[Target] = &[
    Target {
        vuln: Vuln::Sqli,
        method: "GET",
        path: "/products",
        param: "id",
        benign: "1",
    },
    Target {
        vuln: Vuln::Xss,
        method: "GET",
        path: "/search",
        param: "q",
        benign: "grinder",
    },
    Target {
        vuln: Vuln::Traversal,
        method: "GET",
        path: "/download",
        param: "file",
        benign: "report.pdf",
    },
    Target {
        vuln: Vuln::Cmdi,
        method: "POST",
        path: "/tools/ping",
        param: "host",
        benign: "127.0.0.1",
    },
    Target {
        vuln: Vuln::Bola,
        method: "GET",
        path: "/api/orders/{id}",
        param: "id",
        benign: "1002",
    },
    Target {
        vuln: Vuln::BruteForce,
        method: "POST",
        path: "/login",
        param: "password",
        benign: "",
    },
];

pub fn target(v: Vuln) -> &'static Target {
    TARGETS
        .iter()
        .find(|t| t.vuln == v)
        .expect("every vulnerability has a target")
}

/// A browser-like User-Agent: this attacker does not announce itself.
pub const USER_AGENT: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36";

#[cfg(test)]
mod tests {
    use super::*;

    fn obs(status: u16, body: &str) -> Observation {
        Observation {
            status,
            body: body.into(),
            ..Default::default()
        }
    }

    #[test]
    fn gateway_pages_are_recognised() {
        assert_eq!(
            classify(&obs(403, "{\"error\":\"blocked\",\"request_id\":\"1-2\"}")),
            Verdict::Blocked
        );
        assert_eq!(
            classify(&obs(
                403,
                "{\"error\":\"challenge_required\",\"request_id\":\"1\"}"
            )),
            Verdict::Challenged
        );
        let mut r = obs(429, "{\"error\":\"rate_limited\"}");
        r.headers.push(("retry-after".into(), "6".into()));
        assert_eq!(classify(&r), Verdict::RateLimited(Duration::from_secs(6)));
        assert_eq!(
            classify(&obs(400, "{\"error\":\"null_byte\",\"request_id\":\"1\"}")),
            Verdict::Refused
        );
        assert_eq!(classify(&obs(404, "<h1>Not found</h1>")), Verdict::Passed);
        assert_eq!(
            classify(&obs(401, "{\"error\":\"invalid credentials\"}")),
            Verdict::Passed
        );
        assert_eq!(classify(&obs(0, "")), Verdict::Error);
    }
}
