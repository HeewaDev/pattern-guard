//! Decision log lines (EVE/ECS-like JSON) and rate-limited console output.
//!
//! Client-controlled values are truncated before they are logged (a request head may
//! be ~400 KB), so a line stays a few KiB whatever the request looks like. A truncated
//! value ends in `…`; the field names never change.

use std::borrow::Cow;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::Ordering::Relaxed;

use pattern_guard::Assessment;
use pattern_guard::waf::Finding;

use super::{Action, Layer};
use crate::intel::IntelEntry;
use crate::observability::eventlog::rfc3339_now;
use crate::state::State;
use crate::util::header_str;

/// Longest logged `http.hostname` (a DNS name is at most 253 bytes, plus a port).
const MAX_HOST: usize = 256;
/// Longest logged `http.url`: the default `protocol.max_url_bytes`, so a URL the
/// defaults accept is logged whole.
const MAX_URL: usize = 8192;
const MAX_USER_AGENT: usize = 1024;
/// Longest logged reason, WAF location or sample, reputation source or reason.
const MAX_REASON: usize = 512;
const MAX_LOCATION: usize = 256;
const MAX_SAMPLE: usize = 256;
/// Longest path and reason list on the console line.
const MAX_CONSOLE: usize = 256;

/// `s` cut to at most `max` bytes (on a character boundary), marked with `…`.
fn clip(s: &str, max: usize) -> Cow<'_, str> {
    if s.len() <= max {
        return Cow::Borrowed(s);
    }
    let mut end = max;
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    Cow::Owned(format!("{}…", &s[..end]))
}

/// At most one console line per second (with a count of suppressed lines), so an attack
/// can't turn stderr into a bottleneck. Full detail goes to the async decision log.
fn console_slot(state: &State) -> bool {
    let now = crate::util::now_secs();
    let last = state.console_second.load(Relaxed);
    if last != now
        && state
            .console_second
            .compare_exchange(last, now, Relaxed, Relaxed)
            .is_ok()
    {
        let suppressed = state.console_suppressed.swap(0, Relaxed);
        if suppressed > 0 {
            eprintln!(
                "pattern-guard-gateway: … {suppressed} more mitigations in the last second(s), see decision log / metrics"
            );
        }
        true
    } else {
        state.console_suppressed.fetch_add(1, Relaxed);
        false
    }
}

pub(super) struct LogCtx<'a> {
    pub(super) id: &'a str,
    pub(super) ip: IpAddr,
    pub(super) peer: SocketAddr,
    pub(super) assessment: &'a Assessment,
    pub(super) findings: &'a [Finding],
    pub(super) intel: Option<&'a IntelEntry>,
    pub(super) reasons: &'a [String],
    pub(super) action: Action,
    pub(super) layer: Layer,
    pub(super) enforced: bool,
    pub(super) country: Option<&'a str>,
}

/// The decision-log JSON line. Field names are a public contract (SIEM rules, Wazuh
/// decoders and dashboards key on them).
fn line(parts: &hyper::http::request::Parts, c: &LogCtx, status: u16) -> String {
    let waf: Vec<_> = c
        .findings
        .iter()
        .map(|f| {
            serde_json::json!({
                "class": f.class.as_str(), "score": f.score,
                "location": clip(&f.location, MAX_LOCATION),
                "indicators": f.indicators, "sample": clip(&f.sample, MAX_SAMPLE),
            })
        })
        .collect();
    let reasons: Vec<_> = c.reasons.iter().map(|r| clip(r, MAX_REASON)).collect();
    serde_json::json!({
        "timestamp": rfc3339_now(),
        "event_type": if c.action > Action::Allow || !c.findings.is_empty() { "alert" } else { "http" },
        "src_ip": c.ip.to_string(),
        "srcip": c.ip.to_string(),
        "peer_ip": c.peer.ip().to_string(),
        "http": {
            "hostname": header_str(&parts.headers, "host").map(|h| clip(h, MAX_HOST)),
            "url": parts.uri.path_and_query().map(|p| clip(p.as_str(), MAX_URL)),
            "http_method": parts.method.as_str(),
            "http_user_agent": header_str(&parts.headers, "user-agent").map(|u| clip(u, MAX_USER_AGENT)),
            "status": status,
        },
        "pattern_guard": {
            "request_id": c.id,
            "action": c.action.as_str(),
            "layer": c.layer.as_str(),
            "enforced": c.enforced,
            "mode": if c.enforced { "prevent" } else { "detect" },
            "risk": (c.assessment.risk * 1000.0).round() / 1000.0,
            "bot_score": c.assessment.bot_score,
            "reasons": reasons,
            "waf": waf,
            "country": c.country,
            "reputation": c.intel.map(|e| serde_json::json!({
                "source": clip(&e.source, MAX_REASON),
                "reason": clip(&e.reason, MAX_REASON),
            })),
        }
    })
    .to_string()
}

pub(super) fn log_decision(
    state: &State,
    parts: &hyper::http::request::Parts,
    c: &LogCtx,
    status: u16,
) {
    if c.action > Action::Allow && console_slot(state) {
        eprintln!(
            "pattern-guard-gateway: {} {} {} {} [{}] {}",
            if c.enforced {
                c.action.as_str()
            } else {
                "would-mitigate"
            },
            c.ip,
            parts.method,
            clip(parts.uri.path(), MAX_CONSOLE),
            c.layer.as_str(),
            clip(&c.reasons.join(" | "), MAX_CONSOLE)
        );
    }
    if let Some(log) = &state.log {
        log.log(line(parts, c, status));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pattern_guard::waf::AttackClass;
    use pattern_guard::{Event, Guard};

    #[test]
    fn clip_marks_and_respects_char_boundaries() {
        assert_eq!(clip("short", 10), "short");
        assert_eq!(clip("abcdef", 3), "abc…");
        // 'é' is 2 bytes: never cut inside it
        assert_eq!(clip("aé", 2), "a…");
    }

    #[test]
    fn huge_client_values_give_a_small_line() {
        let host = "h".repeat(300_000);
        let ua = "u".repeat(300_000);
        let path = format!("/{}?q={}", "p".repeat(30_000), "q".repeat(30_000));
        let parts = hyper::Request::get(path.as_str())
            .header("host", host.as_str())
            .header("user-agent", ua.as_str())
            .body(())
            .unwrap()
            .into_parts()
            .0;
        let guard = Guard::from_toml_str("").unwrap();
        let assessment = guard.assess(&Event::new(
            "ip:203.0.113.1",
            "GET",
            "/",
            std::time::SystemTime::now(),
        ));
        let findings = vec![Finding {
            class: AttackClass::CrossSiteScripting,
            score: 9.0,
            location: format!("query:{}", "n".repeat(50_000)),
            indicators: vec!["script_tag"],
            sample: "s".repeat(50_000),
        }];
        let reasons = vec![format!(
            "waf:xss at query:{} (score 9.0)",
            "n".repeat(50_000)
        )];
        let ctx = LogCtx {
            id: "1-1",
            ip: "203.0.113.1".parse().unwrap(),
            peer: "127.0.0.1:1".parse().unwrap(),
            assessment: &assessment,
            findings: &findings,
            intel: None,
            reasons: &reasons,
            action: Action::Block,
            layer: Layer::Waf,
            enforced: true,
            country: None,
        };
        let l = line(&parts, &ctx, 403);
        assert!(l.len() < 12 * 1024, "line of {} bytes", l.len());
        let v: serde_json::Value = serde_json::from_str(&l).unwrap();
        let host = v["http"]["hostname"].as_str().unwrap();
        assert!(host.starts_with("hhh") && host.ends_with('…') && host.len() <= MAX_HOST + 3);
        let url = v["http"]["url"].as_str().unwrap();
        assert!(url.starts_with("/ppp") && url.len() <= MAX_URL + 3);
        assert!(v["http"]["http_user_agent"].as_str().unwrap().len() <= MAX_USER_AGENT + 3);
        assert!(v["pattern_guard"]["reasons"][0].as_str().unwrap().len() <= MAX_REASON + 3);
        let f = &v["pattern_guard"]["waf"][0];
        assert!(f["location"].as_str().unwrap().starts_with("query:nnn"));
        assert!(f["location"].as_str().unwrap().len() <= MAX_LOCATION + 3);
        assert!(f["sample"].as_str().unwrap().len() <= MAX_SAMPLE + 3);
        assert_eq!(f["class"], "xss");
        assert_eq!(v["pattern_guard"]["layer"], "waf");
    }
}
