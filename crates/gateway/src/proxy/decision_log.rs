//! Decision log lines (EVE/ECS-like JSON) and rate-limited console output.

use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::Ordering::Relaxed;

use pattern_guard::Assessment;
use pattern_guard::waf::Finding;

use super::Action;
use crate::intel::IntelEntry;
use crate::observability::eventlog::rfc3339_now;
use crate::state::State;
use crate::util::header_str;

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
    pub(super) layer: &'static str,
    pub(super) enforced: bool,
    pub(super) country: Option<&'a str>,
}

pub(super) fn log_decision(
    state: &State,
    parts: &hyper::http::request::Parts,
    c: &LogCtx,
    status: u16,
) {
    let waf: Vec<_> = c
        .findings
        .iter()
        .map(|f| {
            serde_json::json!({
                "class": f.class.as_str(), "score": f.score, "location": f.location,
                "indicators": f.indicators, "sample": f.sample,
            })
        })
        .collect();
    let line = serde_json::json!({
        "timestamp": rfc3339_now(),
        "event_type": if c.action > Action::Allow || !c.findings.is_empty() { "alert" } else { "http" },
        "src_ip": c.ip.to_string(),
        "srcip": c.ip.to_string(),
        "peer_ip": c.peer.ip().to_string(),
        "http": {
            "hostname": header_str(&parts.headers, "host"),
            "url": parts.uri.path_and_query().map(|p| p.as_str()),
            "http_method": parts.method.as_str(),
            "http_user_agent": header_str(&parts.headers, "user-agent"),
            "status": status,
        },
        "pattern_guard": {
            "request_id": c.id,
            "action": c.action.as_str(),
            "layer": c.layer,
            "enforced": c.enforced,
            "mode": if c.enforced { "prevent" } else { "detect" },
            "risk": (c.assessment.risk * 1000.0).round() / 1000.0,
            "bot_score": c.assessment.bot_score,
            "reasons": c.reasons,
            "waf": waf,
            "country": c.country,
            "reputation": c.intel.map(|e| serde_json::json!({"source": e.source, "reason": e.reason})),
        }
    });
    let s = line.to_string();
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
            parts.uri.path(),
            c.layer,
            c.reasons.join(" | ")
        );
    }
    if let Some(log) = &state.log {
        log.log(s);
    }
}
