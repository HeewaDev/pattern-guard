//! Request path: access lists → threat intel → WAF → behavioural ML → one decision →
//! enforce (or log, in detect mode) → forward → feed the response back to the engine.

mod client_ip;
mod decision_log;
mod forward;
mod responses;
mod verify;

use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::Ordering::Relaxed;
use std::time::{Duration, Instant, SystemTime};

use bytes::Bytes;
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Limited};
use hyper::body::Incoming;
use hyper::{Request, Response, StatusCode};
use pattern_guard::waf::{Finding, HttpRequest};
use pattern_guard::{Decision, Event};

pub use client_ip::client_ip;
pub use responses::full;

use decision_log::{LogCtx, log_decision};
use forward::{CloneHead, forward};
use responses::{block_page, header_str, respond, wants_html};
use verify::verify;

use crate::challenge::VERIFY_PATH;
use crate::config::Mode;
use crate::intel::IntelAction;
use crate::ipnet::any_contains;
use crate::state::State;

pub type Body = BoxBody<Bytes, hyper::Error>;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Action {
    Allow,
    Delay,
    Challenge,
    Block,
}

impl Action {
    pub(super) fn as_str(self) -> &'static str {
        match self {
            Action::Allow => "allow",
            Action::Delay => "delay",
            Action::Challenge => "challenge",
            Action::Block => "block",
        }
    }
}

/// Parameter name of a WAF location (`query:id`, `body:comment`, `cookie:sid`, `json.user.name`).
fn param_name(location: &str) -> Option<&str> {
    if let Some((_, n)) = location.split_once(':') {
        return Some(n);
    }
    location.strip_prefix("json").map(|r| {
        r.trim_end_matches("-key")
            .rsplit('.')
            .next()
            .unwrap_or(r)
            .split('[')
            .next()
            .unwrap_or("")
    })
}

pub async fn handle(
    state: Arc<State>,
    peer: SocketAddr,
    req: Request<Incoming>,
) -> Result<Response<Body>, Infallible> {
    let started = Instant::now();
    let id = format!(
        "{:x}-{:x}",
        crate::challenge::now_secs(),
        state.req_counter.fetch_add(1, Relaxed)
    );
    let (parts, body) = req.into_parts();
    let ip = client_ip(&state, peer.ip(), &parts.headers);

    if parts.uri.path() == VERIFY_PATH {
        return Ok(verify(&state, ip, parts.uri.query().unwrap_or("")));
    }

    let body = match Limited::new(body, state.cfg.max_body_bytes).collect().await {
        Ok(b) => b.to_bytes(),
        Err(_) => {
            state.metrics.body_too_large.fetch_add(1, Relaxed);
            return Ok(respond(
                StatusCode::PAYLOAD_TOO_LARGE,
                "text/plain",
                "request body too large",
            ));
        }
    };

    let path_q = parts
        .uri
        .path_and_query()
        .map(|p| p.as_str().to_string())
        .unwrap_or_else(|| "/".into());

    if any_contains(&state.allow, ip) {
        return Ok(forward(&state, parts, body, ip, &id, None).await.0);
    }

    // ---- behavioural ML (always recorded, even if another layer blocks) ----
    let mut event = Event::new(
        format!("ip:{ip}"),
        parts.method.as_str(),
        path_q.clone(),
        SystemTime::now(),
    )
    .with_ip(ip);
    if let Some(ua) = header_str(&parts.headers, "user-agent") {
        event = event.with_user_agent(ua);
    }
    if let Some(fp) = state
        .cfg
        .client_ip
        .fingerprint_header
        .as_deref()
        .and_then(|h| header_str(&parts.headers, h))
    {
        event = event.with_fingerprint(fp);
    }
    let assessment = state.guard.assess(&event);

    // ---- WAF ----
    let findings: Vec<Finding> = if state.cfg.waf.enabled
        && !state
            .cfg
            .waf
            .exclude_paths
            .iter()
            .any(|p| parts.uri.path().starts_with(p.as_str()))
    {
        let headers: Vec<(String, String)> = parts
            .headers
            .iter()
            .filter_map(|(k, v)| {
                v.to_str()
                    .ok()
                    .map(|v| (k.as_str().to_string(), v.to_string()))
            })
            .collect();
        let inspect_len = body.len().min(state.cfg.waf.inspect_body_bytes);
        state
            .waf
            .inspect(&HttpRequest {
                path_and_query: &path_q,
                headers: &headers,
                content_type: header_str(&parts.headers, "content-type"),
                body: &body[..inspect_len],
            })
            .findings
            .into_iter()
            .filter(|f| f.score >= state.cfg.waf.log_score)
            .filter(|f| {
                !param_name(&f.location).is_some_and(|n| {
                    state
                        .cfg
                        .waf
                        .exclude_params
                        .iter()
                        .any(|x| x.eq_ignore_ascii_case(n))
                })
            })
            .collect()
    } else {
        Vec::new()
    };
    for f in &findings {
        state.metrics.inc_waf(f.class.as_str());
    }

    // ---- reputation ----
    let intel = state.intel.lookup(ip);
    let denied = any_contains(&state.deny, ip);

    // ---- fuse ----
    let mut action = Action::Allow;
    let mut layer = "behaviour";
    let mut reasons: Vec<String> = Vec::new();
    let mut raise =
        |a: Action, l: &'static str, why: String, action: &mut Action, layer: &mut &'static str| {
            if a > *action {
                *action = a;
                *layer = l;
            }
            reasons.push(why);
        };
    if denied {
        raise(
            Action::Block,
            "deny_list",
            "deny_list".into(),
            &mut action,
            &mut layer,
        );
    }
    if any_contains(&state.challenge_list, ip) {
        raise(
            Action::Challenge,
            "challenge_list",
            "challenge_list".into(),
            &mut action,
            &mut layer,
        );
    }
    if let Some(e) = &intel {
        let a = match e.action {
            IntelAction::Ban => Action::Block,
            IntelAction::Challenge => Action::Challenge,
        };
        raise(
            a,
            "reputation",
            format!("{}: {}", e.source, e.reason),
            &mut action,
            &mut layer,
        );
    }
    if let Some(top) = findings.iter().max_by(|a, b| a.score.total_cmp(&b.score)) {
        if top.score >= state.cfg.waf.block_score {
            raise(
                Action::Block,
                "waf",
                format!(
                    "waf:{} at {} (score {:.1})",
                    top.class.as_str(),
                    top.location,
                    top.score
                ),
                &mut action,
                &mut layer,
            );
        }
    }
    let ml = match assessment.decision {
        Decision::Block => Action::Block,
        Decision::Challenge => Action::Challenge,
        Decision::Delay(_) => Action::Delay,
        Decision::Allow | Decision::Warn => Action::Allow,
    };
    if ml > Action::Allow {
        let why: Vec<String> = assessment.reasons.iter().map(|r| r.to_string()).collect();
        raise(
            ml,
            "behaviour",
            format!("ml:{}", why.join(",")),
            &mut action,
            &mut layer,
        );
    }
    if action == Action::Challenge && !state.cfg.challenge.enabled {
        action = Action::Block;
    }
    let cleared = matches!(action, Action::Challenge | Action::Delay)
        && state
            .challenger
            .has_clearance(ip, header_str(&parts.headers, "cookie"));
    if cleared {
        action = Action::Allow;
        reasons.push("clearance".into());
    }

    let enforce = state.cfg.mode == Mode::Prevent;
    let decide_us = started.elapsed().as_micros() as u64;
    state.metrics.duration_us_sum.fetch_add(decide_us, Relaxed);
    state.metrics.requests.fetch_add(1, Relaxed);
    let counter = match (action, &assessment.decision) {
        (Action::Block, _) => &state.metrics.block,
        (Action::Challenge, _) => &state.metrics.challenge,
        (Action::Delay, _) => &state.metrics.delay,
        (Action::Allow, Decision::Warn) => &state.metrics.warn,
        _ => &state.metrics.allow,
    };
    counter.fetch_add(1, Relaxed);
    if action == Action::Block {
        state.metrics.inc_blocked_by(layer);
    }
    if !enforce && action > Action::Allow {
        state.metrics.would_mitigate.fetch_add(1, Relaxed);
    }

    let template = pattern_guard::normalize::normalize_path(&path_q).template;
    let ctx = LogCtx {
        id: &id,
        ip,
        peer,
        assessment: &assessment,
        findings: &findings,
        intel: intel.as_ref(),
        reasons: &reasons,
        action,
        layer,
        enforced: enforce,
    };

    // ---- enforce ----
    if enforce {
        match action {
            Action::Block => {
                state.guard.observe_response(&event, 403);
                state
                    .inventory
                    .record(parts.method.as_str(), &template, 403, true);
                log_decision(&state, &parts, &ctx, 403);
                return Ok(block_page(&parts.headers, &id));
            }
            Action::Challenge => {
                // Neutral for the behavioural engine: a human who meets a challenge must
                // not look like a client collecting failures.
                state
                    .inventory
                    .record(parts.method.as_str(), &template, 403, true);
                log_decision(&state, &parts, &ctx, 403);
                let resp = if wants_html(&parts.headers) && parts.method == hyper::Method::GET {
                    respond(
                        StatusCode::FORBIDDEN,
                        "text/html; charset=utf-8",
                        state.challenger.page(ip, &path_q),
                    )
                } else {
                    respond(
                        StatusCode::FORBIDDEN,
                        "application/json",
                        format!("{{\"error\":\"challenge_required\",\"request_id\":\"{id}\"}}"),
                    )
                };
                return Ok(resp);
            }
            Action::Delay => {
                let d = match assessment.decision {
                    Decision::Delay(d) => d,
                    _ => Duration::from_secs(1),
                };
                tokio::time::sleep(
                    d.min(Duration::from_secs_f64(state.cfg.delay_max_secs.max(0.0))),
                )
                .await;
            }
            Action::Allow => {}
        }
    }

    let (resp, status) =
        forward(&state, parts.clone_head(), body, ip, &id, Some(&assessment)).await;
    state.guard.observe_response(&event, status);
    state
        .inventory
        .record(parts.method.as_str(), &template, status, false);
    if action > Action::Allow || !findings.is_empty() || state.cfg.log.include_allowed {
        log_decision(&state, &parts, &ctx, status);
    }
    Ok(resp)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn param_names() {
        assert_eq!(param_name("query:password"), Some("password"));
        assert_eq!(param_name("json.user.password"), Some("password"));
        assert_eq!(param_name("json.items[2]"), Some("items"));
        assert_eq!(param_name("path"), None);
    }
}
