//! Request path: access lists → threat intel → WAF → behavioural ML → one decision →
//! enforce (or log, in detect mode) → forward → feed the response back to the engine.

mod client_ip;
mod decision_log;
mod forward;
mod responses;
mod verdict;
mod verify;

use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::Ordering::Relaxed;
use std::time::{Duration, Instant, SystemTime};

use bytes::Bytes;
use http_body_util::combinators::BoxBody;
use hyper::body::Incoming;
use hyper::{Request, Response, StatusCode};
use pattern_guard::waf::{Finding, HttpRequest};
use pattern_guard::{Decision, Event};

pub use client_ip::client_ip;
pub use responses::full;
pub use verdict::{Action, Layer, Respond, Signal, Verdict};

use decision_log::{LogCtx, log_decision};
use forward::{CloneHead, forward};
use responses::{block_page, error_response, respond, too_many_requests, wants_html};
use verify::verify;

use crate::challenge::VERIFY_PATH;
use crate::config::{LimitAction, Mode, OperationAction, RuleAction};
use crate::intel::IntelAction;
use crate::ipnet::any_contains;
use crate::policy::path::PathView;
use crate::state::State;
use crate::util::header_str;

pub type Body = BoxBody<Bytes, hyper::Error>;

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
        crate::util::now_secs(),
        state.req_counter.fetch_add(1, Relaxed)
    );
    let (parts, body) = req.into_parts();
    let ip = client_ip(&state, peer.ip(), &parts.headers);

    if parts.uri.path() == VERIFY_PATH {
        return Ok(verify(&state, ip, parts.uri.query().unwrap_or("")));
    }

    // 413 / 408 (too slow) / 503 (body budget) / 400; the reservation is held until the
    // request is done, i.e. as long as the buffered body.
    let (body, _body_reservation) = match crate::server::read_body(&state, body).await {
        Ok(b) => b,
        Err(refusal) => return Ok(*refusal),
    };

    let path_q = parts
        .uri
        .path_and_query()
        .map(|p| p.as_str().to_string())
        .unwrap_or_else(|| "/".into());

    if any_contains(&state.allow, ip) {
        return Ok(forward(&state, parts, body, peer.ip(), ip, &id, None)
            .await
            .0);
    }

    // ---- custom rules (an `allow` rule bypasses inspection like the allow list) ----
    let country = state.geo_db.as_ref().and_then(|g| g.lookup(ip));
    let rule = state.rules.evaluate(ip, &parts, country);
    if matches!(rule.terminal, Some((RuleAction::Allow, _))) {
        return Ok(forward(&state, parts, body, peer.ip(), ip, &id, None)
            .await
            .0);
    }
    let limit = state.rate_limiter.check(ip, &parts);
    // business operations and logins (settled with the upstream status below)
    let (op_hit, op_ticket) = state.operations.check(ip, &parts, &body);
    let violation = state.protocol.check(&parts);
    let trap = state.bans.trap(parts.uri.path()).map(str::to_string);
    if let Some(t) = &trap {
        state
            .bans
            .ban_now(ip, &state.intel, format!("honeypot trap {t}"));
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
        && !rule.skip_waf
        && !state
            .cfg
            .waf
            .exclude_paths
            .iter()
            .any(|p| PathView::new(parts.uri.path()).exempts_prefix(p))
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
        // the whole body: the inspector keeps to `inspect_body_bytes` itself, flags
        // what it couldn't inspect, and still finds fields after large file uploads
        state
            .waf
            .inspect(&HttpRequest {
                path_and_query: &path_q,
                headers: &headers,
                content_type: header_str(&parts.headers, "content-type"),
                body: &body,
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

    // ---- fuse: raise order = tie-break order (see verdict.rs) ----
    let mut verdict = Verdict::default();
    if denied {
        verdict.raise(Signal::new(Action::Block, Layer::DenyList, "deny_list"));
    }
    if let Some(v) = &violation {
        verdict.raise(
            Signal::new(
                Action::Block,
                Layer::Protocol,
                format!("protocol:{}", v.reason),
            )
            .respond(Respond::Status {
                status: v.status,
                reason: v.reason.clone(),
            }),
        );
    }
    if let Some(t) = &trap {
        verdict.raise(Signal::new(Action::Block, Layer::Trap, format!("trap:{t}")));
    }
    if let Some((a, name)) = &rule.terminal {
        let a = match a {
            RuleAction::Block => Action::Block,
            RuleAction::Challenge => Action::Challenge,
            _ => Action::Delay,
        };
        verdict.raise(Signal::new(a, Layer::Rule, format!("rule:{name}")));
    }
    let geo = match state.geo_policy.verdict(country) {
        Some(crate::geo::GeoVerdict::Block) => Some(Action::Block),
        Some(crate::geo::GeoVerdict::Challenge) => Some(Action::Challenge),
        None => None,
    };
    if let Some(a) = geo {
        verdict.raise(Signal::new(
            a,
            Layer::Geo,
            format!("geo:{}", country.unwrap_or("?")),
        ));
    }
    if let Some(hit) = &limit {
        let a = match hit.action {
            LimitAction::Block => Action::Block,
            LimitAction::Challenge => Action::Challenge,
            LimitAction::Delay => Action::Delay,
        };
        verdict.raise(
            Signal::new(a, Layer::RateLimit, format!("rate_limit:{}", hit.name)).respond(
                Respond::TooManyRequests {
                    retry_after: hit.retry_after,
                },
            ),
        );
    }
    if let Some(hit) = &op_hit {
        let a = match hit.action {
            OperationAction::Block => Action::Block,
            OperationAction::Challenge => Action::Challenge,
            OperationAction::Delay => Action::Delay,
            OperationAction::Log => Action::Allow,
        };
        let account = hit
            .account
            .as_deref()
            .map(|a| format!(" account={a}"))
            .unwrap_or_default();
        let respond = if hit.status == 429 {
            Respond::TooManyRequests {
                retry_after: hit.retry_after.unwrap_or(1),
            }
        } else {
            Respond::Status {
                status: StatusCode::from_u16(hit.status).unwrap_or(StatusCode::FORBIDDEN),
                reason: hit.kind.to_string(),
            }
        };
        verdict.raise(
            Signal::new(
                a,
                Layer::Operation,
                format!("operation:{}:{}{account}", hit.name, hit.kind),
            )
            .respond(respond),
        );
    }
    for name in &rule.logged {
        verdict.raise(Signal::new(
            Action::Allow,
            Layer::Rule,
            format!("rule-log:{name}"),
        ));
    }
    if any_contains(&state.challenge_list, ip) {
        verdict.raise(Signal::new(
            Action::Challenge,
            Layer::ChallengeList,
            "challenge_list",
        ));
    }
    if let Some(e) = &intel {
        let a = match e.action {
            IntelAction::Ban => Action::Block,
            IntelAction::Challenge => Action::Challenge,
        };
        verdict.raise(Signal::new(
            a,
            Layer::Reputation,
            format!("{}: {}", e.source, e.reason),
        ));
    }
    if let Some(top) = findings.iter().max_by(|a, b| a.score.total_cmp(&b.score)) {
        if top.score >= state.cfg.waf.block_score {
            verdict.raise(Signal::new(
                Action::Block,
                Layer::Waf,
                format!(
                    "waf:{} at {} (score {:.1})",
                    top.class.as_str(),
                    top.location,
                    top.score
                ),
            ));
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
        verdict.raise(Signal::new(
            ml,
            Layer::Behaviour,
            format!("ml:{}", why.join(",")),
        ));
    }
    if !state.cfg.challenge.enabled {
        verdict.challenge_disabled();
    }
    if matches!(verdict.action(), Action::Challenge | Action::Delay)
        && state
            .challenger
            .has_clearance(ip, header_str(&parts.headers, "cookie"))
    {
        verdict.clear();
    }
    let action = verdict.action();
    let layer = verdict.layer();

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
        state.metrics.inc_blocked_by(layer.as_str());
    }
    if !enforce && action > Action::Allow {
        state.metrics.would_mitigate.fetch_add(1, Relaxed);
    }

    // Repeat offenders get banned (bans and traps don't count, they already are one).
    if enforce && action == Action::Block && layer.counts_towards_bans() {
        if let Some(d) = state.bans.record_block(ip, &state.intel) {
            verdict.note(format!("banned for {}s", d.as_secs()));
        }
    }

    // Requests refused by `[protocol]` (oversized, malformed) aren't API routes: they stay
    // out of the inventory, so they can't fill it with attacker-sized templates.
    let template = violation
        .is_none()
        .then(|| pattern_guard::normalize::normalize_path(&path_q).template);
    let ctx = LogCtx {
        id: &id,
        ip,
        peer,
        assessment: &assessment,
        findings: &findings,
        intel: intel.as_ref(),
        reasons: verdict.reasons(),
        action,
        layer,
        enforced: enforce,
        country,
    };

    // ---- enforce ----
    if enforce {
        match action {
            Action::Block => {
                let respond = verdict.respond();
                let status = respond.status().as_u16();
                state.guard.observe_response(&event, status);
                if let Some(t) = &template {
                    state
                        .inventory
                        .record(parts.method.as_str(), t, status, true);
                }
                log_decision(&state, &parts, &ctx, status);
                return Ok(match respond {
                    Respond::BlockPage => block_page(&parts.headers, &id),
                    Respond::TooManyRequests { retry_after } => {
                        too_many_requests(&parts.headers, &id, *retry_after)
                    }
                    Respond::Status { status, reason } => {
                        error_response(&parts.headers, &id, *status, reason)
                    }
                });
            }
            Action::Challenge => {
                // Neutral for the behavioural engine: a human who meets a challenge must
                // not look like a client collecting failures.
                if let Some(t) = &template {
                    state.inventory.record(parts.method.as_str(), t, 403, true);
                }
                log_decision(&state, &parts, &ctx, 403);
                let resp = if wants_html(&parts.headers) {
                    // A browser: the proof-of-work page. A challenged form POST is sent again
                    // once solved when it came from this origin, else the user returns to
                    // the form (see challenge::resubmission).
                    let page = if parts.method == hyper::Method::GET {
                        state.challenger.page(ip, &path_q)
                    } else if let Some(fields) =
                        crate::challenge::resubmission(&parts.headers, &parts.method, &body)
                    {
                        state.challenger.page_resubmit(ip, &path_q, &fields)
                    } else {
                        state
                            .challenger
                            .page(ip, &crate::challenge::return_after_post(&parts.headers))
                    };
                    respond(StatusCode::FORBIDDEN, "text/html; charset=utf-8", page)
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
                    _ => Duration::from_secs_f64(state.cfg.delay_max_secs.max(0.0)),
                };
                tokio::time::sleep(
                    d.min(Duration::from_secs_f64(state.cfg.delay_max_secs.max(0.0))),
                )
                .await;
            }
            Action::Allow => {}
        }
    }

    let (resp, status, leak) = forward(
        &state,
        parts.clone_head(),
        body,
        peer.ip(),
        ip,
        &id,
        Some(&assessment),
    )
    .await;
    op_ticket.complete(status);
    state.guard.observe_response(&event, status);
    if let Some(t) = &template {
        state
            .inventory
            .record(parts.method.as_str(), t, status, false);
    }
    if let Some((signature, blocked)) = leak {
        let mut leak_reasons = verdict.reasons().to_vec();
        leak_reasons.push(format!("data_leak:{signature}"));
        let ctx = LogCtx {
            reasons: &leak_reasons,
            action: if blocked { Action::Block } else { action },
            layer: if blocked { Layer::DataLeak } else { layer },
            ..ctx
        };
        log_decision(&state, &parts, &ctx, status);
    } else if action > Action::Allow
        || !findings.is_empty()
        || !rule.logged.is_empty()
        || state.cfg.log.include_allowed
    {
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
