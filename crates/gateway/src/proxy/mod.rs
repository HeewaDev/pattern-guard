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
use crate::state::{Compiled, State};
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

/// Handles one request. `c` is the config snapshot taken when the request head arrived
/// (see `server::serve`); it sets the body-read limits. Once the body is in, the request
/// takes the current snapshot and keeps it to the end, so the decision and the forward
/// never mix two configs, and an upload that trickled in across a reload is judged on
/// the new config.
pub async fn handle(
    state: Arc<State>,
    c: Arc<Compiled>,
    peer: SocketAddr,
    req: Request<Incoming>,
) -> Result<Response<Body>, Infallible> {
    let started = Instant::now();
    let id = format!(
        "{:x}-{:x}",
        crate::util::now_secs(),
        state.runtime.req_counter.fetch_add(1, Relaxed)
    );
    let (parts, body) = req.into_parts();
    let ip = client_ip(&c, peer.ip(), &parts.headers);

    if parts.uri.path() == VERIFY_PATH {
        return Ok(verify(&state, &c, ip, parts.uri.query().unwrap_or("")));
    }

    // 413 / 408 (too slow) / 503 (body budget) / 400; the reservation is held until the
    // request is done, i.e. as long as the buffered body.
    let (body, _body_reservation) = match crate::server::read_body(&state, &c, body).await {
        Ok(b) => b,
        Err(refusal) => return Ok(*refusal),
    };
    // A body may take hours to arrive (`body_min_bytes_per_sec`); decide on the config
    // current now, not the one from when the head arrived.
    let c = state.compiled();
    let ip = client_ip(&c, peer.ip(), &parts.headers);

    let path_q = parts
        .uri
        .path_and_query()
        .map(|p| p.as_str().to_string())
        .unwrap_or_else(|| "/".into());

    if any_contains(&c.allow, ip) {
        return Ok(forward(&state, &c, parts, body, peer.ip(), ip, &id, None)
            .await
            .0);
    }

    // ---- custom rules (an `allow` rule bypasses inspection like the allow list) ----
    let country = c.geo_db.as_ref().and_then(|g| g.lookup(ip));
    let rule = c.rules.evaluate(ip, &parts, country);
    if matches!(rule.terminal, Some((RuleAction::Allow, _))) {
        return Ok(forward(&state, &c, parts, body, peer.ip(), ip, &id, None)
            .await
            .0);
    }
    let limit = c.rate_limits.check(&state.learned.rate_buckets, ip, &parts);
    // business operations and logins (settled with the upstream status below)
    let (op_hit, op_ticket) = c
        .operations
        .check(&state.learned.operations, ip, &parts, &body);
    let violation = c.protocol.check(&parts);
    let trap = c.bans.trap(parts.uri.path()).map(str::to_string);
    if let Some(t) = &trap {
        c.bans.ban_now(
            &state.learned.offenders,
            ip,
            &state.learned.intel,
            format!("honeypot trap {t}"),
        );
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
    if let Some(fp) = c
        .cfg
        .client_ip
        .fingerprint_header
        .as_deref()
        .and_then(|h| header_str(&parts.headers, h))
    {
        event = event.with_fingerprint(fp);
    }
    let assessment = state.learned.guard.assess(&event);

    // ---- WAF ----
    let findings: Vec<Finding> = if c.cfg.waf.enabled
        && !rule.skip_waf
        && !c
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
        let inspect_len = body.len().min(c.cfg.waf.inspect_body_bytes);
        state
            .runtime
            .waf
            .inspect(&HttpRequest {
                path_and_query: &path_q,
                headers: &headers,
                content_type: header_str(&parts.headers, "content-type"),
                body: &body[..inspect_len],
            })
            .findings
            .into_iter()
            .filter(|f| f.score >= c.cfg.waf.log_score)
            .filter(|f| {
                !param_name(&f.location).is_some_and(|n| {
                    c.cfg
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
        state.runtime.metrics.inc_waf(f.class.as_str());
    }

    // ---- reputation ----
    let intel = state.learned.intel.lookup(ip);
    let denied = any_contains(&c.deny, ip);

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
    let geo = match c.geo_policy.verdict(country) {
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
    if any_contains(&c.challenge_list, ip) {
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
        if top.score >= c.cfg.waf.block_score {
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
    if !c.cfg.challenge.enabled {
        verdict.challenge_disabled();
    }
    if matches!(verdict.action(), Action::Challenge | Action::Delay)
        && c.challenger
            .has_clearance(ip, header_str(&parts.headers, "cookie"))
    {
        verdict.clear();
    }
    let action = verdict.action();
    let layer = verdict.layer();

    let enforce = c.cfg.mode == Mode::Prevent;
    let decide_us = started.elapsed().as_micros() as u64;
    state
        .runtime
        .metrics
        .duration_us_sum
        .fetch_add(decide_us, Relaxed);
    state.runtime.metrics.requests.fetch_add(1, Relaxed);
    let counter = match (action, &assessment.decision) {
        (Action::Block, _) => &state.runtime.metrics.block,
        (Action::Challenge, _) => &state.runtime.metrics.challenge,
        (Action::Delay, _) => &state.runtime.metrics.delay,
        (Action::Allow, Decision::Warn) => &state.runtime.metrics.warn,
        _ => &state.runtime.metrics.allow,
    };
    counter.fetch_add(1, Relaxed);
    if action == Action::Block {
        state.runtime.metrics.inc_blocked_by(layer.as_str());
    }
    if !enforce && action > Action::Allow {
        state.runtime.metrics.would_mitigate.fetch_add(1, Relaxed);
    }

    // Repeat offenders get banned (bans and traps don't count, they already are one).
    if enforce && action == Action::Block && layer.counts_towards_bans() {
        if let Some(d) = c
            .bans
            .record_block(&state.learned.offenders, ip, &state.learned.intel)
        {
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
                state.learned.guard.observe_response(&event, status);
                if let Some(t) = &template {
                    state
                        .learned
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
                    state
                        .learned
                        .inventory
                        .record(parts.method.as_str(), t, 403, true);
                }
                log_decision(&state, &parts, &ctx, 403);
                let resp = if wants_html(&parts.headers) {
                    // A browser: the proof-of-work page. A challenged form POST is sent again
                    // once solved when it came from this origin, else the user returns to
                    // the form (see challenge::resubmission).
                    let page = if parts.method == hyper::Method::GET {
                        c.challenger.page(ip, &path_q)
                    } else if let Some(fields) =
                        crate::challenge::resubmission(&parts.headers, &parts.method, &body)
                    {
                        c.challenger.page_resubmit(ip, &path_q, &fields)
                    } else {
                        c.challenger
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
                    _ => Duration::from_secs_f64(c.cfg.delay_max_secs.max(0.0)),
                };
                tokio::time::sleep(d.min(Duration::from_secs_f64(c.cfg.delay_max_secs.max(0.0))))
                    .await;
            }
            Action::Allow => {}
        }
    }

    let (resp, status, leak) = forward(
        &state,
        &c,
        parts.clone_head(),
        body,
        peer.ip(),
        ip,
        &id,
        Some(&assessment),
    )
    .await;
    op_ticket.complete(status);
    state.learned.guard.observe_response(&event, status);
    if let Some(t) = &template {
        state
            .learned
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
        || c.cfg.log.include_allowed
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
