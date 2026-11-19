//! Request path: access lists → threat intel → WAF → behavioural ML → one decision →
//! enforce (or log, in detect mode) → forward → feed the response back to the engine.

use std::convert::Infallible;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::Ordering::Relaxed;
use std::time::{Duration, Instant, SystemTime};

use bytes::Bytes;
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Full, Limited};
use hyper::body::Incoming;
use hyper::header::{self, HeaderMap, HeaderName, HeaderValue};
use hyper::{Request, Response, StatusCode, Uri};
use pattern_guard::waf::{Finding, HttpRequest};
use pattern_guard::{Assessment, Decision, Event};

use crate::challenge::{VERIFY_PATH, safe_return};
use crate::config::Mode;
use crate::eventlog::rfc3339_now;
use crate::intel::{IntelAction, IntelEntry};
use crate::ipnet::{any_contains, normalize};
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
    fn as_str(self) -> &'static str {
        match self {
            Action::Allow => "allow",
            Action::Delay => "delay",
            Action::Challenge => "challenge",
            Action::Block => "block",
        }
    }
}

const HOP_BY_HOP: [&str; 9] = [
    "connection",
    "keep-alive",
    "proxy-connection",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
];

pub fn full(b: impl Into<Bytes>) -> Body {
    Full::new(b.into())
        .map_err(|n: Infallible| match n {})
        .boxed()
}

fn respond(status: StatusCode, content_type: &str, body: impl Into<Bytes>) -> Response<Body> {
    let mut r = Response::new(full(body));
    *r.status_mut() = status;
    let h = r.headers_mut();
    h.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_str(content_type).unwrap(),
    );
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    r
}

fn header_str<'a>(h: &'a HeaderMap, name: &str) -> Option<&'a str> {
    h.get(name).and_then(|v| v.to_str().ok())
}

/// Client IP: the peer, or — if the peer is a trusted proxy — the right-most untrusted
/// address in the configured header.
pub fn client_ip(state: &State, peer: IpAddr, headers: &HeaderMap) -> IpAddr {
    let peer = normalize(peer);
    if !any_contains(&state.trusted, peer) {
        return peer;
    }
    let Some(v) = header_str(headers, &state.cfg.client_ip.header) else {
        return peer;
    };
    for part in v.rsplit(',') {
        match part.trim().parse::<IpAddr>() {
            Ok(ip) => {
                let ip = normalize(ip);
                if !any_contains(&state.trusted, ip) {
                    return ip;
                }
            }
            Err(_) => return peer,
        }
    }
    peer
}

fn wants_html(h: &HeaderMap) -> bool {
    header_str(h, "accept").is_some_and(|a| a.contains("text/html"))
}

fn block_page(h: &HeaderMap, id: &str) -> Response<Body> {
    if wants_html(h) {
        respond(
            StatusCode::FORBIDDEN,
            "text/html; charset=utf-8",
            format!(
                "<!doctype html><html lang=en><head><meta charset=utf-8><meta name=viewport content=\"width=device-width,initial-scale=1\"><title>Access denied</title>\
                 <style>body{{font:16px/1.5 system-ui,sans-serif;display:grid;place-items:center;min-height:100vh;margin:0;padding:0 1rem}}main{{max-width:30rem}}code{{opacity:.7}}</style></head>\
                 <body><main><h1>Access denied</h1><p>This request was blocked by the site's security policy. If you think this is a mistake, contact the site owner and quote this reference:</p><p><code>{id}</code></p></main></body></html>"
            ),
        )
    } else {
        respond(
            StatusCode::FORBIDDEN,
            "application/json",
            format!("{{\"error\":\"blocked\",\"request_id\":\"{id}\"}}"),
        )
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

trait CloneHead {
    fn clone_head(&self) -> hyper::http::request::Parts;
}

impl CloneHead for hyper::http::request::Parts {
    fn clone_head(&self) -> hyper::http::request::Parts {
        let mut b = Request::builder()
            .method(self.method.clone())
            .uri(self.uri.clone())
            .version(self.version);
        if let Some(h) = b.headers_mut() {
            *h = self.headers.clone();
        }
        b.body(()).expect("valid parts").into_parts().0
    }
}

async fn forward(
    state: &State,
    parts: hyper::http::request::Parts,
    body: Bytes,
    ip: IpAddr,
    id: &str,
    assessment: Option<&Assessment>,
) -> (Response<Body>, u16) {
    let pq = parts
        .uri
        .path_and_query()
        .map(|p| p.as_str())
        .unwrap_or("/");
    let uri = match Uri::builder()
        .scheme(state.upstream_scheme.clone())
        .authority(state.upstream_authority.clone())
        .path_and_query(pq)
        .build()
    {
        Ok(u) => u,
        Err(_) => {
            return (
                respond(StatusCode::BAD_REQUEST, "text/plain", "bad request target"),
                400,
            );
        }
    };
    let mut headers = parts.headers;
    strip_hop_by_hop(&mut headers);
    // Never trust client-supplied copies of our own headers.
    let ours: Vec<HeaderName> = headers
        .keys()
        .filter(|k| k.as_str().starts_with("x-pattern-guard-"))
        .cloned()
        .collect();
    for k in ours {
        headers.remove(k);
    }
    let xff = match header_str(&headers, "x-forwarded-for") {
        Some(prev) if any_contains(&state.trusted, ip) || !prev.is_empty() => {
            format!("{prev}, {ip}")
        }
        _ => ip.to_string(),
    };
    if let Ok(v) = HeaderValue::from_str(&xff) {
        headers.insert("x-forwarded-for", v);
    }
    if let Ok(v) = HeaderValue::from_str(&ip.to_string()) {
        headers.insert("x-real-ip", v);
    }
    if !state.cfg.preserve_host {
        if let Ok(v) = HeaderValue::from_str(state.upstream_authority.as_str()) {
            headers.insert(header::HOST, v);
        }
    }
    if state.cfg.forward_scores {
        if let Ok(v) = HeaderValue::from_str(id) {
            headers.insert("x-pattern-guard-request-id", v);
        }
        if let Some(a) = assessment {
            headers.insert(
                "x-pattern-guard-bot-score",
                HeaderValue::from(a.bot_score as u32),
            );
            if let Ok(v) = HeaderValue::from_str(&format!("{:.3}", a.risk)) {
                headers.insert("x-pattern-guard-risk", v);
            }
        }
    }
    let mut req = Request::new(Full::new(body));
    *req.method_mut() = parts.method;
    *req.uri_mut() = uri;
    *req.headers_mut() = headers;

    let timeout = Duration::from_secs(state.cfg.upstream_timeout_secs.max(1));
    match tokio::time::timeout(timeout, state.client.request(req)).await {
        Ok(Ok(resp)) => {
            let status = resp.status().as_u16();
            let (mut rp, b) = resp.into_parts();
            strip_hop_by_hop(&mut rp.headers);
            (Response::from_parts(rp, b.boxed()), status)
        }
        Ok(Err(e)) => {
            state.metrics.upstream_errors.fetch_add(1, Relaxed);
            eprintln!("pattern-guard-gateway: upstream error: {e}");
            (
                respond(
                    StatusCode::BAD_GATEWAY,
                    "text/plain",
                    "upstream unavailable",
                ),
                502,
            )
        }
        Err(_) => {
            state.metrics.upstream_errors.fetch_add(1, Relaxed);
            (
                respond(
                    StatusCode::GATEWAY_TIMEOUT,
                    "text/plain",
                    "upstream timeout",
                ),
                504,
            )
        }
    }
}

fn strip_hop_by_hop(h: &mut HeaderMap) {
    let listed: Vec<String> = h
        .get_all(header::CONNECTION)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(',').map(|s| s.trim().to_ascii_lowercase()))
        .collect();
    for name in HOP_BY_HOP.iter().map(|s| s.to_string()).chain(listed) {
        if let Ok(n) = HeaderName::from_bytes(name.as_bytes()) {
            h.remove(n);
        }
    }
}

fn verify(state: &State, ip: IpAddr, query: &str) -> Response<Body> {
    let mut q = std::collections::HashMap::new();
    for pair in query.split('&') {
        if let Some((k, v)) = pair.split_once('=') {
            q.insert(k, v);
        }
    }
    let get = |k: &str| q.get(k).copied().unwrap_or("");
    let ret = percent_decode_simple(get("r"));
    let ok = state.challenger.verify(
        ip,
        get("n"),
        get("e").parse().unwrap_or(0),
        get("d").parse().unwrap_or(0),
        get("s"),
        get("c"),
    );
    match ok {
        Some(cookie) => {
            state.metrics.challenges_passed.fetch_add(1, Relaxed);
            let mut r = respond(StatusCode::FOUND, "text/plain", "ok");
            r.headers_mut().insert(
                header::LOCATION,
                HeaderValue::from_str(safe_return(&ret)).unwrap_or(HeaderValue::from_static("/")),
            );
            if let Ok(v) = HeaderValue::from_str(&cookie) {
                r.headers_mut().insert(header::SET_COOKIE, v);
            }
            r
        }
        None => {
            state.metrics.challenges_failed.fetch_add(1, Relaxed);
            respond(
                StatusCode::FORBIDDEN,
                "text/html; charset=utf-8",
                "<!doctype html><meta charset=utf-8><title>Verification failed</title><p>Verification failed or expired. <a href=\"/\">Try again</a>.</p>",
            )
        }
    }
}

fn percent_decode_simple(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' && i + 2 < b.len() {
            if let Ok(v) = u8::from_str_radix(&s[i + 1..i + 3], 16) {
                out.push(v);
                i += 3;
                continue;
            }
        }
        out.push(if b[i] == b'+' { b' ' } else { b[i] });
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// At most one console line per second (with a count of suppressed lines), so an attack
/// can't turn stderr into a bottleneck. Full detail goes to the async decision log.
fn console_slot(state: &State) -> bool {
    let now = crate::challenge::now_secs();
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

struct LogCtx<'a> {
    id: &'a str,
    ip: IpAddr,
    peer: SocketAddr,
    assessment: &'a Assessment,
    findings: &'a [Finding],
    intel: Option<&'a IntelEntry>,
    reasons: &'a [String],
    action: Action,
    layer: &'static str,
    enforced: bool,
}

fn log_decision(state: &State, parts: &hyper::http::request::Parts, c: &LogCtx, status: u16) {
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

    #[test]
    fn simple_percent_decoding() {
        assert_eq!(percent_decode_simple("%2Fcart%3Fx%3D1"), "/cart?x=1");
        assert_eq!(percent_decode_simple("%zz"), "%zz");
    }
}
