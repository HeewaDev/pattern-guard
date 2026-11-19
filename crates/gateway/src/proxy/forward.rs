//! Forwarding to the upstream application.

use std::collections::VecDeque;
use std::net::IpAddr;
use std::pin::Pin;
use std::sync::atomic::Ordering::Relaxed;
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::body::{Frame, Incoming};
use hyper::header::{self, HeaderMap, HeaderName, HeaderValue};
use hyper::{Request, Response, StatusCode, Uri};
use pattern_guard::Assessment;

use super::Body;
use super::responses::{full, header_str, respond};
use crate::config::{LeakAction, Mode};
use crate::hardening::leaks::LeakInspector;
use crate::ipnet::any_contains;
use crate::state::State;

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

pub(super) trait CloneHead {
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

pub(super) async fn forward(
    state: &State,
    parts: hyper::http::request::Parts,
    body: Bytes,
    ip: IpAddr,
    id: &str,
    assessment: Option<&Assessment>,
) -> (Response<Body>, u16, Option<(&'static str, bool)>) {
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
                None,
            );
        }
    };
    let html = header_str(&parts.headers, "accept").is_some_and(|a| a.contains("text/html"));
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
            state.security_headers.apply(&mut rp.headers);
            match state
                .leaks
                .as_ref()
                .filter(|l| l.should_inspect(&rp.headers))
            {
                None => (Response::from_parts(rp, b.boxed()), status, None),
                Some(insp) => inspect_response(state, insp, rp, b, status, html, id).await,
            }
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
                None,
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
                None,
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

/// Buffers up to `max_bytes` of a text response, scans it for data leaks and either
/// replaces it (block, prevent mode) or passes it on unchanged (prefix + rest of stream).
async fn inspect_response(
    state: &State,
    insp: &LeakInspector,
    rp: hyper::http::response::Parts,
    mut body: Incoming,
    status: u16,
    html: bool,
    id: &str,
) -> (Response<Body>, u16, Option<(&'static str, bool)>) {
    let mut chunks: VecDeque<Bytes> = VecDeque::new();
    let mut total = 0usize;
    let mut complete = false;
    loop {
        match body.frame().await {
            Some(Ok(frame)) => {
                if let Ok(data) = frame.into_data() {
                    total += data.len();
                    chunks.push_back(data);
                    if total >= insp.max_bytes {
                        break;
                    }
                }
            }
            Some(Err(e)) => {
                state.metrics.upstream_errors.fetch_add(1, Relaxed);
                eprintln!("pattern-guard-gateway: upstream body error: {e}");
                return (
                    respond(
                        StatusCode::BAD_GATEWAY,
                        "text/plain",
                        "upstream unavailable",
                    ),
                    502,
                    None,
                );
            }
            None => {
                complete = true;
                break;
            }
        }
    }
    let mut buf = Vec::with_capacity(total);
    for c in &chunks {
        buf.extend_from_slice(c);
    }
    let leak = insp.scan(&buf[..buf.len().min(insp.max_bytes)]);
    if let Some(sig) = leak {
        if insp.action == LeakAction::Block && state.cfg.mode == Mode::Prevent {
            state.metrics.inc_blocked_by("data_leak");
            let mut r = if html {
                respond(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "text/html; charset=utf-8",
                    format!(
                        "<!doctype html><html lang=en><head><meta charset=utf-8><title>Internal Server Error</title></head>\
                         <body style=\"font:16px/1.5 system-ui,sans-serif;max-width:30rem;margin:4rem auto;padding:0 1rem\"><h1>Something went wrong</h1><p>Reference: <code>{id}</code></p></body></html>"
                    ),
                )
            } else {
                respond(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "application/json",
                    format!("{{\"error\":\"internal_error\",\"request_id\":\"{id}\"}}"),
                )
            };
            state.security_headers.apply(r.headers_mut());
            return (r, 500, Some((sig, true)));
        }
    }
    let out: Body = if complete {
        full(Bytes::from(buf))
    } else {
        Rejoin {
            prefix: chunks,
            rest: body,
        }
        .boxed()
    };
    (
        Response::from_parts(rp, out),
        status,
        leak.map(|s| (s, false)),
    )
}

/// A body that yields already-read chunks, then the rest of the upstream stream.
struct Rejoin {
    prefix: VecDeque<Bytes>,
    rest: Incoming,
}

impl hyper::body::Body for Rejoin {
    type Data = Bytes;
    type Error = hyper::Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, hyper::Error>>> {
        let this = self.get_mut();
        if let Some(b) = this.prefix.pop_front() {
            return Poll::Ready(Some(Ok(Frame::data(b))));
        }
        Pin::new(&mut this.rest).poll_frame(cx)
    }
}
