//! `/.pattern-guard/verify`: checks a proof-of-work solution and sets the clearance cookie.

use std::net::IpAddr;
use std::sync::atomic::Ordering::Relaxed;

use hyper::header::{self, HeaderValue};
use hyper::{Response, StatusCode};

use super::Body;
use super::responses::respond;
use crate::challenge::safe_return;
use crate::state::State;
use crate::util::form_decode;

pub(super) fn verify(state: &State, ip: IpAddr, query: &str) -> Response<Body> {
    let mut q = std::collections::HashMap::new();
    for pair in query.split('&') {
        if let Some((k, v)) = pair.split_once('=') {
            q.insert(k, v);
        }
    }
    let get = |k: &str| q.get(k).copied().unwrap_or("");
    let ret = form_decode(get("r"));
    let ok = state.challenger.verify(
        ip,
        get("n"),
        get("e").parse().unwrap_or(0),
        get("d").parse().unwrap_or(0),
        get("s"),
        get("c"),
    );
    match ok {
        // `j=1`: the challenge page fetches the cookie itself, then re-sends a form
        Some(cookie) if get("j") == "1" => {
            state.metrics.challenges_passed.fetch_add(1, Relaxed);
            let mut r = respond(StatusCode::NO_CONTENT, "text/plain", "");
            if let Ok(v) = HeaderValue::from_str(&cookie) {
                r.headers_mut().insert(header::SET_COOKIE, v);
            }
            r
        }
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
