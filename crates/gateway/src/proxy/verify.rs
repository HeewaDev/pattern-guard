//! `/.pattern-guard/verify`: checks a proof-of-work solution and sets the clearance cookie.

use std::net::IpAddr;
use std::sync::atomic::Ordering::Relaxed;

use hyper::header::{self, HeaderValue};
use hyper::{Response, StatusCode};

use super::Body;
use super::responses::respond;
use crate::challenge::safe_return;
use crate::state::State;

pub(super) fn verify(state: &State, ip: IpAddr, query: &str) -> Response<Body> {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn simple_percent_decoding() {
        assert_eq!(percent_decode_simple("%2Fcart%3Fx%3D1"), "/cart?x=1");
        assert_eq!(percent_decode_simple("%zz"), "%zz");
    }
}
