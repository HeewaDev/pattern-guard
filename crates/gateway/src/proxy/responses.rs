//! Responses the gateway generates itself: block page, JSON errors, helpers.

use std::convert::Infallible;

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::header::{self, HeaderMap, HeaderValue};
use hyper::{Response, StatusCode};

use super::Body;

pub fn full(b: impl Into<Bytes>) -> Body {
    Full::new(b.into())
        .map_err(|n: Infallible| match n {})
        .boxed()
}

pub(super) fn respond(
    status: StatusCode,
    content_type: &str,
    body: impl Into<Bytes>,
) -> Response<Body> {
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

pub(super) fn header_str<'a>(h: &'a HeaderMap, name: &str) -> Option<&'a str> {
    h.get(name).and_then(|v| v.to_str().ok())
}

pub(super) fn wants_html(h: &HeaderMap) -> bool {
    header_str(h, "accept").is_some_and(|a| a.contains("text/html"))
}

pub(super) fn block_page(h: &HeaderMap, id: &str) -> Response<Body> {
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

/// 429 with `Retry-After`, as HTML for browsers and JSON for API clients.
pub(super) fn too_many_requests(h: &HeaderMap, id: &str, retry_after: u64) -> Response<Body> {
    let mut r = if wants_html(h) {
        respond(
            StatusCode::TOO_MANY_REQUESTS,
            "text/html; charset=utf-8",
            format!(
                "<!doctype html><html lang=en><head><meta charset=utf-8><meta name=viewport content=\"width=device-width,initial-scale=1\"><title>Too many requests</title></head>\
                 <body style=\"font:16px/1.5 system-ui,sans-serif;max-width:30rem;margin:4rem auto;padding:0 1rem\"><h1>Too many requests</h1><p>Please wait {retry_after} seconds and try again.</p><p><code>{id}</code></p></body></html>"
            ),
        )
    } else {
        respond(
            StatusCode::TOO_MANY_REQUESTS,
            "application/json",
            format!(
                "{{\"error\":\"rate_limited\",\"retry_after\":{retry_after},\"request_id\":\"{id}\"}}"
            ),
        )
    };
    r.headers_mut()
        .insert(header::RETRY_AFTER, HeaderValue::from(retry_after));
    r
}
