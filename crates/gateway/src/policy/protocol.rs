//! HTTP protocol enforcement (the ideas of OWASP CRS 911/920): allowed methods, size
//! limits, NUL bytes, Host header, restricted file extensions.

use hyper::StatusCode;
use hyper::http::request::Parts;

use crate::config::ProtocolConfig;

#[derive(Debug, Clone, PartialEq)]
pub struct Violation {
    pub status: StatusCode,
    pub reason: String,
}

pub struct Protocol {
    cfg: ProtocolConfig,
    methods: Vec<String>,
    extensions: Vec<String>,
}

impl Protocol {
    pub fn new(cfg: ProtocolConfig) -> Self {
        Self {
            methods: cfg
                .allowed_methods
                .iter()
                .map(|m| m.to_ascii_uppercase())
                .collect(),
            extensions: cfg
                .restricted_extensions
                .iter()
                .map(|e| {
                    let e = e.to_ascii_lowercase();
                    if e.starts_with('.') {
                        e
                    } else {
                        format!(".{e}")
                    }
                })
                .collect(),
            cfg,
        }
    }

    pub fn check(&self, parts: &Parts) -> Option<Violation> {
        if !self.cfg.enabled {
            return None;
        }
        let v = |status: StatusCode, reason: String| Some(Violation { status, reason });
        if !self.methods.iter().any(|m| m == parts.method.as_str()) {
            return v(
                StatusCode::METHOD_NOT_ALLOWED,
                format!("method {} not allowed", parts.method),
            );
        }
        let target = parts
            .uri
            .path_and_query()
            .map(|p| p.as_str())
            .unwrap_or("/");
        if target.len() > self.cfg.max_url_bytes {
            return v(
                StatusCode::URI_TOO_LONG,
                format!("request target of {} bytes", target.len()),
            );
        }
        if parts.headers.len() > self.cfg.max_headers {
            return v(
                StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE,
                format!("{} header fields", parts.headers.len()),
            );
        }
        let header_bytes: usize = parts
            .headers
            .iter()
            .map(|(k, val)| k.as_str().len() + val.len())
            .sum();
        if header_bytes > self.cfg.max_header_bytes {
            return v(
                StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE,
                format!("{header_bytes} bytes of headers"),
            );
        }
        if let Some(q) = parts.uri.query() {
            let args = q.split('&').filter(|a| !a.is_empty()).count();
            if args > self.cfg.max_query_args {
                return v(StatusCode::BAD_REQUEST, format!("{args} query arguments"));
            }
        }
        if self.cfg.block_null_bytes
            && (target.contains('\0') || target.to_ascii_lowercase().contains("%00"))
        {
            return v(StatusCode::BAD_REQUEST, "NUL byte in request target".into());
        }
        if self.cfg.require_host && !parts.headers.contains_key("host") {
            return v(StatusCode::BAD_REQUEST, "missing Host header".into());
        }
        if !self.extensions.is_empty() {
            let path = parts.uri.path().to_ascii_lowercase();
            if let Some(e) = self.extensions.iter().find(|e| path.ends_with(e.as_str())) {
                return v(StatusCode::FORBIDDEN, format!("restricted extension {e}"));
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyper::Request;

    fn protocol(toml: &str) -> Protocol {
        let cfg = crate::config::GatewayConfig::from_toml_str(&format!(
            "upstream = \"http://127.0.0.1:1\"\n{toml}"
        ))
        .unwrap();
        Protocol::new(cfg.protocol)
    }

    fn req(method: &str, uri: &str, headers: &[(&str, &str)]) -> Parts {
        let mut b = Request::builder()
            .method(method)
            .uri(uri)
            .header("host", "x");
        for (k, v) in headers {
            b = b.header(*k, *v);
        }
        b.body(()).unwrap().into_parts().0
    }

    #[test]
    fn violations_map_to_statuses() {
        let p = protocol(
            "[protocol]\nmax_url_bytes = 50\nmax_headers = 5\nmax_query_args = 3\nrestricted_extensions = [\"bak\", \".sql\"]\n",
        );
        assert_eq!(p.check(&req("GET", "/ok?a=1", &[])), None);
        assert_eq!(
            p.check(&req("TRACE", "/", &[])).unwrap().status,
            StatusCode::METHOD_NOT_ALLOWED
        );
        assert_eq!(
            p.check(&req("GET", &format!("/{}", "a".repeat(60)), &[]))
                .unwrap()
                .status,
            StatusCode::URI_TOO_LONG
        );
        let many: Vec<(String, String)> = (0..6).map(|i| (format!("x-h{i}"), "v".into())).collect();
        let many: Vec<(&str, &str)> = many.iter().map(|(a, b)| (a.as_str(), b.as_str())).collect();
        assert_eq!(
            p.check(&req("GET", "/", &many)).unwrap().status,
            StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE
        );
        assert_eq!(
            p.check(&req("GET", "/?a=1&b=2&c=3&d=4", &[]))
                .unwrap()
                .status,
            StatusCode::BAD_REQUEST
        );
        assert!(
            p.check(&req("GET", "/file.php%00.png", &[]))
                .unwrap()
                .reason
                .contains("NUL")
        );
        assert_eq!(
            p.check(&req("GET", "/db/dump.SQL", &[])).unwrap().status,
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            p.check(&req("GET", "/site.bak", &[])).unwrap().status,
            StatusCode::FORBIDDEN
        );
        let no_host = Request::builder().uri("/").body(()).unwrap().into_parts().0;
        assert!(p.check(&no_host).unwrap().reason.contains("Host"));
        assert!(
            protocol("[protocol]\nenabled = false\n")
                .check(&req("TRACE", "/", &[]))
                .is_none()
        );
    }
}
