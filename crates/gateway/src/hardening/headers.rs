//! Adds security headers the app didn't set and strips fingerprinting headers.

use hyper::header::{HeaderMap, HeaderName, HeaderValue};

use crate::config::ResponseHeadersConfig;

pub struct SecurityHeaders {
    set: Vec<(HeaderName, HeaderValue)>,
    remove: Vec<HeaderName>,
}

impl SecurityHeaders {
    pub fn new(cfg: &ResponseHeadersConfig) -> Result<Self, String> {
        if !cfg.enabled {
            return Ok(Self {
                set: Vec::new(),
                remove: Vec::new(),
            });
        }
        let mut set = Vec::new();
        for (name, value) in [
            ("x-content-type-options", &cfg.content_type_options),
            ("x-frame-options", &cfg.frame_options),
            ("referrer-policy", &cfg.referrer_policy),
            ("strict-transport-security", &cfg.strict_transport_security),
            ("content-security-policy", &cfg.content_security_policy),
            ("permissions-policy", &cfg.permissions_policy),
            (
                "cross-origin-opener-policy",
                &cfg.cross_origin_opener_policy,
            ),
        ] {
            if value.is_empty() {
                continue;
            }
            let v = HeaderValue::from_str(value)
                .map_err(|_| format!("response_headers: invalid value for {name}"))?;
            set.push((HeaderName::from_static(name), v));
        }
        let remove = cfg
            .remove
            .iter()
            .map(|n| {
                HeaderName::from_bytes(n.to_ascii_lowercase().as_bytes())
                    .map_err(|_| format!("response_headers: invalid header name {n:?}"))
            })
            .collect::<Result<_, _>>()?;
        Ok(Self { set, remove })
    }

    pub fn apply(&self, h: &mut HeaderMap) {
        for n in &self.remove {
            h.remove(n);
        }
        for (n, v) in &self.set {
            if !h.contains_key(n) {
                h.insert(n.clone(), v.clone());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn headers(toml: &str) -> SecurityHeaders {
        let cfg = crate::config::GatewayConfig::from_toml_str(&format!(
            "upstream = \"http://127.0.0.1:1\"\n{toml}"
        ))
        .unwrap();
        SecurityHeaders::new(&cfg.response_headers).unwrap()
    }

    #[test]
    fn defaults_add_missing_keep_existing_and_strip() {
        let mut h = HeaderMap::new();
        h.insert("server", HeaderValue::from_static("Apache/2.4.1"));
        h.insert("x-powered-by", HeaderValue::from_static("PHP/8.1"));
        h.insert("x-frame-options", HeaderValue::from_static("DENY"));
        headers("").apply(&mut h);
        assert!(!h.contains_key("server") && !h.contains_key("x-powered-by"));
        assert_eq!(h["x-content-type-options"], "nosniff");
        assert_eq!(h["x-frame-options"], "DENY", "the app's own value wins");
        assert_eq!(h["referrer-policy"], "strict-origin-when-cross-origin");
        assert!(
            !h.contains_key("strict-transport-security"),
            "HSTS is opt-in"
        );
    }

    #[test]
    fn opt_in_disable_and_validation() {
        let mut h = HeaderMap::new();
        headers("[response_headers]\nstrict_transport_security = \"max-age=31536000\"\nframe_options = \"\"\n").apply(&mut h);
        assert_eq!(h["strict-transport-security"], "max-age=31536000");
        assert!(!h.contains_key("x-frame-options"));
        let mut h = HeaderMap::new();
        h.insert("server", HeaderValue::from_static("x"));
        headers("[response_headers]\nenabled = false\n").apply(&mut h);
        assert!(h.contains_key("server") && h.len() == 1);
        let cfg = crate::config::GatewayConfig::from_toml_str(
            "upstream = \"http://127.0.0.1:1\"\n[response_headers]\ncontent_security_policy = \"a\\nb\"\n",
        )
        .unwrap();
        assert!(SecurityHeaders::new(&cfg.response_headers).is_err());
    }
}
