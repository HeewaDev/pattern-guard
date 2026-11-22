//! Token-bucket rate limits per route and key (IP, IP + route template, or a header
//! such as an API key). Every matching limit consumes a token; the most severe
//! exceeded limit decides.

use std::net::IpAddr;
use std::num::NonZeroUsize;
use std::sync::Mutex;
use std::time::Instant;

use hyper::http::request::Parts;
use lru::LruCache;
use regex::Regex;

use crate::config::{LimitAction, RateLimitConfig};
use crate::policy::path::PathView;

const MAX_BUCKETS: usize = 200_000;

enum Key {
    Ip,
    IpRoute,
    Header(String),
}

struct Limit {
    name: String,
    path_prefix: Option<String>,
    path_re: Option<Regex>,
    methods: Vec<String>,
    key: Key,
    capacity: f64,
    refill_per_sec: f64,
    action: LimitAction,
}

#[derive(Clone, Copy)]
struct Bucket {
    tokens: f64,
    at: Instant,
}

/// An exceeded limit.
#[derive(Debug, Clone, PartialEq)]
pub struct LimitHit {
    pub name: String,
    pub action: LimitAction,
    /// Seconds until one request is allowed again.
    pub retry_after: u64,
}

pub struct RateLimiter {
    limits: Vec<Limit>,
    buckets: Mutex<LruCache<(usize, String), Bucket>>,
}

fn severity(a: LimitAction) -> u8 {
    match a {
        LimitAction::Delay => 1,
        LimitAction::Challenge => 2,
        LimitAction::Block => 3,
    }
}

impl RateLimiter {
    pub fn compile(cfgs: &[RateLimitConfig]) -> Result<Self, String> {
        let mut limits = Vec::with_capacity(cfgs.len());
        for c in cfgs {
            let bad = |m: &str| format!("rate limit {:?}: {m}", c.name);
            if c.requests == 0 || c.per_secs.is_nan() || c.per_secs <= 0.0 {
                return Err(bad("requests must be ≥ 1 and per_secs > 0"));
            }
            let key = match c.key.as_str() {
                "ip" => Key::Ip,
                "ip_route" => Key::IpRoute,
                k => match k.strip_prefix("header:") {
                    Some(h) if !h.is_empty() => Key::Header(h.to_ascii_lowercase()),
                    _ => return Err(bad("key must be ip, ip_route or header:<name>")),
                },
            };
            limits.push(Limit {
                name: c.name.clone(),
                path_prefix: c.path.clone(),
                path_re: c
                    .path_regex
                    .as_deref()
                    .map(Regex::new)
                    .transpose()
                    .map_err(|e| bad(&format!("bad path_regex: {e}")))?,
                methods: c.methods.iter().map(|m| m.to_ascii_uppercase()).collect(),
                key,
                capacity: c.requests as f64,
                refill_per_sec: c.requests as f64 / c.per_secs,
                action: c.action,
            });
        }
        Ok(Self {
            limits,
            buckets: Mutex::new(LruCache::new(NonZeroUsize::new(MAX_BUCKETS).unwrap())),
        })
    }

    pub fn check(&self, ip: IpAddr, parts: &Parts) -> Option<LimitHit> {
        self.check_at(ip, parts, Instant::now())
    }

    fn check_at(&self, ip: IpAddr, parts: &Parts, now: Instant) -> Option<LimitHit> {
        if self.limits.is_empty() {
            return None;
        }
        let path = PathView::new(parts.uri.path());
        let mut worst: Option<LimitHit> = None;
        let mut buckets = self.buckets.lock().unwrap_or_else(|e| e.into_inner());
        for (i, l) in self.limits.iter().enumerate() {
            if l.path_prefix
                .as_deref()
                .is_some_and(|p| !path.protects_prefix(p))
                || l.path_re
                    .as_ref()
                    .is_some_and(|re| !path.protects_regex(re))
                || (!l.methods.is_empty() && !l.methods.iter().any(|m| m == parts.method.as_str()))
            {
                continue;
            }
            let key = match &l.key {
                Key::Ip => ip.to_string(),
                Key::IpRoute => format!(
                    "{ip} {} {}",
                    parts.method,
                    pattern_guard::normalize::normalize_path(path.canonical()).template
                ),
                Key::Header(h) => match parts.headers.get(h).and_then(|v| v.to_str().ok()) {
                    Some(v) => format!("h:{v}"),
                    None => ip.to_string(),
                },
            };
            let b = buckets.get_or_insert_mut((i, key), || Bucket {
                tokens: l.capacity,
                at: now,
            });
            let elapsed = now.saturating_duration_since(b.at).as_secs_f64();
            b.tokens = (b.tokens + elapsed * l.refill_per_sec).min(l.capacity);
            b.at = now;
            if b.tokens >= 1.0 {
                b.tokens -= 1.0;
                continue;
            }
            let retry_after = ((1.0 - b.tokens) / l.refill_per_sec).ceil().max(1.0) as u64;
            let hit = LimitHit {
                name: l.name.clone(),
                action: l.action,
                retry_after,
            };
            if worst
                .as_ref()
                .is_none_or(|w| severity(hit.action) > severity(w.action))
            {
                worst = Some(hit);
            }
        }
        worst
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyper::Request;
    use std::time::Duration;

    fn limiter(toml: &str) -> RateLimiter {
        let cfg = crate::config::GatewayConfig::from_toml_str(&format!(
            "upstream = \"http://127.0.0.1:1\"\n{toml}"
        ))
        .unwrap();
        RateLimiter::compile(&cfg.rate_limits).unwrap()
    }

    fn req(method: &str, uri: &str, headers: &[(&str, &str)]) -> Parts {
        let mut b = Request::builder().method(method).uri(uri);
        for (k, v) in headers {
            b = b.header(*k, *v);
        }
        b.body(()).unwrap().into_parts().0
    }

    #[test]
    fn bucket_allows_burst_then_limits_then_refills() {
        let rl = limiter(
            "[[rate_limits]]\nname = \"login\"\npath = \"/login\"\nmethods = [\"POST\"]\nrequests = 5\nper_secs = 60\n",
        );
        let ip: IpAddr = "203.0.113.1".parse().unwrap();
        let t0 = Instant::now();
        let login = req("POST", "/login", &[]);
        for _ in 0..5 {
            assert!(rl.check_at(ip, &login, t0).is_none());
        }
        let hit = rl.check_at(ip, &login, t0).expect("6th is limited");
        assert_eq!(hit.action, LimitAction::Block);
        assert_eq!(hit.retry_after, 12, "one token per 12 s");
        assert!(
            rl.check_at(ip, &req("GET", "/login", &[]), t0).is_none(),
            "method filter"
        );
        assert!(
            rl.check_at("203.0.113.2".parse().unwrap(), &login, t0)
                .is_none(),
            "per IP"
        );
        assert!(
            rl.check_at(ip, &login, t0 + Duration::from_secs(13))
                .is_none(),
            "refilled"
        );
    }

    #[test]
    fn keys_and_severity() {
        let rl = limiter(
            r#"
[[rate_limits]]
name = "api per key"
path = "/api/"
key = "header:x-api-key"
requests = 2
per_secs = 10
action = "challenge"
[[rate_limits]]
name = "per item route"
path = "/api/"
key = "ip_route"
requests = 1
per_secs = 10
action = "delay"
"#,
        );
        let t0 = Instant::now();
        let a: IpAddr = "198.51.100.1".parse().unwrap();
        let b: IpAddr = "198.51.100.2".parse().unwrap();
        let item1 = req("GET", "/api/items/1", &[("x-api-key", "k1")]);
        let item2 = req("GET", "/api/items/2", &[("x-api-key", "k1")]);
        assert!(rl.check_at(a, &item1, t0).is_none());
        // same route template from the same IP → delay; key k1 still has a token
        assert_eq!(
            rl.check_at(a, &item2, t0).unwrap().action,
            LimitAction::Delay
        );
        // key k1 exhausted, even from another IP → challenge beats delay
        assert_eq!(
            rl.check_at(b, &item1, t0).unwrap().action,
            LimitAction::Challenge
        );
    }

    #[test]
    fn invalid_config_rejected() {
        let cfg = crate::config::GatewayConfig::from_toml_str(
            "upstream = \"http://127.0.0.1:1\"\n[[rate_limits]]\nname = \"x\"\nkey = \"cookie\"\nrequests = 1\nper_secs = 1\n",
        )
        .unwrap();
        assert!(RateLimiter::compile(&cfg.rate_limits).is_err());
    }
}
