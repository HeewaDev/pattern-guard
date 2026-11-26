//! Token-bucket rate limits per route and key (IP, IP + route template, or a header
//! such as an API key). Every matching limit consumes a token; the most severe
//! exceeded limit decides.
//!
//! [`Limits`] are the definitions compiled from `[[rate_limits]]`; [`Buckets`] are the
//! learned token buckets. A bucket belongs to its limit by the limit's name (see
//! `policy::definition_ids`), so a limit that is still configured after a reload keeps
//! its buckets.
//!
//! Buckets are keyed by a keyed 64-bit hash of the key, never by the key itself: a
//! client controls header values (up to hyper's ~400 KB request head), and 200 000
//! buckets keyed by whole values could hold tens of GiB.

use std::hash::{BuildHasher, Hash, Hasher, RandomState};
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
    /// Which buckets are this limit's (stable across reloads).
    id: u64,
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

/// The configured rate limits (compiled; rebuilt on reload).
pub struct Limits {
    limits: Vec<Limit>,
}

/// The token buckets of every limit (learned; kept across reloads).
pub struct Buckets {
    /// (limit id, hash of the key) → bucket.
    buckets: Mutex<LruCache<(u64, u64), Bucket>>,
    /// SipHash with a random per-process key, so clients can't craft colliding keys
    /// to share (and drain) someone else's bucket.
    hasher: RandomState,
}

impl Default for Buckets {
    fn default() -> Self {
        Self {
            buckets: Mutex::new(LruCache::new(NonZeroUsize::new(MAX_BUCKETS).unwrap())),
            hasher: RandomState::new(),
        }
    }
}

impl Buckets {
    /// The bucket key of limit `l` for this request: a 64-bit hash, so a bucket costs
    /// the same whatever the size of the value it is keyed by. The leading tag keeps an
    /// IP and a header value with the same text apart.
    fn key(&self, l: &Limit, ip: IpAddr, parts: &Parts, path: &PathView) -> u64 {
        let mut h = self.hasher.build_hasher();
        match &l.key {
            Key::Ip => (0u8, ip).hash(&mut h),
            Key::IpRoute => (
                1u8,
                ip,
                parts.method.as_str(),
                pattern_guard::normalize::normalize_path(path.canonical()).template,
            )
                .hash(&mut h),
            Key::Header(name) => match parts.headers.get(name).and_then(|v| v.to_str().ok()) {
                Some(v) => (2u8, v).hash(&mut h),
                None => (0u8, ip).hash(&mut h),
            },
        }
        h.finish()
    }

    /// Drops the buckets of the limits in `old` that `new` no longer defines (by name);
    /// the others keep their tokens. Returns how many were dropped.
    pub fn forget_removed(&self, old: &Limits, new: &Limits) -> usize {
        let gone = super::removed_ids(&old.ids(), &new.ids());
        super::forget(&self.buckets, &gone, |(id, _)| *id)
    }

    pub fn len(&self) -> usize {
        self.buckets.lock().unwrap_or_else(|e| e.into_inner()).len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

fn severity(a: LimitAction) -> u8 {
    match a {
        LimitAction::Delay => 1,
        LimitAction::Challenge => 2,
        LimitAction::Block => 3,
    }
}

impl Limits {
    pub fn compile(cfgs: &[RateLimitConfig]) -> Result<Self, String> {
        let ids = super::definition_ids(cfgs.iter().map(|c| c.name.as_str()));
        let mut limits = Vec::with_capacity(cfgs.len());
        for (c, id) in cfgs.iter().zip(ids) {
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
                id,
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
        Ok(Self { limits })
    }

    pub fn is_empty(&self) -> bool {
        self.limits.is_empty()
    }

    fn ids(&self) -> Vec<u64> {
        self.limits.iter().map(|l| l.id).collect()
    }

    fn applies(l: &Limit, parts: &Parts, path: &PathView) -> bool {
        l.path_prefix
            .as_deref()
            .is_none_or(|p| path.protects_prefix(p))
            && l.path_re.as_ref().is_none_or(|re| path.protects_regex(re))
            && (l.methods.is_empty() || l.methods.iter().any(|m| m == parts.method.as_str()))
    }

    pub fn check(&self, buckets: &Buckets, ip: IpAddr, parts: &Parts) -> Option<LimitHit> {
        self.check_at(buckets, ip, parts, Instant::now())
    }

    fn check_at(
        &self,
        buckets: &Buckets,
        ip: IpAddr,
        parts: &Parts,
        now: Instant,
    ) -> Option<LimitHit> {
        if self.limits.is_empty() {
            return None;
        }
        let path = PathView::new(parts.uri.path());
        // Hash before taking the lock: hashing a large header value must not hold up
        // every other request.
        let keys: Vec<(&Limit, u64)> = self
            .limits
            .iter()
            .filter(|l| Self::applies(l, parts, &path))
            .map(|l| (l, buckets.key(l, ip, parts, &path)))
            .collect();
        if keys.is_empty() {
            return None;
        }
        let mut worst: Option<LimitHit> = None;
        let mut map = buckets.buckets.lock().unwrap_or_else(|e| e.into_inner());
        for (l, key) in keys {
            let b = map.get_or_insert_mut((l.id, key), || Bucket {
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

    fn limits(toml: &str) -> Limits {
        let cfg = crate::config::GatewayConfig::from_toml_str(&format!(
            "upstream = \"http://127.0.0.1:1\"\n{toml}"
        ))
        .unwrap();
        Limits::compile(&cfg.rate_limits).unwrap()
    }

    /// Definitions and buckets together, as the gateway holds them.
    struct Limiter {
        limits: Limits,
        buckets: Buckets,
    }

    impl Limiter {
        fn check_at(&self, ip: IpAddr, parts: &Parts, now: Instant) -> Option<LimitHit> {
            self.limits.check_at(&self.buckets, ip, parts, now)
        }
    }

    fn limiter(toml: &str) -> Limiter {
        Limiter {
            limits: limits(toml),
            buckets: Buckets::default(),
        }
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
    fn buckets_follow_limits_by_name() {
        let mut rl = limiter(
            "[[rate_limits]]\nname = \"login\"\npath = \"/login\"\nrequests = 2\nper_secs = 60\n",
        );
        let ip: IpAddr = "203.0.113.1".parse().unwrap();
        let t0 = Instant::now();
        let login = req("POST", "/login", &[]);
        for _ in 0..2 {
            assert!(rl.check_at(ip, &login, t0).is_none());
        }
        // new definitions: another limit in front of it, and its own budget raised
        rl.limits = limits(
            "[[rate_limits]]\nname = \"search\"\npath = \"/search\"\nrequests = 1\nper_secs = 60\n\
             [[rate_limits]]\nname = \"login\"\npath = \"/login\"\nrequests = 3\nper_secs = 60\n",
        );
        assert!(rl.check_at(ip, &req("GET", "/search", &[]), t0).is_none());
        assert!(
            rl.check_at(ip, &login, t0).is_some(),
            "the bucket is still empty: no fresh burst for new definitions"
        );
        assert_eq!(rl.buckets.len(), 2);
        // a reload that removes "search": its buckets go, the login bucket stays empty
        let old = std::mem::replace(
            &mut rl.limits,
            limits(
                "[[rate_limits]]\nname = \"login\"\npath = \"/login\"\nrequests = 3\nper_secs = 60\n",
            ),
        );
        assert_eq!(rl.buckets.forget_removed(&old, &rl.limits), 1);
        assert_eq!(rl.buckets.len(), 1);
        assert!(rl.check_at(ip, &login, t0).is_some());
        assert_eq!(rl.buckets.forget_removed(&rl.limits, &rl.limits), 0);
    }

    #[test]
    fn invalid_config_rejected() {
        let cfg = crate::config::GatewayConfig::from_toml_str(
            "upstream = \"http://127.0.0.1:1\"\n[[rate_limits]]\nname = \"x\"\nkey = \"cookie\"\nrequests = 1\nper_secs = 1\n",
        )
        .unwrap();
        assert!(Limits::compile(&cfg.rate_limits).is_err());
    }
}
