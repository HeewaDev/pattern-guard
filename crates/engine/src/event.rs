//! One observation: who, what, what was hit, when — plus optional request signals.

use std::collections::HashMap;
use std::net::IpAddr;
use std::time::SystemTime;

use crate::util::normalize::hash_str;

/// A single request / run / call.
///
/// Only `actor`, `action`, `target` and `timestamp` are required. Every optional
/// signal you add (client IP, user agent, TLS/HTTP fingerprint, response status via
/// [`Guard::observe_response`](crate::Guard::observe_response)) gives the adaptive
/// engine more to work with.
///
/// `timestamp` should come from your server clock (`SystemTime::now()`) or, when
/// replaying logs, from the log line. With the default `time_source = "event"`,
/// all windows are computed on these timestamps, so never pass a client-supplied time.
#[derive(Debug, Clone)]
pub struct Event {
    pub actor: String,
    pub action: String,
    pub target: String,
    pub timestamp: SystemTime,
    /// Cost/impact for weighted overuse; 1.0 if unset.
    pub weight: Option<f64>,
    pub metadata: Option<HashMap<String, String>>,
    /// Client IP. If unset and `actor` looks like `ip:<addr>` or `<addr>`, it is parsed from the actor.
    pub ip: Option<IpAddr>,
    /// `User-Agent` header.
    pub user_agent: Option<String>,
    /// Client fingerprint (e.g. JA3/JA4 TLS hash or an HTTP header-order hash from your proxy).
    pub fingerprint: Option<String>,
}

impl Event {
    pub fn new(
        actor: impl Into<String>,
        action: impl Into<String>,
        target: impl Into<String>,
        timestamp: SystemTime,
    ) -> Self {
        Self {
            actor: actor.into(),
            action: action.into(),
            target: target.into(),
            timestamp,
            weight: None,
            metadata: None,
            ip: None,
            user_agent: None,
            fingerprint: None,
        }
    }

    pub fn with_weight(mut self, weight: f64) -> Self {
        self.weight = Some(weight);
        self
    }

    pub fn with_metadata(mut self, metadata: HashMap<String, String>) -> Self {
        self.metadata = Some(metadata);
        self
    }

    pub fn with_ip(mut self, ip: IpAddr) -> Self {
        self.ip = Some(ip);
        self
    }

    pub fn with_user_agent(mut self, user_agent: impl Into<String>) -> Self {
        self.user_agent = Some(user_agent.into());
        self
    }

    pub fn with_fingerprint(mut self, fingerprint: impl Into<String>) -> Self {
        self.fingerprint = Some(fingerprint.into());
        self
    }

    /// 1.0 if weight unset.
    pub fn effective_weight(&self) -> f64 {
        self.weight.unwrap_or(1.0)
    }

    /// The explicit `ip`, or one parsed from an `ip:<addr>` / `<addr>` actor.
    pub fn client_ip(&self) -> Option<IpAddr> {
        if self.ip.is_some() {
            return self.ip;
        }
        let a = self.actor.strip_prefix("ip:").unwrap_or(&self.actor);
        a.parse().ok()
    }

    /// Seconds since the Unix epoch (0 for pre-epoch timestamps).
    pub fn unix_secs(&self) -> f64 {
        self.timestamp
            .duration_since(SystemTime::UNIX_EPOCH)
            .map(|d| d.as_secs_f64())
            .unwrap_or(0.0)
    }

    /// The key the engine's actor tables (features, rules, cooldowns) use: a 64-bit hash
    /// of `actor`, so an embedder passing long actor strings can't grow memory with them.
    pub(crate) fn actor_key(&self) -> u64 {
        hash_str(&[&self.actor])
    }

    /// The key used for cross-actor grouping: a 64-bit hash of the fingerprint, else of the
    /// user agent (in separate namespaces). Hashed so that a client-chosen user agent of
    /// any size costs 8 bytes in the client table.
    pub(crate) fn client_key(&self) -> Option<u64> {
        match (&self.fingerprint, &self.user_agent) {
            (Some(f), _) if !f.is_empty() => Some(hash_str(&["fp", f])),
            (_, Some(u)) if !u.is_empty() => Some(hash_str(&["ua", u])),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn client_ip_from_actor() {
        let e = Event::new("ip:203.0.113.9", "GET", "/", SystemTime::now());
        assert_eq!(e.client_ip(), Some("203.0.113.9".parse().unwrap()));
        let e = Event::new("2001:db8::1", "GET", "/", SystemTime::now());
        assert!(e.client_ip().is_some());
        let e = Event::new("user:42", "GET", "/", SystemTime::now());
        assert_eq!(e.client_ip(), None);
    }

    #[test]
    fn client_key_prefers_fingerprint() {
        let ev = |ua: Option<&str>, fp: Option<&str>| {
            let mut e = Event::new("a", "GET", "/", SystemTime::now());
            e.user_agent = ua.map(Into::into);
            e.fingerprint = fp.map(Into::into);
            e.client_key()
        };
        let fp = ev(Some("curl/8"), Some("t13d"));
        assert_eq!(fp, ev(None, Some("t13d")));
        assert_eq!(fp, ev(Some("other"), Some("t13d")));
        let ua = ev(Some("curl/8"), None);
        assert_eq!(ua, ev(Some("curl/8"), Some("")));
        assert!(fp.is_some() && ua.is_some());
        // Same string as a fingerprint and as a user agent: different clients.
        assert_ne!(ev(Some("x"), None), ev(None, Some("x")));
        assert_ne!(ua, ev(Some("curl/9"), None));
        assert_eq!(ev(None, None), None);
        assert_eq!(ev(Some(""), Some("")), None);
    }
}
