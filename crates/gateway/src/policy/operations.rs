//! Business-operation protection: what rate limits per IP can't see.
//!
//! * **Operations** (`[[operations]]`): a route that moves money or data (checkout,
//!   transfer, payment callback) gets a budget **per account** (header, cookie, query,
//!   form or JSON field), an optional list of **allowed sources**, and **replay
//!   protection**: a unique value such as a transaction id is accepted once. It is held
//!   while its request is in flight (so concurrent duplicates, the race-condition
//!   double spend, are refused) and kept as used only if the application answered 2xx
//!   (so a provider retrying after a failure still gets through).
//! * **Logins** (`[[logins]]`): failed logins are counted **per account across all
//!   IPs** (distributed brute force) and **per IP across accounts** (credential
//!   stuffing). Only failures count, so an office behind one NAT logging in normally
//!   is not punished.
//!
//! Identifiers are hashed (SHA-256, 64 bits kept); tokens and user names are never
//! stored or logged.

use std::net::IpAddr;
use std::num::NonZeroUsize;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use hyper::http::request::Parts;
use lru::LruCache;
use regex::Regex;
use sha2::{Digest, Sha256};

use crate::config::{LoginConfig, OperationAction, OperationConfig};
use crate::ipnet::{Cidr, any_contains};
use crate::util::form_decode;

const MAX_ENTRIES: usize = 200_000;
/// Distinct failed accounts remembered per IP.
const MAX_ACCOUNTS_TRACKED: usize = 256;

/// Where an identifier comes from.
#[derive(Debug, Clone)]
enum Field {
    Header(String),
    Cookie(String),
    Query(String),
    Form(String),
    Json(Vec<String>),
}

impl Field {
    fn parse(spec: &str) -> Result<Self, String> {
        let (kind, name) = spec
            .split_once(':')
            .filter(|(_, n)| !n.is_empty())
            .ok_or_else(|| {
                format!("{spec:?}: expected header:, cookie:, query:, form: or json:")
            })?;
        Ok(match kind {
            "header" => Field::Header(name.to_ascii_lowercase()),
            "cookie" => Field::Cookie(name.to_string()),
            "query" => Field::Query(name.to_string()),
            "form" => Field::Form(name.to_string()),
            "json" => Field::Json(name.split('.').map(str::to_string).collect()),
            _ => return Err(format!("{spec:?}: unknown source {kind:?}")),
        })
    }

    fn extract(&self, parts: &Parts, body: &[u8]) -> Option<String> {
        let v = match self {
            Field::Header(h) => parts.headers.get(h)?.to_str().ok()?.to_string(),
            Field::Cookie(c) => parts
                .headers
                .get_all("cookie")
                .iter()
                .filter_map(|v| v.to_str().ok())
                .flat_map(|v| v.split(';'))
                .find_map(|kv| {
                    let (k, v) = kv.split_once('=')?;
                    (k.trim() == c).then(|| v.trim().to_string())
                })?,
            Field::Query(q) => form_value(parts.uri.query()?, q)?,
            Field::Form(f) => {
                if !content_type(parts).starts_with("application/x-www-form-urlencoded") {
                    return None;
                }
                form_value(std::str::from_utf8(body).ok()?, f)?
            }
            Field::Json(path) => {
                if !content_type(parts).contains("json") {
                    return None;
                }
                let parsed: serde_json::Value = serde_json::from_slice(body).ok()?;
                let mut v = &parsed;
                for seg in path {
                    v = match v {
                        serde_json::Value::Object(m) => m.get(seg)?,
                        serde_json::Value::Array(a) => a.get(seg.parse::<usize>().ok()?)?,
                        _ => return None,
                    };
                }
                match v {
                    serde_json::Value::String(s) => s.clone(),
                    serde_json::Value::Number(n) => n.to_string(),
                    serde_json::Value::Bool(b) => b.to_string(),
                    _ => return None,
                }
            }
        };
        let v = v.trim().to_string();
        (!v.is_empty()).then_some(v)
    }
}

fn content_type(parts: &Parts) -> String {
    parts
        .headers
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_ascii_lowercase()
}

fn form_value(s: &str, name: &str) -> Option<String> {
    s.split('&').find_map(|kv| {
        let (k, v) = kv.split_once('=').unwrap_or((kv, ""));
        (form_decode(k) == name).then(|| form_decode(v))
    })
}

fn hash(scope: &str, value: &str) -> u64 {
    let d = Sha256::new()
        .chain_update(scope.as_bytes())
        .chain_update([0u8])
        .chain_update(value.as_bytes())
        .finalize();
    u64::from_be_bytes(d[..8].try_into().expect("8 bytes"))
}

struct Route {
    prefix: Option<String>,
    re: Option<Regex>,
    methods: Vec<String>,
}

impl Route {
    fn new(
        what: &str,
        prefix: &Option<String>,
        re: &Option<String>,
        methods: &[String],
    ) -> Result<Self, String> {
        if prefix.is_none() && re.is_none() {
            return Err(format!("{what}: set path or path_regex"));
        }
        Ok(Self {
            prefix: prefix.clone(),
            re: re
                .as_deref()
                .map(Regex::new)
                .transpose()
                .map_err(|e| format!("{what}: bad path_regex: {e}"))?,
            methods: methods.iter().map(|m| m.to_ascii_uppercase()).collect(),
        })
    }

    fn matches(&self, parts: &Parts) -> bool {
        let path = parts.uri.path();
        self.prefix.as_deref().is_none_or(|p| path.starts_with(p))
            && self.re.as_ref().is_none_or(|re| re.is_match(path))
            && (self.methods.is_empty() || self.methods.iter().any(|m| m == parts.method.as_str()))
    }
}

struct Op {
    name: String,
    route: Route,
    account: Option<Field>,
    require_account: bool,
    limit: Option<(f64, f64)>, // capacity, refill per second
    allowed: Vec<Cidr>,
    unique: Option<Field>,
    unique_ttl: Duration,
    action: OperationAction,
}

struct Login {
    name: String,
    route: Route,
    account: Field,
    failure_statuses: Vec<u16>,
    max_failures: u32,
    max_accounts_per_ip: u32,
    window: Duration,
    action: OperationAction,
}

#[derive(Clone, Copy)]
struct Bucket {
    tokens: f64,
    at: Instant,
}

#[derive(Clone, Copy)]
enum Seen {
    InFlight,
    Used(Instant),
}

#[derive(Clone, Copy)]
struct Failures {
    count: u32,
    since: Instant,
}

/// A failed check.
#[derive(Debug, Clone, PartialEq)]
pub struct OpHit {
    /// Operation or login name.
    pub name: String,
    /// `source_not_allowed`, `account_missing`, `account_limit`, `replay`,
    /// `account_locked` or `credential_stuffing`.
    pub kind: &'static str,
    pub action: OperationAction,
    /// Status to answer with when enforced.
    pub status: u16,
    pub retry_after: Option<u64>,
    /// Short hash of the account, for the log.
    pub account: Option<String>,
}

fn severity(a: OperationAction) -> u8 {
    match a {
        OperationAction::Log => 0,
        OperationAction::Delay => 1,
        OperationAction::Challenge => 2,
        OperationAction::Block => 3,
    }
}

/// State to settle once the application has answered.
pub struct Ticket<'a> {
    ops: &'a Operations,
    unique: Vec<(usize, u64)>,
    logins: Vec<(usize, u64, IpAddr)>,
    done: bool,
}

impl Ticket<'_> {
    /// Records the outcome: unique values are kept as used after a 2xx answer (else
    /// released), login failures and successes update the counters.
    pub fn complete(mut self, status: u16) {
        self.done = true;
        let now = Instant::now();
        let ok = (200..300).contains(&status);
        if !self.unique.is_empty() {
            let mut seen = lock(&self.ops.unique);
            for &(i, key) in &self.unique {
                if ok {
                    let ttl = self.ops.ops[i].unique_ttl;
                    seen.put((i, key), Seen::Used(now + ttl));
                } else {
                    seen.pop(&(i, key));
                }
            }
        }
        for &(i, acct, ip) in &self.logins {
            let l = &self.ops.logins[i];
            if l.failure_statuses.contains(&status) {
                {
                    let mut f = lock(&self.ops.failures);
                    let e = f.get_or_insert_mut((i, acct), || Failures {
                        count: 0,
                        since: now,
                    });
                    if now.saturating_duration_since(e.since) > l.window {
                        *e = Failures {
                            count: 0,
                            since: now,
                        };
                    }
                    e.count += 1;
                }
                let mut per_ip = lock(&self.ops.ip_accounts);
                let list = per_ip.get_or_insert_mut((i, ip), Vec::new);
                list.retain(|(a, t)| *a != acct && now.saturating_duration_since(*t) <= l.window);
                if list.len() < MAX_ACCOUNTS_TRACKED {
                    list.push((acct, now));
                }
            } else if ok {
                lock(&self.ops.failures).pop(&(i, acct));
            }
        }
    }
}

impl Drop for Ticket<'_> {
    fn drop(&mut self) {
        // not forwarded (blocked, challenged, error): release in-flight values
        if !self.done && !self.unique.is_empty() {
            let mut seen = lock(&self.ops.unique);
            for k in &self.unique {
                if matches!(seen.peek(k), Some(Seen::InFlight)) {
                    seen.pop(k);
                }
            }
        }
    }
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

fn cache<K: std::hash::Hash + Eq, V>() -> Mutex<LruCache<K, V>> {
    Mutex::new(LruCache::new(
        NonZeroUsize::new(MAX_ENTRIES).expect("non-zero"),
    ))
}

/// Failed accounts (hash, last failure) per (login, IP).
type IpAccounts = LruCache<(usize, IpAddr), Vec<(u64, Instant)>>;

pub struct Operations {
    ops: Vec<Op>,
    logins: Vec<Login>,
    buckets: Mutex<LruCache<(usize, u64), Bucket>>,
    unique: Mutex<LruCache<(usize, u64), Seen>>,
    failures: Mutex<LruCache<(usize, u64), Failures>>,
    ip_accounts: Mutex<IpAccounts>,
}

impl Operations {
    pub fn compile(ops: &[OperationConfig], logins: &[LoginConfig]) -> Result<Self, String> {
        let mut out = Vec::with_capacity(ops.len());
        for c in ops {
            let what = format!("operation {:?}", c.name);
            let bad = |m: String| format!("{what}: {m}");
            let limit = match &c.limit {
                Some(l) if l.requests == 0 || l.per_secs.is_nan() || l.per_secs <= 0.0 => {
                    return Err(bad("limit needs requests ≥ 1 and per_secs > 0".into()));
                }
                Some(l) => Some((l.requests as f64, l.requests as f64 / l.per_secs)),
                None => None,
            };
            let mut allowed = Vec::new();
            for s in &c.allowed_ips {
                allowed.push(
                    Cidr::parse(s).ok_or_else(|| bad(format!("bad allowed_ips entry {s:?}")))?,
                );
            }
            let account = c
                .account
                .as_deref()
                .map(Field::parse)
                .transpose()
                .map_err(bad)?;
            if c.require_account && account.is_none() {
                return Err(bad("require_account needs account".into()));
            }
            out.push(Op {
                route: Route::new(&what, &c.path, &c.path_regex, &c.methods)?,
                name: c.name.clone(),
                account,
                require_account: c.require_account,
                limit,
                allowed,
                unique: c
                    .unique
                    .as_deref()
                    .map(Field::parse)
                    .transpose()
                    .map_err(bad)?,
                unique_ttl: Duration::from_secs(c.unique_ttl_secs.max(1)),
                action: c.action,
            });
        }
        let mut lg = Vec::with_capacity(logins.len());
        for c in logins {
            let what = format!("login {:?}", c.name);
            lg.push(Login {
                route: Route::new(&what, &c.path, &c.path_regex, &c.methods)?,
                name: c.name.clone(),
                account: Field::parse(&c.account).map_err(|e| format!("{what}: {e}"))?,
                failure_statuses: c.failure_statuses.clone(),
                max_failures: c.max_failures,
                max_accounts_per_ip: c.max_accounts_per_ip,
                window: Duration::from_secs(c.window_secs.max(1)),
                action: c.action,
            });
        }
        Ok(Self {
            ops: out,
            logins: lg,
            buckets: cache(),
            unique: cache(),
            failures: cache(),
            ip_accounts: cache(),
        })
    }

    pub fn is_empty(&self) -> bool {
        self.ops.is_empty() && self.logins.is_empty()
    }

    /// Checks a request. The returned ticket must be completed with the upstream
    /// status once the request has been forwarded.
    pub fn check(&self, ip: IpAddr, parts: &Parts, body: &[u8]) -> (Option<OpHit>, Ticket<'_>) {
        self.check_at(ip, parts, body, Instant::now())
    }

    fn check_at(
        &self,
        ip: IpAddr,
        parts: &Parts,
        body: &[u8],
        now: Instant,
    ) -> (Option<OpHit>, Ticket<'_>) {
        let mut ticket = Ticket {
            ops: self,
            unique: Vec::new(),
            logins: Vec::new(),
            done: false,
        };
        if self.is_empty() {
            return (None, ticket);
        }
        let mut worst: Option<OpHit> = None;
        let mut consider = |hit: OpHit| {
            if worst
                .as_ref()
                .is_none_or(|w| severity(hit.action) > severity(w.action))
            {
                worst = Some(hit);
            }
        };
        for (i, op) in self.ops.iter().enumerate() {
            if !op.route.matches(parts) {
                continue;
            }
            let account = op.account.as_ref().and_then(|f| f.extract(parts, body));
            let short = account
                .as_deref()
                .map(|a| format!("{:08x}", hash(&op.name, a) >> 32));
            let hit = |kind, status, retry_after| OpHit {
                name: op.name.clone(),
                kind,
                action: op.action,
                status,
                retry_after,
                account: short.clone(),
            };
            if !op.allowed.is_empty() && !any_contains(&op.allowed, ip) {
                consider(hit("source_not_allowed", 403, None));
                continue;
            }
            if op.require_account && account.is_none() {
                consider(hit("account_missing", 403, None));
                continue;
            }
            if let Some((capacity, refill)) = op.limit {
                let key = match &account {
                    Some(a) => hash(&op.name, a),
                    None => hash(&op.name, &format!("ip:{ip}")),
                };
                let mut buckets = lock(&self.buckets);
                let b = buckets.get_or_insert_mut((i, key), || Bucket {
                    tokens: capacity,
                    at: now,
                });
                let elapsed = now.saturating_duration_since(b.at).as_secs_f64();
                b.tokens = (b.tokens + elapsed * refill).min(capacity);
                b.at = now;
                if b.tokens >= 1.0 {
                    b.tokens -= 1.0;
                } else {
                    let wait = ((1.0 - b.tokens) / refill).ceil().max(1.0) as u64;
                    consider(hit("account_limit", 429, Some(wait)));
                }
            }
            if let Some(v) = op.unique.as_ref().and_then(|f| f.extract(parts, body)) {
                let key = (i, hash(&format!("{}/unique", op.name), &v));
                let mut seen = lock(&self.unique);
                match seen.get(&key).copied() {
                    Some(Seen::InFlight) => consider(hit("replay", 409, None)),
                    Some(Seen::Used(until)) if until > now => consider(hit("replay", 409, None)),
                    _ => {
                        seen.put(key, Seen::InFlight);
                        ticket.unique.push(key);
                    }
                }
            }
        }
        for (i, l) in self.logins.iter().enumerate() {
            if !l.route.matches(parts) {
                continue;
            }
            let Some(account) = l.account.extract(parts, body) else {
                continue;
            };
            let acct = hash(&l.name, &account.to_lowercase());
            let hit = |kind, retry_after: u64| OpHit {
                name: l.name.clone(),
                kind,
                action: l.action,
                status: 429,
                retry_after: Some(retry_after.max(1)),
                account: Some(format!("{:08x}", acct >> 32)),
            };
            if l.max_failures > 0 {
                if let Some(f) = lock(&self.failures).peek(&(i, acct)) {
                    let age = now.saturating_duration_since(f.since);
                    if age <= l.window && f.count >= l.max_failures {
                        consider(hit("account_locked", (l.window - age).as_secs()));
                    }
                }
            }
            if l.max_accounts_per_ip > 0 {
                if let Some(list) = lock(&self.ip_accounts).peek(&(i, ip)) {
                    let recent: Vec<&(u64, Instant)> = list
                        .iter()
                        .filter(|(_, t)| now.saturating_duration_since(*t) <= l.window)
                        .collect();
                    let known = recent.iter().any(|(a, _)| *a == acct);
                    if !known && recent.len() as u32 >= l.max_accounts_per_ip {
                        let oldest = recent.iter().map(|(_, t)| *t).min().unwrap_or(now);
                        let left = l
                            .window
                            .saturating_sub(now.saturating_duration_since(oldest));
                        consider(hit("credential_stuffing", left.as_secs()));
                    }
                }
            }
            ticket.logins.push((i, acct, ip));
        }
        (worst, ticket)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyper::Request;

    fn ops(toml: &str) -> Operations {
        let cfg = crate::config::GatewayConfig::from_toml_str(&format!(
            "upstream = \"http://127.0.0.1:1\"\n{toml}"
        ))
        .unwrap();
        Operations::compile(&cfg.operations, &cfg.logins).unwrap()
    }

    fn req(method: &str, uri: &str, headers: &[(&str, &str)]) -> Parts {
        let mut b = Request::builder().method(method).uri(uri);
        for (k, v) in headers {
            b = b.header(*k, *v);
        }
        b.body(()).unwrap().into_parts().0
    }

    const IP: &str = "198.51.100.7";

    #[test]
    fn per_account_limit_across_ips() {
        let o = ops(r#"
[[operations]]
name = "checkout"
path = "/checkout"
methods = ["POST"]
account = "header:authorization"
limit = { requests = 2, per_secs = 3600 }
"#);
        let p = req("POST", "/checkout", &[("authorization", "Bearer alice")]);
        let t0 = Instant::now();
        for ip in ["198.51.100.1", "198.51.100.2"] {
            let (h, t) = o.check_at(ip.parse().unwrap(), &p, b"", t0);
            assert!(h.is_none());
            t.complete(200);
        }
        // third purchase by the same account from a new IP is over budget
        let (h, _) = o.check_at("198.51.100.3".parse().unwrap(), &p, b"", t0);
        let h = h.expect("over budget");
        assert_eq!((h.kind, h.status), ("account_limit", 429));
        assert!(h.retry_after.unwrap() > 1000);
        // another account is unaffected
        let bob = req("POST", "/checkout", &[("authorization", "Bearer bob")]);
        assert!(o.check_at(IP.parse().unwrap(), &bob, b"", t0).0.is_none());
    }

    #[test]
    fn replay_and_race_are_refused_but_failures_can_retry() {
        let o = ops(r#"
[[operations]]
name = "payment callback"
path = "/payment/callback"
unique = "json:transaction.id"
allowed_ips = ["203.0.113.0/24"]
"#);
        let gw: IpAddr = "203.0.113.9".parse().unwrap();
        let p = req(
            "POST",
            "/payment/callback",
            &[("content-type", "application/json")],
        );
        let body = br#"{"transaction": {"id": "TX-1001"}, "status": "paid"}"#;
        // concurrent duplicate while the first is in flight
        let (h1, t1) = o.check(gw, &p, body);
        assert!(h1.is_none());
        let (h2, t2) = o.check(gw, &p, body);
        assert_eq!(h2.unwrap().kind, "replay", "race refused");
        drop(t2);
        // first one failed upstream: the provider may retry
        t1.complete(500);
        let (h3, t3) = o.check(gw, &p, body);
        assert!(h3.is_none(), "retry after failure allowed");
        t3.complete(200);
        // after success the same transaction id is a replay
        let (h4, _) = o.check(gw, &p, body);
        assert_eq!(h4.unwrap().status, 409);
        // a different id passes; a blocked (dropped) ticket releases its id
        let other = br#"{"transaction": {"id": "TX-1002"}}"#;
        let (h5, t5) = o.check(gw, &p, other);
        assert!(h5.is_none());
        drop(t5);
        assert!(o.check(gw, &p, other).0.is_none(), "released on drop");
        // anyone else calling the callback is refused
        let (h6, _) = o.check(
            "192.0.2.66".parse().unwrap(),
            &p,
            br#"{"transaction":{"id":"X"}}"#,
        );
        assert_eq!(h6.unwrap().kind, "source_not_allowed");
    }

    #[test]
    fn require_account_and_field_sources() {
        let o = ops(r#"
[[operations]]
name = "transfer"
path = "/transfer"
account = "cookie:session"
require_account = true
[[operations]]
name = "order"
path = "/order"
account = "form:user"
limit = { requests = 1, per_secs = 60 }
"#);
        let ip: IpAddr = IP.parse().unwrap();
        let (h, _) = o.check(ip, &req("POST", "/transfer", &[]), b"");
        assert_eq!(h.unwrap().kind, "account_missing");
        let ok = req(
            "POST",
            "/transfer",
            &[("cookie", "theme=dark; session=abc123")],
        );
        assert!(o.check(ip, &ok, b"").0.is_none());
        let form = req(
            "POST",
            "/order",
            &[("content-type", "application/x-www-form-urlencoded")],
        );
        assert!(
            o.check(ip, &form, b"item=1&user=ann%40example.com")
                .0
                .is_none()
        );
        assert_eq!(
            o.check(ip, &form, b"user=ann%40example.com&item=2")
                .0
                .unwrap()
                .kind,
            "account_limit"
        );
    }

    #[test]
    fn logins_lock_accounts_and_catch_stuffing() {
        let o = ops(r#"
[[logins]]
name = "login"
path = "/login"
account = "json:email"
max_failures = 3
max_accounts_per_ip = 2
window_secs = 600
"#);
        let p = req("POST", "/login", &[("content-type", "application/json")]);
        let body = |u: &str| format!(r#"{{"email": "{u}", "password": "x"}}"#);
        // distributed brute force: 3 failures for alice from 3 IPs
        for k in 1..=3 {
            let ip: IpAddr = format!("203.0.113.{k}").parse().unwrap();
            let (h, t) = o.check(ip, &p, body("alice@example.com").as_bytes());
            assert!(h.is_none());
            t.complete(401);
        }
        let (h, _) = o.check(
            "203.0.113.50".parse().unwrap(),
            &p,
            body("ALICE@example.com").as_bytes(),
        );
        let h = h.expect("alice locked from any IP, case-insensitive");
        assert_eq!((h.kind, h.status), ("account_locked", 429));
        // credential stuffing: one IP failing on many accounts
        let ip: IpAddr = "198.51.100.200".parse().unwrap();
        for u in ["a@x.io", "b@x.io"] {
            let (_, t) = o.check(ip, &p, body(u).as_bytes());
            t.complete(401);
        }
        let (h, _) = o.check(ip, &p, body("c@x.io").as_bytes());
        assert_eq!(h.unwrap().kind, "credential_stuffing");
        // a known account from that IP is not stuffing; success resets failures
        let (h, t) = o.check(ip, &p, body("a@x.io").as_bytes());
        assert!(h.is_none());
        t.complete(200);
        // an office NAT where people log in successfully is never flagged
        let office: IpAddr = "192.0.2.10".parse().unwrap();
        for u in ["u1@x.io", "u2@x.io", "u3@x.io", "u4@x.io"] {
            let (h, t) = o.check(office, &p, body(u).as_bytes());
            assert!(h.is_none());
            t.complete(200);
        }
    }

    #[test]
    fn invalid_config_rejected() {
        let cfg = |t: &str| {
            crate::config::GatewayConfig::from_toml_str(&format!(
                "upstream = \"http://127.0.0.1:1\"\n{t}"
            ))
            .unwrap()
        };
        let c = cfg("[[operations]]\nname = \"x\"\npath = \"/x\"\naccount = \"body:user\"\n");
        assert!(Operations::compile(&c.operations, &c.logins).is_err());
        let c = cfg("[[operations]]\nname = \"x\"\naccount = \"form:user\"\n");
        assert!(
            Operations::compile(&c.operations, &c.logins).is_err(),
            "needs a path"
        );
        let c = cfg("[[operations]]\nname = \"x\"\npath = \"/x\"\nallowed_ips = [\"nope\"]\n");
        assert!(Operations::compile(&c.operations, &c.logins).is_err());
    }
}
