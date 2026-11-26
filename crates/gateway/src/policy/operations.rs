//! Business-operation protection: what rate limits per IP can't see.
//!
//! * **Operations** (`[[operations]]`): a route that moves money or data (checkout,
//!   transfer, payment callback) gets a budget **per account** (header, cookie, query,
//!   form or JSON field), an optional list of **allowed sources**, and **replay
//!   protection**: a unique value such as a transaction id is accepted once. It is held
//!   while its request is in flight (so concurrent duplicates, the race-condition
//!   double spend, are refused) and kept as used only if the application answered 2xx
//!   (so a provider retrying after a failure still gets through).
//! * **Logins** (`[[logins]]`, `logins.rs`): failed logins are counted **per account
//!   across all IPs** (distributed brute force) and **per IP across accounts**
//!   (credential stuffing).
//!
//! [`Operations`] are the definitions of both (compiled); [`OperationCaches`] hold the
//! budgets, unique values and login counters (learned). Cache entries are keyed by
//! their definition's identity (see `policy::definition_ids`), so they follow a
//! definition by name.
//!
//! Identifiers are hashed (SHA-256, 64 bits kept); tokens and user names are never
//! stored or logged. How they are read from a request is in `fields.rs`.

use std::net::IpAddr;
use std::num::NonZeroUsize;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use hyper::http::request::Parts;
use lru::LruCache;

use super::fields::{Body, Field, Route, hash};
use super::logins::{Login, LoginCaches};
use crate::config::{LoginConfig, OperationAction, OperationConfig};
use crate::ipnet::{Cidr, any_contains};

const MAX_ENTRIES: usize = 200_000;

struct Op {
    /// Which cache entries are this operation's (stable across reloads).
    id: u64,
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
    caches: &'a OperationCaches,
    /// Budget tokens reserved at check time: (operation, bucket key).
    tokens: Vec<(usize, u64)>,
    /// Unique values held in flight: (operation, value hash).
    unique: Vec<(usize, u64)>,
    /// Login attempts: (login, account hash, IP).
    logins: Vec<(usize, u64, IpAddr)>,
    done: bool,
}

impl Ticket<'_> {
    /// Records the outcome: budget tokens are given back after a 401 / 403 answer (the
    /// requester was not that account), unique values are kept as used after a 2xx
    /// answer (else released), login failures and successes update the counters.
    pub fn complete(mut self, status: u16) {
        self.done = true;
        if matches!(status, 401 | 403) {
            self.refund();
        }
        let now = Instant::now();
        let ok = (200..300).contains(&status);
        if !self.unique.is_empty() {
            let mut seen = lock(&self.caches.unique);
            for &(i, key) in &self.unique {
                let op = &self.ops.ops[i];
                if ok {
                    seen.put((op.id, key), Seen::Used(now + op.unique_ttl));
                } else {
                    seen.pop(&(op.id, key));
                }
            }
        }
        for &(i, acct, ip) in &self.logins {
            self.ops.logins[i].settle(&self.caches.logins, acct, ip, status, now);
        }
    }

    /// Gives the reserved budget tokens back (at most up to each bucket's capacity).
    fn refund(&mut self) {
        if self.tokens.is_empty() {
            return;
        }
        let mut buckets = lock(&self.caches.buckets);
        for (i, key) in self.tokens.drain(..) {
            let op = &self.ops.ops[i];
            if let (Some((capacity, _)), Some(b)) = (op.limit, buckets.peek_mut(&(op.id, key))) {
                b.tokens = (b.tokens + 1.0).min(capacity);
            }
        }
    }
}

impl Drop for Ticket<'_> {
    fn drop(&mut self) {
        if self.done {
            return;
        }
        // not forwarded (blocked, challenged, error): the request spent nothing, and
        // its in-flight values are released
        self.refund();
        if !self.unique.is_empty() {
            let mut seen = lock(&self.caches.unique);
            for &(i, key) in &self.unique {
                let k = (self.ops.ops[i].id, key);
                if matches!(seen.peek(&k), Some(Seen::InFlight)) {
                    seen.pop(&k);
                }
            }
        }
    }
}

pub(super) fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

pub(super) fn cache<K: std::hash::Hash + Eq, V>() -> Mutex<LruCache<K, V>> {
    Mutex::new(LruCache::new(
        NonZeroUsize::new(MAX_ENTRIES).expect("non-zero"),
    ))
}

/// The configured `[[operations]]` and `[[logins]]` (compiled; rebuilt on reload).
pub struct Operations {
    ops: Vec<Op>,
    logins: Vec<Login>,
}

/// Budgets, unique values and login counters (learned; kept across reloads).
pub struct OperationCaches {
    /// (operation id, account hash) → budget.
    buckets: Mutex<LruCache<(u64, u64), Bucket>>,
    /// (operation id, value hash) → in flight or used.
    unique: Mutex<LruCache<(u64, u64), Seen>>,
    logins: LoginCaches,
}

impl OperationCaches {
    /// Drops the budgets, unique values and login counters of the operations and logins
    /// in `old` that `new` no longer defines (by name). Returns how many entries.
    pub fn forget_removed(&self, old: &Operations, new: &Operations) -> usize {
        let ops = |o: &Operations| o.ops.iter().map(|op| op.id).collect::<Vec<_>>();
        let logins = |o: &Operations| o.logins.iter().map(|l| l.id).collect::<Vec<_>>();
        let gone = super::removed_ids(&ops(old), &ops(new));
        super::forget(&self.buckets, &gone, |(id, _)| *id)
            + super::forget(&self.unique, &gone, |(id, _)| *id)
            + self
                .logins
                .forget(&super::removed_ids(&logins(old), &logins(new)))
    }
}

impl Default for OperationCaches {
    fn default() -> Self {
        Self {
            buckets: cache(),
            unique: cache(),
            logins: LoginCaches::default(),
        }
    }
}

impl Operations {
    pub fn compile(ops: &[OperationConfig], logins: &[LoginConfig]) -> Result<Self, String> {
        let ids = super::definition_ids(ops.iter().map(|c| c.name.as_str()));
        let mut out = Vec::with_capacity(ops.len());
        for (c, id) in ops.iter().zip(ids) {
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
                id,
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
        let ids = super::definition_ids(logins.iter().map(|c| c.name.as_str()));
        let mut lg = Vec::with_capacity(logins.len());
        for (c, id) in logins.iter().zip(ids) {
            lg.push(Login::compile(c, id)?);
        }
        Ok(Self {
            ops: out,
            logins: lg,
        })
    }

    pub fn is_empty(&self) -> bool {
        self.ops.is_empty() && self.logins.is_empty()
    }

    /// Checks a request. The returned ticket must be completed with the upstream
    /// status once the request has been forwarded.
    pub fn check<'a>(
        &'a self,
        caches: &'a OperationCaches,
        ip: IpAddr,
        parts: &Parts,
        body: &[u8],
    ) -> (Option<OpHit>, Ticket<'a>) {
        self.check_at(caches, ip, parts, body, Instant::now())
    }

    fn check_at<'a>(
        &'a self,
        caches: &'a OperationCaches,
        ip: IpAddr,
        parts: &Parts,
        body: &[u8],
        now: Instant,
    ) -> (Option<OpHit>, Ticket<'a>) {
        let mut ticket = Ticket {
            ops: self,
            caches,
            tokens: Vec::new(),
            unique: Vec::new(),
            logins: Vec::new(),
            done: false,
        };
        if self.is_empty() {
            return (None, ticket);
        }
        let ops: Vec<(usize, &Op)> = (self.ops.iter().enumerate())
            .filter(|(_, op)| op.route.matches(parts))
            .collect();
        let logins: Vec<(usize, &Login)> = (self.logins.iter().enumerate())
            .filter(|(_, l)| l.route.matches(parts))
            .collect();
        // one lazy reading of the body, shared by every matching entry
        let mut wanted: Vec<&[String]> = Vec::new();
        let fields = ops
            .iter()
            .flat_map(|(_, op)| [op.account.as_ref(), op.unique.as_ref()])
            .flatten()
            .chain(logins.iter().map(|(_, l)| &l.account));
        for path in fields.filter_map(Field::body_path) {
            if !wanted.contains(&path) {
                wanted.push(path);
            }
        }
        let body = Body::new(body, parts, wanted);
        let mut worst: Option<OpHit> = None;
        let mut consider = |hit: OpHit| {
            if worst
                .as_ref()
                .is_none_or(|w| severity(hit.action) > severity(w.action))
            {
                worst = Some(hit);
            }
        };
        for (i, op) in ops {
            let account = op.account.as_ref().and_then(|f| f.extract(parts, &body));
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
                let mut buckets = lock(&caches.buckets);
                let b = buckets.get_or_insert_mut((op.id, key), || Bucket {
                    tokens: capacity,
                    at: now,
                });
                let elapsed = now.saturating_duration_since(b.at).as_secs_f64();
                b.tokens = (b.tokens + elapsed * refill).min(capacity);
                b.at = now;
                if b.tokens >= 1.0 {
                    // reserved now, so a concurrent burst is limited; the ticket gives
                    // it back if the request is not forwarded or not that account's
                    b.tokens -= 1.0;
                    ticket.tokens.push((i, key));
                } else {
                    let wait = ((1.0 - b.tokens) / refill).ceil().max(1.0) as u64;
                    consider(hit("account_limit", 429, Some(wait)));
                }
            }
            if let Some(v) = op.unique.as_ref().and_then(|f| f.extract(parts, &body)) {
                let key = hash(&format!("{}/unique", op.name), &v);
                let mut seen = lock(&caches.unique);
                match seen.get(&(op.id, key)).copied() {
                    Some(Seen::InFlight) => consider(hit("replay", 409, None)),
                    Some(Seen::Used(until)) if until > now => consider(hit("replay", 409, None)),
                    _ => {
                        seen.put((op.id, key), Seen::InFlight);
                        ticket.unique.push((i, key));
                    }
                }
            }
        }
        for (i, l) in logins {
            let Some(account) = l.account.extract(parts, &body) else {
                continue;
            };
            let acct = l.check(&caches.logins, ip, &account, now, &mut consider);
            ticket.logins.push((i, acct, ip));
        }
        (worst, ticket)
    }
}

#[cfg(test)]
pub(super) mod testing {
    use super::*;
    use hyper::Request;

    /// Definitions and caches together, as the gateway holds them.
    pub(in crate::policy) struct Ops {
        pub(in crate::policy) defs: Operations,
        pub(in crate::policy) caches: OperationCaches,
    }

    impl Ops {
        pub(in crate::policy) fn check(
            &self,
            ip: IpAddr,
            parts: &Parts,
            body: &[u8],
        ) -> (Option<OpHit>, Ticket<'_>) {
            self.defs.check(&self.caches, ip, parts, body)
        }

        pub(in crate::policy) fn check_at(
            &self,
            ip: IpAddr,
            parts: &Parts,
            body: &[u8],
            now: Instant,
        ) -> (Option<OpHit>, Ticket<'_>) {
            self.defs.check_at(&self.caches, ip, parts, body, now)
        }
    }

    pub(in crate::policy) fn ops(toml: &str) -> Ops {
        let cfg = crate::config::GatewayConfig::from_toml_str(&format!(
            "upstream = \"http://127.0.0.1:1\"\n{toml}"
        ))
        .unwrap();
        Ops {
            defs: Operations::compile(&cfg.operations, &cfg.logins).unwrap(),
            caches: OperationCaches::default(),
        }
    }

    pub(in crate::policy) fn req(method: &str, uri: &str, headers: &[(&str, &str)]) -> Parts {
        let mut b = Request::builder().method(method).uri(uri);
        for (k, v) in headers {
            b = b.header(*k, *v);
        }
        b.body(()).unwrap().into_parts().0
    }

    pub(in crate::policy) const IP: &str = "198.51.100.7";
}

#[cfg(test)]
mod tests {
    use super::testing::*;
    use super::*;

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
    fn requests_never_forwarded_or_refused_by_the_app_do_not_spend_the_budget() {
        let o = ops(r#"
[[operations]]
name = "checkout"
path = "/checkout"
account = "query:account"
limit = { requests = 2, per_secs = 3600 }
"#);
        let p = req("POST", "/checkout?account=victim", &[]);
        let t0 = Instant::now();
        // someone who knows the identifier: blocked by another layer (the ticket is
        // dropped) or answered 401 / 403 by the application (not that account)
        for k in 0..12 {
            let ip: IpAddr = format!("203.0.113.{k}").parse().unwrap();
            let (h, t) = o.check_at(ip, &p, b"", t0);
            assert!(h.is_none(), "attempt {k}");
            match k % 3 {
                0 => drop(t),
                1 => t.complete(401),
                _ => t.complete(403),
            }
        }
        // the owner still has the whole budget; what the app accepted is spent
        let owner: IpAddr = "198.51.100.5".parse().unwrap();
        for status in [200, 500] {
            let (h, t) = o.check_at(owner, &p, b"", t0);
            assert!(h.is_none());
            t.complete(status);
        }
        let (h, _) = o.check_at(owner, &p, b"", t0);
        assert_eq!(h.unwrap().kind, "account_limit");
    }

    #[test]
    fn budget_is_reserved_while_requests_are_in_flight() {
        let o = ops(r#"
[[operations]]
name = "checkout"
path = "/checkout"
account = "header:authorization"
limit = { requests = 2, per_secs = 3600 }
"#);
        let p = req("POST", "/checkout", &[("authorization", "Bearer alice")]);
        let ip: IpAddr = IP.parse().unwrap();
        let t0 = Instant::now();
        // a concurrent burst: two in flight, the third is refused
        let (h1, t1) = o.check_at(ip, &p, b"", t0);
        let (h2, t2) = o.check_at(ip, &p, b"", t0);
        let (h3, t3) = o.check_at(ip, &p, b"", t0);
        assert!(h1.is_none() && h2.is_none());
        assert_eq!(h3.unwrap().kind, "account_limit");
        drop(t3); // took no token, gives none back
        assert!(o.check_at(ip, &p, b"", t0).0.is_some());
        // one is refused by the application: its token comes back, once
        t1.complete(403);
        let (h, t4) = o.check_at(ip, &p, b"", t0);
        assert!(h.is_none());
        t2.complete(200);
        t4.complete(200);
        assert!(o.check_at(ip, &p, b"", t0).0.is_some());
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
        let (h, t) = o.check(ip, &form, b"item=1&user=ann%40example.com");
        assert!(h.is_none());
        t.complete(200);
        assert_eq!(
            o.check(ip, &form, b"user=ann%40example.com&item=2")
                .0
                .unwrap()
                .kind,
            "account_limit"
        );
    }

    /// The fields of operations and logins come from one reading of the body.
    #[test]
    fn several_fields_from_one_reading() {
        let o = ops(r#"
[[operations]]
name = "transfer"
path = "/transfer"
account = "json:from"
unique = "json:id"
limit = { requests = 1, per_secs = 3600 }
[[logins]]
name = "step-up"
path = "/transfer"
account = "form:from"
"#);
        let p = req("POST", "/transfer", &[("content-type", "text/plain")]);
        let (h, t) = o.check(IP.parse().unwrap(), &p, br#"{"from":"ann","id":"T1"}"#);
        assert!(h.is_none());
        assert_eq!((t.unique.len(), t.logins.len()), (1, 1));
        let (h, _) = o.check(IP.parse().unwrap(), &p, br#"{"from":"ann","id":"T2"}"#);
        assert_eq!(h.unwrap().kind, "account_limit");
    }

    #[test]
    fn caches_follow_definitions_by_name() {
        let checkout = "[[operations]]\nname = \"checkout\"\npath = \"/checkout\"\n\
                        account = \"header:authorization\"\nlimit = { requests = 1, per_secs = 3600 }\n";
        let refund = checkout.replace("checkout", "refund");
        let login = "[[logins]]\nname = \"login\"\npath = \"/signin\"\naccount = \"form:user\"\n\
                     max_failures = 1\nmax_accounts_per_ip = 0\n";
        let mut o = ops(&format!("{checkout}{refund}{login}"));
        let ip: IpAddr = IP.parse().unwrap();
        let alice = [("authorization", "Bearer alice")];
        let form = [("content-type", "application/x-www-form-urlencoded")];
        for path in ["/checkout", "/refund"] {
            let (h, t) = o.check(ip, &req("POST", path, &alice), b"");
            assert!(h.is_none());
            t.complete(200);
        }
        let (_, t) = o.check(ip, &req("POST", "/signin", &form), b"user=ann");
        t.complete(401);
        // reload: "refund" removed, a new operation in front, the login unchanged
        let old = std::mem::replace(
            &mut o.defs,
            ops(&format!(
                "{}{checkout}{login}",
                checkout.replace("checkout", "order")
            ))
            .defs,
        );
        assert_eq!(o.caches.forget_removed(&old, &o.defs), 1);
        let spent = |o: &Ops, path: &str| o.check(ip, &req("POST", path, &alice), b"").0;
        assert_eq!(spent(&o, "/checkout").unwrap().kind, "account_limit");
        assert!(spent(&o, "/order").is_none());
        let locked = o.check(ip, &req("POST", "/signin", &form), b"user=ann").0;
        assert_eq!(locked.unwrap().kind, "account_locked");
        // "order" and the login removed: the budget, the failures, the accounts per IP
        let old = std::mem::replace(&mut o.defs, ops(checkout).defs);
        assert_eq!(o.caches.forget_removed(&old, &o.defs), 3);
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
