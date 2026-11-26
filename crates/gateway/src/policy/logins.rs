//! Login protection (`[[logins]]`): failed logins are counted **per account across all
//! IPs** (distributed brute force) and **per IP across accounts** (credential
//! stuffing). Only failures count, so an office behind one NAT logging in normally
//! is not punished.
//!
//! Logins are checked together with `[[operations]]`, with one reading of the body and
//! one ticket settled with the upstream status (see `operations.rs`). A [`Login`] is a
//! definition (compiled); [`LoginCaches`] holds the counters (learned).

use std::net::IpAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use lru::LruCache;

use super::fields::{Field, Route, hash};
use super::operations::{OpHit, cache, lock};
use crate::config::{LoginConfig, OperationAction};

/// Distinct failed accounts remembered per IP.
const MAX_ACCOUNTS_TRACKED: usize = 256;

pub(super) struct Login {
    /// Which counters are this login's (stable across reloads).
    pub(super) id: u64,
    name: String,
    pub(super) route: Route,
    pub(super) account: Field,
    failure_statuses: Vec<u16>,
    max_failures: u32,
    max_accounts_per_ip: u32,
    window: Duration,
    action: OperationAction,
}

#[derive(Clone, Copy)]
struct Failures {
    count: u32,
    since: Instant,
}

/// Failed accounts (hash, last failure) per (login id, IP).
type IpAccounts = LruCache<(u64, IpAddr), Vec<(u64, Instant)>>;

/// The counters of every login (learned).
pub(super) struct LoginCaches {
    /// (login id, account hash) → failures within the window.
    failures: Mutex<LruCache<(u64, u64), Failures>>,
    ip_accounts: Mutex<IpAccounts>,
}

impl Default for LoginCaches {
    fn default() -> Self {
        Self {
            failures: cache(),
            ip_accounts: cache(),
        }
    }
}

impl Login {
    pub(super) fn compile(c: &LoginConfig, id: u64) -> Result<Self, String> {
        let what = format!("login {:?}", c.name);
        Ok(Login {
            id,
            route: Route::new(&what, &c.path, &c.path_regex, &c.methods)?,
            name: c.name.clone(),
            account: Field::parse(&c.account).map_err(|e| format!("{what}: {e}"))?,
            failure_statuses: c.failure_statuses.clone(),
            max_failures: c.max_failures,
            max_accounts_per_ip: c.max_accounts_per_ip,
            window: Duration::from_secs(c.window_secs.max(1)),
            action: c.action,
        })
    }

    /// Checks an attempt on `account` from `ip`, passing failed checks to `consider`.
    /// Returns the account hash to settle the attempt with.
    pub(super) fn check(
        &self,
        caches: &LoginCaches,
        ip: IpAddr,
        account: &str,
        now: Instant,
        consider: &mut impl FnMut(OpHit),
    ) -> u64 {
        let acct = hash(&self.name, &account.to_lowercase());
        let hit = |kind, retry_after: u64| OpHit {
            name: self.name.clone(),
            kind,
            action: self.action,
            status: 429,
            retry_after: Some(retry_after.max(1)),
            account: Some(format!("{:08x}", acct >> 32)),
        };
        if self.max_failures > 0 {
            if let Some(f) = lock(&caches.failures).peek(&(self.id, acct)) {
                let age = now.saturating_duration_since(f.since);
                if age <= self.window && f.count >= self.max_failures {
                    consider(hit("account_locked", (self.window - age).as_secs()));
                }
            }
        }
        if self.max_accounts_per_ip > 0 {
            if let Some(list) = lock(&caches.ip_accounts).peek(&(self.id, ip)) {
                let recent: Vec<&(u64, Instant)> = list
                    .iter()
                    .filter(|(_, t)| now.saturating_duration_since(*t) <= self.window)
                    .collect();
                let known = recent.iter().any(|(a, _)| *a == acct);
                if !known && recent.len() as u32 >= self.max_accounts_per_ip {
                    let oldest = recent.iter().map(|(_, t)| *t).min().unwrap_or(now);
                    let left = self
                        .window
                        .saturating_sub(now.saturating_duration_since(oldest));
                    consider(hit("credential_stuffing", left.as_secs()));
                }
            }
        }
        acct
    }

    /// Records the outcome of an attempt: a failure status counts for the account and
    /// the IP, a 2xx resets the account's failures.
    pub(super) fn settle(
        &self,
        caches: &LoginCaches,
        acct: u64,
        ip: IpAddr,
        status: u16,
        now: Instant,
    ) {
        if self.failure_statuses.contains(&status) {
            {
                let mut f = lock(&caches.failures);
                let e = f.get_or_insert_mut((self.id, acct), || Failures {
                    count: 0,
                    since: now,
                });
                if now.saturating_duration_since(e.since) > self.window {
                    *e = Failures {
                        count: 0,
                        since: now,
                    };
                }
                e.count += 1;
            }
            let mut per_ip = lock(&caches.ip_accounts);
            let list = per_ip.get_or_insert_mut((self.id, ip), Vec::new);
            list.retain(|(a, t)| *a != acct && now.saturating_duration_since(*t) <= self.window);
            if list.len() < MAX_ACCOUNTS_TRACKED {
                list.push((acct, now));
            }
        } else if (200..300).contains(&status) {
            lock(&caches.failures).pop(&(self.id, acct));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::operations::testing::*;
    use std::net::IpAddr;

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

    /// Fails twice with `body`, then tells whether the account is locked.
    fn locked_after_two_failures(account: &str, content_type: Option<&str>, body: &[u8]) -> bool {
        let o = ops(&format!(
            "[[logins]]\nname = \"login\"\npath = \"/signin\"\naccount = \"{account}\"\n\
             max_failures = 2\nmax_accounts_per_ip = 0\nwindow_secs = 600\n"
        ));
        let headers: Vec<(&str, &str)> = content_type
            .map(|c| ("content-type", c))
            .into_iter()
            .collect();
        let p = req("POST", "/signin", &headers);
        let ip: IpAddr = IP.parse().unwrap();
        for _ in 0..2 {
            let (h, t) = o.check(ip, &p, body);
            assert!(h.is_none());
            t.complete(401);
        }
        o.check(ip, &p, body)
            .0
            .is_some_and(|h| h.kind == "account_locked")
    }

    fn utf16le(s: &str) -> Vec<u8> {
        s.encode_utf16().flat_map(u16::to_le_bytes).collect()
    }

    #[test]
    fn login_failures_count_whatever_the_content_type() {
        let json = br#"{"email":"victim@x.io","password":"x"}"#;
        for ct in [
            Some("application/json"),
            Some("text/plain"),
            Some("application/octet-stream"),
            Some("application/x-www-form-urlencoded"),
            None,
        ] {
            assert!(locked_after_two_failures("json:email", ct, json), "{ct:?}");
        }
        let wide = utf16le(r#"{"email":"victim@x.io"}"#);
        let ct = Some("application/json; charset=utf-16le");
        assert!(locked_after_two_failures("json:email", ct, &wide), "UTF-16");
        let bom = [&[0xFF, 0xFE][..], &wide].concat();
        assert!(locked_after_two_failures("json:email", None, &bom), "BOM");

        let form = Some("application/x-www-form-urlencoded");
        let body = b"username=alice&password=x";
        assert!(locked_after_two_failures("form:username", form, body));
        let mp =
            b"--b\r\nContent-Disposition: form-data; name=\"username\"\r\n\r\nalice\r\n--b--\r\n";
        let ct = Some("multipart/form-data; boundary=b");
        assert!(
            locked_after_two_failures("form:username", ct, mp),
            "multipart"
        );
        let ct = Some("application/x-www-form-urlencoded; charset=utf-16le");
        let wide = utf16le("username=alice");
        assert!(locked_after_two_failures("form:username", ct, &wide));
        // frameworks that merge JSON and form parameters
        let ct = Some("application/json");
        assert!(locked_after_two_failures(
            "form:username",
            ct,
            br#"{"username":"alice"}"#
        ));
        let body = b"email=victim%40x.io&password=x";
        assert!(locked_after_two_failures("json:email", form, body));
    }
}
