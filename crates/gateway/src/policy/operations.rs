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
//!
//! Body identifiers (`form:` / `json:`) are read the way applications read them, not
//! by the declared content type alone (see `Body`), so switching the Content-Type
//! does not hide an account from the counters.

use std::cell::OnceCell;
use std::fmt;
use std::net::IpAddr;
use std::num::NonZeroUsize;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use hyper::http::request::Parts;
use lru::LruCache;
use pattern_guard::waf::{body_text, form_fields};
use regex::Regex;
use serde::de::{DeserializeSeed, Deserializer, IgnoredAny, MapAccess, SeqAccess, Visitor};
use sha2::{Digest, Sha256};

use crate::config::{LoginConfig, OperationAction, OperationConfig};
use crate::ipnet::{Cidr, any_contains};
use crate::policy::path::PathView;
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

    /// The path of a body field: `[name]` for `form:`, the segments for `json:`.
    fn body_path(&self) -> Option<&[String]> {
        match self {
            Field::Form(f) => Some(std::slice::from_ref(f)),
            Field::Json(path) => Some(path),
            _ => None,
        }
    }

    fn extract(&self, parts: &Parts, body: &Body<'_>) -> Option<String> {
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
            Field::Form(_) | Field::Json(_) => body.get(self.body_path()?)?.to_string(),
        };
        let v = v.trim().to_string();
        (!v.is_empty()).then_some(v)
    }
}

fn form_value(s: &str, name: &str) -> Option<String> {
    s.split('&').find_map(|kv| {
        let (k, v) = kv.split_once('=').unwrap_or((kv, ""));
        (form_decode(k) == name).then(|| form_decode(v))
    })
}

/// A request body as the matching operations and logins read it.
///
/// Applications parse bodies whatever the declared type: many parse JSON from any
/// body, PHP, Django and Rails read multipart forms into the same parameters as
/// URL-encoded ones, and Laravel, Rails and Express merge JSON and form fields. So:
///
/// * the text comes from [`body_text`] (byte-order mark, charset, UTF-16 / UTF-32);
/// * `multipart/*` is read as form fields ([`form_fields`]);
/// * `application/x-www-form-urlencoded` is read as form fields first, then as JSON
///   if it looks like JSON;
/// * anything else is read as JSON first when the content type says JSON or the text
///   starts with `{` / `[`, then as form fields;
/// * `form:name` also matches a top-level JSON field `name`, and a one-segment
///   `json:name` a form field `name`.
///
/// The body is parsed at most once per request (lazily, only if a matching entry has
/// a body field), in one pass for the fields of all matching entries, and never into
/// a tree: JSON values off the wanted paths are skipped, and form pairs are compared
/// as they are read. Memory stays at one decoded copy of the text whatever the body's
/// shape, so the whole body is read and padding cannot push an identifier out of
/// view. Form fields keep their first value and JSON fields their last, like most
/// frameworks.
struct Body<'a> {
    raw: &'a [u8],
    content_type: &'a str,
    multipart: bool,
    urlencoded: bool,
    declared_json: bool,
    /// The distinct body paths of the matching entries.
    wanted: Vec<&'a [String]>,
    text: OnceCell<String>,
    /// Per wanted path; `None` when the body isn't read as JSON.
    json: OnceCell<Option<Vec<Option<String>>>>,
    /// Per wanted path.
    form: OnceCell<Vec<Option<String>>>,
}

impl<'a> Body<'a> {
    fn new(raw: &'a [u8], parts: &'a Parts, wanted: Vec<&'a [String]>) -> Self {
        let content_type = parts
            .headers
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        let ct = content_type.trim_start().to_ascii_lowercase();
        Self {
            raw,
            content_type,
            multipart: ct.starts_with("multipart/"),
            urlencoded: ct.starts_with("application/x-www-form-urlencoded"),
            declared_json: ct.contains("json"),
            wanted,
            text: OnceCell::new(),
            json: OnceCell::new(),
            form: OnceCell::new(),
        }
    }

    /// The value at a wanted `path`: from the body's main reading, else the other one.
    fn get(&self, path: &[String]) -> Option<&str> {
        let i = self.wanted.iter().position(|w| *w == path)?;
        let json = || self.json().and_then(|v| v[i].as_deref());
        let form = || self.form()[i].as_deref();
        if self.multipart {
            form()
        } else if !self.urlencoded && self.json().is_some() {
            json().or_else(form)
        } else {
            form().or_else(json)
        }
    }

    fn text(&self) -> &str {
        self.text
            .get_or_init(|| body_text(self.raw, self.content_type))
    }

    fn json(&self) -> Option<&Vec<Option<String>>> {
        self.json
            .get_or_init(|| {
                if self.multipart {
                    return None;
                }
                let text = self.text();
                let t = text.trim_start();
                (self.declared_json || t.starts_with('{') || t.starts_with('['))
                    .then(|| json_fields(text, &self.wanted))
            })
            .as_ref()
    }

    fn form(&self) -> &Vec<Option<String>> {
        self.form.get_or_init(|| {
            let mut out = vec![None; self.wanted.len()];
            let names: Vec<(usize, &str)> = self
                .wanted
                .iter()
                .enumerate()
                .filter_map(|(i, p)| match p {
                    [name] => Some((i, name.as_str())),
                    _ => None,
                })
                .collect();
            if names.is_empty() {
                return out;
            }
            if self.multipart {
                for (k, v) in form_fields(self.raw, self.content_type) {
                    for &(i, name) in &names {
                        if out[i].is_none() && k == name {
                            out[i] = Some(v.clone());
                        }
                    }
                }
                return out;
            }
            let mut left = names.len();
            for pair in self.text().split('&').filter(|p| !p.is_empty()) {
                let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
                for &(i, name) in &names {
                    if out[i].is_none() && form_key_is(k, name) {
                        out[i] = Some(form_decode(v));
                        left -= 1;
                    }
                }
                if left == 0 {
                    break;
                }
            }
            out
        })
    }
}

/// Whether a raw form key decodes to `name`. Decodes only keys that could: `%XX`
/// shrinks three bytes to one, so the decoded length lies between a third of the raw
/// length and the raw length.
fn form_key_is(raw: &str, name: &str) -> bool {
    if !raw.contains(['%', '+']) {
        return raw == name;
    }
    raw.len() >= name.len() && raw.len() <= name.len() * 3 && form_decode(raw) == name
}

/// The scalar (string, number or boolean) at each of `paths` in the JSON `text`. One
/// pass: values off the wanted paths are skipped without being built. A syntax error
/// keeps what was found before it.
fn json_fields(text: &str, paths: &[&[String]]) -> Vec<Option<String>> {
    let root = PathNode::build(paths);
    let mut out = vec![None; paths.len()];
    let mut de = serde_json::Deserializer::from_str(text);
    let _ = Seek {
        node: &root,
        out: &mut out,
    }
    .deserialize(&mut de);
    out
}

/// The wanted JSON paths as a tree.
#[derive(Default)]
struct PathNode<'a> {
    /// The path ending here.
    slot: Option<usize>,
    /// Every path ending in this subtree, cleared when a later duplicate key replaces it.
    below: Vec<usize>,
    children: Vec<(&'a str, PathNode<'a>)>,
}

impl<'a> PathNode<'a> {
    fn build(paths: &[&'a [String]]) -> Self {
        let mut root = PathNode::default();
        for (i, path) in paths.iter().enumerate() {
            let mut node = &mut root;
            for seg in path.iter() {
                node.below.push(i);
                let at = match node.children.iter().position(|(k, _)| k == seg) {
                    Some(at) => at,
                    None => {
                        node.children.push((seg.as_str(), PathNode::default()));
                        node.children.len() - 1
                    }
                };
                node = &mut node.children[at].1;
            }
            node.below.push(i);
            node.slot = Some(i);
        }
        root
    }

    fn child(&self, key: &str) -> Option<&PathNode<'a>> {
        self.children
            .iter()
            .find(|(k, _)| *k == key)
            .map(|(_, n)| n)
    }

    fn element(&self, index: usize) -> Option<&PathNode<'a>> {
        self.children
            .iter()
            .find(|(k, _)| k.parse::<usize>() == Ok(index))
            .map(|(_, n)| n)
    }

    fn last_element(&self) -> Option<usize> {
        self.children
            .iter()
            .filter_map(|(k, _)| k.parse::<usize>().ok())
            .max()
    }

    fn clear(&self, out: &mut [Option<String>]) {
        for &i in &self.below {
            out[i] = None;
        }
    }
}

/// Visits one JSON value at `node`, recording the scalars that end a wanted path.
struct Seek<'n, 'a, 'o> {
    node: &'n PathNode<'a>,
    out: &'o mut [Option<String>],
}

impl Seek<'_, '_, '_> {
    fn scalar(self, value: impl FnOnce() -> String) {
        if let Some(i) = self.node.slot {
            self.out[i] = Some(value());
        }
    }
}

impl<'de> DeserializeSeed<'de> for Seek<'_, '_, '_> {
    type Value = ();

    fn deserialize<D: Deserializer<'de>>(self, d: D) -> Result<(), D::Error> {
        d.deserialize_any(self)
    }
}

impl<'de> Visitor<'de> for Seek<'_, '_, '_> {
    type Value = ();

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a JSON value")
    }

    fn visit_bool<E>(self, v: bool) -> Result<(), E> {
        self.scalar(|| v.to_string());
        Ok(())
    }

    fn visit_i64<E>(self, v: i64) -> Result<(), E> {
        self.scalar(|| v.to_string());
        Ok(())
    }

    fn visit_u64<E>(self, v: u64) -> Result<(), E> {
        self.scalar(|| v.to_string());
        Ok(())
    }

    fn visit_f64<E>(self, v: f64) -> Result<(), E> {
        self.scalar(|| {
            serde_json::Number::from_f64(v)
                .map(|n| n.to_string())
                .unwrap_or_default()
        });
        Ok(())
    }

    fn visit_str<E>(self, v: &str) -> Result<(), E> {
        self.scalar(|| v.to_string());
        Ok(())
    }

    fn visit_unit<E>(self) -> Result<(), E> {
        Ok(())
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<(), A::Error> {
        let Seek { node, out } = self;
        while let Some(child) = map.next_key_seed(Key(node))? {
            match child {
                Some(n) => {
                    n.clear(out);
                    map.next_value_seed(Seek {
                        node: n,
                        out: &mut *out,
                    })?;
                }
                None => {
                    map.next_value::<IgnoredAny>()?;
                }
            }
        }
        Ok(())
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<(), A::Error> {
        let Seek { node, out } = self;
        let last = node.last_element();
        let mut index = 0usize;
        loop {
            let child = last
                .filter(|&l| index <= l)
                .and_then(|_| node.element(index));
            let more = match child {
                Some(n) => {
                    n.clear(out);
                    seq.next_element_seed(Seek {
                        node: n,
                        out: &mut *out,
                    })?
                    .is_some()
                }
                None => seq.next_element::<IgnoredAny>()?.is_some(),
            };
            if !more {
                return Ok(());
            }
            index += 1;
        }
    }
}

/// An object key: the matching child of the node, without copying the key.
struct Key<'n, 'a>(&'n PathNode<'a>);

impl<'de, 'n, 'a> DeserializeSeed<'de> for Key<'n, 'a> {
    type Value = Option<&'n PathNode<'a>>;

    fn deserialize<D: Deserializer<'de>>(self, d: D) -> Result<Self::Value, D::Error> {
        d.deserialize_str(self)
    }
}

impl<'de, 'n, 'a> Visitor<'de> for Key<'n, 'a> {
    type Value = Option<&'n PathNode<'a>>;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("an object key")
    }

    fn visit_str<E>(self, k: &str) -> Result<Self::Value, E> {
        Ok(self.0.child(k))
    }
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
        let path = PathView::new(parts.uri.path());
        self.prefix
            .as_deref()
            .is_none_or(|p| path.protects_prefix(p))
            && self.re.as_ref().is_none_or(|re| path.protects_regex(re))
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
    /// Budget tokens reserved at check time: (operation, bucket key).
    tokens: Vec<(usize, u64)>,
    unique: Vec<(usize, u64)>,
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

    /// Gives the reserved budget tokens back (at most up to each bucket's capacity).
    fn refund(&mut self) {
        if self.tokens.is_empty() {
            return;
        }
        let mut buckets = lock(&self.ops.buckets);
        for (i, key) in self.tokens.drain(..) {
            if let (Some((capacity, _)), Some(b)) =
                (self.ops.ops[i].limit, buckets.peek_mut(&(i, key)))
            {
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
                let mut buckets = lock(&self.buckets);
                let b = buckets.get_or_insert_mut((i, key), || Bucket {
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
        for (i, l) in logins {
            let Some(account) = l.account.extract(parts, &body) else {
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

    /// The identifier `spec` read from a body.
    fn read(spec: &str, content_type: Option<&str>, body: &[u8]) -> Option<String> {
        let headers: Vec<(&str, &str)> = content_type
            .map(|c| ("content-type", c))
            .into_iter()
            .collect();
        let p = req("POST", "/", &headers);
        let field = Field::parse(spec).unwrap();
        let b = Body::new(body, &p, vec![field.body_path().unwrap()]);
        field.extract(&p, &b)
    }

    #[test]
    fn json_fields_are_read_in_one_pass_like_a_json_parser() {
        let json = Some("application/json");
        let r = |spec, body: &str| read(spec, json, body.as_bytes());
        assert_eq!(
            r("json:user.email", r#"{"user":{"email":"a@x.io"}}"#).as_deref(),
            Some("a@x.io")
        );
        let items = r#"{"items":[{"id":1},{"id":"two"}]}"#;
        assert_eq!(r("json:items.1.id", items).as_deref(), Some("two"));
        assert_eq!(r("json:items.2.id", items), None);
        let scalars = r#"{"n": 12.5, "b": true, "i": -3, "z": null}"#;
        assert_eq!(r("json:n", scalars).as_deref(), Some("12.5"));
        assert_eq!(r("json:b", scalars).as_deref(), Some("true"));
        assert_eq!(r("json:i", scalars).as_deref(), Some("-3"));
        assert_eq!(r("json:z", scalars), None);
        assert_eq!(
            r("json:email", r#"{"email":{"x":"y"}}"#),
            None,
            "not a scalar"
        );
        // the last duplicate wins, as in JSON parsers
        assert_eq!(
            r("json:email", r#"{"email":"a","email":"b"}"#).as_deref(),
            Some("b")
        );
        assert_eq!(r("json:email", r#"{"email":"a","email":[1]}"#), None);
        let dup = r#"{"user":{"email":"a"},"user":{"name":"n"}}"#;
        assert_eq!(r("json:user.email", dup), None);
        // what precedes a syntax error (NaN, comments: lenient parsers accept them) counts
        assert_eq!(
            r("json:email", r#"{"email":"a", "x": NaN}"#).as_deref(),
            Some("a")
        );
        // deep nesting in another field is skipped, not refused
        let deep = format!(
            r#"{{"x":{}{},"email":"a"}}"#,
            "[".repeat(500),
            "]".repeat(500)
        );
        assert_eq!(r("json:email", &deep).as_deref(), Some("a"));
        // padding cannot push the identifier out of view
        let padded = format!(r#"{{"pad":"{}","email":"victim"}}"#, "x".repeat(200_000));
        assert_eq!(r("json:email", &padded).as_deref(), Some("victim"));
        let form = Some("application/x-www-form-urlencoded");
        let padded = format!("pad={}&username=victim", "x".repeat(200_000));
        assert_eq!(
            read("form:username", form, padded.as_bytes()).as_deref(),
            Some("victim")
        );
    }

    #[test]
    fn the_body_is_read_the_way_the_application_reads_it() {
        let form = Some("application/x-www-form-urlencoded");
        // a body that is valid JSON and also a form with a clean `email` field: a
        // URL-encoded body is a form to PHP and every framework, so the form decides
        let both = br#"{"a":"&email=target&","email":"decoy"}"#;
        assert_eq!(read("form:email", form, both).as_deref(), Some("target"));
        assert_eq!(read("json:email", form, both).as_deref(), Some("target"));
        // any other type is read as JSON first
        assert_eq!(
            read("form:email", Some("text/plain"), both).as_deref(),
            Some("decoy")
        );
        assert_eq!(read("json:email", None, both).as_deref(), Some("decoy"));
        // forms keep the first value; keys are decoded once
        assert_eq!(
            read("form:email", form, b"email=a&email=b").as_deref(),
            Some("a")
        );
        assert_eq!(
            read("form:email", form, b"%65mail=a%40x").as_deref(),
            Some("a@x")
        );
        assert_eq!(read("form:e mail", form, b"e+mail=a").as_deref(), Some("a"));
        assert_eq!(
            read("form:email", form, b"%2565mail=a"),
            None,
            "decoded once"
        );
        // multipart: text fields only, never file parts
        let mp = b"--b\r\nContent-Disposition: form-data; name=\"email\"; filename=\"e.txt\"\r\n\r\nfile\r\n--b--\r\n";
        assert_eq!(
            read("form:email", Some("multipart/form-data; boundary=b"), mp),
            None
        );
        // several fields from one reading
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
