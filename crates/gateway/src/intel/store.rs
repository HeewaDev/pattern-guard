//! Shared threat intelligence: IPs and ranges flagged by CrowdSec, Suricata, Wazuh, the
//! gateway's own bans, or config.
//!
//! **Bounded.** Every source (`crowdsec:CAPI`, `suricata`, `gateway:ban`, …) has a cap.
//! When a source goes over it, its entry closest to expiry is dropped (entries that never
//! expire go last): that entry would have lapsed soonest anyway. A source can only evict
//! its own entries, so a flood of gateway bans never pushes out CrowdSec decisions.
//!
//! **IPv6 aggregation.** `add_aggregated` (used for gateway bans) replaces a source's
//! single-address entries with one `/64` entry once `AGGREGATE_V6` of them fall in the
//! same `/64`. A host that rotates through its `/64` then costs one entry, and the ban
//! covers the addresses it hasn't used yet.
//!
//! Each source keeps an expiry-ordered index, so eviction and `sweep()` touch only the
//! entries they remove, and `len()` is a counter.

use std::collections::{BTreeMap, HashMap};
use std::net::{IpAddr, Ipv6Addr};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering::Relaxed};
use std::sync::{Arc, RwLock, RwLockWriteGuard};
use std::time::Instant;

use crate::ipnet::{Cidr, normalize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum IntelAction {
    Challenge,
    Ban,
}

#[derive(Debug, Clone)]
pub struct IntelEntry {
    pub action: IntelAction,
    /// e.g. `crowdsec:CAPI`, `crowdsec:cscli`, `suricata`, `wazuh`.
    pub source: String,
    /// Why (scenario / signature / rule description).
    pub reason: String,
    pub expires: Option<Instant>,
}

/// Single-address entries of one source in one IPv6 `/64` after which `add_aggregated`
/// merges them into a `/64` entry. High enough that a few hosts behind one LAN prefix
/// don't ban their neighbours, low enough that address rotation stops paying.
pub const AGGREGATE_V6: usize = 16;

/// Default cap per source (see `limits.max_intel_entries_per_source`).
pub const DEFAULT_MAX_PER_SOURCE: usize = 500_000;

/// Most expired entries removed per write-lock acquisition in `sweep()`.
const SWEEP_BATCH: usize = 4096;

/// Expiry order: `At` sorts before `Never`, earlier instants first.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Deadline {
    At(Instant),
    Never,
}

impl Deadline {
    fn of(e: &IntelEntry) -> Self {
        e.expires.map_or(Deadline::Never, Deadline::At)
    }
}

/// Where an entry lives.
#[derive(Debug, Clone, Copy)]
enum Key {
    Ip(IpAddr),
    /// The upper 64 bits of an IPv6 `/64`.
    Net64(u64),
    Range(Cidr),
}

struct Stored {
    entry: IntelEntry,
    /// Insertion sequence: makes the index key unique.
    seq: u64,
}

#[derive(Default)]
struct Inner {
    /// Single addresses. Ordered, so the addresses of one `/64` can be enumerated.
    ips: BTreeMap<IpAddr, Vec<Stored>>,
    nets64: HashMap<u64, Vec<Stored>>,
    /// Other ranges (scanned linearly on lookup).
    ranges: Vec<(Cidr, Stored)>,
    /// Per source: (deadline, seq) → key, soonest-expiring first.
    sources: HashMap<String, BTreeMap<(Deadline, u64), Key>>,
    seq: u64,
    len: usize,
}

fn prefix64(a: Ipv6Addr) -> u64 {
    (u128::from(a) >> 64) as u64
}

fn net64_addr(p: u64) -> Ipv6Addr {
    Ipv6Addr::from(u128::from(p) << 64)
}

fn key_of(cidr: Cidr) -> Key {
    if cidr.is_single() {
        return Key::Ip(normalize(cidr.addr()));
    }
    if let IpAddr::V6(a) = cidr.addr() {
        if Cidr::parse(&format!("{a}/64")) == Some(cidr) {
            return Key::Net64(prefix64(a));
        }
    }
    Key::Range(cidr)
}

fn key_string(key: Key) -> String {
    match key {
        Key::Ip(ip) => ip.to_string(),
        Key::Net64(p) => format!("{}/64", net64_addr(p)),
        Key::Range(c) => c.to_string(),
    }
}

/// The later of two expiries; `None` (never) wins.
fn later(a: Option<Instant>, b: Option<Instant>) -> Option<Instant> {
    Some(a?.max(b?))
}

fn take(list: &mut Vec<Stored>, source: &str) -> Option<Stored> {
    let i = list.iter().position(|s| s.entry.source == source)?;
    Some(list.swap_remove(i))
}

impl Inner {
    fn entries_at(&self, key: Key) -> Box<dyn Iterator<Item = &Stored> + '_> {
        match key {
            Key::Ip(ip) => Box::new(self.ips.get(&ip).into_iter().flatten()),
            Key::Net64(p) => Box::new(self.nets64.get(&p).into_iter().flatten()),
            Key::Range(c) => Box::new(
                self.ranges
                    .iter()
                    .filter(move |(rc, _)| *rc == c)
                    .map(|(_, s)| s),
            ),
        }
    }

    /// Adds `entry` at `key`, replacing the same source's entry there.
    fn insert(&mut self, key: Key, entry: IntelEntry) {
        self.remove(key, &entry.source);
        self.seq += 1;
        let seq = self.seq;
        let index_key = (Deadline::of(&entry), seq);
        match self.sources.get_mut(&entry.source) {
            Some(ix) => {
                ix.insert(index_key, key);
            }
            None => {
                self.sources
                    .insert(entry.source.clone(), BTreeMap::from([(index_key, key)]));
            }
        }
        let stored = Stored { entry, seq };
        // Most addresses are listed by one source: don't let `push` reserve room for four.
        let one = || Vec::with_capacity(1);
        match key {
            Key::Ip(ip) => self.ips.entry(ip).or_insert_with(one).push(stored),
            Key::Net64(p) => self.nets64.entry(p).or_insert_with(one).push(stored),
            Key::Range(c) => self.ranges.push((c, stored)),
        }
        self.len += 1;
    }

    /// Removes `source`'s entry at `key`.
    fn remove(&mut self, key: Key, source: &str) -> Option<IntelEntry> {
        let stored = match key {
            Key::Ip(ip) => {
                let list = self.ips.get_mut(&ip)?;
                let s = take(list, source)?;
                if list.is_empty() {
                    self.ips.remove(&ip);
                }
                s
            }
            Key::Net64(p) => {
                let list = self.nets64.get_mut(&p)?;
                let s = take(list, source)?;
                if list.is_empty() {
                    self.nets64.remove(&p);
                }
                s
            }
            Key::Range(c) => {
                let i = self
                    .ranges
                    .iter()
                    .position(|(rc, s)| *rc == c && s.entry.source == source)?;
                self.ranges.swap_remove(i).1
            }
        };
        if let Some(ix) = self.sources.get_mut(source) {
            ix.remove(&(Deadline::of(&stored.entry), stored.seq));
            if ix.is_empty() {
                self.sources.remove(source);
            }
        }
        self.len -= 1;
        Some(stored.entry)
    }

    /// Drops `source`'s soonest-expiring entries until it has at most `cap`.
    fn evict(&mut self, source: &str, cap: usize) -> u64 {
        let mut n = 0;
        while let Some(ix) = self.sources.get(source) {
            if ix.len() <= cap {
                break;
            }
            let Some((_, &key)) = ix.first_key_value() else {
                break;
            };
            self.remove(key, source);
            n += 1;
        }
        n
    }

    /// Sources whose name starts with `prefix`.
    fn matching(&self, prefix: &str) -> Vec<String> {
        self.sources
            .keys()
            .filter(|s| s.starts_with(prefix))
            .cloned()
            .collect()
    }
}

pub struct IntelStore {
    inner: RwLock<Inner>,
    /// Entries in the store (kept equal to `Inner::len`), read without the lock.
    len: AtomicUsize,
    evicted: Arc<AtomicU64>,
    max_per_source: usize,
    caps: HashMap<String, usize>,
}

impl Default for IntelStore {
    fn default() -> Self {
        Self::new(DEFAULT_MAX_PER_SOURCE)
    }
}

impl IntelStore {
    /// A store that keeps at most `max_per_source` entries for every source.
    pub fn new(max_per_source: usize) -> Self {
        Self {
            inner: RwLock::default(),
            len: AtomicUsize::new(0),
            evicted: Arc::default(),
            max_per_source: max_per_source.max(1),
            caps: HashMap::new(),
        }
    }

    /// A different cap for one source (e.g. the gateway's own bans).
    pub fn with_source_cap(mut self, source: &str, cap: usize) -> Self {
        self.caps.insert(source.to_string(), cap.max(1));
        self
    }

    /// Counts evicted entries in `counter` (a metric).
    pub fn with_eviction_counter(mut self, counter: Arc<AtomicU64>) -> Self {
        self.evicted = counter;
        self
    }

    fn cap(&self, source: &str) -> usize {
        self.caps
            .get(source)
            .copied()
            .unwrap_or(self.max_per_source)
    }

    fn write(&self) -> RwLockWriteGuard<'_, Inner> {
        self.inner.write().unwrap_or_else(|e| e.into_inner())
    }

    /// Ends a write: enforces the cap of `source` and publishes the length.
    fn settle(&self, g: &mut Inner, source: Option<&str>) {
        if let Some(source) = source {
            let n = g.evict(source, self.cap(source));
            if n > 0 {
                self.evicted.fetch_add(n, Relaxed);
            }
        }
        self.len.store(g.len, Relaxed);
    }

    pub fn add(&self, cidr: Cidr, entry: IntelEntry) {
        let source = entry.source.clone();
        let mut g = self.write();
        g.insert(key_of(cidr), entry);
        self.settle(&mut g, Some(&source));
    }

    /// Adds an entry for one address. For IPv6, an address inside a `/64` the same source
    /// already covers extends that entry instead, and once `AGGREGATE_V6` addresses of the
    /// same `/64` are listed by the source, they are replaced by one `/64` entry (the
    /// strongest action, the latest expiry).
    pub fn add_aggregated(&self, ip: IpAddr, entry: IntelEntry) {
        let ip = normalize(ip);
        let source = entry.source.clone();
        let mut g = self.write();
        let IpAddr::V6(v6) = ip else {
            g.insert(Key::Ip(ip), entry);
            self.settle(&mut g, Some(&source));
            return;
        };
        let p = prefix64(v6);
        let covering = g
            .nets64
            .get(&p)
            .and_then(|l| l.iter().find(|s| s.entry.source == source))
            .map(|s| s.entry.clone());
        if let Some(mut net) = covering {
            net.expires = later(net.expires, entry.expires);
            net.action = net.action.max(entry.action);
            g.insert(Key::Net64(p), net);
            self.settle(&mut g, Some(&source));
            return;
        }
        let (action, reason, expires) = (entry.action, entry.reason.clone(), entry.expires);
        g.insert(Key::Ip(ip), entry);
        let lo = IpAddr::V6(net64_addr(p));
        let hi = IpAddr::V6(Ipv6Addr::from(
            u128::from(net64_addr(p)) | u128::from(u64::MAX),
        ));
        let singles: Vec<(IpAddr, IntelAction, Option<Instant>)> = g
            .ips
            .range(lo..=hi)
            .filter_map(|(a, l)| {
                l.iter()
                    .find(|s| s.entry.source == source)
                    .map(|s| (*a, s.entry.action, s.entry.expires))
            })
            .collect();
        if singles.len() >= AGGREGATE_V6 {
            let mut net = IntelEntry {
                action,
                source: source.clone(),
                reason: format!(
                    "{} addresses of {}/64 listed (last: {reason})",
                    singles.len(),
                    net64_addr(p)
                ),
                expires,
            };
            for (a, act, exp) in singles {
                net.action = net.action.max(act);
                net.expires = later(net.expires, exp);
                g.remove(Key::Ip(a), &source);
            }
            g.insert(Key::Net64(p), net);
        }
        self.settle(&mut g, Some(&source));
    }

    /// Removes entries for `cidr` whose source starts with `source_prefix`.
    pub fn remove(&self, cidr: Cidr, source_prefix: &str) {
        let key = key_of(cidr);
        let mut g = self.write();
        let sources: Vec<String> = g
            .entries_at(key)
            .filter(|s| s.entry.source.starts_with(source_prefix))
            .map(|s| s.entry.source.clone())
            .collect();
        for s in sources {
            g.remove(key, &s);
        }
        self.settle(&mut g, None);
    }

    pub fn clear_source(&self, source_prefix: &str) {
        let mut g = self.write();
        for source in g.matching(source_prefix) {
            let keys: Vec<Key> = g
                .sources
                .get(&source)
                .map(|ix| ix.values().copied().collect())
                .unwrap_or_default();
            for k in keys {
                g.remove(k, &source);
            }
        }
        self.settle(&mut g, None);
    }

    /// Strongest non-expired entry for `ip`.
    pub fn lookup(&self, ip: IpAddr) -> Option<IntelEntry> {
        let ip = normalize(ip);
        let now = Instant::now();
        let live = |e: &&IntelEntry| e.expires.is_none_or(|x| x > now);
        let g = self.inner.read().unwrap_or_else(|e| e.into_inner());
        let from_ip = g.ips.get(&ip).into_iter().flatten();
        let from_net = match ip {
            IpAddr::V6(v6) => g.nets64.get(&prefix64(v6)),
            IpAddr::V4(_) => None,
        }
        .into_iter()
        .flatten();
        let from_ranges = g
            .ranges
            .iter()
            .filter(|(c, _)| c.contains(ip))
            .map(|(_, s)| s);
        from_ip
            .chain(from_net)
            .chain(from_ranges)
            .map(|s| &s.entry)
            .filter(live)
            .max_by_key(|e| e.action)
            .cloned()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Entries in the store (including expired ones not swept yet). Lock-free.
    pub fn len(&self) -> usize {
        self.len.load(Relaxed)
    }

    /// Entries dropped because their source was at its cap.
    pub fn evicted(&self) -> u64 {
        self.evicted.load(Relaxed)
    }

    /// Live entries whose source starts with `source_prefix`, as (ip or cidr, entry),
    /// soonest-expiring first within each source.
    pub fn list(&self, source_prefix: &str) -> Vec<(String, IntelEntry)> {
        let now = Instant::now();
        let g = self.inner.read().unwrap_or_else(|e| e.into_inner());
        let mut out = Vec::new();
        for (source, ix) in g
            .sources
            .iter()
            .filter(|(s, _)| s.starts_with(source_prefix))
        {
            for (&(deadline, _), &key) in ix {
                if matches!(deadline, Deadline::At(t) if t <= now) {
                    continue;
                }
                if let Some(s) = g.entries_at(key).find(|s| s.entry.source == *source) {
                    out.push((key_string(key), s.entry.clone()));
                }
            }
        }
        out
    }

    /// Drops expired entries (call periodically). Works in batches of `SWEEP_BATCH`,
    /// releasing the write lock in between, and only visits expired entries.
    pub fn sweep(&self) {
        self.sweep_at(Instant::now());
    }

    fn sweep_at(&self, now: Instant) {
        loop {
            let mut g = self.write();
            let expired: Vec<(String, Key)> = g
                .sources
                .iter()
                .flat_map(|(source, ix)| {
                    ix.iter()
                        .take_while(|((d, _), _)| matches!(d, Deadline::At(t) if *t <= now))
                        .map(move |(_, k)| (source.clone(), *k))
                })
                .take(SWEEP_BATCH)
                .collect();
            if expired.is_empty() {
                break;
            }
            for (source, k) in expired {
                g.remove(k, &source);
            }
            self.settle(&mut g, None);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn entry(action: IntelAction, source: &str, ttl: Option<u64>) -> IntelEntry {
        IntelEntry {
            action,
            source: source.into(),
            reason: "test".into(),
            expires: ttl.map(|s| Instant::now() + Duration::from_secs(s)),
        }
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn lookup_strongest_and_remove() {
        let s = IntelStore::default();
        s.add(
            Cidr::parse("1.2.3.4").unwrap(),
            entry(IntelAction::Challenge, "crowdsec:CAPI", None),
        );
        s.add(
            Cidr::parse("1.2.3.0/24").unwrap(),
            entry(IntelAction::Ban, "suricata", Some(60)),
        );
        assert_eq!(s.lookup(ip("1.2.3.4")).unwrap().action, IntelAction::Ban);
        s.remove(Cidr::parse("1.2.3.0/24").unwrap(), "suricata");
        assert_eq!(
            s.lookup(ip("1.2.3.4")).unwrap().action,
            IntelAction::Challenge
        );
        s.clear_source("crowdsec");
        assert!(s.lookup(ip("1.2.3.4")).is_none());
        s.add(
            Cidr::parse("5.5.5.5").unwrap(),
            entry(IntelAction::Ban, "wazuh", Some(0)),
        );
        assert!(s.lookup(ip("5.5.5.5")).is_none(), "expired");
        s.sweep();
        assert_eq!(s.len(), 0);
    }

    #[test]
    fn same_source_replaces_other_sources_add_up() {
        let s = IntelStore::default();
        let c = Cidr::parse("2001:db8::1").unwrap();
        s.add(c, entry(IntelAction::Challenge, "suricata", Some(60)));
        s.add(c, entry(IntelAction::Ban, "suricata", Some(60)));
        s.add(c, entry(IntelAction::Challenge, "wazuh", Some(60)));
        assert_eq!(s.len(), 2);
        assert_eq!(
            s.lookup(ip("2001:db8::1")).unwrap().action,
            IntelAction::Ban
        );
        // a /64 range from any source is found in O(1)
        s.add(
            Cidr::parse("2001:db8:5:6::/64").unwrap(),
            entry(IntelAction::Ban, "crowdsec:cscli", None),
        );
        assert!(s.lookup(ip("2001:db8:5:6::abcd")).is_some());
        assert!(s.lookup(ip("2001:db8:5:7::1")).is_none());
        assert_eq!(
            s.list("crowdsec")[0].0,
            "2001:db8:5:6::/64",
            "listed as its /64"
        );
        s.remove(Cidr::parse("2001:db8:5:6::/64").unwrap(), "crowdsec");
        assert!(s.lookup(ip("2001:db8:5:6::abcd")).is_none());
        assert_eq!(s.len(), 2);
    }

    #[test]
    fn caps_evict_soonest_expiring_of_the_same_source_only() {
        let s = IntelStore::new(1_000).with_source_cap("gateway:ban", 3);
        s.add(
            Cidr::parse("192.0.2.1").unwrap(),
            entry(IntelAction::Ban, "crowdsec:CAPI", Some(10)),
        );
        for (i, ttl) in [(1, Some(600)), (2, Some(60)), (3, None), (4, Some(3600))] {
            s.add(
                Cidr::parse(&format!("203.0.113.{i}")).unwrap(),
                entry(IntelAction::Ban, "gateway:ban", ttl),
            );
        }
        // 203.0.113.2 expired soonest and was evicted; the CrowdSec entry stays
        assert_eq!(s.len(), 4);
        assert_eq!(s.evicted(), 1);
        assert!(s.lookup(ip("203.0.113.2")).is_none());
        for kept in ["203.0.113.1", "203.0.113.3", "203.0.113.4", "192.0.2.1"] {
            assert!(s.lookup(ip(kept)).is_some(), "{kept}");
        }
        // a never-expiring entry goes last
        s.add(
            Cidr::parse("203.0.113.5").unwrap(),
            entry(IntelAction::Ban, "gateway:ban", Some(7200)),
        );
        assert!(s.lookup(ip("203.0.113.1")).is_none());
        assert!(s.lookup(ip("203.0.113.3")).is_some());
        assert_eq!(s.list("gateway:ban").len(), 3);
    }

    #[test]
    fn many_addresses_of_one_slash64_become_one_entry() {
        let s = IntelStore::default();
        let ban = |a: &str, ttl| {
            s.add_aggregated(ip(a), entry(IntelAction::Ban, "gateway:ban", Some(ttl)));
        };
        for i in 1..AGGREGATE_V6 {
            ban(&format!("2001:db8:1:2::{i:x}"), 60);
        }
        // another source's entry in the same /64 is left alone
        s.add(
            Cidr::parse("2001:db8:1:2::ffff").unwrap(),
            entry(IntelAction::Challenge, "suricata", Some(60)),
        );
        assert_eq!(s.len(), AGGREGATE_V6);
        ban("2001:db8:1:2::100", 600);
        assert_eq!(s.len(), 2, "one /64 ban plus the Suricata entry");
        let listed = s.list("gateway:ban");
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].0, "2001:db8:1:2::/64");
        assert!(
            listed[0]
                .1
                .reason
                .starts_with("16 addresses of 2001:db8:1:2::/64")
        );
        // covers addresses never seen, keeps the latest expiry
        let e = s.lookup(ip("2001:db8:1:2:dead:beef::1")).unwrap();
        assert_eq!(e.action, IntelAction::Ban);
        assert!(e.expires.unwrap() > Instant::now() + Duration::from_secs(500));
        // later bans inside it extend it rather than add entries
        ban("2001:db8:1:2::200", 7200);
        assert_eq!(s.len(), 2);
        let e = s.lookup(ip("2001:db8:1:2::1")).unwrap();
        assert!(e.expires.unwrap() > Instant::now() + Duration::from_secs(7000));
        // the neighbouring /64 and IPv4 are untouched
        assert!(s.lookup(ip("2001:db8:1:3::1")).is_none());
        for i in 0..40 {
            s.add_aggregated(
                ip(&format!("198.51.100.{i}")),
                entry(IntelAction::Ban, "gateway:ban", Some(60)),
            );
        }
        assert_eq!(s.len(), 42, "IPv4 is never aggregated");
    }

    #[test]
    fn sweep_removes_only_expired_and_len_is_counted() {
        let s = IntelStore::default();
        for i in 0..10_000u32 {
            let a = std::net::Ipv4Addr::from(0x0a00_0000 + i);
            s.add(
                Cidr::parse(&a.to_string()).unwrap(),
                entry(
                    IntelAction::Ban,
                    "gateway:ban",
                    Some(if i % 2 == 0 { 0 } else { 3600 }),
                ),
            );
        }
        assert_eq!(s.len(), 10_000);
        s.sweep_at(Instant::now() + Duration::from_millis(1));
        assert_eq!(s.len(), 5_000);
        assert_eq!(s.list("gateway").len(), 5_000);
        assert!(s.lookup(ip("10.0.0.1")).is_some());
        assert!(s.lookup(ip("10.0.0.2")).is_none());
    }
}
