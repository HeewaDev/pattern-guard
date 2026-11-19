//! Shared threat intelligence: IPs and ranges flagged by CrowdSec, Suricata, Wazuh or config.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::RwLock;
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

#[derive(Default)]
struct Inner {
    ips: HashMap<IpAddr, Vec<IntelEntry>>,
    ranges: Vec<(Cidr, IntelEntry)>,
}

#[derive(Default)]
pub struct IntelStore {
    inner: RwLock<Inner>,
}

impl IntelStore {
    pub fn add(&self, cidr: Cidr, entry: IntelEntry) {
        let mut g = self.inner.write().unwrap_or_else(|e| e.into_inner());
        if cidr.is_single() {
            let list = g.ips.entry(normalize(cidr.addr())).or_default();
            list.retain(|e| e.source != entry.source);
            list.push(entry);
        } else {
            g.ranges
                .retain(|(c, e)| !(*c == cidr && e.source == entry.source));
            g.ranges.push((cidr, entry));
        }
    }

    /// Removes entries for `cidr` whose source starts with `source_prefix`.
    pub fn remove(&self, cidr: Cidr, source_prefix: &str) {
        let mut g = self.inner.write().unwrap_or_else(|e| e.into_inner());
        if cidr.is_single() {
            let ip = normalize(cidr.addr());
            if let Some(list) = g.ips.get_mut(&ip) {
                list.retain(|e| !e.source.starts_with(source_prefix));
                if list.is_empty() {
                    g.ips.remove(&ip);
                }
            }
        } else {
            g.ranges
                .retain(|(c, e)| !(*c == cidr && e.source.starts_with(source_prefix)));
        }
    }

    pub fn clear_source(&self, source_prefix: &str) {
        let mut g = self.inner.write().unwrap_or_else(|e| e.into_inner());
        g.ips.retain(|_, list| {
            list.retain(|e| !e.source.starts_with(source_prefix));
            !list.is_empty()
        });
        g.ranges
            .retain(|(_, e)| !e.source.starts_with(source_prefix));
    }

    /// Strongest non-expired entry for `ip`.
    pub fn lookup(&self, ip: IpAddr) -> Option<IntelEntry> {
        let ip = normalize(ip);
        let now = Instant::now();
        let live = |e: &&IntelEntry| e.expires.is_none_or(|x| x > now);
        let g = self.inner.read().unwrap_or_else(|e| e.into_inner());
        let from_ip = g.ips.get(&ip).into_iter().flatten().filter(live);
        let from_ranges = g
            .ranges
            .iter()
            .filter(|(c, _)| c.contains(ip))
            .map(|(_, e)| e)
            .filter(live);
        from_ip.chain(from_ranges).max_by_key(|e| e.action).cloned()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn len(&self) -> usize {
        let g = self.inner.read().unwrap_or_else(|e| e.into_inner());
        g.ips.values().map(Vec::len).sum::<usize>() + g.ranges.len()
    }

    /// Drops expired entries (call periodically).
    pub fn sweep(&self) {
        let now = Instant::now();
        let mut g = self.inner.write().unwrap_or_else(|e| e.into_inner());
        g.ips.retain(|_, list| {
            list.retain(|e| e.expires.is_none_or(|x| x > now));
            !list.is_empty()
        });
        g.ranges.retain(|(_, e)| e.expires.is_none_or(|x| x > now));
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
        assert_eq!(
            s.lookup("1.2.3.4".parse().unwrap()).unwrap().action,
            IntelAction::Ban
        );
        s.remove(Cidr::parse("1.2.3.0/24").unwrap(), "suricata");
        assert_eq!(
            s.lookup("1.2.3.4".parse().unwrap()).unwrap().action,
            IntelAction::Challenge
        );
        s.clear_source("crowdsec");
        assert!(s.lookup("1.2.3.4".parse().unwrap()).is_none());
        s.add(
            Cidr::parse("5.5.5.5").unwrap(),
            entry(IntelAction::Ban, "wazuh", Some(0)),
        );
        assert!(s.lookup("5.5.5.5".parse().unwrap()).is_none(), "expired");
        s.sweep();
        assert_eq!(s.len(), 0);
    }
}
