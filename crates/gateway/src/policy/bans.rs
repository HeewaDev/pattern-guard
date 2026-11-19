//! Escalating bans (fail2ban / CrowdSec style) and honeypot traps.
//!
//! Bans are written to the shared intel store with source `gateway:ban`, so they are
//! enforced like any other reputation entry, expire on their own and show up in
//! `/bans` on the admin port.

use std::collections::VecDeque;
use std::net::IpAddr;
use std::num::NonZeroUsize;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use lru::LruCache;

use crate::config::{BanConfig, TrapConfig};
use crate::intel::{IntelAction, IntelEntry, IntelStore};
use crate::ipnet::Cidr;

pub const SOURCE: &str = "gateway:ban";

#[derive(Default)]
struct Offender {
    recent: VecDeque<Instant>,
    bans: u32,
}

pub struct Bans {
    cfg: BanConfig,
    traps: TrapConfig,
    offenders: Mutex<LruCache<IpAddr, Offender>>,
}

impl Bans {
    pub fn new(cfg: BanConfig, traps: TrapConfig) -> Self {
        Self {
            cfg,
            traps,
            offenders: Mutex::new(LruCache::new(NonZeroUsize::new(100_000).unwrap())),
        }
    }

    /// The trap prefix this path hits, if any.
    pub fn trap(&self, path: &str) -> Option<&str> {
        self.traps
            .paths
            .iter()
            .find(|p| path.starts_with(p.as_str()))
            .map(String::as_str)
    }

    /// Records an enforced block; returns the ban length if this block triggered a ban.
    pub fn record_block(&self, ip: IpAddr, intel: &IntelStore) -> Option<Duration> {
        self.record_block_at(ip, intel, Instant::now())
    }

    fn record_block_at(&self, ip: IpAddr, intel: &IntelStore, now: Instant) -> Option<Duration> {
        if !self.cfg.enabled {
            return None;
        }
        let window = Duration::from_secs(self.cfg.window_secs.max(1));
        let mut g = self.offenders.lock().unwrap_or_else(|e| e.into_inner());
        let o = g.get_or_insert_mut(ip, Offender::default);
        while o
            .recent
            .front()
            .is_some_and(|t| now.duration_since(*t) > window)
        {
            o.recent.pop_front();
        }
        o.recent.push_back(now);
        if (o.recent.len() as u32) < self.cfg.threshold {
            return None;
        }
        o.recent.clear();
        let secs = self.duration_for(o.bans, self.cfg.ban_secs);
        o.bans += 1;
        let reason = format!(
            "{} blocks within {}s (ban #{})",
            self.cfg.threshold, self.cfg.window_secs, o.bans
        );
        drop(g);
        add_ban(intel, ip, secs, reason, now);
        Some(Duration::from_secs(secs))
    }

    /// Bans immediately (traps); counts towards escalation.
    pub fn ban_now(&self, ip: IpAddr, intel: &IntelStore, reason: String) -> Duration {
        let now = Instant::now();
        let mut g = self.offenders.lock().unwrap_or_else(|e| e.into_inner());
        let o = g.get_or_insert_mut(ip, Offender::default);
        let secs = self.duration_for(o.bans, self.traps.ban_secs);
        o.bans += 1;
        drop(g);
        add_ban(intel, ip, secs, reason, now);
        Duration::from_secs(secs)
    }

    fn duration_for(&self, previous_bans: u32, base: u64) -> u64 {
        let factor = self.cfg.escalation.powi(previous_bans.min(32) as i32);
        ((base as f64 * factor) as u64).min(self.cfg.max_ban_secs.max(base))
    }
}

fn add_ban(intel: &IntelStore, ip: IpAddr, secs: u64, reason: String, now: Instant) {
    intel.add(
        Cidr::parse(&ip.to_string()).expect("an IP is a valid CIDR"),
        IntelEntry {
            action: IntelAction::Ban,
            source: SOURCE.into(),
            reason,
            expires: Some(now + Duration::from_secs(secs)),
        },
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bans(toml: &str) -> Bans {
        let cfg = crate::config::GatewayConfig::from_toml_str(&format!(
            "upstream = \"http://127.0.0.1:1\"\n{toml}"
        ))
        .unwrap();
        Bans::new(cfg.bans, cfg.traps)
    }

    #[test]
    fn threshold_window_and_escalation() {
        let b = bans(
            "[bans]\nthreshold = 3\nwindow_secs = 10\nban_secs = 60\nescalation = 2.0\nmax_ban_secs = 200\n",
        );
        let intel = IntelStore::default();
        let ip: IpAddr = "203.0.113.7".parse().unwrap();
        let t0 = Instant::now();
        assert!(b.record_block_at(ip, &intel, t0).is_none());
        assert!(
            b.record_block_at(ip, &intel, t0 + Duration::from_secs(1))
                .is_none()
        );
        // a block outside the window doesn't count with the old ones
        assert!(
            b.record_block_at(ip, &intel, t0 + Duration::from_secs(20))
                .is_none()
        );
        assert!(
            b.record_block_at(ip, &intel, t0 + Duration::from_secs(21))
                .is_none()
        );
        let first = b
            .record_block_at(ip, &intel, t0 + Duration::from_secs(22))
            .unwrap();
        assert_eq!(first.as_secs(), 60);
        let e = intel.lookup(ip).unwrap();
        assert_eq!((e.action, e.source.as_str()), (IntelAction::Ban, SOURCE));
        for i in 0..2 {
            assert!(
                b.record_block_at(ip, &intel, t0 + Duration::from_secs(30 + i))
                    .is_none()
            );
        }
        assert_eq!(
            b.record_block_at(ip, &intel, t0 + Duration::from_secs(33))
                .unwrap()
                .as_secs(),
            120
        );
        for i in 0..2 {
            b.record_block_at(ip, &intel, t0 + Duration::from_secs(40 + i));
        }
        assert_eq!(
            b.record_block_at(ip, &intel, t0 + Duration::from_secs(43))
                .unwrap()
                .as_secs(),
            200,
            "capped"
        );
    }

    #[test]
    fn traps_and_disabled() {
        let b = bans(
            "[bans]\nenabled = false\n[traps]\npaths = [\"/wp-login.php\", \"/.env\"]\nban_secs = 900\n",
        );
        let intel = IntelStore::default();
        let ip: IpAddr = "198.51.100.9".parse().unwrap();
        for _ in 0..50 {
            assert!(
                b.record_block(ip, &intel).is_none(),
                "automatic bans disabled"
            );
        }
        assert_eq!(b.trap("/wp-login.php?x=1"), Some("/wp-login.php"));
        assert_eq!(b.trap("/shop"), None);
        assert_eq!(b.ban_now(ip, &intel, "trap".into()).as_secs(), 900);
        assert!(intel.lookup(ip).is_some());
    }
}
