//! Per-actor sliding windows for the explicit rules, with incremental aggregates.
//!
//! Each actor keeps a bounded deque of (time, keys) plus running counts, so a check is
//! O(1) amortised regardless of how many events are in the window (0.2 copied and
//! scanned the full window on every call, which made floods quadratic).

use std::collections::{HashMap, VecDeque};
use std::num::NonZeroUsize;

use lru::LruCache;

use crate::config::EffectiveConfig;

/// Fewer gaps than this and interval regularity is not judged (0.2 blocked any actor
/// whose first two requests happened to be `interval_secs` apart).
pub const INTERVAL_MIN_GAPS: usize = 5;

struct Entry {
    ts: f64,
    rep_key: u64,
    target_key: u64,
    weight: f64,
    /// Gap to the previous entry matched `interval_secs` ± tolerance.
    interval_hit: bool,
}

#[derive(Default)]
struct ActorWindow {
    q: VecDeque<Entry>,
    rep: HashMap<u64, u32>,
    targets: HashMap<u64, u32>,
    weight_sum: f64,
    /// Interval hits among entries *after* the front (each hit describes the gap to its predecessor).
    interval_hits: usize,
}

/// Aggregates for the current actor's window, including the event just recorded.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct WindowStats {
    pub count: usize,
    /// Occurrences of the current (action, target) in the window.
    pub repetition: usize,
    pub distinct_targets: usize,
    pub weight_sum: f64,
    pub interval_gaps: usize,
    pub interval_hits: usize,
}

pub struct Tracker {
    actors: LruCache<String, ActorWindow>,
}

impl Tracker {
    pub fn new(max_actors: Option<NonZeroUsize>) -> Self {
        Self {
            actors: match max_actors {
                Some(cap) => LruCache::new(cap),
                None => LruCache::unbounded(),
            },
        }
    }

    pub fn record(
        &mut self,
        actor: &str,
        rep_key: u64,
        target_key: u64,
        weight: f64,
        now: f64,
        cfg: &EffectiveConfig,
    ) -> WindowStats {
        let w = self
            .actors
            .get_or_insert_mut(actor.to_string(), ActorWindow::default);

        let interval_hit = match (cfg.interval_secs, w.q.back()) {
            (Some(t), Some(prev)) => {
                ((now - prev.ts) - t).abs() <= t * cfg.interval_tolerance_ratio
            }
            _ => false,
        };
        if !w.q.is_empty() && interval_hit {
            w.interval_hits += 1;
        }
        w.q.push_back(Entry {
            ts: now,
            rep_key,
            target_key,
            weight,
            interval_hit,
        });
        *w.rep.entry(rep_key).or_default() += 1;
        *w.targets.entry(target_key).or_default() += 1;
        w.weight_sum += weight;

        // Rules saturate at 2× their threshold, so keeping 2× the largest threshold
        // is enough to compute every rule exactly while bounding memory per actor.
        let cap = [
            cfg.burst_max_events,
            cfg.repetition_max_count,
            cfg.hopping_max_targets,
        ]
        .into_iter()
        .flatten()
        .max()
        .map(|m| 2 * m as usize + 2)
        .unwrap_or(256)
        .max(2 * INTERVAL_MIN_GAPS + 2);

        let horizon = now - cfg.window_secs as f64;
        while w.q.len() > 1 && (w.q.len() > cap || w.q.front().is_some_and(|e| e.ts < horizon)) {
            w.pop_front();
        }

        WindowStats {
            count: w.q.len(),
            repetition: w.rep.get(&rep_key).copied().unwrap_or(0) as usize,
            distinct_targets: w.targets.len(),
            weight_sum: w.weight_sum,
            interval_gaps: w.q.len().saturating_sub(1),
            interval_hits: w.interval_hits,
        }
    }
}

impl ActorWindow {
    fn pop_front(&mut self) {
        let Some(e) = self.q.pop_front() else { return };
        dec(&mut self.rep, e.rep_key);
        dec(&mut self.targets, e.target_key);
        self.weight_sum -= e.weight;
        // The new front's gap pointed at the entry we just removed; stop counting it.
        if let Some(front) = self.q.front() {
            if front.interval_hit {
                self.interval_hits -= 1;
            }
        }
    }
}

fn dec(m: &mut HashMap<u64, u32>, k: u64) {
    if let Some(c) = m.get_mut(&k) {
        *c -= 1;
        if *c == 0 {
            m.remove(&k);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;

    fn cfg(s: &str) -> EffectiveConfig {
        Config::from_toml_str(s).unwrap().guard.for_actor("a")
    }

    #[test]
    fn window_slides_on_event_time() {
        let c = cfg("[guard]\nwindow_secs = 10\nburst_max_events = 100\n");
        let mut t = Tracker::new(None);
        for i in 0..5 {
            t.record("a", 1, 1, 1.0, i as f64, &c);
        }
        let s = t.record("a", 1, 1, 1.0, 5.0, &c);
        assert_eq!(s.count, 6);
        let s = t.record("a", 2, 2, 1.0, 14.5, &c); // 0..4 expired
        assert_eq!(s.count, 2);
        assert_eq!(s.repetition, 1);
        assert_eq!(s.distinct_targets, 2);
    }

    #[test]
    fn per_actor_memory_is_capped() {
        let c = cfg("[guard]\nburst_max_events = 10\n");
        let mut t = Tracker::new(None);
        let mut s = None;
        for _ in 0..10_000 {
            s = Some(t.record("a", 1, 1, 1.0, 0.0, &c));
        }
        let s = s.unwrap();
        assert_eq!(s.count, 22);
        assert_eq!(s.repetition, 22);
    }

    #[test]
    fn interval_hits_track_window() {
        let c = cfg("[guard]\ninterval_secs = 2.0\nwindow_secs = 100\n");
        let mut t = Tracker::new(None);
        let mut s = None;
        for i in 0..10 {
            s = Some(t.record("a", 1, 1, 1.0, i as f64 * 2.0, &c));
        }
        let s = s.unwrap();
        assert_eq!((s.interval_gaps, s.interval_hits), (9, 9));
        // irregular gap
        let s = t.record("a", 1, 1, 1.0, 30.0, &c);
        assert_eq!((s.interval_gaps, s.interval_hits), (10, 9));
    }

    #[test]
    fn interval_hits_consistent_after_eviction() {
        let c = cfg("[guard]\ninterval_secs = 1.0\nwindow_secs = 5\n");
        let mut t = Tracker::new(None);
        let mut last = None;
        for i in 0..50 {
            last = Some(t.record("a", 1, 1, 1.0, i as f64, &c));
        }
        let s = last.unwrap();
        assert_eq!(s.interval_hits, s.interval_gaps);
    }

    #[test]
    fn lru_evicts_least_recent_actor() {
        let c = cfg("[guard]\nburst_max_events = 10\n");
        let mut t = Tracker::new(NonZeroUsize::new(2));
        t.record("a1", 1, 1, 1.0, 0.0, &c);
        t.record("a2", 1, 1, 1.0, 0.0, &c);
        t.record("a3", 1, 1, 1.0, 0.0, &c);
        assert_eq!(t.record("a1", 1, 1, 1.0, 0.0, &c).count, 1);
    }
}
