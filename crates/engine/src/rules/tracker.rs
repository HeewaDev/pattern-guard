//! Per-actor sliding windows for the explicit rules, with incremental aggregates.
//!
//! Each actor keeps a bounded deque of (time, keys) plus running counts, so a check is
//! O(1) amortised regardless of how many events are in the window (0.2 copied and
//! scanned the full window on every call, which made floods quadratic).

use std::collections::{HashMap, VecDeque};
use std::num::NonZeroUsize;

use lru::LruCache;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::config::EffectiveConfig;
use crate::snapshot::bits::F;
use crate::snapshot::{With, copy_in_chunks};

/// Fewer gaps than this and interval regularity is not judged (0.2 blocked any actor
/// whose first two requests happened to be `interval_secs` apart).
pub const INTERVAL_MIN_GAPS: usize = 5;

#[derive(Debug, Clone)]
struct Entry {
    ts: f64,
    rep_key: u64,
    target_key: u64,
    weight: f64,
    /// Gap to the previous entry matched `interval_secs` ± tolerance.
    interval_hit: bool,
}

/// In a snapshot: a tuple of the fields, floats as bits.
impl Serialize for Entry {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        (
            F(self.ts),
            self.rep_key,
            self.target_key,
            F(self.weight),
            self.interval_hit,
        )
            .serialize(s)
    }
}

impl<'de> Deserialize<'de> for Entry {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let (F(ts), rep_key, target_key, F(weight), interval_hit) = Deserialize::deserialize(d)?;
        Ok(Self {
            ts,
            rep_key,
            target_key,
            weight,
            interval_hit,
        })
    }
}

/// One actor's window in a snapshot: the entries (oldest first) and the running weight
/// sum (kept as is: re-adding the weights could differ in the last bit). The other
/// aggregates are counts, rebuilt from the entries.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct WindowSnapshot(Vec<Entry>, F);

/// What a [`Tracker`] has learned: each actor's window, least recently used first.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct Learned {
    actors: Vec<(u64, WindowSnapshot)>,
}

impl Learned {
    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.actors.len()
    }
}

/// Entries an actor's window keeps at most: rules saturate at 2× their threshold, so
/// keeping 2× the largest threshold is enough to compute every rule exactly while
/// bounding memory per actor.
pub(crate) fn window_cap(cfg: &EffectiveConfig) -> usize {
    [
        cfg.burst_max_events,
        cfg.repetition_max_count,
        cfg.hopping_max_targets,
    ]
    .into_iter()
    .flatten()
    .max()
    .map(|m| 2 * m as usize + 2)
    .unwrap_or(256)
    .max(2 * INTERVAL_MIN_GAPS + 2)
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
    /// Keyed by `Event::actor_key` (a 64-bit hash of the actor id).
    actors: LruCache<u64, ActorWindow>,
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
        actor: u64,
        rep_key: u64,
        target_key: u64,
        weight: f64,
        now: f64,
        cfg: &EffectiveConfig,
    ) -> WindowStats {
        let w = self.actors.get_or_insert_mut(actor, ActorWindow::default);

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

        let cap = window_cap(cfg);
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

    /// Copies every window of the tracker `with` lends out, a chunk per lock hold (for
    /// [`crate::Snapshot`]; see `snapshot::copy_in_chunks`).
    pub(crate) fn snapshot(with: With<'_, Tracker>) -> Learned {
        let copy = |w: &ActorWindow| WindowSnapshot(w.q.iter().cloned().collect(), F(w.weight_sum));
        Learned {
            actors: copy_in_chunks(with, |t| &t.actors, copy),
        }
    }

    /// Replaces every window with `s`: at most this tracker's actor cap (the most
    /// recently used), each window at most `window_cap` entries (the newest), no entry
    /// later than `as_of` (the snapshot's clock).
    pub(crate) fn restore(&mut self, s: Learned, window_cap: usize, as_of: f64) {
        self.actors.clear();
        let skip = s.actors.len().saturating_sub(self.actors.cap().get());
        for (k, WindowSnapshot(entries, F(weight_sum))) in s.actors.into_iter().skip(skip) {
            let mut w = ActorWindow {
                weight_sum,
                ..ActorWindow::default()
            };
            for mut e in entries {
                e.ts = e.ts.min(as_of);
                *w.rep.entry(e.rep_key).or_default() += 1;
                *w.targets.entry(e.target_key).or_default() += 1;
                w.q.push_back(e);
            }
            w.interval_hits = w.q.iter().skip(1).filter(|e| e.interval_hit).count();
            while w.q.len() > window_cap.max(1) {
                w.pop_front();
            }
            self.actors.put(k, w);
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
            t.record(1, 1, 1, 1.0, i as f64, &c);
        }
        let s = t.record(1, 1, 1, 1.0, 5.0, &c);
        assert_eq!(s.count, 6);
        let s = t.record(1, 2, 2, 1.0, 14.5, &c); // 0..4 expired
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
            s = Some(t.record(1, 1, 1, 1.0, 0.0, &c));
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
            s = Some(t.record(1, 1, 1, 1.0, i as f64 * 2.0, &c));
        }
        let s = s.unwrap();
        assert_eq!((s.interval_gaps, s.interval_hits), (9, 9));
        // irregular gap
        let s = t.record(1, 1, 1, 1.0, 30.0, &c);
        assert_eq!((s.interval_gaps, s.interval_hits), (10, 9));
    }

    #[test]
    fn interval_hits_consistent_after_eviction() {
        let c = cfg("[guard]\ninterval_secs = 1.0\nwindow_secs = 5\n");
        let mut t = Tracker::new(None);
        let mut last = None;
        for i in 0..50 {
            last = Some(t.record(1, 1, 1, 1.0, i as f64, &c));
        }
        let s = last.unwrap();
        assert_eq!(s.interval_hits, s.interval_gaps);
    }

    #[test]
    fn lru_evicts_least_recent_actor() {
        let c = cfg("[guard]\nburst_max_events = 10\n");
        let mut t = Tracker::new(NonZeroUsize::new(2));
        t.record(11, 1, 1, 1.0, 0.0, &c);
        t.record(12, 1, 1, 1.0, 0.0, &c);
        t.record(13, 1, 1, 1.0, 0.0, &c);
        assert_eq!(t.record(11, 1, 1, 1.0, 0.0, &c).count, 1);
    }
}
