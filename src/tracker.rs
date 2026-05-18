//! Per-actor event store; prune on record. Optional LRU cap on actor count.
//!
//! Windowing uses a monotonic `Instant` stamped at `record()` time, so wall-clock
//! adjustments (NTP, leap seconds) cannot corrupt eviction. The public `Event::timestamp`
//! (`SystemTime`) is preserved untouched for callers that need it.

use std::collections::HashMap;
use std::num::NonZeroUsize;
use std::sync::RwLock;
use std::time::{Duration, Instant};

use lru::LruCache;

use crate::event::Event;

struct Entry {
    event: Event,
    recorded_at: Instant,
}

enum Store {
    Unbounded(HashMap<String, Vec<Entry>>),
    Bounded(LruCache<String, Vec<Entry>>),
}

pub struct Tracker {
    inner: RwLock<Store>,
    max_window: Duration,
}

impl Tracker {
    pub fn new(max_window_secs: u64, max_actors: Option<NonZeroUsize>) -> Self {
        let store = match max_actors {
            Some(cap) => Store::Bounded(LruCache::new(cap)),
            None => Store::Unbounded(HashMap::new()),
        };
        Self {
            inner: RwLock::new(store),
            max_window: Duration::from_secs(max_window_secs),
        }
    }

    pub fn record(&self, event: &Event) {
        let now = Instant::now();
        let max_window = self.max_window;
        let mut guard = self.inner.write().unwrap();
        match &mut *guard {
            Store::Unbounded(m) => {
                let entries = m.entry(event.actor.clone()).or_default();
                push_and_prune(entries, event, now, max_window);
            }
            Store::Bounded(cache) => {
                let entries = cache.get_or_insert_mut(event.actor.clone(), Vec::new);
                push_and_prune(entries, event, now, max_window);
            }
        }
    }

    pub fn events_in_window(&self, actor: &str, window_secs: u64) -> Vec<Event> {
        let window = Duration::from_secs(window_secs);
        let now = Instant::now();

        let guard = self.inner.read().unwrap();
        let entries: Option<&Vec<Entry>> = match &*guard {
            Store::Unbounded(m) => m.get(actor),
            Store::Bounded(c) => c.peek(actor),
        };
        let Some(entries) = entries else {
            return Vec::new();
        };
        entries
            .iter()
            .filter(|e| now.duration_since(e.recorded_at) <= window)
            .map(|e| e.event.clone())
            .collect()
    }
}

fn push_and_prune(entries: &mut Vec<Entry>, event: &Event, now: Instant, max_window: Duration) {
    entries.push(Entry {
        event: event.clone(),
        recorded_at: now,
    });
    entries.retain(|e| now.duration_since(e.recorded_at) <= max_window);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::SystemTime;

    #[test]
    fn tracker_record_and_window() {
        let t = Tracker::new(60, None);
        let event = Event::new("a", "run", "x", SystemTime::now());
        t.record(&event);
        t.record(&event);
        t.record(&event);
        let events = t.events_in_window("a", 60);
        assert_eq!(events.len(), 3);
        assert!(t.events_in_window("b", 60).is_empty());
    }

    #[test]
    fn tracker_lru_evicts_least_recent_actor() {
        let cap = NonZeroUsize::new(2).unwrap();
        let t = Tracker::new(60, Some(cap));
        let now = SystemTime::now();
        t.record(&Event::new("a1", "run", "x", now));
        t.record(&Event::new("a2", "run", "x", now));
        t.record(&Event::new("a3", "run", "x", now));
        assert!(t.events_in_window("a1", 60).is_empty());
        assert!(!t.events_in_window("a2", 60).is_empty());
        assert!(!t.events_in_window("a3", 60).is_empty());
    }

    #[test]
    fn tracker_ignores_stale_event_timestamp() {
        // Even if a caller hands in an ancient SystemTime, windowing is based on
        // the monotonic Instant at record time — the entry stays in the window.
        let t = Tracker::new(60, None);
        let ancient = SystemTime::UNIX_EPOCH;
        t.record(&Event::new("a", "run", "x", ancient));
        assert_eq!(t.events_in_window("a", 60).len(), 1);
    }
}
