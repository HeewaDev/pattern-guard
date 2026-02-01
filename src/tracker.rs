//! Per-actor event store; prune on record.

use std::collections::HashMap;
use std::sync::RwLock;
use std::time::{Duration, SystemTime};

use crate::event::Event;

fn cutoff_time(now: SystemTime, window_secs: u64) -> SystemTime {
    now.checked_sub(Duration::from_secs(window_secs))
        .unwrap_or(SystemTime::UNIX_EPOCH)
}

pub struct Tracker {
    inner: RwLock<HashMap<String, Vec<Event>>>,
    max_window_secs: u64,
}

impl Tracker {
    pub fn new(max_window_secs: u64) -> Self {
        Self {
            inner: RwLock::new(HashMap::new()),
            max_window_secs,
        }
    }

    pub fn record(&self, event: &Event) {
        let now = SystemTime::now();
        let cutoff = cutoff_time(now, self.max_window_secs);

        let mut guard = self.inner.write().unwrap();
        let entries = guard.entry(event.actor.clone()).or_default();
        entries.push(event.clone());
        entries.retain(|e| e.timestamp >= cutoff);
    }

    pub fn events_in_window(&self, actor: &str, window_secs: u64) -> Vec<Event> {
        let now = SystemTime::now();
        let cutoff = cutoff_time(now, window_secs);

        let guard = self.inner.read().unwrap();
        let entries = match guard.get(actor) {
            Some(v) => v,
            None => return Vec::new(),
        };
        entries
            .iter()
            .filter(|e| e.timestamp >= cutoff)
            .cloned()
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tracker_record_and_window() {
        let t = Tracker::new(60);
        let event = Event::new("a", "run", "x", SystemTime::now());
        t.record(&event);
        t.record(&event);
        t.record(&event);
        let events = t.events_in_window("a", 60);
        assert_eq!(events.len(), 3);
        assert!(t.events_in_window("b", 60).is_empty());
    }
}
