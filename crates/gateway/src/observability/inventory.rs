//! API discovery: every route template seen, with methods, volume and outcomes.

use std::collections::{BTreeMap, HashMap};
use std::sync::Mutex;

use crate::util::now_secs;

const MAX_ROUTES: usize = 10_000;

#[derive(Default, Clone, serde::Serialize)]
pub struct RouteStat {
    pub requests: u64,
    pub blocked: u64,
    pub statuses: BTreeMap<u16, u64>,
    pub first_seen: u64,
    pub last_seen: u64,
}

#[derive(Default)]
pub struct Inventory {
    routes: Mutex<HashMap<String, RouteStat>>,
}

impl Inventory {
    pub fn record(&self, method: &str, template: &str, status: u16, blocked: bool) {
        let key = format!("{method} {template}");
        let mut g = self.routes.lock().unwrap_or_else(|e| e.into_inner());
        if !g.contains_key(&key) && g.len() >= MAX_ROUTES {
            return;
        }
        let now = now_secs();
        let r = g.entry(key).or_insert_with(|| RouteStat {
            first_seen: now,
            ..Default::default()
        });
        r.requests += 1;
        r.blocked += blocked as u64;
        r.last_seen = now;
        if r.statuses.len() < 16 || r.statuses.contains_key(&status) {
            *r.statuses.entry(status).or_default() += 1;
        }
    }

    pub fn to_json(&self) -> String {
        let g = self.routes.lock().unwrap_or_else(|e| e.into_inner());
        let mut v: Vec<_> = g.iter().collect();
        v.sort_by_key(|(_, s)| std::cmp::Reverse(s.requests));
        let items: Vec<_> = v
            .into_iter()
            .map(|(k, s)| serde_json::json!({"route": k, "stats": s}))
            .collect();
        serde_json::json!({"routes": items, "count": g.len()}).to_string()
    }
}
