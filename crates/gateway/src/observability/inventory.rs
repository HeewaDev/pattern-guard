//! API discovery: every route template seen, with methods, volume and outcomes.
//!
//! Bounded: at most `MAX_ROUTES` routes, each keyed by a method and a template cut to
//! `MAX_TEMPLATE` bytes (a 64 KB path would otherwise make a ~120 KB key). The request
//! path doesn't record requests refused by `[protocol]` (see `proxy/mod.rs`).

use std::collections::{BTreeMap, HashMap};
use std::sync::Mutex;

use crate::util::now_secs;

const MAX_ROUTES: usize = 10_000;
/// Longest template kept; longer ones are cut and marked with `…`, so they share an
/// entry with every route that has the same first `MAX_TEMPLATE` bytes.
pub const MAX_TEMPLATE: usize = 512;
/// Longest method kept (methods outside `protocol.allowed_methods` are refused before
/// they reach the inventory, unless `[protocol]` is disabled).
const MAX_METHOD: usize = 32;

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

/// `s` cut to at most `max` bytes on a character boundary, marked with `…`.
fn clip(s: &str, max: usize) -> std::borrow::Cow<'_, str> {
    if s.len() <= max {
        return s.into();
    }
    let mut end = max;
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}…", &s[..end]).into()
}

impl Inventory {
    pub fn record(&self, method: &str, template: &str, status: u16, blocked: bool) {
        let key = format!(
            "{} {}",
            clip(method, MAX_METHOD),
            clip(template, MAX_TEMPLATE)
        );
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

    /// The `/inventory` document. The table is copied under the lock and serialised
    /// after it is released, so an (unauthenticated) scrape never holds up requests
    /// for longer than the copy.
    pub fn to_json(&self) -> String {
        let mut v: Vec<(String, RouteStat)> = {
            let g = self.routes.lock().unwrap_or_else(|e| e.into_inner());
            g.iter().map(|(k, s)| (k.clone(), s.clone())).collect()
        };
        v.sort_by_key(|(_, s)| std::cmp::Reverse(s.requests));
        let count = v.len();
        let items: Vec<_> = v
            .into_iter()
            .map(|(k, s)| serde_json::json!({"route": k, "stats": s}))
            .collect();
        serde_json::json!({"routes": items, "count": count}).to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn templates_are_capped() {
        let inv = Inventory::default();
        let long = format!("/{}", "{n}a/".repeat(10_000));
        inv.record("GET", &long, 200, false);
        inv.record("GET", &format!("{long}x"), 404, false);
        inv.record("GET", "/api/items/{n}", 200, false);
        inv.record("GET", "/api/items/{n}", 403, true);
        let v: serde_json::Value = serde_json::from_str(&inv.to_json()).unwrap();
        assert_eq!(v["count"], 2, "both long paths share one capped entry");
        let routes = v["routes"].as_array().unwrap();
        for r in routes {
            assert!(r["route"].as_str().unwrap().len() <= 4 + MAX_TEMPLATE + 3);
        }
        let items = routes
            .iter()
            .find(|r| r["route"] == "GET /api/items/{n}")
            .unwrap();
        assert_eq!(items["stats"]["requests"], 2);
        assert_eq!(items["stats"]["blocked"], 1);
        let long = routes
            .iter()
            .find(|r| r["route"].as_str().unwrap().ends_with('…'))
            .unwrap();
        assert_eq!(long["stats"]["requests"], 2);
    }
}
