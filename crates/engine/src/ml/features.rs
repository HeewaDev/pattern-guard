//! Streaming feature extraction for the adaptive engine.
//!
//! Every request updates constant-size state for four entities and produces a fixed
//! feature vector for the model:
//!
//! * **actor** — the client (IP or user): burstiness, volume, failure ratio, how
//!   concentrated it is on one route, novel/sequential object access, timer-like pacing.
//! * **subnet** — the client's network (/24, /56 by default): new-client churn, failures.
//!   Catches attacks spread over many addresses in the same network.
//! * **client fingerprint** — JA3/JA4/header hash, else user agent: failure ratio,
//!   share of brand-new actors, route concentration, enumeration. Catches botnets that
//!   rotate IPs but run the same tool.
//! * **route** — `METHOD /template`: a *learned baseline* of request rate, failure rate
//!   and new-client arrival rate, and the current surge above it. Catches distributed
//!   floods and credential stuffing that look harmless per IP.
//!
//! Route surges are **never evidence on their own** — flash sales, viral links and
//! Monday-morning logins are surges too. They only enter the model multiplied by
//! actor- or client-level evidence (e.g. "this route is surging *and* this fingerprint
//! sends almost all its traffic to it"), so legitimate crowds are not punished.
//!
//! All counters decay exponentially, so memory per entity is fixed and old behaviour
//! fades out on its own.

use std::net::IpAddr;
use std::num::NonZeroUsize;

use lru::LruCache;

use crate::config::AdaptiveConfig;
use crate::event::Event;
use crate::util::stats::{Decay, GapStats, RecentIds, TopCounts, smoothed_ratio};

pub const N_FEATURES: usize = 28;
pub type Features = [f64; N_FEATURES];

/// Names of the model inputs, in vector order.
pub const FEATURE_NAMES: [&str; N_FEATURES] = [
    "actor_burst",
    "actor_volume",
    "actor_new",
    "actor_fail_ratio",
    "actor_fail_count",
    "actor_route_share",
    "actor_route_diversity",
    "actor_novel_objects",
    "actor_sequential",
    "actor_regularity",
    "cold_write",
    "probe_path",
    "subnet_new_actors",
    "subnet_fail_ratio",
    "client_known",
    "client_fail_ratio",
    "client_new_actor_share",
    "client_route_share",
    "client_sequential",
    "surge_x_actor_route_share",
    "surge_x_client_route_share",
    "new_actor_surge_x_client_route_share",
    "new_actor_surge_x_client_new_share",
    "fail_surge_x_actor_fail_ratio",
    "fail_surge_x_client_fail_ratio",
    "client_route_share_x_new_share",
    "actor_route_fail_ratio",
    "actor_burst_excess",
];

const TAU_BURST: f64 = 10.0;
const TAU_VOLUME: f64 = 300.0;
const TAU_OUTCOME: f64 = 600.0;
const TAU_OBJECTS: f64 = 600.0;
const TAU_CLIENT: f64 = 300.0;
const TAU_ROUTE_SHORT: f64 = 60.0;
const TAU_FAIL_SHORT: f64 = 120.0;
/// Baselines follow quiet periods quickly but spikes only slowly, so an attack cannot
/// redefine "normal" within minutes (baseline poisoning) while real growth is absorbed.
const TAU_BASE_DOWN: f64 = 600.0;
const TAU_BASE_UP: f64 = 4.0 * 3600.0;
/// Requests in ~10 s that a single browser page load (html + XHR + images) can produce.
/// `actor_burst_excess` is zero below this, so a linear model can treat "bursty like a
/// page load" and "flood" differently instead of extrapolating one slope.
const BROWSER_BURST: f64 = 30.0;
/// Smoothing for rate ratios: one request per minute.
const RATE_FLOOR: f64 = 1.0 / 60.0;

/// Request facts derived once per request and shared with the rules engine.
#[derive(Debug, Clone, Copy)]
pub struct Prepared {
    pub route: u64,
    pub id: Option<u64>,
    pub probe: bool,
}

/// Response codes that count as a failed/abusive outcome.
pub fn is_failure(status: u16) -> bool {
    matches!(status, 400 | 401 | 403 | 404 | 405 | 422 | 429)
}

#[derive(Default)]
struct ActorState {
    n: u64,
    reads: u64,
    last_seen: Option<f64>,
    gaps: GapStats,
    burst: Decay,
    volume: Decay,
    fails: Decay,
    responses: Decay,
    novel: Decay,
    id_reqs: Decay,
    seq: Decay,
    routes: TopCounts,
    route_resp: TopCounts,
    route_fail: TopCounts,
    ids: RecentIds,
}

#[derive(Default)]
struct ClientState {
    volume: Decay,
    new_actors: Decay,
    fails: Decay,
    responses: Decay,
    id_reqs: Decay,
    seq: Decay,
    routes: TopCounts,
    ids: RecentIds,
}

#[derive(Default)]
struct SubnetState {
    new_actors: Decay,
    fails: Decay,
    responses: Decay,
}

struct RouteState {
    first_seen: f64,
    short: Decay,
    fails_short: Decay,
    resp_short: Decay,
    new_short: Decay,
    /// Asymmetric baselines of the short-window signals: (rate, fail ratio, new-actor rate).
    base: Option<[f64; 3]>,
    base_t: f64,
}

impl RouteState {
    fn new(now: f64) -> Self {
        Self {
            first_seen: now,
            short: Decay::default(),
            fails_short: Decay::default(),
            resp_short: Decay::default(),
            new_short: Decay::default(),
            base: None,
            base_t: now,
        }
    }
}

pub struct FeatureEngine {
    cfg: AdaptiveConfig,
    actors: LruCache<String, ActorState>,
    clients: LruCache<String, ClientState>,
    subnets: LruCache<(u8, u128), SubnetState>,
    routes: LruCache<u64, RouteState>,
}

impl FeatureEngine {
    pub fn new(cfg: AdaptiveConfig, max_actors: Option<NonZeroUsize>) -> Self {
        Self {
            actors: match max_actors {
                Some(n) => LruCache::new(n),
                None => LruCache::unbounded(),
            },
            clients: LruCache::new(cfg.max_fingerprints),
            subnets: LruCache::new(cfg.max_subnets),
            routes: LruCache::new(cfg.max_routes),
            cfg,
        }
    }

    pub fn probe_paths(&self) -> &[String] {
        &self.cfg.probe_paths
    }

    fn subnet_key(&self, ip: IpAddr) -> (u8, u128) {
        match ip {
            IpAddr::V4(v4) => {
                let bits = u32::from(v4);
                let p = self.cfg.ipv4_prefix as u32;
                let mask = if p == 0 { 0 } else { u32::MAX << (32 - p) };
                (4, (bits & mask) as u128)
            }
            IpAddr::V6(v6) => {
                let bits = u128::from(v6);
                let p = self.cfg.ipv6_prefix as u32;
                let mask = if p == 0 { 0 } else { u128::MAX << (128 - p) };
                (6, bits & mask)
            }
        }
    }

    /// Records the request and returns its feature vector (computed including this request).
    pub fn observe_request(&mut self, ev: &Event, p: &Prepared, now: f64) -> Features {
        let mut f = [0.0; N_FEATURES];
        let method = ev.action.as_str();
        let is_write = ["POST", "PUT", "PATCH", "DELETE"]
            .iter()
            .any(|m| method.eq_ignore_ascii_case(m));
        let is_read = ["GET", "HEAD"]
            .iter()
            .any(|m| method.eq_ignore_ascii_case(m));

        // ---- actor ----
        let actor_is_new = !self.actors.contains(&ev.actor);
        let a = self
            .actors
            .get_or_insert_mut(ev.actor.clone(), ActorState::default);
        let n_prev = a.n;
        a.n += 1;
        if let Some(last) = a.last_seen {
            a.gaps.push((now - last).clamp(0.0, 120.0));
        }
        a.last_seen = Some(a.last_seen.map_or(now, |l| l.max(now)));
        a.burst.add(1.0, now, TAU_BURST);
        a.volume.add(1.0, now, TAU_VOLUME);
        let route_new_for_actor = a.routes.add(p.route, 1.0, now, TAU_VOLUME, 16);
        let cold_write = is_write && a.reads == 0;
        if is_read {
            a.reads += 1;
        }
        if let Some(id) = p.id {
            a.id_reqs.add(1.0, now, TAU_OBJECTS);
            let (seen, near) = a.ids.push(p.route, id, 3, 32);
            if !seen {
                a.novel.add(1.0, now, TAU_OBJECTS);
            }
            if near {
                a.seq.add(1.0, now, TAU_OBJECTS);
            }
        }
        let vol = a.volume.get(now, TAU_VOLUME).max(1.0);
        f[0] = a.burst.get(now, TAU_BURST).ln_1p();
        f[1] = vol.ln_1p();
        f[2] = (-(n_prev as f64) / 5.0).exp();
        f[3] = smoothed_ratio(
            a.fails.get(now, TAU_OUTCOME),
            a.responses.get(now, TAU_OUTCOME),
            0.2,
            2.0,
        );
        f[4] = a.fails.get(now, TAU_OUTCOME).ln_1p();
        f[5] = (a.routes.get(p.route, now, TAU_VOLUME) / vol).min(1.0);
        f[6] = (a.routes.active(now, TAU_VOLUME, 0.5) as f64).ln_1p();
        f[7] = a.novel.get(now, TAU_OBJECTS).ln_1p();
        f[8] = a.seq.get(now, TAU_OBJECTS) / (a.id_reqs.get(now, TAU_OBJECTS) + 2.0);
        f[9] = a.gaps.regularity(6);
        f[10] = cold_write as u8 as f64;
        f[11] = p.probe as u8 as f64;
        f[26] = Self::actor_route_fail_ratio(a, p.route, now);
        f[27] = (f[0] - BROWSER_BURST.ln_1p()).max(0.0);

        // ---- subnet ----
        if let Some(ip) = ev.client_ip() {
            let key = self.subnet_key(ip);
            let s = self.subnets.get_or_insert_mut(key, SubnetState::default);
            if actor_is_new {
                s.new_actors.add(1.0, now, TAU_CLIENT);
            }
            f[12] = s.new_actors.get(now, TAU_CLIENT).ln_1p();
            f[13] = smoothed_ratio(
                s.fails.get(now, TAU_OUTCOME),
                s.responses.get(now, TAU_OUTCOME),
                0.2,
                2.0,
            );
        }

        // ---- client fingerprint / user agent ----
        if let Some(key) = ev.client_key() {
            let c = self.clients.get_or_insert_mut(key, ClientState::default);
            c.volume.add(1.0, now, TAU_CLIENT);
            if actor_is_new {
                c.new_actors.add(1.0, now, TAU_CLIENT);
            }
            c.routes.add(p.route, 1.0, now, TAU_CLIENT, 32);
            if let Some(id) = p.id {
                c.id_reqs.add(1.0, now, TAU_OBJECTS);
                let (_, near) = c.ids.push(p.route, id, 3, 64);
                if near {
                    c.seq.add(1.0, now, TAU_OBJECTS);
                }
            }
            let cv = c.volume.get(now, TAU_CLIENT).max(1.0);
            f[14] = 1.0;
            f[15] = smoothed_ratio(
                c.fails.get(now, TAU_OUTCOME),
                c.responses.get(now, TAU_OUTCOME),
                0.2,
                2.0,
            );
            f[16] = (c.new_actors.get(now, TAU_CLIENT) / cv).min(1.0);
            f[17] = (c.routes.get(p.route, now, TAU_CLIENT) / cv).min(1.0);
            f[18] = c.seq.get(now, TAU_OBJECTS) / (c.id_reqs.get(now, TAU_OBJECTS) + 2.0);
        }

        // ---- route baseline ----
        let r = self
            .routes
            .get_or_insert_mut(p.route, || RouteState::new(now));
        r.short.add(1.0, now, TAU_ROUTE_SHORT);
        if route_new_for_actor {
            r.new_short.add(1.0, now, TAU_ROUTE_SHORT);
        }
        let age = now - r.first_seen;
        let short_span = effective_span(TAU_ROUTE_SHORT, age);
        let current = [
            r.short.get(now, TAU_ROUTE_SHORT) / short_span,
            smoothed_ratio(
                r.fails_short.get(now, TAU_FAIL_SHORT),
                r.resp_short.get(now, TAU_FAIL_SHORT),
                0.2,
                2.0,
            ),
            r.new_short.get(now, TAU_ROUTE_SHORT) / short_span,
        ];
        // The short window needs ~1 time constant before its rate means anything.
        if age >= TAU_ROUTE_SHORT {
            match &mut r.base {
                None => r.base = Some(current),
                Some(base) => {
                    let dt = (now - r.base_t).max(0.0);
                    for (b, x) in base.iter_mut().zip(current) {
                        let tau = if x > *b { TAU_BASE_UP } else { TAU_BASE_DOWN };
                        *b += (x - *b) * (1.0 - (-dt / tau).exp());
                    }
                }
            }
            r.base_t = now;
        }
        let (mut surge, mut fail_surge, mut new_surge) = (0.0, 0.0, 0.0);
        if let (true, Some(base)) = (age >= self.cfg.warmup_secs, r.base) {
            surge = log_ratio(current[0], base[0]);
            fail_surge = (current[1] - base[1]).max(0.0);
            new_surge = log_ratio(current[2], base[2]);
        }

        // ---- route context × actor/client evidence ("only suspicious together") ----
        f[19] = surge * f[5];
        f[20] = surge * f[17];
        f[21] = new_surge * f[17];
        f[22] = new_surge * f[16];
        f[23] = fail_surge * f[3];
        f[24] = fail_surge * f[15];
        f[25] = f[17] * f[16];
        f
    }

    fn actor_route_fail_ratio(a: &ActorState, route: u64, now: f64) -> f64 {
        smoothed_ratio(
            a.route_fail.get(route, now, TAU_OUTCOME),
            a.route_resp.get(route, now, TAU_OUTCOME),
            0.2,
            2.0,
        )
    }

    /// Feeds back the response status of a request already passed to `observe_request`.
    pub fn observe_response(&mut self, ev: &Event, p: &Prepared, status: u16, now: f64) {
        let fail = is_failure(status) as u8 as f64;
        if let Some(a) = self.actors.peek_mut(&ev.actor) {
            a.responses.add(1.0, now, TAU_OUTCOME);
            a.fails.add(fail, now, TAU_OUTCOME);
            a.route_resp.add(p.route, 1.0, now, TAU_OUTCOME, 8);
            if fail > 0.0 {
                a.route_fail.add(p.route, 1.0, now, TAU_OUTCOME, 8);
            }
        }
        if let Some(ip) = ev.client_ip() {
            let key = self.subnet_key(ip);
            if let Some(s) = self.subnets.peek_mut(&key) {
                s.responses.add(1.0, now, TAU_OUTCOME);
                s.fails.add(fail, now, TAU_OUTCOME);
            }
        }
        if let Some(key) = ev.client_key() {
            if let Some(c) = self.clients.peek_mut(&key) {
                c.responses.add(1.0, now, TAU_OUTCOME);
                c.fails.add(fail, now, TAU_OUTCOME);
            }
        }
        if let Some(r) = self.routes.peek_mut(&p.route) {
            r.resp_short.add(1.0, now, TAU_FAIL_SHORT);
            r.fails_short.add(fail, now, TAU_FAIL_SHORT);
        }
    }
}

/// How many seconds a decayed counter with time constant `tau` has effectively
/// integrated after `age` seconds (so young baselines are not under-estimated).
fn effective_span(tau: f64, age: f64) -> f64 {
    (tau * (1.0 - (-age / tau).exp())).max(1.0)
}

fn log_ratio(current_rate: f64, baseline_rate: f64) -> f64 {
    ((current_rate + RATE_FLOOR) / (baseline_rate + RATE_FLOOR))
        .ln()
        .clamp(0.0, 5.0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::normalize::{hash_str, normalize_path};
    use std::time::{Duration, SystemTime};

    fn ev(actor: &str, method: &str, path: &str, t: f64) -> (Event, Prepared) {
        let e = Event::new(
            actor,
            method,
            path,
            SystemTime::UNIX_EPOCH + Duration::from_secs_f64(t),
        )
        .with_user_agent("test-agent");
        let n = normalize_path(path);
        let p = Prepared {
            route: hash_str(&[method, &n.template]),
            id: n.id,
            probe: false,
        };
        (e, p)
    }

    fn idx(name: &str) -> usize {
        FEATURE_NAMES.iter().position(|n| *n == name).unwrap()
    }

    #[test]
    fn enumeration_and_failures() {
        let mut fe = FeatureEngine::new(AdaptiveConfig::default(), None);
        let mut f = [0.0; N_FEATURES];
        for i in 0..30 {
            let (e, p) = ev(
                "ip:192.0.2.1",
                "GET",
                &format!("/product/{}", 1000 + i),
                i as f64 * 5.0,
            );
            f = fe.observe_request(&e, &p, i as f64 * 5.0);
            fe.observe_response(&e, &p, 404, i as f64 * 5.0);
        }
        assert!(f[idx("actor_sequential")] > 0.8, "{:?}", f);
        assert!(f[idx("actor_fail_ratio")] > 0.8);
        assert!(f[idx("actor_regularity")] > 0.9);
        assert_eq!(f[idx("actor_route_share")], 1.0);
        assert_eq!(f[idx("actor_new")], (-29.0f64 / 5.0).exp());
    }

    #[test]
    fn route_surge_after_warmup() {
        let mut fe = FeatureEngine::new(AdaptiveConfig::default(), None);
        let mut t = 0.0;
        // baseline: one request every 10s for an hour
        while t < 3600.0 {
            let (e, p) = ev(
                &format!("ip:198.51.100.{}", (t as u64 / 10) % 200),
                "GET",
                "/search?q=a",
                t,
            );
            let f = fe.observe_request(&e, &p, t);
            let s = f[idx("surge_x_client_route_share")];
            assert!(s < 1.0, "no surge at baseline (t={t}): {s}");
            t += 10.0;
        }
        // flood: 50 rps from many IPs, same client fingerprint, one route
        let mut f = [0.0; N_FEATURES];
        for i in 0..3000 {
            let (e, p) = ev(
                &format!("ip:203.0.113.{}", i % 250),
                "GET",
                "/search?q=b",
                t,
            );
            f = fe.observe_request(&e, &p, t);
            t += 0.02;
        }
        let s = f[idx("surge_x_client_route_share")];
        assert!(s > 2.0, "surge: {s}");
    }

    #[test]
    fn baseline_resists_poisoning() {
        let mut fe = FeatureEngine::new(AdaptiveConfig::default(), None);
        let fail_x = idx("fail_surge_x_actor_fail_ratio");
        let mut t = 0.0;
        let mut n = 0u64;
        let mut login = |fe: &mut FeatureEngine, t: f64, status: u16| {
            n += 1;
            let (e, p) = ev(
                &format!("ip:198.51.{}.{}", n / 250 % 250, n % 250),
                "POST",
                "/login",
                t,
            );
            let f = fe.observe_request(&e, &p, t);
            fe.observe_response(&e, &p, status, t);
            f
        };
        // 30 min of normal logins, 10% failures
        while t < 1800.0 {
            login(&mut fe, t, if (t as u64 / 5) % 10 == 0 { 401 } else { 302 });
            t += 5.0;
        }
        // 15 min stuffing wave: 5 failures/s
        while t < 2700.0 {
            login(&mut fe, t, 401);
            t += 0.2;
        }
        // 2 min quiet, then a second wave must still register as a failure surge
        t += 120.0;
        let mut f = [0.0; N_FEATURES];
        for _ in 0..300 {
            f = login(&mut fe, t, 401);
            t += 0.2;
        }
        assert!(f[idx("actor_route_fail_ratio")] < 0.2, "fresh actor");
        let a = ev("ip:192.0.2.9", "POST", "/login", t);
        for _ in 0..3 {
            f = fe.observe_request(&a.0, &a.1, t);
            fe.observe_response(&a.0, &a.1, 401, t);
            t += 1.0;
        }
        assert!(f[fail_x] > 0.2, "second wave still a surge: {}", f[fail_x]);
        assert!(f[idx("actor_route_fail_ratio")] > 0.5);
    }

    #[test]
    fn subnet_masking() {
        let fe = FeatureEngine::new(AdaptiveConfig::default(), None);
        let a = fe.subnet_key("203.0.113.7".parse().unwrap());
        let b = fe.subnet_key("203.0.113.200".parse().unwrap());
        let c = fe.subnet_key("203.0.114.7".parse().unwrap());
        assert_eq!(a, b);
        assert_ne!(a, c);
        let v6a = fe.subnet_key("2001:db8:1:2::1".parse().unwrap());
        let v6b = fe.subnet_key("2001:db8:1:2:ffff::9".parse().unwrap());
        assert_eq!(v6a, v6b);
    }
}
