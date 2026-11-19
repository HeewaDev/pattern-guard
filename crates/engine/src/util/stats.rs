//! Constant-memory streaming statistics.
//!
//! Instead of storing every event, state is kept as exponentially decayed counters:
//! `v(t) = v(t0) * exp(-(t - t0) / tau) + x`. A counter with time constant `tau`
//! approximates "events in the last `tau` seconds" and costs 16 bytes.

/// Exponentially decayed counter. The time constant is passed on each call so the
/// struct stays two floats.
#[derive(Debug, Clone, Copy, Default)]
pub struct Decay {
    v: f64,
    t: f64,
}

impl Decay {
    #[inline]
    pub fn get(&self, now: f64, tau: f64) -> f64 {
        if now <= self.t {
            self.v
        } else {
            self.v * (-(now - self.t) / tau).exp()
        }
    }

    #[inline]
    pub fn add(&mut self, x: f64, now: f64, tau: f64) {
        self.v = self.get(now, tau) + x;
        if now > self.t {
            self.t = now;
        }
    }
}

/// Smoothed ratio `(num + a) / (den + a + b)` — a Beta(a, b) prior so a single
/// observation cannot swing the ratio to 0 or 1.
#[inline]
pub fn smoothed_ratio(num: f64, den: f64, prior_num: f64, prior_den: f64) -> f64 {
    ((num + prior_num) / (den + prior_den)).clamp(0.0, 1.0)
}

/// Exponentially weighted mean/variance of inter-arrival gaps (≈ last 10 gaps).
#[derive(Debug, Clone, Copy, Default)]
pub struct GapStats {
    n: u32,
    mean: f64,
    sq: f64,
}

impl GapStats {
    const ALPHA: f64 = 0.15;

    pub fn push(&mut self, gap: f64) {
        if self.n == 0 {
            self.mean = gap;
            self.sq = gap * gap;
        } else {
            self.mean += Self::ALPHA * (gap - self.mean);
            self.sq += Self::ALPHA * (gap * gap - self.sq);
        }
        self.n = self.n.saturating_add(1);
    }

    /// 1 − coefficient of variation, clamped to [0, 1]; 0 until `min_samples` gaps.
    /// ~1.0 = metronome-like (timer-driven), ~0 = bursty/irregular (human).
    pub fn regularity(&self, min_samples: u32) -> f64 {
        if self.n < min_samples || self.mean <= 1e-3 {
            return 0.0;
        }
        let var = (self.sq - self.mean * self.mean).max(0.0);
        let cv = var.sqrt() / self.mean;
        (1.0 - cv).clamp(0.0, 1.0)
    }
}

/// A handful of decayed counters keyed by u64, evicting the smallest when full.
#[derive(Debug, Clone, Default)]
pub struct TopCounts {
    items: Vec<(u64, Decay)>,
}

impl TopCounts {
    /// Adds `x` to `key`; returns true if `key` was not being tracked.
    pub fn add(&mut self, key: u64, x: f64, now: f64, tau: f64, cap: usize) -> bool {
        if let Some((_, d)) = self.items.iter_mut().find(|(k, _)| *k == key) {
            d.add(x, now, tau);
            return false;
        }
        let mut d = Decay::default();
        d.add(x, now, tau);
        if self.items.len() < cap {
            self.items.push((key, d));
        } else if let Some(slot) = self
            .items
            .iter_mut()
            .min_by(|a, b| a.1.get(now, tau).total_cmp(&b.1.get(now, tau)))
        {
            *slot = (key, d);
        }
        true
    }

    pub fn get(&self, key: u64, now: f64, tau: f64) -> f64 {
        self.items
            .iter()
            .find(|(k, _)| *k == key)
            .map(|(_, d)| d.get(now, tau))
            .unwrap_or(0.0)
    }

    /// Number of keys whose decayed count is at least `min`.
    pub fn active(&self, now: f64, tau: f64, min: f64) -> usize {
        self.items
            .iter()
            .filter(|(_, d)| d.get(now, tau) >= min)
            .count()
    }
}

/// Ring buffer of recently requested (route, numeric id) pairs.
#[derive(Debug, Clone, Default)]
pub struct RecentIds {
    buf: Vec<(u64, u64)>,
    pos: usize,
}

impl RecentIds {
    /// Records `(route, id)`; returns `(seen_before, near_neighbour)` where
    /// `near_neighbour` means a *different* id within `±near` on the same route was
    /// requested recently (sequential enumeration).
    pub fn push(&mut self, route: u64, id: u64, near: u64, cap: usize) -> (bool, bool) {
        let mut seen = false;
        let mut neighbour = false;
        for &(r, i) in &self.buf {
            if r == route {
                if i == id {
                    seen = true;
                } else if i.abs_diff(id) <= near {
                    neighbour = true;
                }
            }
        }
        if self.buf.len() < cap {
            self.buf.push((route, id));
        } else {
            self.buf[self.pos] = (route, id);
            self.pos = (self.pos + 1) % cap;
        }
        (seen, neighbour)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decay_halves_after_ln2_tau() {
        let mut d = Decay::default();
        d.add(10.0, 0.0, 10.0);
        let v = d.get(10.0 * std::f64::consts::LN_2, 10.0);
        assert!((v - 5.0).abs() < 1e-9);
        // late (out-of-order) events do not decay backwards
        d.add(1.0, 1.0, 10.0);
        assert!(d.get(0.5, 10.0) > 0.0);
    }

    #[test]
    fn regularity_separates_timer_from_human() {
        let mut timer = GapStats::default();
        let mut human = GapStats::default();
        let human_gaps = [0.1, 0.2, 25.0, 0.1, 0.3, 40.0, 0.2, 0.1, 18.0, 0.2];
        for g in human_gaps {
            timer.push(2.0);
            human.push(g);
        }
        assert!(timer.regularity(5) > 0.95);
        assert!(human.regularity(5) < 0.2);
        assert_eq!(GapStats::default().regularity(5), 0.0);
    }

    #[test]
    fn top_counts_evicts_smallest() {
        let mut t = TopCounts::default();
        assert!(t.add(1, 5.0, 0.0, 100.0, 2));
        assert!(t.add(2, 1.0, 0.0, 100.0, 2));
        assert!(!t.add(1, 1.0, 0.0, 100.0, 2));
        assert!(t.add(3, 1.0, 0.0, 100.0, 2)); // evicts key 2
        assert_eq!(t.get(2, 0.0, 100.0), 0.0);
        assert!(t.get(1, 0.0, 100.0) > 5.0);
    }

    #[test]
    fn recent_ids_detects_enumeration() {
        let mut r = RecentIds::default();
        assert_eq!(r.push(7, 100, 3, 8), (false, false));
        assert_eq!(r.push(7, 101, 3, 8), (false, true));
        assert_eq!(r.push(7, 101, 3, 8), (true, true));
        assert_eq!(r.push(8, 102, 3, 8), (false, false)); // other route
    }
}
