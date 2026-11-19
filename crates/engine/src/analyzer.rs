//! Explicit threshold rules over a window; combined via max or probabilistic OR.

use crate::config::{EffectiveConfig, RiskCombine};
use crate::tracker::{INTERVAL_MIN_GAPS, WindowStats};

/// 0 at or below `max`, rising linearly to 1 at `2 × max`.
pub fn threshold_risk(value: f64, max: f64) -> f64 {
    if max <= 0.0 || value <= max {
        0.0
    } else {
        ((value - max) / max).min(1.0)
    }
}

pub fn interval_risk(stats: &WindowStats) -> f64 {
    if stats.interval_gaps < INTERVAL_MIN_GAPS {
        return 0.0;
    }
    stats.interval_hits as f64 / stats.interval_gaps as f64
}

/// Returns (combined risk, name of the strongest rule).
pub fn rules_risk(stats: &WindowStats, cfg: &EffectiveConfig) -> (f64, &'static str) {
    let mut risks: Vec<(f64, &'static str)> = Vec::with_capacity(5);
    if let Some(m) = cfg.burst_max_events {
        risks.push((threshold_risk(stats.count as f64, m as f64), "rule:burst"));
    }
    if let Some(m) = cfg.repetition_max_count {
        risks.push((
            threshold_risk(stats.repetition as f64, m as f64),
            "rule:repetition",
        ));
    }
    if let Some(m) = cfg.hopping_max_targets {
        risks.push((
            threshold_risk(stats.distinct_targets as f64, m as f64),
            "rule:hopping",
        ));
    }
    if let Some(m) = cfg.weight_max_total {
        risks.push((threshold_risk(stats.weight_sum, m), "rule:weight"));
    }
    if cfg.interval_secs.is_some() {
        risks.push((interval_risk(stats), "rule:interval"));
    }
    let top = risks
        .iter()
        .copied()
        .max_by(|a, b| a.0.total_cmp(&b.0))
        .unwrap_or((0.0, "rule:none"));
    let combined = match cfg.risk_combine {
        RiskCombine::Max => top.0,
        RiskCombine::WeightedSum => 1.0 - risks.iter().map(|(r, _)| 1.0 - r).product::<f64>(),
    };
    (combined.clamp(0.0, 1.0), top.1)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;

    fn stats(count: usize) -> WindowStats {
        WindowStats {
            count,
            repetition: 0,
            distinct_targets: 0,
            weight_sum: 0.0,
            interval_gaps: 0,
            interval_hits: 0,
        }
    }

    #[test]
    fn threshold_risk_shape() {
        assert_eq!(threshold_risk(0.0, 100.0), 0.0);
        assert_eq!(threshold_risk(100.0, 100.0), 0.0);
        assert!(threshold_risk(101.0, 100.0) > 0.0);
        assert_eq!(threshold_risk(200.0, 100.0), 1.0);
    }

    #[test]
    fn interval_needs_enough_gaps() {
        let mut s = stats(2);
        s.interval_gaps = 1;
        s.interval_hits = 1;
        assert_eq!(
            interval_risk(&s),
            0.0,
            "two requests 2s apart must not block"
        );
        s.interval_gaps = 8;
        s.interval_hits = 8;
        assert_eq!(interval_risk(&s), 1.0);
    }

    #[test]
    fn disabled_rules_contribute_nothing() {
        let cfg = Config::default().guard.for_actor("a");
        assert_eq!(rules_risk(&stats(1_000_000), &cfg).0, 0.0);
    }

    #[test]
    fn weighted_sum_is_monotonic() {
        let cfg = Config::from_toml_str(
            "[guard]\nrisk_combine = \"weighted_sum\"\nburst_max_events = 10\nrepetition_max_count = 10\n",
        )
        .unwrap()
        .guard
        .for_actor("a");
        let mut s = stats(20); // burst risk 1.0
        let alone = rules_risk(&s, &cfg).0;
        s.repetition = 11; // add a weak signal
        let both = rules_risk(&s, &cfg).0;
        assert_eq!(alone, 1.0);
        assert!(both >= alone, "extra evidence must not lower risk");
        let mut s = stats(15);
        let a = rules_risk(&s, &cfg).0;
        s.repetition = 15;
        assert!(rules_risk(&s, &cfg).0 > a);
    }
}
