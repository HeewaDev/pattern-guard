//! Risk from patterns; combined via max or weighted_sum.

use crate::config::{EffectiveConfig, RiskCombine};
use crate::event::Event;

pub fn burst_risk(count: usize, max_events: u32) -> f64 {
    let n = max_events as usize;
    if count <= n {
        0.0
    } else {
        ((count - n) as f64 / n as f64).min(1.0)
    }
}

pub fn compute_risk(events: &[Event], config: &EffectiveConfig) -> f64 {
    let burst = burst_risk(events.len(), config.burst_max_events);
    let repetition = repetition_risk(events, config.repetition_max_count);
    let hopping = hopping_risk(events, config.hopping_max_targets);
    let weight = weighted_risk(events, config.weight_max_total);
    let interval = interval_risk(
        events,
        config.interval_secs,
        config.interval_tolerance_ratio,
    );
    combine_risk(&[burst, repetition, hopping, weight, interval], config)
}

fn combine_risk(risks: &[f64], config: &EffectiveConfig) -> f64 {
    let effective: Vec<f64> = risks.iter().copied().filter(|r| *r > 0.0).collect();
    if effective.is_empty() {
        return 0.0;
    }
    match config.risk_combine {
        RiskCombine::WeightedSum => {
            (effective.iter().sum::<f64>() / effective.len() as f64).min(1.0)
        }
        RiskCombine::Max => effective.into_iter().fold(0.0_f64, f64::max),
    }
}

pub fn repetition_risk(events: &[Event], max_count: u32) -> f64 {
    use std::collections::HashMap;
    let mut counts: HashMap<(String, String), usize> = HashMap::new();
    for e in events {
        *counts
            .entry((e.action.clone(), e.target.clone()))
            .or_default() += 1;
    }
    let max = counts.values().copied().max().unwrap_or(0);
    let n = max_count as usize;
    if max <= n {
        0.0
    } else {
        ((max - n) as f64 / n as f64).min(1.0)
    }
}

pub fn hopping_risk(events: &[Event], max_targets: u32) -> f64 {
    use std::collections::HashSet;
    let distinct: HashSet<&str> = events.iter().map(|e| e.target.as_str()).collect();
    let k = max_targets as usize;
    if distinct.len() <= k {
        0.0
    } else {
        ((distinct.len() - k) as f64 / k as f64).min(1.0)
    }
}

pub fn weighted_risk(events: &[Event], max_total: f64) -> f64 {
    let sum: f64 = events.iter().map(Event::effective_weight).sum();
    if sum <= max_total {
        0.0
    } else {
        ((sum - max_total) / max_total).min(1.0)
    }
}

pub fn interval_risk(events: &[Event], expected_secs: Option<f64>, tolerance_ratio: f64) -> f64 {
    let Some(t) = expected_secs else { return 0.0 };
    if events.len() < 2 {
        return 0.0;
    }
    let mut timestamps: Vec<std::time::Duration> = events
        .iter()
        .map(|e| {
            e.timestamp
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
        })
        .collect();
    timestamps.sort();
    let gaps: Vec<f64> = timestamps
        .windows(2)
        .map(|w| (w[1].as_secs_f64() - w[0].as_secs_f64()).abs())
        .collect();
    if gaps.is_empty() {
        return 0.0;
    }
    let tolerance = t * tolerance_ratio;
    let within = gaps.iter().filter(|g| (*g - t).abs() <= tolerance).count();
    let ratio = within as f64 / gaps.len() as f64;
    ratio.min(1.0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::RiskCombine;
    use std::time::UNIX_EPOCH;

    fn default_config() -> EffectiveConfig {
        EffectiveConfig {
            window_secs: 60,
            burst_max_events: 10,
            repetition_max_count: 5,
            hopping_max_targets: 20,
            weight_max_total: 100.0,
            interval_secs: None,
            interval_tolerance_ratio: 0.2,
            risk_combine: RiskCombine::Max,
            allow_below: 0.3,
            warn_below: 0.6,
            delay_below: 0.85,
            delay_secs: 5.0,
        }
    }

    #[test]
    fn burst_risk_below_threshold() {
        assert_eq!(burst_risk(0, 100), 0.0);
        assert_eq!(burst_risk(100, 100), 0.0);
    }

    #[test]
    fn burst_risk_above_threshold() {
        assert!(burst_risk(101, 100) > 0.0);
        assert_eq!(burst_risk(200, 100), 1.0);
    }

    #[test]
    fn repetition_risk_pattern() {
        let mut events = Vec::new();
        for _ in 0..6 {
            events.push(Event::new("a", "GET", "/x", UNIX_EPOCH));
        }
        assert!(repetition_risk(&events, 5) > 0.0);
        assert_eq!(repetition_risk(&events, 10), 0.0);
    }

    #[test]
    fn hopping_risk_pattern() {
        let mut events = Vec::new();
        for t in ["/a", "/b", "/c", "/d", "/e", "/f"] {
            events.push(Event::new("a", "GET", t, UNIX_EPOCH));
        }
        assert!(hopping_risk(&events, 3) > 0.0);
        assert_eq!(hopping_risk(&events, 10), 0.0);
    }

    #[test]
    fn weighted_risk_pattern() {
        let mut events = Vec::new();
        for _ in 0..11 {
            events.push(Event::new("a", "x", "y", UNIX_EPOCH).with_weight(10.0));
        }
        assert!(weighted_risk(&events, 100.0) > 0.0);
        assert_eq!(weighted_risk(&events, 1000.0), 0.0);
    }

    #[test]
    fn compute_risk_combines_burst() {
        let config = default_config();
        let events: Vec<Event> = (0..15)
            .map(|i| Event::new("a", "run", format!("{}", i), UNIX_EPOCH))
            .collect();
        let risk = compute_risk(&events, &config);
        assert!(risk > 0.0);
    }

    #[test]
    fn interval_risk_high_when_regular() {
        let t0 = UNIX_EPOCH;
        let t1 = t0 + std::time::Duration::from_secs(10);
        let t2 = t1 + std::time::Duration::from_secs(10);
        let events = vec![
            Event::new("a", "x", "y", t0),
            Event::new("a", "x", "y", t1),
            Event::new("a", "x", "y", t2),
        ];
        let r = interval_risk(&events, Some(10.0), 0.2);
        assert!(r > 0.9, "regular 10s gaps should score high, got {}", r);
    }

    #[test]
    fn interval_risk_zero_when_irregular() {
        let events = vec![
            Event::new("a", "x", "y", UNIX_EPOCH),
            Event::new(
                "a",
                "x",
                "y",
                UNIX_EPOCH + std::time::Duration::from_secs(3),
            ),
            Event::new(
                "a",
                "x",
                "y",
                UNIX_EPOCH + std::time::Duration::from_secs(100),
            ),
        ];
        let r = interval_risk(&events, Some(10.0), 0.2);
        assert!(r < 0.5, "irregular gaps should score lower, got {}", r);
    }

    #[test]
    fn interval_risk_disabled_without_expected() {
        let events = vec![
            Event::new("a", "x", "y", UNIX_EPOCH),
            Event::new(
                "a",
                "x",
                "y",
                UNIX_EPOCH + std::time::Duration::from_secs(10),
            ),
        ];
        assert_eq!(interval_risk(&events, None, 0.2), 0.0);
    }

    #[test]
    fn weighted_sum_averages_nonzero_risks() {
        let mut c = default_config();
        c.risk_combine = RiskCombine::WeightedSum;
        c.burst_max_events = 5;
        c.repetition_max_count = 2;
        let events: Vec<Event> = (0..8)
            .map(|_| Event::new("a", "GET", "/same", UNIX_EPOCH))
            .collect();
        let risk = compute_risk(&events, &c);
        let burst = burst_risk(events.len(), c.burst_max_events);
        let rep = repetition_risk(&events, c.repetition_max_count);
        let expected = ((burst + rep) / 2.0).min(1.0);
        assert!(
            (risk - expected).abs() < 1e-9,
            "risk {} expected ~{}",
            risk,
            expected
        );
    }
}
