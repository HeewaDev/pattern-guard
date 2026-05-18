//! Config; see docs/CONFIG.md.

use serde::Deserialize;
use std::collections::HashMap;
use std::num::NonZeroUsize;
use std::path::Path;
use std::time::Duration;

use crate::decision::Decision;
use crate::error::Error;

/// How independent pattern risks are merged into one score.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskCombine {
    #[default]
    Max,
    WeightedSum,
}

#[derive(Debug, Deserialize)]
pub struct Config {
    pub guard: GuardConfig,
}

#[derive(Debug, Deserialize)]
pub struct GuardConfig {
    #[serde(default = "default_window_secs")]
    pub window_secs: u64,
    #[serde(default = "default_burst_max_events")]
    pub burst_max_events: u32,
    #[serde(default = "default_repetition_max_count")]
    pub repetition_max_count: u32,
    #[serde(default = "default_hopping_max_targets")]
    pub hopping_max_targets: u32,
    #[serde(default = "default_weight_max_total")]
    pub weight_max_total: f64,
    pub interval_secs: Option<f64>,
    #[serde(default = "default_interval_tolerance_ratio")]
    pub interval_tolerance_ratio: f64,
    #[serde(default)]
    pub risk_combine: RiskCombine,
    #[serde(default = "default_allow_below")]
    pub allow_below: f64,
    #[serde(default = "default_warn_below")]
    pub warn_below: f64,
    #[serde(default = "default_delay_below")]
    pub delay_below: f64,
    #[serde(default = "default_delay_secs")]
    pub delay_secs: f64,
    /// When set, at most this many distinct actors are retained; least-recently-used actors are dropped.
    #[serde(default)]
    pub max_actors: Option<NonZeroUsize>,
    #[serde(default)]
    pub actors: HashMap<String, ActorOverride>,
}

/// Per-actor fields; omitted keys inherit from `[guard]`.
#[derive(Debug, Default, Deserialize)]
pub struct ActorOverride {
    #[serde(default)]
    pub window_secs: Option<u64>,
    #[serde(default)]
    pub burst_max_events: Option<u32>,
    #[serde(default)]
    pub repetition_max_count: Option<u32>,
    #[serde(default)]
    pub hopping_max_targets: Option<u32>,
    #[serde(default)]
    pub weight_max_total: Option<f64>,
    #[serde(default)]
    pub interval_secs: Option<f64>,
    #[serde(default)]
    pub interval_tolerance_ratio: Option<f64>,
    #[serde(default)]
    pub risk_combine: Option<RiskCombine>,
    #[serde(default)]
    pub allow_below: Option<f64>,
    #[serde(default)]
    pub warn_below: Option<f64>,
    #[serde(default)]
    pub delay_below: Option<f64>,
    #[serde(default)]
    pub delay_secs: Option<f64>,
}

fn default_window_secs() -> u64 {
    300
}
fn default_burst_max_events() -> u32 {
    100
}
fn default_repetition_max_count() -> u32 {
    10
}
fn default_hopping_max_targets() -> u32 {
    50
}
fn default_weight_max_total() -> f64 {
    1000.0
}
fn default_interval_tolerance_ratio() -> f64 {
    0.2
}
fn default_allow_below() -> f64 {
    0.3
}
fn default_warn_below() -> f64 {
    0.6
}
fn default_delay_below() -> f64 {
    0.85
}
fn default_delay_secs() -> f64 {
    5.0
}

impl Config {
    pub fn load(path: impl AsRef<Path>) -> Result<Self, Error> {
        let path = path.as_ref();
        let s =
            std::fs::read_to_string(path).map_err(|e| Error::ConfigLoad(path.to_path_buf(), e))?;
        let config: Config = toml::from_str(&s).map_err(Error::ConfigParse)?;
        Ok(config)
    }
}

impl GuardConfig {
    /// Effective config: `[guard]` values merged with `[guard.actors."id"]` when present.
    pub fn for_actor(&self, actor_id: &str) -> EffectiveConfig {
        let o = self.actors.get(actor_id);
        EffectiveConfig {
            window_secs: o.and_then(|a| a.window_secs).unwrap_or(self.window_secs),
            burst_max_events: o
                .and_then(|a| a.burst_max_events)
                .unwrap_or(self.burst_max_events),
            repetition_max_count: o
                .and_then(|a| a.repetition_max_count)
                .unwrap_or(self.repetition_max_count),
            hopping_max_targets: o
                .and_then(|a| a.hopping_max_targets)
                .unwrap_or(self.hopping_max_targets),
            weight_max_total: o
                .and_then(|a| a.weight_max_total)
                .unwrap_or(self.weight_max_total),
            interval_secs: o.and_then(|a| a.interval_secs).or(self.interval_secs),
            interval_tolerance_ratio: o
                .and_then(|a| a.interval_tolerance_ratio)
                .unwrap_or(self.interval_tolerance_ratio),
            risk_combine: o.and_then(|a| a.risk_combine).unwrap_or(self.risk_combine),
            allow_below: o.and_then(|a| a.allow_below).unwrap_or(self.allow_below),
            warn_below: o.and_then(|a| a.warn_below).unwrap_or(self.warn_below),
            delay_below: o.and_then(|a| a.delay_below).unwrap_or(self.delay_below),
            delay_secs: o.and_then(|a| a.delay_secs).unwrap_or(self.delay_secs),
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct EffectiveConfig {
    pub window_secs: u64,
    pub burst_max_events: u32,
    pub repetition_max_count: u32,
    pub hopping_max_targets: u32,
    pub weight_max_total: f64,
    pub interval_secs: Option<f64>,
    pub interval_tolerance_ratio: f64,
    pub risk_combine: RiskCombine,
    pub allow_below: f64,
    pub warn_below: f64,
    pub delay_below: f64,
    pub delay_secs: f64,
}

impl EffectiveConfig {
    pub fn risk_to_decision(&self, risk: f64) -> Decision {
        if risk < self.allow_below {
            Decision::Allow
        } else if risk < self.warn_below {
            Decision::Warn
        } else if risk < self.delay_below {
            Decision::Delay(Duration::from_secs_f64(self.delay_secs))
        } else {
            Decision::Block
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_parse() {
        let s = r#"[guard]
window_secs = 60
burst_max_events = 3
"#;
        let config: Config = toml::from_str(s).unwrap();
        assert_eq!(config.guard.window_secs, 60);
        assert_eq!(config.guard.burst_max_events, 3);
    }

    #[test]
    fn config_for_actor_inherits_parent_window() {
        let s = r#"[guard]
window_secs = 120
burst_max_events = 100
[guard.actors."bot"]
burst_max_events = 5
"#;
        let config: Config = toml::from_str(s).unwrap();
        let eff = config.guard.for_actor("bot");
        assert_eq!(eff.burst_max_events, 5);
        assert_eq!(eff.window_secs, 120);
        let other = config.guard.for_actor("other");
        assert_eq!(other.burst_max_events, 100);
        assert_eq!(other.window_secs, 120);
    }

    #[test]
    fn config_for_actor_override_interval() {
        let s = r#"[guard]
interval_secs = 2.0
[guard.actors."fast"]
interval_secs = 0.5
"#;
        let config: Config = toml::from_str(s).unwrap();
        assert_eq!(config.guard.for_actor("fast").interval_secs, Some(0.5));
        assert_eq!(config.guard.for_actor("other").interval_secs, Some(2.0));
    }

    #[test]
    fn risk_combine_deserializes() {
        let s = r#"[guard]
risk_combine = "weighted_sum"
"#;
        let config: Config = toml::from_str(s).unwrap();
        assert_eq!(config.guard.risk_combine, RiskCombine::WeightedSum);
    }

    #[test]
    fn risk_combine_invalid_rejected() {
        let s = r#"[guard]
risk_combine = "not_a_mode"
"#;
        assert!(toml::from_str::<Config>(s).is_err());
    }

    #[test]
    fn max_actors_optional() {
        let s = r#"[guard]
max_actors = 64
"#;
        let config: Config = toml::from_str(s).unwrap();
        assert_eq!(config.guard.max_actors.map(|n| n.get()), Some(64));
    }
}
