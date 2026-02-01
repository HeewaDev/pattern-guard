//! Config; see docs/CONFIG.md.

use serde::Deserialize;
use std::collections::HashMap;
use std::path::Path;
use std::time::Duration;

use crate::decision::Decision;
use crate::error::Error;

#[derive(Debug, Deserialize)]
pub struct Config {
    pub guard: GuardConfig,
}

#[derive(Debug, Deserialize, Default)]
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
    #[serde(default = "default_risk_combine")]
    pub risk_combine: String,
    #[serde(default = "default_allow_below")]
    pub allow_below: f64,
    #[serde(default = "default_warn_below")]
    pub warn_below: f64,
    #[serde(default = "default_delay_below")]
    pub delay_below: f64,
    #[serde(default = "default_delay_secs")]
    pub delay_secs: f64,
    #[serde(default)]
    pub actors: HashMap<String, GuardConfig>,
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
fn default_risk_combine() -> String {
    "max".into()
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
        let s = std::fs::read_to_string(path).map_err(|e| Error::ConfigLoad(path.to_path_buf(), e))?;
        let config: Config = toml::from_str(&s).map_err(Error::ConfigParse)?;
        Ok(config)
    }
}

impl GuardConfig {
    /// Effective config for an entity. Per-actor overrides (when present) are full configs with defaults for missing keys.
    pub fn for_actor(&self, actor_id: &str) -> EffectiveConfig {
        let g = self.actors.get(actor_id).unwrap_or(self);
        EffectiveConfig {
            window_secs: g.window_secs,
            burst_max_events: g.burst_max_events,
            repetition_max_count: g.repetition_max_count,
            hopping_max_targets: g.hopping_max_targets,
            weight_max_total: g.weight_max_total,
            interval_secs: g.interval_secs,
            interval_tolerance_ratio: g.interval_tolerance_ratio,
            risk_combine: g.risk_combine.clone(),
            allow_below: g.allow_below,
            warn_below: g.warn_below,
            delay_below: g.delay_below,
            delay_secs: g.delay_secs,
        }
    }
}

#[derive(Debug, Clone)]
pub struct EffectiveConfig {
    pub window_secs: u64,
    pub burst_max_events: u32,
    pub repetition_max_count: u32,
    pub hopping_max_targets: u32,
    pub weight_max_total: f64,
    pub interval_secs: Option<f64>,
    pub interval_tolerance_ratio: f64,
    pub risk_combine: String,
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
    fn config_for_actor_override() {
        let s = r#"[guard]
window_secs = 300
burst_max_events = 100
[guard.actors."bot"]
burst_max_events = 5
"#;
        let config: Config = toml::from_str(s).unwrap();
        let eff = config.guard.for_actor("bot");
        assert_eq!(eff.burst_max_events, 5);
        assert_eq!(eff.window_secs, 300);
        let default = config.guard.for_actor("other");
        assert_eq!(default.burst_max_events, 100);
    }
}
