//! Config; see docs/CONFIG.md.

use serde::Deserialize;
use std::collections::HashMap;
use std::num::NonZeroUsize;
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::decision::Decision;
use crate::error::Error;

/// How independent rule risks are merged into one score.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskCombine {
    /// Highest single rule risk.
    #[default]
    Max,
    /// Probabilistic OR: `1 − Π(1 − r)`. Every extra signal can only raise the risk.
    WeightedSum,
}

/// Which detectors run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Mode {
    /// Only the explicit threshold rules (`burst_max_events`, …).
    Rules,
    /// Only the adaptive ML engine.
    Adaptive,
    /// Both; final risk is the max of the two.
    #[default]
    Hybrid,
}

/// Which clock drives sliding windows and decay.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TimeSource {
    /// `Event::timestamp` (monotonised: never moves backwards). Required for log replay.
    #[default]
    Event,
    /// The process's monotonic clock at check time; `Event::timestamp` is ignored.
    System,
}

#[derive(Debug, Default, Deserialize)]
pub struct Config {
    #[serde(default)]
    pub guard: GuardConfig,
}

#[derive(Debug, Deserialize)]
pub struct GuardConfig {
    #[serde(default)]
    pub mode: Mode,
    #[serde(default)]
    pub time_source: TimeSource,
    /// Collapse ids in paths (`/product/123` → `/product/{n}`) before rules and features.
    #[serde(default = "default_true")]
    pub normalize_targets: bool,

    // ---- explicit rules (opt-in hard limits; unset = rule disabled) ----
    #[serde(default = "default_window_secs")]
    pub window_secs: u64,
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
    #[serde(default = "default_interval_tolerance_ratio")]
    pub interval_tolerance_ratio: f64,
    #[serde(default)]
    pub risk_combine: RiskCombine,

    // ---- risk → decision ----
    #[serde(default = "default_allow_below")]
    pub allow_below: f64,
    #[serde(default = "default_warn_below")]
    pub warn_below: f64,
    #[serde(default = "default_delay_below")]
    pub delay_below: f64,
    /// When set, risk in `[delay_below, challenge_below)` → `Challenge`.
    #[serde(default)]
    pub challenge_below: Option<f64>,
    #[serde(default = "default_delay_secs")]
    pub delay_secs: f64,
    /// After a `Block`, keep blocking that actor for this many seconds (0 = off).
    #[serde(default = "default_cooldown_secs")]
    pub cooldown_secs: f64,
    /// Blocks within roughly `cooldown_secs` needed before the cooldown kicks in, so a
    /// single borderline block never locks a user out.
    #[serde(default = "default_cooldown_after_blocks")]
    pub cooldown_after_blocks: u32,

    /// At most this many distinct actors are retained (LRU). Default 100 000.
    #[serde(default = "default_max_actors")]
    pub max_actors: Option<NonZeroUsize>,

    /// Path to a trained model (TOML). Relative paths resolve against the config file.
    /// Unset = built-in default model.
    #[serde(default)]
    pub model: Option<PathBuf>,

    #[serde(default)]
    pub adaptive: AdaptiveConfig,

    #[serde(default)]
    pub actors: HashMap<String, ActorOverride>,
}

/// Tuning for the adaptive engine. Defaults are sensible for HTTP traffic.
#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct AdaptiveConfig {
    /// Seconds a route must be observed before its learned baseline is trusted.
    #[serde(default = "default_warmup_secs")]
    pub warmup_secs: f64,
    /// Prefix length used to group IPv4 clients into networks.
    #[serde(default = "default_ipv4_prefix")]
    pub ipv4_prefix: u8,
    /// Prefix length used to group IPv6 clients into networks.
    #[serde(default = "default_ipv6_prefix")]
    pub ipv6_prefix: u8,
    #[serde(default = "default_max_routes")]
    pub max_routes: NonZeroUsize,
    #[serde(default = "default_max_clients")]
    pub max_fingerprints: NonZeroUsize,
    #[serde(default = "default_max_clients")]
    pub max_subnets: NonZeroUsize,
    /// Extra path substrings to treat as scanner probes (case-insensitive).
    #[serde(default)]
    pub probe_paths: Vec<String>,
}

impl Default for AdaptiveConfig {
    fn default() -> Self {
        Self {
            warmup_secs: default_warmup_secs(),
            ipv4_prefix: default_ipv4_prefix(),
            ipv6_prefix: default_ipv6_prefix(),
            max_routes: default_max_routes(),
            max_fingerprints: default_max_clients(),
            max_subnets: default_max_clients(),
            probe_paths: Vec::new(),
        }
    }
}

/// Per-actor fields; omitted keys inherit from `[guard]`.
#[derive(Debug, Default, Deserialize)]
pub struct ActorOverride {
    /// Always `Allow` (still observed so baselines stay accurate). For monitors, partners, internal jobs.
    #[serde(default)]
    pub trusted: Option<bool>,
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
    pub challenge_below: Option<f64>,
    #[serde(default)]
    pub delay_secs: Option<f64>,
    #[serde(default)]
    pub cooldown_secs: Option<f64>,
}

fn default_true() -> bool {
    true
}
fn default_window_secs() -> u64 {
    300
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
fn default_cooldown_secs() -> f64 {
    60.0
}
fn default_cooldown_after_blocks() -> u32 {
    3
}
fn default_max_actors() -> Option<NonZeroUsize> {
    NonZeroUsize::new(100_000)
}
fn default_warmup_secs() -> f64 {
    300.0
}
fn default_ipv4_prefix() -> u8 {
    24
}
fn default_ipv6_prefix() -> u8 {
    56
}
fn default_max_routes() -> NonZeroUsize {
    NonZeroUsize::new(10_000).unwrap()
}
fn default_max_clients() -> NonZeroUsize {
    NonZeroUsize::new(50_000).unwrap()
}

impl Default for GuardConfig {
    fn default() -> Self {
        toml::from_str("").expect("every GuardConfig field has a serde default")
    }
}

impl Config {
    pub fn load(path: impl AsRef<Path>) -> Result<Self, Error> {
        let path = path.as_ref();
        let s =
            std::fs::read_to_string(path).map_err(|e| Error::ConfigLoad(path.to_path_buf(), e))?;
        let mut config = Self::from_toml_str(&s)?;
        if let (Some(m), Some(dir)) = (&config.guard.model, path.parent()) {
            if m.is_relative() {
                config.guard.model = Some(dir.join(m));
            }
        }
        Ok(config)
    }

    pub fn from_toml_str(s: &str) -> Result<Self, Error> {
        let config: Config = toml::from_str(s).map_err(Error::ConfigParse)?;
        config.validate()?;
        Ok(config)
    }

    pub fn validate(&self) -> Result<(), Error> {
        let g = &self.guard;
        g.for_actor("").validate("[guard]")?;
        for id in g.actors.keys() {
            g.for_actor(id)
                .validate(&format!("[guard.actors.\"{id}\"]"))?;
        }
        let a = &g.adaptive;
        if a.ipv4_prefix > 32 || a.ipv6_prefix > 128 {
            return Err(Error::ConfigInvalid(
                "adaptive.ipv4_prefix must be ≤ 32 and ipv6_prefix ≤ 128".into(),
            ));
        }
        Ok(())
    }
}

impl GuardConfig {
    /// Effective config: `[guard]` values merged with `[guard.actors."id"]` when present.
    pub fn for_actor(&self, actor_id: &str) -> EffectiveConfig {
        let o = self.actors.get(actor_id);
        EffectiveConfig {
            trusted: o.and_then(|a| a.trusted).unwrap_or(false),
            window_secs: o.and_then(|a| a.window_secs).unwrap_or(self.window_secs),
            burst_max_events: o.and_then(|a| a.burst_max_events).or(self.burst_max_events),
            repetition_max_count: o
                .and_then(|a| a.repetition_max_count)
                .or(self.repetition_max_count),
            hopping_max_targets: o
                .and_then(|a| a.hopping_max_targets)
                .or(self.hopping_max_targets),
            weight_max_total: o.and_then(|a| a.weight_max_total).or(self.weight_max_total),
            interval_secs: o.and_then(|a| a.interval_secs).or(self.interval_secs),
            interval_tolerance_ratio: o
                .and_then(|a| a.interval_tolerance_ratio)
                .unwrap_or(self.interval_tolerance_ratio),
            risk_combine: o.and_then(|a| a.risk_combine).unwrap_or(self.risk_combine),
            allow_below: o.and_then(|a| a.allow_below).unwrap_or(self.allow_below),
            warn_below: o.and_then(|a| a.warn_below).unwrap_or(self.warn_below),
            delay_below: o.and_then(|a| a.delay_below).unwrap_or(self.delay_below),
            challenge_below: o.and_then(|a| a.challenge_below).or(self.challenge_below),
            delay_secs: o.and_then(|a| a.delay_secs).unwrap_or(self.delay_secs),
            cooldown_secs: o
                .and_then(|a| a.cooldown_secs)
                .unwrap_or(self.cooldown_secs),
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct EffectiveConfig {
    pub trusted: bool,
    pub window_secs: u64,
    pub burst_max_events: Option<u32>,
    pub repetition_max_count: Option<u32>,
    pub hopping_max_targets: Option<u32>,
    pub weight_max_total: Option<f64>,
    pub interval_secs: Option<f64>,
    pub interval_tolerance_ratio: f64,
    pub risk_combine: RiskCombine,
    pub allow_below: f64,
    pub warn_below: f64,
    pub delay_below: f64,
    pub challenge_below: Option<f64>,
    pub delay_secs: f64,
    pub cooldown_secs: f64,
}

impl EffectiveConfig {
    pub fn rules_enabled(&self) -> bool {
        self.burst_max_events.is_some()
            || self.repetition_max_count.is_some()
            || self.hopping_max_targets.is_some()
            || self.weight_max_total.is_some()
            || self.interval_secs.is_some()
    }

    pub fn risk_to_decision(&self, risk: f64) -> Decision {
        if risk < self.allow_below {
            Decision::Allow
        } else if risk < self.warn_below {
            Decision::Warn
        } else if risk < self.delay_below {
            Decision::Delay(Duration::from_secs_f64(self.delay_secs.max(0.0)))
        } else if self.challenge_below.is_some_and(|c| risk < c) {
            Decision::Challenge
        } else {
            Decision::Block
        }
    }

    fn validate(&self, section: &str) -> Result<(), Error> {
        let bad = |m: String| Err(Error::ConfigInvalid(format!("{section}: {m}")));
        let mut bands = vec![self.allow_below, self.warn_below, self.delay_below];
        bands.extend(self.challenge_below);
        if bands.iter().any(|b| !(0.0..=1.0).contains(b)) {
            return bad("risk bands must be within [0, 1]".into());
        }
        if bands.windows(2).any(|w| w[0] > w[1]) {
            return bad(
                "risk bands must satisfy allow_below ≤ warn_below ≤ delay_below ≤ challenge_below"
                    .into(),
            );
        }
        if self.delay_secs < 0.0 || self.cooldown_secs < 0.0 || !self.delay_secs.is_finite() {
            return bad("delay_secs and cooldown_secs must be ≥ 0".into());
        }
        if self.window_secs == 0 {
            return bad("window_secs must be ≥ 1".into());
        }
        for (k, v) in [
            ("burst_max_events", self.burst_max_events),
            ("repetition_max_count", self.repetition_max_count),
            ("hopping_max_targets", self.hopping_max_targets),
        ] {
            if v == Some(0) {
                return bad(format!("{k} must be ≥ 1 (omit it to disable the rule)"));
            }
        }
        if self.weight_max_total.is_some_and(|w| w <= 0.0) {
            return bad("weight_max_total must be > 0".into());
        }
        if self.interval_secs.is_some_and(|t| t <= 0.0) {
            return bad("interval_secs must be > 0".into());
        }
        Ok(())
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
        let config = Config::from_toml_str(s).unwrap();
        assert_eq!(config.guard.window_secs, 60);
        assert_eq!(config.guard.burst_max_events, Some(3));
        assert_eq!(config.guard.mode, Mode::Hybrid);
        assert_eq!(config.guard.time_source, TimeSource::Event);
    }

    #[test]
    fn empty_config_is_valid_and_rules_off() {
        let config = Config::from_toml_str("").unwrap();
        assert!(!config.guard.for_actor("x").rules_enabled());
        assert_eq!(config.guard.max_actors.map(|n| n.get()), Some(100_000));
    }

    #[test]
    fn config_for_actor_inherits_parent_window() {
        let s = r#"[guard]
window_secs = 120
burst_max_events = 100
[guard.actors."bot"]
burst_max_events = 5
"#;
        let config = Config::from_toml_str(s).unwrap();
        let eff = config.guard.for_actor("bot");
        assert_eq!(eff.burst_max_events, Some(5));
        assert_eq!(eff.window_secs, 120);
        let other = config.guard.for_actor("other");
        assert_eq!(other.burst_max_events, Some(100));
        assert_eq!(other.window_secs, 120);
    }

    #[test]
    fn config_for_actor_override_interval() {
        let s = r#"[guard]
interval_secs = 2.0
[guard.actors."fast"]
interval_secs = 0.5
"#;
        let config = Config::from_toml_str(s).unwrap();
        assert_eq!(config.guard.for_actor("fast").interval_secs, Some(0.5));
        assert_eq!(config.guard.for_actor("other").interval_secs, Some(2.0));
    }

    #[test]
    fn trusted_actor() {
        let s = r#"[guard.actors."ip:10.0.0.1"]
trusted = true
"#;
        let config = Config::from_toml_str(s).unwrap();
        assert!(config.guard.for_actor("ip:10.0.0.1").trusted);
        assert!(!config.guard.for_actor("ip:10.0.0.2").trusted);
    }

    #[test]
    fn risk_combine_deserializes() {
        let config = Config::from_toml_str("[guard]\nrisk_combine = \"weighted_sum\"\n").unwrap();
        assert_eq!(config.guard.risk_combine, RiskCombine::WeightedSum);
    }

    #[test]
    fn invalid_values_rejected() {
        assert!(Config::from_toml_str("[guard]\nrisk_combine = \"nope\"\n").is_err());
        assert!(Config::from_toml_str("[guard]\nmode = \"magic\"\n").is_err());
        assert!(Config::from_toml_str("[guard]\nallow_below = 0.9\nwarn_below = 0.5\n").is_err());
        assert!(Config::from_toml_str("[guard]\nburst_max_events = 0\n").is_err());
        assert!(Config::from_toml_str("[guard]\nchallenge_below = 0.5\n").is_err());
        assert!(
            Config::from_toml_str("[guard.actors.\"a\"]\nwarn_below = 2.0\n").is_err(),
            "per-actor bands are validated too"
        );
    }

    #[test]
    fn challenge_band() {
        let config = Config::from_toml_str("[guard]\nchallenge_below = 0.95\n").unwrap();
        let eff = config.guard.for_actor("a");
        assert_eq!(eff.risk_to_decision(0.9), Decision::Challenge);
        assert_eq!(eff.risk_to_decision(0.97), Decision::Block);
        let plain = Config::default().guard.for_actor("a");
        assert_eq!(plain.risk_to_decision(0.9), Decision::Block);
    }

    #[test]
    fn max_actors_optional() {
        let config = Config::from_toml_str("[guard]\nmax_actors = 64\n").unwrap();
        assert_eq!(config.guard.max_actors.map(|n| n.get()), Some(64));
    }
}
