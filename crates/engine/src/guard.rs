use std::num::NonZeroUsize;
use std::path::Path;
use std::sync::{Mutex, MutexGuard, PoisonError};
use std::time::Instant;

use lru::LruCache;

use crate::config::{Config, EffectiveConfig, Mode, TimeSource};
use crate::decision::Decision;
use crate::error::Error;
use crate::event::Event;
use crate::ml::features::{FEATURE_NAMES, FeatureEngine, Features, N_FEATURES, Prepared};
use crate::ml::model::Model;
use crate::rules::analyzer;
use crate::rules::tracker::Tracker;
use crate::util::normalize::{hash_str, is_probe_path, normalize_path};
use crate::util::stats::Decay;

/// Why a request scored the way it did.
#[derive(Debug, Clone, PartialEq)]
pub struct Reason {
    /// Feature name (see [`FEATURE_NAMES`]), `rule:<name>`, `cooldown` or `trusted`.
    pub signal: &'static str,
    /// Contribution in log-odds for model signals; the rule's risk for rules.
    pub weight: f64,
    /// For model signals: whether the feature was unusually high (`true`) or unusually
    /// low (`false`, e.g. low route diversity) to push the risk up.
    pub high: bool,
}

impl std::fmt::Display for Reason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.high {
            f.write_str(self.signal)
        } else {
            write!(f, "low {}", self.signal)
        }
    }
}

/// Full result of [`Guard::assess`].
#[derive(Debug, Clone)]
pub struct Assessment {
    pub decision: Decision,
    /// Final risk in [0, 1].
    pub risk: f64,
    /// Cloudflare-style bot score: 1 = almost certainly automated/abusive, 99 = almost certainly fine.
    pub bot_score: u8,
    /// Adaptive model's probability of abuse (0 when the model is not running).
    pub model_risk: f64,
    /// Explicit rules' risk (0 when no rules are configured).
    pub rules_risk: f64,
    /// Strongest contributors, most important first.
    pub reasons: Vec<Reason>,
    /// The raw feature vector (in [`FEATURE_NAMES`] order); used for training and debugging.
    pub features: Features,
}

enum Clock {
    Event { max: f64 },
    System { start: Instant },
}

impl Clock {
    /// `event_secs`: the event's Unix timestamp (ignored by the system clock).
    fn now(&mut self, event_secs: f64) -> f64 {
        match self {
            Clock::Event { max } => {
                if event_secs > *max {
                    *max = event_secs;
                }
                *max
            }
            Clock::System { start } => start.elapsed().as_secs_f64(),
        }
    }
}

/// What `assess` and `observe_response` derive from an event before taking the state
/// lock: everything whose cost grows with the request's size.
struct Request {
    p: Prepared,
    rep_key: u64,
    target_key: u64,
    unix_secs: f64,
    weight: f64,
}

/// What `assess` computes while holding the state lock.
struct Scored {
    features: Features,
    model_risk: f64,
    contrib: Features,
    rules_risk: f64,
    rule_name: &'static str,
    in_cooldown: bool,
}

#[derive(Default)]
struct Strikes {
    blocks: Decay,
    until: f64,
}

struct State {
    clock: Clock,
    engine: FeatureEngine,
    rules: Tracker,
    /// Keyed by `Event::actor_key` (a 64-bit hash of the actor id).
    cooldowns: LruCache<u64, Strikes>,
}

pub struct Guard {
    config: Config,
    model: Model,
    state: Mutex<State>,
}

impl Guard {
    /// Builds a guard; loads `config.guard.model` if set, else the built-in model.
    pub fn new(config: Config) -> Result<Self, Error> {
        config.validate()?;
        let model = match &config.guard.model {
            Some(p) => Model::load(p)?,
            None => Model::builtin(),
        };
        let g = &config.guard;
        let clock = match g.time_source {
            TimeSource::Event => Clock::Event {
                max: f64::NEG_INFINITY,
            },
            TimeSource::System => Clock::System {
                start: Instant::now(),
            },
        };
        let state = State {
            clock,
            engine: FeatureEngine::new(g.adaptive.clone(), g.max_actors),
            rules: Tracker::new(g.max_actors),
            cooldowns: LruCache::new(g.max_actors.unwrap_or(NonZeroUsize::new(100_000).unwrap())),
        };
        Ok(Self {
            config,
            model,
            state: Mutex::new(state),
        })
    }

    pub fn from_config_path(path: impl AsRef<Path>) -> Result<Self, Error> {
        Self::new(Config::load(path)?)
    }

    pub fn from_toml_str(s: &str) -> Result<Self, Error> {
        Self::new(Config::from_toml_str(s)?)
    }

    /// Replaces the scoring model (e.g. one you trained with `pattern-guard train`).
    pub fn with_model(mut self, model: Model) -> Self {
        self.model = model;
        self
    }

    pub fn config(&self) -> &Config {
        &self.config
    }

    pub fn model(&self) -> &Model {
        &self.model
    }

    pub fn check(&self, event: &Event) -> Decision {
        self.assess(event).decision
    }

    /// Returns (decision, risk 0–1).
    pub fn check_with_risk(&self, event: &Event) -> (Decision, f64) {
        let a = self.assess(event);
        (a.decision, a.risk)
    }

    fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Route templating, probe scanning and key hashing. Runs before the state lock is
    /// taken: the lock is shared by every request, and a 64 KB path with a 400 KB user
    /// agent held it for ~830 µs when this ran inside it.
    fn prepare(&self, ev: &Event) -> Request {
        let g = &self.config.guard;
        let n = normalize_path(&ev.target);
        let route = hash_str(&[&ev.action, &n.template]);
        let (rep_key, target_key) = if g.normalize_targets {
            (route, hash_str(&[&n.template]))
        } else {
            (hash_str(&[&ev.action, &ev.target]), hash_str(&[&ev.target]))
        };
        let probe = is_probe_path(&ev.target, &g.adaptive.probe_paths);
        Request {
            p: Prepared::new(ev, route, n.id, probe),
            rep_key,
            target_key,
            unix_secs: ev.unix_secs(),
            weight: ev.effective_weight(),
        }
    }

    /// The part of `assess` that reads and updates shared state. Constant time.
    fn score(&self, st: &mut State, req: &Request, eff: &EffectiveConfig) -> Scored {
        let g = &self.config.guard;
        let now = st.clock.now(req.unix_secs);
        let (features, model_risk, contrib) = if g.mode != Mode::Rules {
            let f = st.engine.observe_request(&req.p, now);
            let (risk, contrib) = self.model.predict(&f);
            (f, risk, contrib)
        } else {
            ([0.0; N_FEATURES], 0.0, [0.0; N_FEATURES])
        };

        let (rules_risk, rule_name) = if g.mode != Mode::Adaptive && eff.rules_enabled() {
            let s = st.rules.record(
                req.p.actor,
                req.rep_key,
                req.target_key,
                req.weight,
                now,
                eff,
            );
            analyzer::rules_risk(&s, eff)
        } else {
            (0.0, "rule:none")
        };

        let block_at = eff.challenge_below.unwrap_or(eff.delay_below);
        let own_risk = model_risk.max(rules_risk);
        let in_cooldown = st
            .cooldowns
            .get(&req.p.actor)
            .is_some_and(|s| now < s.until);
        if !eff.trusted && eff.cooldown_secs > 0.0 && own_risk >= block_at {
            let s = st
                .cooldowns
                .get_or_insert_mut(req.p.actor, Strikes::default);
            s.blocks.add(1.0, now, eff.cooldown_secs);
            if s.blocks.get(now, eff.cooldown_secs) >= g.cooldown_after_blocks as f64 - 0.5 {
                s.until = now + eff.cooldown_secs;
            }
        }
        Scored {
            features,
            model_risk,
            contrib,
            rules_risk,
            rule_name,
            in_cooldown,
        }
    }

    /// Scores one request and records it. Call once per request, before handling it.
    pub fn assess(&self, event: &Event) -> Assessment {
        let eff = self.config.guard.for_actor(&event.actor);
        let req = self.prepare(event);
        let Scored {
            features,
            model_risk,
            contrib,
            rules_risk,
            rule_name,
            in_cooldown,
        } = self.score(&mut self.lock(), &req, &eff);

        let block_at = eff.challenge_below.unwrap_or(eff.delay_below);
        let mut risk = model_risk.max(rules_risk);
        let mut reasons: Vec<Reason> = Vec::new();

        if eff.trusted {
            risk = 0.0;
            reasons.push(Reason {
                signal: "trusted",
                weight: 0.0,
                high: true,
            });
        } else {
            if in_cooldown && risk < block_at {
                risk = block_at;
                reasons.push(Reason {
                    signal: "cooldown",
                    weight: block_at,
                    high: true,
                });
            }
            if rules_risk > 0.0 && rules_risk >= model_risk {
                reasons.push(Reason {
                    signal: rule_name,
                    weight: rules_risk,
                    high: true,
                });
            }
            let mut order: Vec<usize> = (0..N_FEATURES).filter(|&i| contrib[i] > 0.25).collect();
            order.sort_by(|&a, &b| contrib[b].total_cmp(&contrib[a]));
            reasons.extend(order.into_iter().take(3).map(|i| Reason {
                signal: FEATURE_NAMES[i],
                weight: contrib[i],
                high: self.model.weight(i) >= 0.0,
            }));
        }

        Assessment {
            decision: eff.risk_to_decision(risk),
            risk,
            bot_score: (1.0 + ((1.0 - risk) * 98.0).round()) as u8,
            model_risk,
            rules_risk,
            reasons,
            features,
        }
    }

    /// Reports the HTTP status your handler returned for `event` (the same event passed
    /// to [`assess`](Self::assess)). Failure ratios (401/403/404/429…) are among the
    /// strongest signals for credential stuffing, scanning and scraping.
    pub fn observe_response(&self, event: &Event, status: u16) {
        if self.config.guard.mode == Mode::Rules {
            return;
        }
        let req = self.prepare(event);
        self.record_response(&mut self.lock(), &req, status);
    }

    /// The part of `observe_response` that updates shared state. Constant time.
    fn record_response(&self, st: &mut State, req: &Request, status: u16) {
        let now = st.clock.now(req.unix_secs);
        st.engine.observe_response(&req.p, status, now);
    }
}

const _: () = {
    const fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<Guard>();
    assert_send_sync::<Event>();
    assert_send_sync::<Decision>();
};

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, SystemTime};

    fn at(t: f64) -> SystemTime {
        SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000) + Duration::from_secs_f64(t)
    }

    #[test]
    fn log_replay_uses_event_time() {
        // A light user (1 req / 5 min for a day) replayed instantly must not trip burst.
        let g =
            Guard::from_toml_str("[guard]\nmode = \"rules\"\nburst_max_events = 100\n").unwrap();
        let mut last = Decision::Allow;
        for i in 0..288 {
            last = g.check(&Event::new("user:7", "GET", "/home", at(300.0 * i as f64)));
        }
        assert_eq!(last, Decision::Allow);
    }

    #[test]
    fn two_requests_two_seconds_apart_are_fine() {
        let g = Guard::from_toml_str("[guard]\nmode = \"rules\"\ninterval_secs = 2.0\n").unwrap();
        g.check(&Event::new("ip:1.2.3.4", "GET", "/", at(0.0)));
        assert_eq!(
            g.check(&Event::new("ip:1.2.3.4", "GET", "/pricing", at(2.1))),
            Decision::Allow
        );
    }

    #[test]
    fn rules_still_work_and_cooldown_holds() {
        let g = Guard::from_toml_str(
            "[guard]\nmode = \"rules\"\nwindow_secs = 5\nburst_max_events = 3\ncooldown_secs = 30\n",
        )
        .unwrap();
        let mut ds = Vec::new();
        for i in 0..8 {
            ds.push(g.check(&Event::new("demo", "run", "x", at(i as f64 * 0.1))));
        }
        assert_eq!(ds[0], Decision::Allow);
        assert_eq!(ds[7], Decision::Block);
        // window (5s) has expired, but the cooldown keeps blocking until 0.7 + 30s
        let a = g.assess(&Event::new("demo", "run", "x", at(20.0)));
        assert_eq!(a.decision, Decision::Block);
        assert_eq!(a.reasons[0].signal, "cooldown");
        assert_eq!(
            g.check(&Event::new("demo", "run", "x", at(40.0))),
            Decision::Allow
        );
    }

    #[test]
    fn single_block_does_not_start_cooldown() {
        let g = Guard::from_toml_str(
            "[guard]\nmode = \"rules\"\nwindow_secs = 5\nburst_max_events = 2\ncooldown_secs = 30\n",
        )
        .unwrap();
        for i in 0..4 {
            g.check(&Event::new("a", "GET", "/", at(i as f64 * 0.1))); // 4th = one block
        }
        assert_eq!(
            g.check(&Event::new("a", "GET", "/", at(20.0))),
            Decision::Allow
        );
    }

    #[test]
    fn trusted_actor_always_allowed() {
        let g = Guard::from_toml_str(
            "[guard]\nmode = \"rules\"\nburst_max_events = 1\n[guard.actors.\"ip:10.0.0.1\"]\ntrusted = true\n",
        )
        .unwrap();
        for i in 0..50 {
            let a = g.assess(&Event::new("ip:10.0.0.1", "GET", "/", at(i as f64 * 0.01)));
            assert_eq!(a.decision, Decision::Allow);
            assert_eq!(a.bot_score, 99);
        }
    }

    #[test]
    fn rules_mode_skips_model() {
        let g = Guard::from_toml_str("[guard]\nmode = \"rules\"\n").unwrap();
        let a = g.assess(&Event::new("a", "GET", "/", at(0.0)));
        assert_eq!(a.model_risk, 0.0);
        assert_eq!(a.features, [0.0; N_FEATURES]);
    }

    #[test]
    fn system_clock_mode() {
        let g = Guard::from_toml_str(
            "[guard]\ntime_source = \"system\"\nmode = \"rules\"\nburst_max_events = 2\n",
        )
        .unwrap();
        // event timestamps are ignored; all three land in the same instant
        for i in 0..3 {
            g.check(&Event::new("a", "GET", "/", at(i as f64 * 1000.0)));
        }
        assert!(g.check_with_risk(&Event::new("a", "GET", "/", at(0.0))).1 > 0.0);
    }

    #[test]
    fn bot_score_bounds() {
        let g = Guard::from_toml_str("").unwrap();
        let a = g.assess(&Event::new("a", "GET", "/", at(0.0)));
        assert!((1..=99).contains(&a.bot_score));
    }
}
