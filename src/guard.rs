use std::num::NonZeroUsize;
use std::path::Path;
use std::sync::{Mutex, PoisonError};
use std::time::Instant;

use lru::LruCache;

use crate::analyzer;
use crate::config::{Config, TimeSource};
use crate::decision::Decision;
use crate::error::Error;
use crate::event::Event;
use crate::normalize::{hash_str, normalize_path};
use crate::stats::Decay;
use crate::tracker::Tracker;

/// Why a request scored the way it did.
#[derive(Debug, Clone, PartialEq)]
pub struct Reason {
    /// `rule:<name>`, `cooldown` or `trusted`.
    pub signal: &'static str,
    /// The rule's risk.
    pub weight: f64,
    /// Whether an unusually high (`true`) or low (`false`) value raised the risk.
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
    /// Explicit rules' risk (0 when no rules are configured).
    pub rules_risk: f64,
    /// Strongest contributors, most important first.
    pub reasons: Vec<Reason>,
}

enum Clock {
    Event { max: f64 },
    System { start: Instant },
}

impl Clock {
    fn now(&mut self, ev: &Event) -> f64 {
        match self {
            Clock::Event { max } => {
                let t = ev.unix_secs();
                if t > *max {
                    *max = t;
                }
                *max
            }
            Clock::System { start } => start.elapsed().as_secs_f64(),
        }
    }
}

#[derive(Default)]
struct Strikes {
    blocks: Decay,
    until: f64,
}

struct State {
    clock: Clock,
    rules: Tracker,
    cooldowns: LruCache<String, Strikes>,
}

pub struct Guard {
    config: Config,
    state: Mutex<State>,
}

impl Guard {
    pub fn new(config: Config) -> Result<Self, Error> {
        config.validate()?;
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
            rules: Tracker::new(g.max_actors),
            cooldowns: LruCache::new(g.max_actors.unwrap_or(NonZeroUsize::new(100_000).unwrap())),
        };
        Ok(Self {
            config,
            state: Mutex::new(state),
        })
    }

    pub fn from_config_path(path: impl AsRef<Path>) -> Result<Self, Error> {
        Self::new(Config::load(path)?)
    }

    pub fn from_toml_str(s: &str) -> Result<Self, Error> {
        Self::new(Config::from_toml_str(s)?)
    }

    pub fn config(&self) -> &Config {
        &self.config
    }

    pub fn check(&self, event: &Event) -> Decision {
        self.assess(event).decision
    }

    /// Returns (decision, risk 0–1).
    pub fn check_with_risk(&self, event: &Event) -> (Decision, f64) {
        let a = self.assess(event);
        (a.decision, a.risk)
    }

    fn rule_keys(&self, ev: &Event) -> (u64, u64) {
        if self.config.guard.normalize_targets {
            let n = normalize_path(&ev.target);
            (hash_str(&[&ev.action, &n.template]), hash_str(&[&n.template]))
        } else {
            (hash_str(&[&ev.action, &ev.target]), hash_str(&[&ev.target]))
        }
    }

    /// Scores one request and records it. Call once per request, before handling it.
    pub fn assess(&self, event: &Event) -> Assessment {
        let g = &self.config.guard;
        let eff = g.for_actor(&event.actor);
        let mut st = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        let st = &mut *st;
        let now = st.clock.now(event);
        let (rep_key, target_key) = self.rule_keys(event);

        let (rules_risk, rule_name) = if eff.rules_enabled() {
            let s = st.rules.record(
                &event.actor,
                rep_key,
                target_key,
                event.effective_weight(),
                now,
                &eff,
            );
            analyzer::rules_risk(&s, &eff)
        } else {
            (0.0, "rule:none")
        };

        let block_at = eff.challenge_below.unwrap_or(eff.delay_below);
        let in_cooldown = st
            .cooldowns
            .get(&event.actor)
            .is_some_and(|s| now < s.until);
        let mut risk = rules_risk;
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
            if rules_risk > 0.0 {
                reasons.push(Reason {
                    signal: rule_name,
                    weight: rules_risk,
                    high: true,
                });
            }
        }

        let decision = eff.risk_to_decision(risk);
        if !eff.trusted && eff.cooldown_secs > 0.0 && rules_risk >= block_at {
            let s = st
                .cooldowns
                .get_or_insert_mut(event.actor.clone(), Strikes::default);
            s.blocks.add(1.0, now, eff.cooldown_secs);
            if s.blocks.get(now, eff.cooldown_secs) >= g.cooldown_after_blocks as f64 - 0.5 {
                s.until = now + eff.cooldown_secs;
            }
        }

        Assessment {
            decision,
            risk,
            bot_score: (1.0 + ((1.0 - risk) * 98.0).round()) as u8,
            rules_risk,
            reasons,
        }
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
