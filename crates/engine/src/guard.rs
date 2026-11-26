use std::num::NonZeroUsize;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError, RwLock};
use std::time::{Instant, SystemTime};

use lru::LruCache;
use serde::{Deserialize, Serialize};

use crate::config::{Config, EffectiveConfig, GuardConfig, Mode, TimeSource};
use crate::decision::Decision;
use crate::error::Error;
use crate::event::Event;
use crate::ml::features::{self, FEATURE_NAMES, FeatureEngine, Features, N_FEATURES, Prepared};
use crate::ml::model::Model;
use crate::rules::analyzer;
use crate::rules::tracker::{self, Tracker};
use crate::snapshot::{
    MAX_CLOCK_AHEAD_SECS, MAX_RESTART_GAP_SECS, MAX_SYSTEM_CLOCK_SECS, Snapshot, bits,
    copy_in_chunks, lru_refill,
};
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
    Event {
        max: f64,
    },
    /// Seconds since `start`, plus `offset` (where a restored snapshot's clock resumes).
    System {
        start: Instant,
        offset: f64,
    },
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
            Clock::System { start, offset } => *offset + start.elapsed().as_secs_f64(),
        }
    }

    /// The current reading without an event; `None` before the first event.
    fn reading(&self) -> Option<f64> {
        match self {
            Clock::Event { max } => max.is_finite().then_some(*max),
            Clock::System { start, offset } => Some(*offset + start.elapsed().as_secs_f64()),
        }
    }
}

fn unix_secs(t: SystemTime) -> f64 {
    t.duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0)
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
/// Model inputs that describe what *other* actors sharing this client key or network did,
/// or that every legitimate first contact has (a first request, a write before any page
/// view). They can raise the risk, but a block needs the actor's own behaviour too: an
/// attacker copying a popular browser's user agent must not get that browser's users
/// blocked and banned, and a password manager's first login must not look like stuffing.
const SHARED_EVIDENCE: &[&str] = &[
    // first contact: every legitimate client's first request has these
    "actor_new",
    "cold_write",
    // failures and new arrivals pooled over the network or the client key (user agent /
    // fingerprint), which innocent users share with whoever else uses it
    "subnet_new_actors",
    "subnet_fail_ratio",
    "client_fail_ratio",
    "client_new_actor_share",
    "new_actor_surge_x_client_new_share",
    "fail_surge_x_client_fail_ratio",
    "client_route_share_x_new_share",
    // Not here: route concentration and surges (`client_route_share`,
    // `surge_x_client_route_share`, …). They are how distributed floods and scrapers are
    // caught, and an innocent user doesn't share them by accident.
];

/// The model's risk without the positive contributions of shared evidence.
fn own_model_risk(model_risk: f64, contrib: &Features, shared: &[bool; N_FEATURES]) -> f64 {
    let r = model_risk.clamp(1e-12, 1.0 - 1e-12);
    let z = (r / (1.0 - r)).ln()
        - (0..N_FEATURES)
            .filter(|&i| shared[i])
            .map(|i| contrib[i].max(0.0))
            .sum::<f64>();
    1.0 / (1.0 + (-z).exp())
}

struct Scored {
    features: Features,
    model_risk: f64,
    /// `model_risk` without shared evidence (see `SHARED_EVIDENCE`).
    own_model_risk: f64,
    contrib: Features,
    rules_risk: f64,
    rule_name: &'static str,
    in_cooldown: bool,
    /// The running cooldown was earned by the actor's own behaviour.
    cooldown_own: bool,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
struct Strikes {
    blocks: Decay,
    #[serde(with = "bits")]
    until: f64,
    /// Whether the actor's own behaviour (not only shared evidence) reached the block
    /// threshold when the cooldown started: then it blocks, else it challenges.
    own: bool,
}

struct State {
    clock: Clock,
    engine: FeatureEngine,
    rules: Tracker,
    /// Keyed by `Event::actor_key` (a 64-bit hash of the actor id).
    cooldowns: LruCache<u64, Strikes>,
}

/// What a guard scores with. A call takes it once, so a [`Guard::reload`] in the middle
/// of a call never mixes two configs or models.
struct Settings {
    config: Arc<Config>,
    model: Arc<Model>,
}

/// What [`Guard::reload`] did besides applying the new settings.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct ReloadReport {
    /// Keys that need a restart: their running values were kept (`guard.time_source`,
    /// `guard.max_actors`, `guard.adaptive`).
    pub kept: Vec<&'static str>,
    /// Set on the first reload that keeps a model which fails [`Model::check_layout`]
    /// (one the guard started with, or another with the same layout).
    pub model_warning: Option<String>,
}

impl State {
    /// Nothing learned yet, with the caps of `g`.
    fn empty(g: &GuardConfig) -> Self {
        let clock = match g.time_source {
            TimeSource::Event => Clock::Event {
                max: f64::NEG_INFINITY,
            },
            TimeSource::System => Clock::System {
                start: Instant::now(),
                offset: 0.0,
            },
        };
        Self {
            clock,
            engine: FeatureEngine::new(g.adaptive.clone(), g.max_actors),
            rules: Tracker::new(g.max_actors),
            cooldowns: LruCache::new(g.max_actors.unwrap_or(NonZeroUsize::new(100_000).unwrap())),
        }
    }
}

/// The learned state inside a [`Snapshot`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct Learned {
    /// Wall clock when it was taken (Unix seconds).
    #[serde(with = "bits")]
    taken_at: f64,
    time_source: TimeSource,
    /// The guard's clock then; `None` before its first event.
    #[serde(with = "bits::opt")]
    clock: Option<f64>,
    features: features::Learned,
    rules: tracker::Learned,
    /// Least recently used first.
    cooldowns: Vec<(u64, Strikes)>,
}

impl Learned {
    pub(crate) fn actors(&self) -> usize {
        self.features.actors()
    }
}

pub struct Guard {
    settings: RwLock<Arc<Settings>>,
    /// A reload already reported that the model doesn't fit this engine's features.
    layout_warned: AtomicBool,
    /// `SHARED_EVIDENCE` as a mask over `FEATURE_NAMES`.
    shared: [bool; N_FEATURES],
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
        let state = State::empty(&config.guard);
        let mut shared = [false; N_FEATURES];
        for (i, name) in FEATURE_NAMES.iter().enumerate() {
            shared[i] = SHARED_EVIDENCE.contains(name);
        }
        Ok(Self {
            settings: RwLock::new(Arc::new(Settings {
                config: Arc::new(config),
                model: Arc::new(model),
            })),
            layout_warned: AtomicBool::new(false),
            shared,
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
        let s = self
            .settings
            .get_mut()
            .unwrap_or_else(PoisonError::into_inner);
        *s = Arc::new(Settings {
            config: s.config.clone(),
            model: Arc::new(model),
        });
        self
    }

    /// The config in use (it changes with [`reload`](Self::reload)).
    pub fn config(&self) -> Arc<Config> {
        self.settings().config.clone()
    }

    /// The model in use (it changes with [`reload`](Self::reload)).
    pub fn model(&self) -> Arc<Model> {
        self.settings().model.clone()
    }

    fn settings(&self) -> Arc<Settings> {
        self.settings
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// Replaces the config and the model of a running guard and keeps everything it has
    /// learned: baselines, actor history, rule windows, cooldowns. Calls already running
    /// finish with the settings they started with.
    ///
    /// The model is `config.guard.model`, else the built-in one. A reload refuses to
    /// switch to a model that fails [`Model::check_layout`] (trained for another
    /// version's features). A model with the same layout as the running one is accepted
    /// even if it fails the check, so a guard that started with an older model (which
    /// [`Guard::new`] allows) can still reload the rest of its config; the first such
    /// reload sets [`ReloadReport::model_warning`]. If the config is invalid, the model
    /// can't be read or is refused, nothing changes and the error is returned.
    ///
    /// `time_source`, `max_actors` and `[guard.adaptive]` shape the learned state, so they
    /// can't change without a restart: their running values are kept, and the keys whose
    /// new values were ignored are in [`ReloadReport::kept`].
    pub fn reload(&self, mut config: Config) -> Result<ReloadReport, Error> {
        config.validate()?;
        let model = match &config.guard.model {
            Some(p) => Model::load(p)?,
            None => Model::builtin(),
        };
        let mut settings = self
            .settings
            .write()
            .unwrap_or_else(PoisonError::into_inner);
        let mut model_warning = None;
        if let Err(e) = model.check_layout() {
            if !model.same_layout(&settings.model) {
                return Err(e);
            }
            if !self.layout_warned.swap(true, Ordering::Relaxed) {
                model_warning = Some(format!(
                    "{e}; accepted, because the running model has the same layout"
                ));
            }
        }
        let (old, new) = (&settings.config.guard, &mut config.guard);
        let mut kept = Vec::new();
        if new.time_source != old.time_source {
            new.time_source = old.time_source;
            kept.push("guard.time_source");
        }
        if new.max_actors != old.max_actors {
            new.max_actors = old.max_actors;
            kept.push("guard.max_actors");
        }
        if new.adaptive != old.adaptive {
            new.adaptive = old.adaptive.clone();
            kept.push("guard.adaptive");
        }
        *settings = Arc::new(Settings {
            config: Arc::new(config),
            model: Arc::new(model),
        });
        Ok(ReloadReport {
            kept,
            model_warning,
        })
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
    fn prepare(g: &GuardConfig, ev: &Event) -> Request {
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
    fn score(&self, s: &Settings, st: &mut State, req: &Request, eff: &EffectiveConfig) -> Scored {
        let g = &s.config.guard;
        let now = st.clock.now(req.unix_secs);
        let (features, model_risk, contrib) = if g.mode != Mode::Rules {
            let f = st.engine.observe_request(&req.p, now);
            let (risk, contrib) = s.model.predict(&f);
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
        let own_model_risk = own_model_risk(model_risk, &contrib, &self.shared);
        let full_risk = model_risk.max(rules_risk);
        let own_blocks = own_model_risk.max(rules_risk) >= block_at;
        let (in_cooldown, cooldown_own) = st
            .cooldowns
            .get(&req.p.actor)
            .filter(|s| now < s.until)
            .map_or((false, false), |s| (true, s.own));
        if !eff.trusted && eff.cooldown_secs > 0.0 && full_risk >= block_at {
            let s = st
                .cooldowns
                .get_or_insert_mut(req.p.actor, Strikes::default);
            s.blocks.add(1.0, now, eff.cooldown_secs);
            if s.blocks.get(now, eff.cooldown_secs) >= g.cooldown_after_blocks as f64 - 0.5 {
                if now >= s.until {
                    s.own = false;
                }
                s.until = now + eff.cooldown_secs;
                s.own |= own_blocks;
            }
        }
        Scored {
            features,
            model_risk,
            own_model_risk,
            contrib,
            rules_risk,
            rule_name,
            in_cooldown,
            cooldown_own,
        }
    }

    /// Scores one request and records it. Call once per request, before handling it.
    pub fn assess(&self, event: &Event) -> Assessment {
        let s = self.settings();
        let eff = s.config.guard.for_actor(&event.actor);
        let req = Self::prepare(&s.config.guard, event);
        let Scored {
            features,
            model_risk,
            own_model_risk,
            contrib,
            rules_risk,
            rule_name,
            in_cooldown,
            cooldown_own,
        } = self.score(&s, &mut self.lock(), &req, &eff);

        let block_at = eff.challenge_below.unwrap_or(eff.delay_below);
        let mut risk = model_risk.max(rules_risk);
        let mut reasons: Vec<Reason> = Vec::new();
        let mut shared_only = false;

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
            // Shared or first-contact evidence alone can't block: such a request is
            // challenged instead. A real browser passes the challenge (and a challenged form
            // is sent again); a script without a JS engine doesn't.
            // A cooldown earned by shared evidence challenges too.
            let own_says_block =
                own_model_risk.max(rules_risk) >= block_at || (in_cooldown && cooldown_own);
            if risk >= block_at && !own_says_block {
                shared_only = true;
                reasons.push(Reason {
                    signal: "shared_evidence_only",
                    weight: model_risk,
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
                high: s.model.weight(i) >= 0.0,
            }));
        }

        Assessment {
            decision: if shared_only {
                Decision::Challenge
            } else {
                eff.risk_to_decision(risk)
            },
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
        let s = self.settings();
        if s.config.guard.mode == Mode::Rules {
            return;
        }
        let req = Self::prepare(&s.config.guard, event);
        self.record_response(&mut self.lock(), &req, status);
    }

    /// The part of `observe_response` that updates shared state. Constant time.
    fn record_response(&self, st: &mut State, req: &Request, status: u16) {
        let now = st.clock.now(req.unix_secs);
        st.engine.observe_response(&req.p, status, now);
    }

    /// Copies what the guard has learned (see [`crate::snapshot`]). Requests keep being
    /// served meanwhile: the state lock is taken once per table to list its keys (a few
    /// milliseconds for 100 000), then for 1 024 entries at a time (≤ 1.5 ms), with a
    /// 50 µs pause in between. So the copy is not atomic, which costs nothing here (each
    /// entry is consistent, and the clock is read last). It blocks the calling thread
    /// for 0.1–0.3 s at the default caps: call it from a background thread, and
    /// serialise the snapshot after it returns.
    pub fn snapshot(&self) -> Snapshot {
        let taken_at = unix_secs(SystemTime::now());
        let features = FeatureEngine::snapshot(&|f| f(&self.lock().engine));
        let rules = Tracker::snapshot(&|f| f(&self.lock().rules));
        let cooldowns = copy_in_chunks(&|f| f(&self.lock()), |s| &s.cooldowns, Strikes::clone);
        Snapshot::new(Learned {
            taken_at,
            time_source: self.settings().config.guard.time_source,
            // after the tables, so no entry is newer than the clock
            clock: self.lock().clock.reading(),
            features,
            rules,
            cooldowns,
        })
    }

    /// Replaces what the guard has learned with `snapshot`, within this guard's caps
    /// (the most recently used entries are kept). Call it before the first request. On an
    /// error nothing changes: another format or layout ([`Error::SnapshotVersion`],
    /// [`Error::SnapshotLayout`]), another `time_source`, or an event clock more than
    /// [`MAX_CLOCK_AHEAD_SECS`] ahead of the system clock ([`Error::SnapshotIncompatible`]).
    ///
    /// Values are checked for range as well as shape: no stored time may lie after the
    /// snapshot's clock (a later one is set to it), a cooldown ends at most
    /// `cooldown_secs` after it, counters are not negative, and the system-mode clock and
    /// the gap since `taken_at` are bounded ([`MAX_SYSTEM_CLOCK_SECS`],
    /// [`MAX_RESTART_GAP_SECS`]).
    pub fn restore(&self, snapshot: Snapshot) -> Result<(), Error> {
        self.restore_at(snapshot, SystemTime::now())
    }

    /// [`restore`](Self::restore) with the system clock reading `now`.
    pub fn restore_at(&self, snapshot: Snapshot, now: SystemTime) -> Result<(), Error> {
        let s = snapshot.into_state()?;
        let settings = self.settings();
        let g = &settings.config.guard;
        if s.time_source != g.time_source {
            return Err(Error::SnapshotIncompatible(format!(
                "taken with time_source {:?}, this guard uses {:?}",
                s.time_source, g.time_source
            )));
        }
        let now = unix_secs(now);
        // Built before taking the lock: only the swap happens under it.
        let mut fresh = State::empty(g);
        // the engine time the state is as of: nothing in it may be later
        let as_of = match &mut fresh.clock {
            Clock::Event { max } => match s.clock {
                Some(clock) if clock > now + MAX_CLOCK_AHEAD_SECS => {
                    return Err(Error::SnapshotIncompatible(format!(
                        "its clock is {:.0} s ahead of the system clock",
                        clock - now
                    )));
                }
                Some(clock) => {
                    *max = clock;
                    clock
                }
                None => now, // no event yet: there should be nothing to clamp
            },
            // resume where it stopped, plus the time that passed in between
            Clock::System { offset, .. } => {
                let clock = s.clock.unwrap_or(0.0).clamp(0.0, MAX_SYSTEM_CLOCK_SECS);
                let gap = (now - s.taken_at).clamp(0.0, MAX_RESTART_GAP_SECS);
                *offset = clock + gap;
                clock
            }
        };
        fresh.engine.restore(s.features, as_of);
        let actor_configs =
            || std::iter::once(g.for_actor("")).chain(g.actors.keys().map(|id| g.for_actor(id)));
        let window_cap = actor_configs()
            .map(|eff| tracker::window_cap(&eff))
            .max()
            .unwrap_or(1);
        fresh.rules.restore(s.rules, window_cap, as_of);
        let cooldown = actor_configs()
            .map(|eff| eff.cooldown_secs)
            .fold(0.0, f64::max);
        lru_refill(&mut fresh.cooldowns, s.cooldowns, |c| {
            c.blocks.clamp_to(as_of);
            c.until = c.until.min(as_of + cooldown);
        });
        let mut st = self.lock();
        if let (Clock::Event { max }, Clock::Event { max: seen }) = (&mut fresh.clock, &st.clock) {
            *max = max.max(*seen); // the clock never goes backwards
        }
        let old = std::mem::replace(&mut *st, fresh);
        drop(st);
        drop(old); // freeing a full state takes a while: not under the lock
        Ok(())
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
    fn reload_keeps_what_was_learned_and_applies_the_new_config() {
        let cfg = |burst: u32| {
            Config::from_toml_str(&format!(
                "[guard]\nmode = \"rules\"\nwindow_secs = 60\nburst_max_events = {burst}\n"
            ))
            .unwrap()
        };
        let g = Guard::new(cfg(10)).unwrap();
        for i in 0..5 {
            let a = g.assess(&Event::new("a", "GET", "/", at(i as f64)));
            assert_eq!(a.rules_risk, 0.0);
        }
        assert_eq!(g.reload(cfg(5)).unwrap(), ReloadReport::default());
        assert_eq!(g.config().guard.burst_max_events, Some(5));
        // the five requests before the reload still count
        let a = g.assess(&Event::new("a", "GET", "/", at(5.0)));
        assert!(a.rules_risk > 0.0, "{a:?}");
        assert_eq!(
            g.assess(&Event::new("b", "GET", "/", at(5.0))).rules_risk,
            0.0
        );
    }

    #[test]
    fn reload_keeps_keys_that_shape_learned_state() {
        let g = Guard::from_toml_str("[guard]\nwarn_below = 0.5\n").unwrap();
        let kept = g
            .reload(
                Config::from_toml_str(
                    "[guard]\nwarn_below = 0.55\ntime_source = \"system\"\nmax_actors = 10\n\
                     [guard.adaptive]\nwarmup_secs = 1\n",
                )
                .unwrap(),
            )
            .unwrap()
            .kept;
        assert_eq!(
            kept,
            ["guard.time_source", "guard.max_actors", "guard.adaptive"]
        );
        let c = g.config();
        assert_eq!(c.guard.warn_below, 0.55, "the rest applies");
        assert_eq!(c.guard.time_source, TimeSource::Event);
        assert_eq!(c.guard.max_actors, NonZeroUsize::new(100_000));
        assert_eq!(c.guard.adaptive.warmup_secs, 300.0);
    }

    #[test]
    fn reload_refuses_a_model_for_another_feature_layout() {
        let dir = std::env::temp_dir().join(format!("pg_reload_model_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let full = Model::builtin().to_toml_string();
        let older = full.replacen(
            &format!("name = \"{}\"", FEATURE_NAMES[0]),
            "name = \"renamed\"",
            1,
        );
        std::fs::write(dir.join("old.toml"), older.replace("built-in", "older")).unwrap();
        std::fs::write(dir.join("new.toml"), full.replace("built-in", "retrained")).unwrap();
        let g = Guard::from_toml_str("").unwrap();
        let load =
            |m: &str| Config::from_toml_str(&format!("[guard]\nmodel = {:?}\n", dir.join(m)));
        let e = g.reload(load("old.toml").unwrap()).unwrap_err().to_string();
        assert!(e.contains("feature layout"), "{e}");
        assert!(g.model().description.starts_with("built-in"), "kept");
        assert!(g.reload(load("missing.toml").unwrap()).is_err());
        assert!(g.reload(load("new.toml").unwrap()).is_ok());
        assert!(g.model().description.starts_with("retrained"));
        // startup stays lenient: an older model still loads …
        let old = Guard::new(load("old.toml").unwrap()).unwrap();
        // … and the rest of the config can still be reloaded with it (one warning)
        let r = old.reload(load("old.toml").unwrap()).unwrap();
        assert!(r.model_warning.unwrap().contains("feature layout"));
        assert_eq!(
            old.reload(load("old.toml").unwrap()).unwrap().model_warning,
            None
        );
        // switching it to a model that fits is fine, and back is not
        assert!(old.reload(load("new.toml").unwrap()).is_ok());
        assert!(old.reload(load("old.toml").unwrap()).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn bot_score_bounds() {
        let g = Guard::from_toml_str("").unwrap();
        let a = g.assess(&Event::new("a", "GET", "/", at(0.0)));
        assert!((1..=99).contains(&a.bot_score));
    }
}

#[cfg(test)]
mod snapshot_tests {
    use super::*;
    use crate::snapshot::{FORMAT_VERSION, layout_fingerprint};
    use serde_json::Value;
    use std::net::IpAddr;
    use std::time::{Duration, SystemTime};

    /// Hybrid mode with rules and a small actor cap, so every table is used, LRU
    /// eviction happens and cooldowns start.
    const CONFIG: &str = "[guard]\nmax_actors = 50\nwindow_secs = 60\nburst_max_events = 25\nrepetition_max_count = 15\ncooldown_secs = 120\ncooldown_after_blocks = 2\n[guard.adaptive]\nwarmup_secs = 30\n";

    fn at(t: f64) -> SystemTime {
        SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000) + Duration::from_secs_f64(t)
    }

    /// Request `i` of a deterministic mix: 80 browsing actors over 5 routes (object ids,
    /// failed logins, two user agents) and a flooding scraper.
    fn event(i: u64, t: f64) -> (Event, u16) {
        let flood = i % 4 == 0;
        let n = if flood { 250 } else { i * 7 % 80 };
        let ip: IpAddr = format!("198.51.100.{n}").parse().unwrap();
        let (method, path, status) = match (flood, i % 5) {
            (true, _) => ("GET", format!("/product/{}", 5000 + i), 404),
            (_, 0) => ("GET", format!("/product/{}", 1000 + i % 40), 200),
            (_, 1) => ("POST", "/login".to_string(), 401),
            (_, 2) => ("GET", "/search?q=shoes".to_string(), 200),
            (_, 3) => ("GET", format!("/api/items/{i}"), 200),
            _ => ("GET", "/".to_string(), 200),
        };
        let ua = if i % 3 == 0 {
            "curl/8.4"
        } else {
            "Mozilla/5.0"
        };
        let ev = Event::new(format!("ip:{ip}"), method, path, at(t))
            .with_ip(ip)
            .with_user_agent(ua);
        (ev, status)
    }

    /// Runs requests `range` at 4 per second starting at `t0`.
    fn traffic(g: &Guard, range: std::ops::Range<u64>, t0: f64) -> Vec<Assessment> {
        range
            .map(|i| {
                let (ev, status) = event(i, t0 + i as f64 * 0.25);
                let a = g.assess(&ev);
                g.observe_response(&ev, status);
                a
            })
            .collect()
    }

    fn assert_same(a: &[Assessment], b: &[Assessment]) {
        assert_eq!(a.len(), b.len());
        for (i, (x, y)) in a.iter().zip(b).enumerate() {
            assert_eq!(x.decision, y.decision, "request {i}");
            assert_eq!(x.risk.to_bits(), y.risk.to_bits(), "request {i}");
            assert_eq!(
                x.model_risk.to_bits(),
                y.model_risk.to_bits(),
                "request {i}"
            );
            assert_eq!(
                x.rules_risk.to_bits(),
                y.rules_risk.to_bits(),
                "request {i}"
            );
            assert_eq!(x.features, y.features, "request {i}");
            assert_eq!(x.reasons, y.reasons, "request {i}");
        }
    }

    fn json(s: &Snapshot) -> Value {
        serde_json::from_slice(&s.to_json()).unwrap()
    }

    /// The learned state without the wall-clock time it was taken at.
    fn learned(s: &Snapshot) -> Value {
        let mut v = json(s);
        v["state"]["taken_at"] = Value::Null;
        v
    }

    fn restored(v: &Value) -> Result<Guard, Error> {
        let g = Guard::from_toml_str(CONFIG).unwrap();
        g.restore(Snapshot::from_json(&serde_json::to_vec(v).unwrap())?)?;
        Ok(g)
    }

    #[test]
    fn round_trip_gives_identical_decisions() {
        let original = Guard::from_toml_str(CONFIG).unwrap();
        let first = traffic(&original, 0..3000, 0.0);
        assert!(
            first.iter().any(|a| a.decision == Decision::Block),
            "the scraper is blocked"
        );
        let snap = original.snapshot();
        let s = snap.state.as_ref().unwrap();
        let end = 3000.0 * 0.25;
        assert!(
            s.cooldowns.iter().any(|(_, c)| c.until
                > at(end)
                    .duration_since(SystemTime::UNIX_EPOCH)
                    .unwrap()
                    .as_secs_f64()),
            "and is in a cooldown"
        );
        assert!(
            s.rules.len() > 0 && s.features.actors() == 50,
            "tables full"
        );
        let copy = Guard::from_toml_str(CONFIG).unwrap();
        copy.restore(Snapshot::from_json(&snap.to_json()).unwrap())
            .unwrap();
        assert_eq!(learned(&copy.snapshot()), learned(&snap), "lossless");

        // the same events right after, after a restart gap of an hour and of 400 days
        for gap in [0.0, 3600.0, 400.0 * 86400.0] {
            let a = traffic(&original, 3000..3600, end + gap);
            let b = traffic(&copy, 3000..3600, end + gap);
            assert_same(&a, &b);
            assert!(a.iter().all(|x| x.risk.is_finite()));
        }
    }

    #[test]
    fn restart_gap_decays_as_if_time_passed() {
        let g = Guard::from_toml_str(CONFIG).unwrap();
        let ev = |t: f64| Event::new("ip:192.0.2.1", "GET", "/", at(t));
        for i in 0..60 {
            g.assess(&ev(i as f64 * 0.1));
        }
        let burst = |a: &Assessment| a.features[0];
        let hot = burst(&g.assess(&ev(6.0)));
        let copy = Guard::from_toml_str(CONFIG).unwrap();
        copy.restore(g.snapshot()).unwrap();
        // ten minutes later the burst has decayed as if the gateway had kept running
        let later = burst(&copy.assess(&ev(606.0)));
        assert_eq!(later.to_bits(), burst(&g.assess(&ev(606.0))).to_bits());
        assert!(hot > 3.0 && later < 0.8, "{hot} → {later}");
    }

    #[test]
    fn version_and_layout_mismatch_are_refused() {
        let g = Guard::from_toml_str(CONFIG).unwrap();
        traffic(&g, 0..500, 0.0);
        let snap = g.snapshot();
        assert_eq!(snap.version(), FORMAT_VERSION);
        assert!(snap.actors() > 0);

        let mut v = json(&snap);
        v["format"] = Value::from(FORMAT_VERSION + 1);
        // another format's body isn't even parsed
        v["state"] = Value::from("whatever format 2 looks like");
        assert!(matches!(
            restored(&v),
            Err(Error::SnapshotVersion { found, expected }) if found == FORMAT_VERSION + 1 && expected == FORMAT_VERSION
        ));

        let mut v = json(&snap);
        v["layout"] = Value::from(v["layout"].as_u64().unwrap() ^ 1);
        assert!(matches!(restored(&v), Err(Error::SnapshotLayout)));

        // a refused snapshot leaves the guard as it was
        let before = learned(&g.snapshot());
        let mut v = json(&snap);
        v["format"] = Value::from(0);
        let bad = Snapshot::from_json(&serde_json::to_vec(&v).unwrap()).unwrap();
        assert!(g.restore(bad).is_err());
        assert_eq!(learned(&g.snapshot()), before);

        // another time source
        let sys = Guard::from_toml_str("[guard]\ntime_source = \"system\"\n").unwrap();
        assert!(matches!(
            sys.restore(snap.clone()),
            Err(Error::SnapshotIncompatible(_))
        ));
    }

    #[test]
    fn a_clock_ahead_of_the_system_clock_is_refused() {
        let g = Guard::from_toml_str(CONFIG).unwrap();
        let now = SystemTime::now();
        g.assess(&Event::new(
            "a",
            "GET",
            "/",
            now + Duration::from_secs(3600),
        ));
        let copy = Guard::from_toml_str(CONFIG).unwrap();
        assert!(matches!(
            copy.restore_at(g.snapshot(), now),
            Err(Error::SnapshotIncompatible(_))
        ));
        assert!(
            copy.restore_at(g.snapshot(), now + Duration::from_secs(3600))
                .is_ok()
        );
    }

    #[test]
    fn system_clock_resumes_after_the_gap() {
        let cfg = "[guard]\ntime_source = \"system\"\n";
        let g = Guard::from_toml_str(cfg).unwrap();
        g.assess(&Event::new("a", "GET", "/", at(0.0)));
        let snap = g.snapshot();
        let s = snap.state.as_ref().unwrap();
        let (taken_at, saved) = (s.taken_at, s.clock.unwrap());
        let copy = Guard::from_toml_str(cfg).unwrap();
        let day = 86_400.0;
        copy.restore_at(
            snap,
            SystemTime::UNIX_EPOCH + Duration::from_secs_f64(taken_at + day),
        )
        .unwrap();
        let resumed = copy.snapshot().state.unwrap().clock.unwrap();
        assert!(
            resumed >= saved + day && resumed < saved + day + 5.0,
            "{saved} → {resumed}"
        );

        // a crafted clock and taken_at are bounded
        let mut v = json(&g.snapshot());
        v["state"]["clock"] = Value::from(1e300f64.to_bits());
        v["state"]["taken_at"] = Value::from(0u64);
        let crafted = Guard::from_toml_str(cfg).unwrap();
        crafted
            .restore(Snapshot::from_json(&serde_json::to_vec(&v).unwrap()).unwrap())
            .unwrap();
        let clock = crafted.snapshot().state.unwrap().clock.unwrap();
        assert!(
            clock <= MAX_SYSTEM_CLOCK_SECS + MAX_RESTART_GAP_SECS + 5.0,
            "{clock}"
        );
    }

    #[test]
    fn restored_times_are_clamped_to_the_clock() {
        let g = Guard::from_toml_str(CONFIG).unwrap();
        traffic(&g, 0..3000, 0.0);
        let mut v = json(&g.snapshot());
        let clock = f64::from_bits(v["state"]["clock"].as_u64().unwrap());
        let bits = |x: f64| Value::from(x.to_bits());
        // a cooldown for a year, a counter from the future, a negative counter, a window
        // entry and a route baseline from the future
        let cooldowns = v["state"]["cooldowns"].as_array_mut().unwrap();
        assert!(!cooldowns.is_empty());
        for c in cooldowns.iter_mut() {
            c[1]["until"] = bits(clock + 365.0 * 86_400.0);
        }
        let actor = &mut v["state"]["features"]["actors"][0][1];
        actor[4][0] = Value::from(vec![bits(-5.0), bits(clock + 1e6)]); // burst [v, t]
        actor[2] = bits(clock + 1e6); // last_seen
        v["state"]["rules"]["actors"][0][1][0][0][0] = bits(clock + 1e6); // entry ts
        v["state"]["features"]["routes"][0][1][0] = bits(clock + 1e6); // first_seen
        let copy = Guard::from_toml_str(CONFIG).unwrap();
        copy.restore(Snapshot::from_json(&serde_json::to_vec(&v).unwrap()).unwrap())
            .unwrap();
        let s = json(&copy.snapshot());
        let f = |v: &Value| f64::from_bits(v.as_u64().unwrap());
        for c in s["state"]["cooldowns"].as_array().unwrap() {
            assert!(
                f(&c[1]["until"]) <= clock + 120.0,
                "at most cooldown_secs ahead"
            );
        }
        let actors = s["state"]["features"]["actors"].as_array().unwrap();
        let restored = actors
            .iter()
            .find(|a| a[0] == v["state"]["features"]["actors"][0][0]);
        let a = &restored.unwrap()[1];
        assert_eq!((f(&a[4][0][0]), f(&a[4][0][1])), (0.0, clock));
        assert_eq!(f(&a[2]), clock);
        assert!(f(&s["state"]["features"]["routes"][0][1][0]) <= clock);
        for w in s["state"]["rules"]["actors"].as_array().unwrap() {
            for e in w[1][0].as_array().unwrap() {
                assert!(f(&e[0]) <= clock);
            }
        }
        // and the guard keeps deciding with finite numbers
        assert!(
            traffic(&copy, 3000..3100, 0.0)
                .iter()
                .all(|a| a.risk.is_finite())
        );
    }

    /// The serialised shape of format `FORMAT_VERSION`, frozen. If this fails, the
    /// snapshot's shape changed (a field added, removed, reordered or re-encoded in
    /// `ActorState`, `ClientState`, `SubnetState`, `RouteState`, `Strikes`, tracker
    /// `Entry` or the containers): bump `FORMAT_VERSION`, so files of the old shape are
    /// refused cleanly, and regenerate the file with
    /// `PG_BLESS=1 cargo test -p pattern-guard --lib golden`.
    #[test]
    fn golden_snapshot_keeps_its_shape() {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/data/snapshot-v1.json");
        if std::env::var_os("PG_BLESS").is_some() {
            let g = Guard::from_toml_str(
                "[guard]\nwindow_secs = 60\nburst_max_events = 5\ncooldown_secs = 120\ncooldown_after_blocks = 2\n",
            )
            .unwrap();
            for i in 0..90u64 {
                let (actor, ua, path, status) = match i % 3 {
                    0 => (
                        "ip:198.51.100.7",
                        "Mozilla/5.0",
                        format!("/item/{}", i / 3),
                        200,
                    ),
                    1 => ("ip:198.51.100.8", "Mozilla/5.0", "/login".to_string(), 401),
                    _ => (
                        "ip:203.0.113.9",
                        "curl/8",
                        format!("/item/{}", 1000 + i),
                        404,
                    ),
                };
                let ev = Event::new(actor, "GET", path, at(i as f64))
                    .with_ip(actor[3..].parse().unwrap())
                    .with_user_agent(ua);
                g.assess(&ev);
                g.observe_response(&ev, status);
            }
            let mut v = json(&g.snapshot());
            v["state"]["taken_at"] = Value::from(1_700_000_100f64.to_bits());
            std::fs::write(path, serde_json::to_string_pretty(&v).unwrap() + "\n").unwrap();
        }
        let golden: Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
        assert_eq!(
            golden["format"], FORMAT_VERSION,
            "FORMAT_VERSION changed: regenerate {path} (see this test's docs)"
        );
        let s = &golden["state"];
        let nonempty = |p: &[&str]| {
            p.iter()
                .fold(s, |v, k| &v[*k])
                .as_array()
                .is_some_and(|a| !a.is_empty())
        };
        assert!(
            ["actors", "clients", "subnets", "routes"]
                .iter()
                .all(|t| nonempty(&["features", t]))
                && nonempty(&["rules", "actors"])
                && nonempty(&["cooldowns"]),
            "the golden file uses every table"
        );
        // the layout fingerprint follows the toolchain's hash; the shape is what's tested
        let mut current = golden.clone();
        current["layout"] = Value::from(layout_fingerprint());
        let parsed =
            Snapshot::from_json(&serde_json::to_vec(&current).unwrap()).unwrap_or_else(|e| {
                panic!("the format-{FORMAT_VERSION} golden file no longer parses: {e}")
            });
        assert!(parsed.state.is_some());
        assert_eq!(
            serde_json::from_slice::<Value>(&parsed.to_json()).unwrap(),
            current,
            "a format-{FORMAT_VERSION} snapshot no longer serialises the same way: bump FORMAT_VERSION"
        );
    }

    #[test]
    fn restore_reapplies_the_caps() {
        let big = Guard::from_toml_str("[guard]\nmax_actors = 1000\n").unwrap();
        for i in 0..500 {
            big.assess(&Event::new(
                format!("ip:10.0.{}.{}", i / 250, i % 250),
                "GET",
                "/",
                at(i as f64),
            ));
        }
        let mut v = json(&big.snapshot());
        // a hand-made entry far over the per-actor list sizes, and a bad ring position
        let actors = v["state"]["features"]["actors"].as_array_mut().unwrap();
        let newest = &mut actors.last_mut().unwrap()[1];
        newest[5][0] = Value::from(
            (0..500u64)
                .map(|k| Value::from(vec![Value::from(k), Value::from(vec![0u64, 0])]))
                .collect::<Vec<_>>(),
        );
        let ids: Vec<Value> = (0..40u64).map(|i| serde_json::json!([i, i])).collect();
        newest[6] = serde_json::json!([ids, 12345]);
        let small = Guard::from_toml_str("[guard]\nmax_actors = 10\n").unwrap();
        small
            .restore(Snapshot::from_json(&serde_json::to_vec(&v).unwrap()).unwrap())
            .unwrap();
        let s = json(&small.snapshot());
        let actors = s["state"]["features"]["actors"].as_array().unwrap();
        assert_eq!(actors.len(), 10, "the 10 most recent actors");
        assert_eq!(
            actors.last().unwrap()[0],
            v["state"]["features"]["actors"]
                .as_array()
                .unwrap()
                .last()
                .unwrap()[0]
        );
        let newest = &actors.last().unwrap()[1];
        assert_eq!(newest[5][0].as_array().unwrap().len(), 16);
        assert_eq!(newest[6][0].as_array().unwrap().len(), 32);
        assert!(newest[6][1].as_u64().unwrap() < 32);
        // the clamped ring position works
        for id in 0..100 {
            small.assess(&Event::new(
                "ip:10.0.1.249",
                "GET",
                format!("/o/{id}"),
                at(600.0),
            ));
        }
    }

    /// Size and cost of a snapshot with every table at its default cap (100 000 actors,
    /// 50 000 clients and subnets, 10 000 routes, cooldowns, and with `burst_max_events`
    /// set the rules windows too), each actor sending `per_actor` requests over distinct
    /// routes and object ids. While the snapshot is copied, another thread keeps calling
    /// `assess` and records its slowest call (how long a request waits for the lock).
    /// `cargo test --release -p pattern-guard --lib -- --ignored full_caps --nocapture`
    #[test]
    #[ignore]
    fn measure_snapshot_at_full_caps() {
        let word = |mut n: u64| {
            let mut s = String::new();
            for _ in 0..3 {
                s.push((b'a' + (n % 26) as u8) as char);
                n /= 26;
            }
            s
        };
        for (cfg, per_actor) in [("", 4u64), ("", 40), ("burst_max_events = 100", 40)] {
            let cfg = format!("[guard]\n{cfg}\n");
            let g = Guard::from_toml_str(&cfg).unwrap();
            let fill = std::time::Instant::now();
            for i in 0..100_000u64 {
                let net = i % 60_000; // 60 000 /24 networks, one or two actors each
                let ip: IpAddr = format!("10.{}.{}.{}", net / 256, net % 256, i / 60_000 + 1)
                    .parse()
                    .unwrap();
                for j in 0..per_actor {
                    let ev = Event::new(
                        format!("ip:{ip}"),
                        "GET",
                        format!("/{}/{}", word((i + j) % 12_000), i * 50 + j),
                        at(i as f64 * 0.01 + j as f64 * 0.001),
                    )
                    .with_ip(ip)
                    .with_user_agent(format!("agent-{}", i % 60_000));
                    g.assess(&ev);
                    g.observe_response(&ev, if j % 3 == 0 { 404 } else { 200 });
                }
            }
            let fill = fill.elapsed();
            // the same probe without a snapshot: scheduling noise on this machine
            let idle = {
                let mut worst = Duration::ZERO;
                let ev = Event::new("ip:192.0.2.1", "GET", "/", at(2000.0));
                let start = std::time::Instant::now();
                while start.elapsed() < Duration::from_millis(300) {
                    let t = std::time::Instant::now();
                    g.assess(&ev);
                    worst = worst.max(t.elapsed());
                }
                worst
            };
            println!("slowest assess without a snapshot: {idle:.2?}");
            let done = std::sync::atomic::AtomicBool::new(false);
            let (snap, copy_time, worst_wait) = std::thread::scope(|sc| {
                let probe = sc.spawn(|| {
                    let mut worst = Duration::ZERO;
                    let ev = Event::new("ip:192.0.2.1", "GET", "/", at(2000.0));
                    while !done.load(std::sync::atomic::Ordering::Relaxed) {
                        let t = std::time::Instant::now();
                        g.assess(&ev);
                        worst = worst.max(t.elapsed());
                    }
                    worst
                });
                let t = std::time::Instant::now();
                let snap = g.snapshot();
                let copy_time = t.elapsed();
                done.store(true, std::sync::atomic::Ordering::Relaxed);
                (snap, copy_time, probe.join().unwrap())
            });
            let t = std::time::Instant::now();
            let bytes = snap.to_json();
            let ser = t.elapsed();
            let t = std::time::Instant::now();
            let back = Snapshot::from_json(&bytes).unwrap();
            let de = t.elapsed();
            let fresh = Guard::from_toml_str(&cfg).unwrap();
            let t = std::time::Instant::now();
            fresh.restore(back).unwrap();
            let restore = t.elapsed();
            let s = snap.state.as_ref().unwrap();
            let [actors, clients, subnets, routes] = s.features.sizes();
            println!(
                "{} {per_actor} requests/actor (fill {fill:.1?}): actors {actors} clients {clients} subnets {subnets} \
                 routes {routes} windows {} cooldowns {}: {:.1} MB JSON; copy {copy_time:.1?} (slowest assess \
                 meanwhile {worst_wait:.2?}), serialise {ser:.1?}, parse {de:.1?}, restore {restore:.1?}",
                cfg.trim().replace('\n', " "),
                s.rules.len(),
                s.cooldowns.len(),
                bytes.len() as f64 / 1e6,
            );
        }
    }

    #[test]
    fn truncated_or_garbage_input_is_refused_without_a_panic() {
        let g = Guard::from_toml_str(CONFIG).unwrap();
        traffic(&g, 0..400, 0.0);
        let bytes = g.snapshot().to_json();
        for cut in (0..bytes.len()).step_by(97) {
            assert!(Snapshot::from_json(&bytes[..cut]).is_err(), "cut at {cut}");
        }
        let load = |b: &[u8]| {
            let copy = Guard::from_toml_str(CONFIG).unwrap();
            Snapshot::from_json(b).and_then(|s| copy.restore(s))
        };
        for garbage in [
            &b""[..],
            b"\x00\xff garbage",
            b"null",
            b"{}",
            b"{\"format\": 1}",
            b"{\"format\": 1, \"layout\": 2, \"state\": {}}",
            b"[1, 2, 3]",
            b"[1]",
        ] {
            assert!(
                load(garbage).is_err(),
                "{}",
                String::from_utf8_lossy(garbage)
            );
        }
        // NaN and infinities are refused
        let mut v: Value = serde_json::from_slice(&bytes).unwrap();
        v["state"]["clock"] = Value::from(f64::INFINITY.to_bits());
        assert!(Snapshot::from_json(&serde_json::to_vec(&v).unwrap()).is_err());
        // flipped bytes anywhere: an error or a usable guard, never a panic
        let mut state = 0x2545_f491_4f6c_dd1du64;
        for _ in 0..300 {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            let mut b = bytes.clone();
            let pos = state as usize % b.len();
            b[pos] = b"0123456789[]{},\":-e9"[(state >> 32) as usize % 20];
            let copy = Guard::from_toml_str(CONFIG).unwrap();
            if let Ok(s) = Snapshot::from_json(&b) {
                if copy.restore(s).is_ok() {
                    traffic(&copy, 400..420, 200.0);
                }
            }
        }
    }
}
