use std::path::Path;

use crate::analyzer;
use crate::config::Config;
use crate::decision::Decision;
use crate::error::Error;
use crate::event::Event;
use crate::tracker::Tracker;

pub struct Guard {
    config: Config,
    tracker: Tracker,
}

impl Guard {
    pub fn from_config_path(path: impl AsRef<Path>) -> Result<Self, Error> {
        let config = Config::load(path)?;
        let max_window_secs = config
            .guard
            .actors
            .values()
            .map(|g| g.window_secs)
            .max()
            .unwrap_or(0)
            .max(config.guard.window_secs);
        let tracker = Tracker::new(max_window_secs);
        Ok(Self { config, tracker })
    }

    pub fn check(&self, event: &Event) -> Decision {
        self.check_with_risk(event).0
    }

    /// Returns (decision, risk 0–1).
    pub fn check_with_risk(&self, event: &Event) -> (Decision, f64) {
        let effective = self.config.guard.for_actor(&event.actor);
        self.tracker.record(event);
        let events = self.tracker.events_in_window(&event.actor, effective.window_secs);
        let risk = analyzer::compute_risk(&events, &effective);
        let decision = effective.risk_to_decision(risk);
        (decision, risk)
    }
}

unsafe impl Send for Guard {}
unsafe impl Sync for Guard {}
