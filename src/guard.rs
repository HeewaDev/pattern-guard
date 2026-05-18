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
        let mut max_window_secs = config.guard.window_secs;
        for o in config.guard.actors.values() {
            let w = o.window_secs.unwrap_or(config.guard.window_secs);
            max_window_secs = max_window_secs.max(w);
        }
        let tracker = Tracker::new(max_window_secs, config.guard.max_actors);
        Ok(Self { config, tracker })
    }

    pub fn check(&self, event: &Event) -> Decision {
        self.check_with_risk(event).0
    }

    /// Returns (decision, risk 0–1).
    pub fn check_with_risk(&self, event: &Event) -> (Decision, f64) {
        let effective = self.config.guard.for_actor(&event.actor);
        self.tracker.record(event);
        let events = self
            .tracker
            .events_in_window(&event.actor, effective.window_secs);
        let risk = analyzer::compute_risk(&events, &effective);
        let decision = effective.risk_to_decision(risk);
        (decision, risk)
    }
}

const _: () = {
    const fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<Guard>();
    assert_send_sync::<Event>();
    assert_send_sync::<Decision>();
};
