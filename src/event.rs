//! One observation: who, what, what was hit, when.

use std::collections::HashMap;
use std::time::SystemTime;

#[derive(Debug, Clone)]
pub struct Event {
    pub actor: String,
    pub action: String,
    pub target: String,
    pub timestamp: SystemTime,
    /// Cost/impact for weighted overuse; 1.0 if unset.
    pub weight: Option<f64>,
    pub metadata: Option<HashMap<String, String>>,
}

impl Event {
    pub fn new(
        actor: impl Into<String>,
        action: impl Into<String>,
        target: impl Into<String>,
        timestamp: SystemTime,
    ) -> Self {
        Self {
            actor: actor.into(),
            action: action.into(),
            target: target.into(),
            timestamp,
            weight: None,
            metadata: None,
        }
    }

    pub fn with_weight(mut self, weight: f64) -> Self {
        self.weight = Some(weight);
        self
    }

    pub fn with_metadata(mut self, metadata: HashMap<String, String>) -> Self {
        self.metadata = Some(metadata);
        self
    }

    /// 1.0 if weight unset.
    pub fn effective_weight(&self) -> f64 {
        self.weight.unwrap_or(1.0)
    }
}
