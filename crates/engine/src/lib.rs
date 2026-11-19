//! Adaptive request-abuse detection. Event in, decision out
//! (allow / warn / delay / challenge / block). Your code enforces.
//!
//! ```no_run
//! use pattern_guard::{Guard, Event};
//! use std::time::SystemTime;
//!
//! # fn main() -> Result<(), pattern_guard::Error> {
//! let guard = Guard::from_config_path("guard.toml")?;
//! let event = Event::new("ip:203.0.113.7", "GET", "/api/foo", SystemTime::now())
//!     .with_user_agent("Mozilla/5.0 ...");
//! let assessment = guard.assess(&event);
//! // ... handle the request according to assessment.decision ...
//! guard.observe_response(&event, 200);
//! # Ok(())
//! # }
//! ```

mod analyzer;
pub mod config;
pub mod decision;
pub mod error;
pub mod event;
pub mod features;
pub mod guard;
pub mod logs;
pub mod model;
pub mod normalize;
mod stats;
mod tracker;
pub mod waf;

pub use config::{Config, Mode, RiskCombine, TimeSource};
pub use decision::Decision;
pub use error::Error;
pub use event::Event;
pub use features::{FEATURE_NAMES, Features, N_FEATURES};
pub use guard::{Assessment, Guard, Reason};
pub use model::{Model, TrainOptions};
