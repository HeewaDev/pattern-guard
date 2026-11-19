//! Event in, decision out (allow / warn / delay / challenge / block). Your code enforces.
//!
//! ```no_run
//! use pattern_guard::{Guard, Event};
//! use std::time::SystemTime;
//!
//! # fn main() -> Result<(), pattern_guard::Error> {
//! let guard = Guard::from_config_path("guard.toml")?;
//! let event = Event::new("user:123", "GET", "/api/foo", SystemTime::now());
//! let (decision, risk) = guard.check_with_risk(&event);
//! # Ok(())
//! # }
//! ```

mod analyzer;
pub mod config;
pub mod decision;
pub mod error;
pub mod event;
pub mod guard;
pub mod normalize;
mod stats;
mod tracker;

pub use config::{Config, Mode, RiskCombine, TimeSource};
pub use decision::Decision;
pub use error::Error;
pub use event::Event;
pub use guard::{Assessment, Guard, Reason};
