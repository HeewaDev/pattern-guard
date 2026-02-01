//! Event in, decision out (allow / warn / delay / block). Your code enforces.
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
//!

pub mod config;
pub mod decision;
pub mod error;
pub mod event;
pub mod guard;
mod analyzer;
mod tracker;

pub use config::Config;
pub use decision::Decision;
pub use error::Error;
pub use event::Event;
pub use guard::Guard;
