//! Threat intelligence: the reputation store and the sources that feed it
//! (CrowdSec decision stream, Suricata EVE and Wazuh alert files).

pub mod crowdsec;
pub mod feeds;
mod store;
pub mod tasks;

pub use store::{IntelAction, IntelEntry, IntelStore};
