//! Pattern-Guard Gateway: a reverse proxy that puts the Pattern-Guard engine in front of
//! any HTTP application and enforces its decisions.
//!
//! Per request: access lists → reputation (CrowdSec, Suricata, Wazuh) → WAF payload
//! inspection → behavioural ML → one decision → block / proof-of-work challenge / delay /
//! forward. `mode = "detect"` logs the same decisions without enforcing them.

pub mod config;
pub mod intel;
pub mod ipnet;
