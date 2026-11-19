//! Shared gateway state.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::AtomicU64;
use std::sync::{Arc, Mutex};

use bytes::Bytes;
use http_body_util::Full;
use hyper::http::uri::{Authority, Scheme};
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::HttpConnector;
use pattern_guard::Guard;
use pattern_guard::waf::Inspector;

use crate::challenge::Challenger;
use crate::config::GatewayConfig;
use crate::intel::IntelStore;
use crate::ipnet::Cidr;
use crate::observability::eventlog::EventLog;
use crate::observability::inventory::Inventory;
use crate::observability::metrics::Metrics;

pub struct State {
    pub cfg: GatewayConfig,
    pub guard: Guard,
    pub waf: Inspector,
    pub challenger: Challenger,
    pub intel: Arc<IntelStore>,
    pub metrics: Arc<Metrics>,
    pub log: Option<EventLog>,
    pub inventory: Inventory,
    pub client: Client<HttpConnector, Full<Bytes>>,
    pub upstream_scheme: Scheme,
    pub upstream_authority: Authority,
    pub trusted: Vec<Cidr>,
    pub allow: Vec<Cidr>,
    pub deny: Vec<Cidr>,
    pub challenge_list: Vec<Cidr>,
    pub rules: crate::policy::rules::RuleSet,
    pub rate_limiter: crate::policy::rate_limit::RateLimiter,
    pub bans: crate::policy::bans::Bans,
    pub protocol: crate::policy::protocol::Protocol,
    pub security_headers: crate::hardening::headers::SecurityHeaders,
    pub conns: Mutex<HashMap<IpAddr, u32>>,
    pub req_counter: AtomicU64,
    pub console_second: AtomicU64,
    pub console_suppressed: AtomicU64,
}
