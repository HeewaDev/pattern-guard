//! Shared gateway state, split by how long it lives:
//!
//! * [`Compiled`]: everything built from the config (rules, limit and operation
//!   definitions, lists, protocol, geo, security headers, leak signatures, upstream,
//!   the challenge settings, the config itself). It is one immutable snapshot behind
//!   [`State::compiled`], replaced as a whole on a reload. A request reads its body
//!   under the snapshot current when its head arrived, then takes the current one and
//!   keeps it for the decision and the forward, so they never see two configs.
//! * [`Learned`]: what the gateway learns from traffic (behavioural baselines,
//!   reputation and bans, rate buckets, operation and login caches, the API inventory).
//!   It is kept across reloads, and it is what persistence will snapshot.
//! * [`Runtime`]: process plumbing (HTTP client, metrics, decision log, connection
//!   counts, request counter, console throttle, the WAF inspector).

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::AtomicU64;
use std::sync::{Arc, Mutex, PoisonError, RwLock};
use std::time::Duration;

use bytes::Bytes;
use http_body_util::Full;
use hyper::http::uri::{Authority, Scheme};
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::TokioExecutor;
use pattern_guard::Guard;
use pattern_guard::waf::Inspector;

use crate::challenge::Challenger;
use crate::config::GatewayConfig;
use crate::geo::{GeoDb, GeoPolicy};
use crate::hardening::headers::SecurityHeaders;
use crate::hardening::leaks::LeakInspector;
use crate::intel::IntelStore;
use crate::intel::tasks::IntelTasks;
use crate::ipnet::Cidr;
use crate::observability::eventlog::EventLog;
use crate::observability::inventory::Inventory;
use crate::observability::metrics::Metrics;
use crate::policy::bans::{self, Bans, Offenders};
use crate::policy::operations::{OperationCaches, Operations};
use crate::policy::protocol::Protocol;
use crate::policy::rate_limit::{Buckets, Limits};
use crate::policy::rules::RuleSet;

pub struct State {
    compiled: RwLock<Arc<Compiled>>,
    pub learned: Learned,
    pub runtime: Runtime,
}

impl State {
    pub fn new(compiled: Compiled, learned: Learned, runtime: Runtime) -> Self {
        Self {
            compiled: RwLock::new(Arc::new(compiled)),
            learned,
            runtime,
        }
    }

    /// The current config snapshot. Take it once per request (or connection) and keep
    /// it: a reload swaps in a new one, and the old one lives on until its last user is
    /// done.
    pub fn compiled(&self) -> Arc<Compiled> {
        self.compiled
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// Makes `new` the snapshot that requests from now on take (see `reload`).
    pub(crate) fn replace_compiled(&self, new: Arc<Compiled>) {
        let old = std::mem::replace(
            &mut *self
                .compiled
                .write()
                .unwrap_or_else(PoisonError::into_inner),
            new,
        );
        drop(old); // outside the lock: the last user of a snapshot frees it
    }
}

/// Everything built from the config.
pub struct Compiled {
    pub cfg: GatewayConfig,
    /// The challenge settings and the key that signs challenges and clearance cookies.
    pub challenger: Challenger,
    pub upstream_scheme: Scheme,
    pub upstream_authority: Authority,
    pub trusted: Vec<Cidr>,
    pub allow: Vec<Cidr>,
    pub deny: Vec<Cidr>,
    pub challenge_list: Vec<Cidr>,
    pub rules: RuleSet,
    pub rate_limits: Limits,
    pub operations: Operations,
    pub bans: Bans,
    pub protocol: Protocol,
    pub security_headers: SecurityHeaders,
    pub leaks: Option<LeakInspector>,
    pub geo_db: Option<GeoDb>,
    pub geo_policy: GeoPolicy,
}

impl Compiled {
    /// Validates `cfg` ([`GatewayConfig::validate`]), then compiles and checks every
    /// section (regexes, CIDRs, the geo database). Has no side effects, so a failure
    /// leaves nothing behind.
    pub fn compile(cfg: GatewayConfig) -> Result<Self, String> {
        cfg.validate()?;
        let up: hyper::Uri = cfg
            .upstream
            .parse()
            .map_err(|e| format!("bad upstream: {e}"))?;
        let cidrs = |l: &[String]| l.iter().filter_map(|c| Cidr::parse(c)).collect::<Vec<_>>();
        let geo_db = cfg.geo.database.as_deref().map(GeoDb::load).transpose()?;
        let g = &cfg.geo;
        let needs_geo = !(g.deny_countries.is_empty()
            && g.challenge_countries.is_empty()
            && g.allow_countries.is_empty())
            || cfg.rules.iter().any(|r| !r.countries.is_empty());
        if needs_geo && geo_db.is_none() {
            return Err("country rules are configured but [geo] database is not set".into());
        }
        Ok(Self {
            challenger: Challenger::new(
                &cfg.challenge.secret,
                cfg.challenge.difficulty,
                cfg.challenge.ttl_secs,
            ),
            upstream_scheme: up.scheme().cloned().ok_or("upstream needs a scheme")?,
            upstream_authority: up.authority().cloned().ok_or("upstream needs host:port")?,
            trusted: cidrs(&cfg.client_ip.trusted_proxies),
            allow: cidrs(&cfg.access.allow),
            deny: cidrs(&cfg.access.deny),
            challenge_list: cidrs(&cfg.access.challenge),
            rules: RuleSet::compile(&cfg.rules)?,
            rate_limits: Limits::compile(&cfg.rate_limits)?,
            operations: Operations::compile(&cfg.operations, &cfg.logins)?,
            bans: Bans::new(cfg.bans.clone(), cfg.traps.clone()),
            protocol: Protocol::new(cfg.protocol.clone()),
            security_headers: SecurityHeaders::new(&cfg.response_headers)?,
            leaks: LeakInspector::new(&cfg.response_inspection),
            geo_db,
            geo_policy: GeoPolicy::new(&cfg.geo),
            cfg,
        })
    }
}

/// What the gateway learns from traffic; kept across reloads.
pub struct Learned {
    /// The behavioural engine: baselines, actor history, cooldowns.
    pub guard: Guard,
    /// Reputation from every source, including the gateway's own bans.
    pub intel: Arc<IntelStore>,
    pub offenders: Offenders,
    pub rate_buckets: Buckets,
    pub operations: OperationCaches,
    pub inventory: Inventory,
}

impl Learned {
    /// Empty learned state. The caps of the reputation store come from `cfg.limits`.
    pub fn new(cfg: &GatewayConfig, guard: Guard, metrics: &Metrics) -> Self {
        Self {
            guard,
            intel: Arc::new(
                IntelStore::new(cfg.limits.max_intel_entries_per_source)
                    .with_source_cap(bans::SOURCE, cfg.limits.max_bans)
                    .with_eviction_counter(metrics.intel_evicted.clone()),
            ),
            offenders: Offenders::default(),
            rate_buckets: Buckets::default(),
            operations: OperationCaches::default(),
            inventory: Inventory::default(),
        }
    }
}

/// Process-wide plumbing.
pub struct Runtime {
    /// The WAF. It doesn't depend on the config, and building it is expensive (it
    /// compiles every pattern), so it is built once per process.
    pub waf: Inspector,
    pub metrics: Arc<Metrics>,
    pub log: Option<EventLog>,
    pub client: Client<HttpConnector, Full<Bytes>>,
    /// Open connections per peer address (`limits.max_connections_per_ip`).
    pub conns: Mutex<HashMap<IpAddr, u32>>,
    /// Requests being handled per resolved client address
    /// (`limits.max_requests_in_flight_per_ip`).
    pub in_flight: Mutex<HashMap<IpAddr, u32>>,
    pub req_counter: AtomicU64,
    pub console_second: AtomicU64,
    pub console_suppressed: AtomicU64,
    /// CrowdSec and feed tasks, restarted by a reload when their config changes.
    pub intel_tasks: IntelTasks,
    /// Held for the whole of a reload, so two reloads never interleave.
    pub(crate) reload_lock: Mutex<()>,
}

impl Runtime {
    /// Starts the decision-log writer when `log.decisions` is set.
    pub fn new(cfg: &GatewayConfig, metrics: Arc<Metrics>) -> Self {
        let mut client = Client::builder(TokioExecutor::new());
        client.pool_idle_timeout(Duration::from_secs(60));
        Self {
            waf: Inspector::new(),
            log: cfg.log.decisions.clone().map(|path| {
                EventLog::start(path, cfg.limits.decision_log_queue_bytes, metrics.clone())
            }),
            metrics,
            client: client.build_http(),
            conns: Mutex::new(HashMap::new()),
            in_flight: Mutex::new(HashMap::new()),
            req_counter: AtomicU64::new(0),
            console_second: AtomicU64::new(0),
            console_suppressed: AtomicU64::new(0),
            intel_tasks: IntelTasks::default(),
            reload_lock: Mutex::new(()),
        }
    }
}
