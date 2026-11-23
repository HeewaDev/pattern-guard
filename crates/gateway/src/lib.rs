//! Pattern-Guard Gateway: a reverse proxy that puts the Pattern-Guard engine in front of
//! any HTTP application and enforces its decisions.
//!
//! Per request: access lists → reputation (CrowdSec, Suricata, Wazuh) → WAF payload
//! inspection → behavioural ML → one decision → block / proof-of-work challenge / delay /
//! forward. `mode = "detect"` logs the same decisions without enforcing them.

mod admin;
pub mod challenge;
pub mod config;
pub mod geo;
pub mod hardening;
pub mod intel;
pub mod ipnet;
pub mod observability;
pub mod policy;
pub mod proxy;
mod server;
pub mod state;
pub mod util;

pub use server::serve;

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::AtomicU64;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use pattern_guard::Guard;
use pattern_guard::waf::Inspector;
use tokio::net::TcpListener;

use crate::challenge::Challenger;
use crate::config::GatewayConfig;
use crate::intel::IntelStore;
use crate::ipnet::Cidr;
use crate::observability::eventlog::EventLog;
use crate::observability::inventory::Inventory;
use crate::observability::metrics::Metrics;
use crate::state::State;

/// Builds the shared state (loads the engine config, starts the decision log writer).
pub fn build_state(cfg: GatewayConfig) -> Result<Arc<State>, String> {
    let guard = match &cfg.guard_config {
        Some(p) => Guard::from_config_path(p).map_err(|e| e.to_string())?,
        None => Guard::from_toml_str("").map_err(|e| e.to_string())?,
    };
    let up: hyper::Uri = cfg
        .upstream
        .parse()
        .map_err(|e| format!("bad upstream: {e}"))?;
    let cidrs = |l: &[String]| l.iter().filter_map(|c| Cidr::parse(c)).collect::<Vec<_>>();
    let geo_db = cfg
        .geo
        .database
        .as_deref()
        .map(geo::GeoDb::load)
        .transpose()?;
    let g = &cfg.geo;
    let needs_geo = !(g.deny_countries.is_empty()
        && g.challenge_countries.is_empty()
        && g.allow_countries.is_empty())
        || cfg.rules.iter().any(|r| !r.countries.is_empty());
    if needs_geo && geo_db.is_none() {
        return Err("country rules are configured but [geo] database is not set".into());
    }
    let mut client = Client::builder(TokioExecutor::new());
    client.pool_idle_timeout(Duration::from_secs(60));
    let metrics = Arc::new(Metrics::default());
    let state = State {
        challenger: Challenger::new(
            &cfg.challenge.secret,
            cfg.challenge.difficulty,
            cfg.challenge.ttl_secs,
        ),
        guard,
        waf: {
            let mut w = Inspector::new();
            w.max_body_len = cfg.waf.inspect_body_bytes;
            // a body inspected up to this size may be one value of this size
            w.max_value_len = w.max_value_len.max(cfg.waf.inspect_body_bytes);
            w.flag_oversize = cfg.waf.flag_oversize;
            w
        },
        intel: Arc::new(
            IntelStore::new(cfg.limits.max_intel_entries_per_source)
                .with_source_cap(policy::bans::SOURCE, cfg.limits.max_bans)
                .with_eviction_counter(metrics.intel_evicted.clone()),
        ),
        log: cfg.log.decisions.clone().map(|path| {
            EventLog::start(path, cfg.limits.decision_log_queue_bytes, metrics.clone())
        }),
        metrics,
        inventory: Inventory::default(),
        client: client.build_http(),
        upstream_scheme: up.scheme().cloned().ok_or("upstream needs a scheme")?,
        upstream_authority: up.authority().cloned().ok_or("upstream needs host:port")?,
        trusted: cidrs(&cfg.client_ip.trusted_proxies),
        allow: cidrs(&cfg.access.allow),
        deny: cidrs(&cfg.access.deny),
        challenge_list: cidrs(&cfg.access.challenge),
        rules: policy::rules::RuleSet::compile(&cfg.rules)?,
        rate_limiter: policy::rate_limit::RateLimiter::compile(&cfg.rate_limits)?,
        operations: policy::operations::Operations::compile(&cfg.operations, &cfg.logins)?,
        bans: policy::bans::Bans::new(cfg.bans.clone(), cfg.traps.clone()),
        protocol: policy::protocol::Protocol::new(cfg.protocol.clone()),
        security_headers: hardening::headers::SecurityHeaders::new(&cfg.response_headers)?,
        leaks: hardening::leaks::LeakInspector::new(&cfg.response_inspection),
        geo_db,
        geo_policy: geo::GeoPolicy::new(&cfg.geo),
        conns: Mutex::new(HashMap::new()),
        in_flight: Mutex::new(HashMap::new()),
        req_counter: AtomicU64::new(0),
        console_second: AtomicU64::new(0),
        console_suppressed: AtomicU64::new(0),
        cfg,
    };
    Ok(Arc::new(state))
}

/// Starts background tasks (CrowdSec, feeds, sweeper) and the admin server.
pub fn start_background(state: &Arc<State>, admin: Option<TcpListener>) -> Result<(), String> {
    if state.cfg.crowdsec.enabled {
        let key = intel::crowdsec::api_key(&state.cfg.crowdsec)?;
        tokio::spawn(intel::crowdsec::run(
            state.cfg.crowdsec.clone(),
            key,
            state.intel.clone(),
            state.metrics.clone(),
        ));
    }
    for f in &state.cfg.feeds {
        tokio::spawn(intel::feeds::run(
            f.clone(),
            state.intel.clone(),
            state.metrics.clone(),
        ));
    }
    let intel = state.intel.clone();
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_secs(30)).await;
            intel.sweep();
        }
    });
    if let Some(l) = admin {
        tokio::spawn(admin::serve_admin(state.clone(), l));
    }
    Ok(())
}

/// Binds listeners from the config and runs until Ctrl-C.
pub async fn run(cfg: GatewayConfig) -> Result<(), String> {
    let listener = TcpListener::bind(cfg.listen)
        .await
        .map_err(|e| format!("cannot listen on {}: {e}", cfg.listen))?;
    let admin = match cfg.admin_listen {
        Some(a) => Some(
            TcpListener::bind(a)
                .await
                .map_err(|e| format!("cannot listen on {a}: {e}"))?,
        ),
        None => None,
    };
    let listen: SocketAddr = listener.local_addr().map_err(|e| e.to_string())?;
    let state = build_state(cfg)?;
    start_background(&state, admin)?;
    eprintln!(
        "pattern-guard-gateway: listening on {listen} → {} (mode: {:?}, model: {})",
        state.cfg.upstream,
        state.cfg.mode,
        state.guard.model().description
    );
    tokio::select! {
        _ = serve(state.clone(), listener) => Ok(()),
        _ = tokio::signal::ctrl_c() => {
            eprintln!("pattern-guard-gateway: shutting down");
            Ok(())
        }
    }
}

#[allow(dead_code)]
fn _assert_send_sync() {
    fn f<T: Send + Sync>() {}
    f::<State>();
    let _ = Inspector::new;
}
