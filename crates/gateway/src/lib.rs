//! Pattern-Guard Gateway: a reverse proxy that puts the Pattern-Guard engine in front of
//! any HTTP application and enforces its decisions.
//!
//! Per request: access lists → reputation (CrowdSec, Suricata, Wazuh) → WAF payload
//! inspection → behavioural ML → one decision → block / proof-of-work challenge / delay /
//! forward. `mode = "detect"` logs the same decisions without enforcing them.
//!
//! The config can be reloaded while running ([`reload`], or `SIGHUP` with [`run`]).

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
mod reload;
mod server;
pub mod state;
pub mod util;

#[cfg(unix)]
pub use reload::watch_sighup;
pub use reload::{RESTART_ONLY, Reloaded, reload, reload_from_path};
pub use server::serve;

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use pattern_guard::Guard;
use pattern_guard::waf::Inspector;
use tokio::net::TcpListener;

use crate::config::GatewayConfig;
use crate::observability::metrics::Metrics;
use crate::state::{Compiled, Learned, Runtime, State};

/// Builds the shared state (loads the engine config, compiles the gateway config,
/// starts the decision log writer).
pub fn build_state(cfg: GatewayConfig) -> Result<Arc<State>, String> {
    let guard = match &cfg.guard_config {
        Some(p) => Guard::from_config_path(p).map_err(|e| e.to_string())?,
        None => Guard::from_toml_str("").map_err(|e| e.to_string())?,
    };
    let compiled = Compiled::compile(cfg)?;
    let metrics = Arc::new(Metrics::default());
    let learned = Learned::new(&compiled.cfg, guard, &metrics);
    let runtime = Runtime::new(&compiled.cfg, metrics);
    Ok(Arc::new(State::new(compiled, learned, runtime)))
}

/// Starts background tasks (CrowdSec, feeds, sweeper) and the admin server.
pub fn start_background(state: &Arc<State>, admin: Option<TcpListener>) -> Result<(), String> {
    let c = state.compiled();
    let key = intel::tasks::crowdsec_key(&c.cfg)?;
    state
        .runtime
        .intel_tasks
        .start(&c.cfg, key, &state.learned.intel, &state.runtime.metrics);
    let intel = state.learned.intel.clone();
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

/// Binds listeners from the config and runs until Ctrl-C. With `config_path` (the file
/// `cfg` was loaded from), a `SIGHUP` reloads the config from it (Unix).
pub async fn run(cfg: GatewayConfig, config_path: Option<PathBuf>) -> Result<(), String> {
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
    #[cfg(unix)]
    if let Some(path) = config_path {
        watch_sighup(state.clone(), path)?;
    }
    #[cfg(not(unix))]
    let _ = config_path;
    let c = state.compiled();
    eprintln!(
        "pattern-guard-gateway: listening on {listen} → {} (mode: {:?}, model: {})",
        c.cfg.upstream,
        c.cfg.mode,
        state.learned.guard.model().description
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
