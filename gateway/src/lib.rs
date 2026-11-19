//! Pattern-Guard Gateway: a reverse proxy that puts the Pattern-Guard engine in front of
//! any HTTP application and enforces its decisions.
//!
//! Per request: access lists → reputation (CrowdSec, Suricata, Wazuh) → WAF payload
//! inspection → behavioural ML → one decision → block / proof-of-work challenge / delay /
//! forward. `mode = "detect"` logs the same decisions without enforcing them.

pub mod challenge;
pub mod config;
pub mod crowdsec;
pub mod eventlog;
pub mod intel;
pub mod inventory;
pub mod ipnet;
pub mod metrics;
pub mod proxy;
pub mod state;

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering::Relaxed};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Response, StatusCode};
use hyper_util::client::legacy::Client;
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use pattern_guard::Guard;
use pattern_guard::waf::Inspector;
use tokio::net::TcpListener;

use crate::challenge::Challenger;
use crate::config::GatewayConfig;
use crate::eventlog::EventLog;
use crate::intel::IntelStore;
use crate::inventory::Inventory;
use crate::ipnet::{Cidr, any_contains, normalize};
use crate::metrics::Metrics;
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
    let mut client = Client::builder(TokioExecutor::new());
    client.pool_idle_timeout(Duration::from_secs(60));
    let state = State {
        challenger: Challenger::new(
            &cfg.challenge.secret,
            cfg.challenge.difficulty,
            cfg.challenge.ttl_secs,
        ),
        guard,
        waf: Inspector::new(),
        intel: Arc::new(IntelStore::default()),
        metrics: Arc::new(Metrics::default()),
        log: cfg.log.decisions.clone().map(EventLog::start),
        inventory: Inventory::default(),
        client: client.build_http(),
        upstream_scheme: up.scheme().cloned().ok_or("upstream needs a scheme")?,
        upstream_authority: up.authority().cloned().ok_or("upstream needs host:port")?,
        trusted: cidrs(&cfg.client_ip.trusted_proxies),
        allow: cidrs(&cfg.access.allow),
        deny: cidrs(&cfg.access.deny),
        challenge_list: cidrs(&cfg.access.challenge),
        conns: Mutex::new(HashMap::new()),
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
        let key = crowdsec::api_key(&state.cfg.crowdsec)?;
        tokio::spawn(crowdsec::run(
            state.cfg.crowdsec.clone(),
            key,
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
        tokio::spawn(serve_admin(state.clone(), l));
    }
    Ok(())
}

struct ConnGuard {
    state: Arc<State>,
    ip: IpAddr,
}

impl Drop for ConnGuard {
    fn drop(&mut self) {
        let mut g = self.state.conns.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(c) = g.get_mut(&self.ip) {
            *c -= 1;
            if *c == 0 {
                g.remove(&self.ip);
            }
        }
    }
}

/// Accept loop for the protected listener. Runs until the listener fails.
pub async fn serve(state: Arc<State>, listener: TcpListener) {
    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(x) => x,
            Err(e) => {
                eprintln!("pattern-guard-gateway: accept error: {e}");
                tokio::time::sleep(Duration::from_millis(50)).await;
                continue;
            }
        };
        let pip = normalize(peer.ip());
        let limit = state.cfg.limits.max_connections_per_ip;
        let guard = if limit > 0 && !any_contains(&state.trusted, pip) {
            let mut g = state.conns.lock().unwrap_or_else(|e| e.into_inner());
            let c = g.entry(pip).or_default();
            if *c >= limit {
                state.metrics.connections_rejected.fetch_add(1, Relaxed);
                continue; // drop the stream
            }
            *c += 1;
            Some(ConnGuard {
                state: state.clone(),
                ip: pip,
            })
        } else {
            None
        };
        let st = state.clone();
        let header_timeout = Duration::from_secs(state.cfg.limits.header_read_timeout_secs.max(1));
        tokio::spawn(async move {
            let _guard = guard;
            let svc = service_fn(move |req| proxy::handle(st.clone(), peer, req));
            let mut b = http1::Builder::new();
            b.timer(TokioTimer::new())
                .header_read_timeout(header_timeout)
                .keep_alive(true);
            let _ = b.serve_connection(TokioIo::new(stream), svc).await;
        });
    }
}

async fn serve_admin(state: Arc<State>, listener: TcpListener) {
    loop {
        let Ok((stream, _)) = listener.accept().await else {
            continue;
        };
        let st = state.clone();
        tokio::spawn(async move {
            let svc = service_fn(move |req: hyper::Request<hyper::body::Incoming>| {
                let st = st.clone();
                async move {
                    let (ct, body, status) = match req.uri().path() {
                        "/metrics" => (
                            "text/plain; version=0.0.4",
                            st.metrics.render(st.intel.len()),
                            StatusCode::OK,
                        ),
                        "/healthz" => ("text/plain", "ok".to_string(), StatusCode::OK),
                        "/inventory" => {
                            ("application/json", st.inventory.to_json(), StatusCode::OK)
                        }
                        _ => ("text/plain", "not found".to_string(), StatusCode::NOT_FOUND),
                    };
                    let mut r = Response::new(proxy::full(body));
                    *r.status_mut() = status;
                    r.headers_mut()
                        .insert(hyper::header::CONTENT_TYPE, ct.parse().unwrap());
                    Ok::<_, std::convert::Infallible>(r)
                }
            });
            let _ = http1::Builder::new()
                .serve_connection(TokioIo::new(stream), svc)
                .await;
        });
    }
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
