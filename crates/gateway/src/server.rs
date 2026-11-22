//! Accept loop for the protected listener: per-IP connection cap (trusted proxies
//! exempt), header-read timeout against slowloris, one task per connection.

use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::Ordering::Relaxed;
use std::time::Duration;

use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::{TokioIo, TokioTimer};
use tokio::net::TcpListener;

use crate::ipnet::{any_contains, normalize};
use crate::proxy;
use crate::state::State;

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
