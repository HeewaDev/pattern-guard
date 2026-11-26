//! Admin server on `admin_listen`: `/metrics`, `/healthz`, `/inventory`, `/bans`,
//! `POST /bans/unban`. It has no authentication: bind it to loopback or a private
//! network.

use std::sync::Arc;

use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Response, StatusCode};
use hyper_util::rt::TokioIo;
use tokio::net::TcpListener;

use crate::ipnet::Cidr;
use crate::policy;
use crate::proxy;
use crate::state::State;

fn bans_json(state: &State) -> String {
    let now = std::time::Instant::now();
    let items: Vec<_> = state
        .learned
        .intel
        .list(policy::bans::SOURCE)
        .into_iter()
        .map(|(ip, e)| {
            serde_json::json!({
                "ip": ip,
                "reason": e.reason,
                "expires_in_secs": e.expires.map(|x| x.saturating_duration_since(now).as_secs()),
            })
        })
        .collect();
    serde_json::json!({ "bans": items }).to_string()
}

fn unban(state: &State, query: &str) -> (&'static str, String, StatusCode) {
    let ip = query
        .split('&')
        .find_map(|kv| kv.strip_prefix("ip="))
        .and_then(Cidr::parse);
    match ip {
        Some(c) => {
            state.learned.intel.remove(c, policy::bans::SOURCE);
            (
                "application/json",
                serde_json::json!({ "unbanned": c.to_string() }).to_string(),
                StatusCode::OK,
            )
        }
        None => (
            "text/plain",
            "missing or invalid ?ip=".to_string(),
            StatusCode::BAD_REQUEST,
        ),
    }
}

pub(crate) async fn serve_admin(state: Arc<State>, listener: TcpListener) {
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
                        "/bans" => ("application/json", bans_json(&st), StatusCode::OK),
                        "/bans/unban" if req.method() == hyper::Method::POST => {
                            unban(&st, req.uri().query().unwrap_or(""))
                        }
                        "/bans/unban" => (
                            "text/plain",
                            "use POST /bans/unban?ip=<address>".to_string(),
                            StatusCode::METHOD_NOT_ALLOWED,
                        ),
                        "/metrics" => (
                            "text/plain; version=0.0.4",
                            st.runtime.metrics.render(st.learned.intel.len()),
                            StatusCode::OK,
                        ),
                        "/healthz" => ("text/plain", "ok".to_string(), StatusCode::OK),
                        "/inventory" => (
                            "application/json",
                            st.learned.inventory.to_json(),
                            StatusCode::OK,
                        ),
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
