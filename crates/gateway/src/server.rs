//! Connection-level protection: the accept loop for the protected listener (per-IP
//! connection cap with trusted proxies exempt, header-read timeout against slowloris,
//! one task per connection), the in-flight request cap per resolved client IP, and the
//! request-body reader (minimum rate / stall timeout, global budget for buffered body
//! bytes).

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::Ordering::Relaxed;
use std::time::Duration;

use bytes::{Bytes, BytesMut};
use http_body_util::BodyExt;
use hyper::body::{Body as _, Incoming};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Response, StatusCode, header};
use hyper_util::rt::{TokioIo, TokioTimer};
use tokio::net::TcpListener;

use crate::ipnet::{any_contains, normalize};
use crate::observability::metrics::Metrics;
use crate::proxy;
use crate::state::{Compiled, State};

/// Request-body bytes reserved against `limits.max_buffered_body_bytes`; released when
/// dropped (keep it alive as long as the buffered body is).
pub(crate) struct BodyReservation {
    metrics: Arc<Metrics>,
    bytes: u64,
}

impl BodyReservation {
    fn new(metrics: Arc<Metrics>) -> Self {
        Self { metrics, bytes: 0 }
    }

    /// Reserves `n` more bytes unless that would take the total over `budget`.
    fn try_reserve(&mut self, n: u64, budget: Option<u64>) -> bool {
        let before = self.metrics.buffered_body_bytes.fetch_add(n, Relaxed);
        if budget.is_some_and(|b| before + n > b) {
            self.metrics.buffered_body_bytes.fetch_sub(n, Relaxed);
            return false;
        }
        self.bytes += n;
        true
    }
}

impl Drop for BodyReservation {
    fn drop(&mut self) {
        self.metrics
            .buffered_body_bytes
            .fetch_sub(self.bytes, Relaxed);
    }
}

/// A plain-text refusal that closes the connection (the rest of the request was not
/// read, so the connection can't be reused).
fn refuse(status: StatusCode, msg: &'static str) -> Response<proxy::Body> {
    let mut r = Response::new(proxy::full(msg));
    *r.status_mut() = status;
    let h = r.headers_mut();
    h.insert(header::CONTENT_TYPE, "text/plain".parse().unwrap());
    h.insert(header::CACHE_CONTROL, "no-store".parse().unwrap());
    h.insert(header::CONNECTION, "close".parse().unwrap());
    if matches!(
        status,
        StatusCode::SERVICE_UNAVAILABLE | StatusCode::TOO_MANY_REQUESTS
    ) {
        h.insert(header::RETRY_AFTER, "1".parse().unwrap());
    }
    r
}

fn refused(status: StatusCode, msg: &'static str) -> Box<Response<proxy::Body>> {
    Box::new(refuse(status, msg))
}

/// Reads the whole request body for inspection, or returns the response to send instead:
///
/// - **413** over `max_body_bytes` (checked against `Content-Length` before reading);
/// - **408** when the body doesn't keep arriving: every `body_read_timeout_secs` period
///   must bring `body_min_bytes_per_sec × body_read_timeout_secs` bytes or the end of the
///   body (a trickle of a few bytes per second, or a client that stops sending);
/// - **503** when buffering it would take all bodies being buffered over
///   `max_buffered_body_bytes` (reserved frame by frame, so a stalled upload holds only
///   what it has sent);
/// - **400** when the client breaks the body framing or disconnects.
///
/// The returned reservation must live as long as the body bytes.
pub(crate) async fn read_body(
    state: &State,
    c: &Compiled,
    mut body: Incoming,
) -> Result<(Bytes, BodyReservation), Box<Response<proxy::Body>>> {
    let metrics = &state.runtime.metrics;
    let max = c.cfg.max_body_bytes;
    if body.size_hint().lower() > max as u64 {
        metrics.body_too_large.fetch_add(1, Relaxed);
        return Err(refused(
            StatusCode::PAYLOAD_TOO_LARGE,
            "request body too large",
        ));
    }
    let lim = &c.cfg.limits;
    let budget = c.cfg.body_budget().map(|b| b as u64);
    let period = Duration::from_secs(lim.body_read_timeout_secs.max(1));
    let per_period = lim.body_min_bytes_per_sec.saturating_mul(period.as_secs());
    let mut reservation = BodyReservation::new(metrics.clone());
    let mut chunks: Vec<Bytes> = Vec::new();
    let mut total = 0usize;
    let mut deadline = tokio::time::Instant::now() + period;
    let mut this_period = 0u64;
    loop {
        let frame = match tokio::time::timeout_at(deadline, body.frame()).await {
            Err(_) => {
                metrics.rejected_body_timeout.fetch_add(1, Relaxed);
                return Err(refused(
                    StatusCode::REQUEST_TIMEOUT,
                    "request body too slow",
                ));
            }
            Ok(None) => break,
            Ok(Some(Err(_))) => {
                return Err(refused(StatusCode::BAD_REQUEST, "bad request body"));
            }
            Ok(Some(Ok(frame))) => frame,
        };
        let Ok(data) = frame.into_data() else {
            continue; // trailers
        };
        total += data.len();
        if total > max {
            metrics.body_too_large.fetch_add(1, Relaxed);
            return Err(refused(
                StatusCode::PAYLOAD_TOO_LARGE,
                "request body too large",
            ));
        }
        if !reservation.try_reserve(data.len() as u64, budget) {
            metrics.rejected_body_budget.fetch_add(1, Relaxed);
            return Err(refused(
                StatusCode::SERVICE_UNAVAILABLE,
                "too many request bodies in progress, retry shortly",
            ));
        }
        this_period += data.len() as u64;
        if this_period >= per_period {
            this_period = 0;
            deadline = tokio::time::Instant::now() + period;
        }
        chunks.push(data);
    }
    let body = match chunks.len() {
        0 => Bytes::new(),
        1 => chunks.pop().unwrap_or_default(),
        _ => {
            let mut b = BytesMut::with_capacity(total);
            for c in chunks {
                b.extend_from_slice(&c);
            }
            b.freeze()
        }
    };
    Ok((body, reservation))
}

/// Which per-IP count a [`Slot`] holds.
#[derive(Clone, Copy)]
enum Count {
    /// Open connections per peer address (`Runtime::conns`).
    Connections,
    /// Requests being handled per resolved client address (`Runtime::in_flight`).
    InFlight,
}

/// One unit of a per-IP count, given back on drop. A map entry exists only while its
/// count is above zero, so the maps are bounded by the connections that are open.
struct Slot {
    state: Arc<State>,
    ip: IpAddr,
    count: Count,
}

fn counts(state: &State, count: Count) -> &std::sync::Mutex<HashMap<IpAddr, u32>> {
    match count {
        Count::Connections => &state.runtime.conns,
        Count::InFlight => &state.runtime.in_flight,
    }
}

impl Slot {
    /// Takes a slot for `ip` unless it already holds `limit`.
    fn acquire(state: &Arc<State>, ip: IpAddr, count: Count, limit: u32) -> Option<Slot> {
        let mut g = counts(state, count)
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let c = g.entry(ip).or_default();
        if *c >= limit {
            if *c == 0 {
                g.remove(&ip);
            }
            return None;
        }
        *c += 1;
        Some(Slot {
            state: state.clone(),
            ip,
            count,
        })
    }
}

impl Drop for Slot {
    fn drop(&mut self) {
        let mut g = counts(&self.state, self.count)
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        if let Some(c) = g.get_mut(&self.ip) {
            *c -= 1;
            if *c == 0 {
                g.remove(&self.ip);
            }
        }
    }
}

/// Admits a request under `limits.max_requests_in_flight_per_ip`, counted per
/// **resolved** client IP (after `client_ip.trusted_proxies`), so it also bounds a
/// single client behind a CDN or load balancer, where the per-peer connection cap
/// doesn't apply. The allow list is exempt. Over the cap: 429 with `Retry-After: 1`.
fn admit(
    state: &Arc<State>,
    c: &Compiled,
    peer: IpAddr,
    headers: &hyper::HeaderMap,
) -> Result<Option<Slot>, Box<Response<proxy::Body>>> {
    let limit = c.cfg.limits.max_requests_in_flight_per_ip;
    if limit == 0 {
        return Ok(None);
    }
    let ip = proxy::client_ip(c, peer, headers);
    if any_contains(&c.allow, ip) {
        return Ok(None);
    }
    match Slot::acquire(state, ip, Count::InFlight, limit) {
        Some(slot) => Ok(Some(slot)),
        None => {
            state
                .runtime
                .metrics
                .rejected_in_flight
                .fetch_add(1, Relaxed);
            Err(refused(
                StatusCode::TOO_MANY_REQUESTS,
                "too many concurrent requests",
            ))
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
        // connection settings come from the config current when it was accepted
        let c = state.compiled();
        let limit = c.cfg.limits.max_connections_per_ip;
        let guard = if limit > 0 && !any_contains(&c.trusted, pip) {
            match Slot::acquire(&state, pip, Count::Connections, limit) {
                Some(slot) => Some(slot),
                None => {
                    state
                        .runtime
                        .metrics
                        .connections_rejected
                        .fetch_add(1, Relaxed);
                    continue; // drop the stream
                }
            }
        } else {
            None
        };
        let st = state.clone();
        let header_timeout = Duration::from_secs(c.cfg.limits.header_read_timeout_secs.max(1));
        tokio::spawn(async move {
            let _guard = guard;
            let svc = service_fn(move |req: hyper::Request<Incoming>| {
                let st = st.clone();
                async move {
                    // one config snapshot for the whole request, from admission on
                    let c = st.compiled();
                    // held until the response head is ready (body read, inspection, upstream)
                    let _slot = match admit(&st, &c, peer.ip(), req.headers()) {
                        Ok(slot) => slot,
                        Err(refusal) => return Ok(*refusal),
                    };
                    proxy::handle(st, c, peer, req).await
                }
            });
            let mut b = http1::Builder::new();
            b.timer(TokioTimer::new())
                .header_read_timeout(header_timeout)
                .keep_alive(true);
            let _ = b.serve_connection(TokioIo::new(stream), svc).await;
        });
    }
}
