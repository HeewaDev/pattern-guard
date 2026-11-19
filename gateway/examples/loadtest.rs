//! Throughput/latency of the gateway vs. the bare upstream, all in one process.
//!
//! `cargo run --release -p pattern-guard-gateway --example loadtest -- [concurrency] [seconds]`
//! Shares CPU between client, gateway and upstream, so absolute numbers are a lower bound.

use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;
use http_body_util::{BodyExt, Empty, Full};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::client::legacy::Client;
use hyper_util::rt::{TokioExecutor, TokioIo};
use pattern_guard_gateway::config::GatewayConfig;
use tokio::net::TcpListener;

async fn upstream() -> SocketAddr {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let a = l.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (s, _) = l.accept().await.unwrap();
            tokio::spawn(async move {
                let svc = service_fn(|_r: Request<hyper::body::Incoming>| async {
                    Ok::<_, Infallible>(Response::new(Full::new(Bytes::from_static(
                        b"{\"ok\":true}",
                    ))))
                });
                let _ = http1::Builder::new()
                    .serve_connection(TokioIo::new(s), svc)
                    .await;
            });
        }
    });
    a
}

async fn load(addr: SocketAddr, conc: usize, secs: u64, label: &str) {
    let client = Client::builder(TokioExecutor::new())
        .pool_max_idle_per_host(conc)
        .build_http::<Empty<Bytes>>();
    let deadline = Instant::now() + Duration::from_secs(secs);
    let lat = Arc::new(std::sync::Mutex::new(Vec::<u32>::new()));
    let mut tasks = Vec::new();
    for w in 0..conc {
        let client = client.clone();
        let lat = lat.clone();
        tasks.push(tokio::spawn(async move {
            let mut local = Vec::new();
            let mut i = 0u64;
            while Instant::now() < deadline {
                i += 1;
                let uri = format!(
                    "http://{addr}/api/products/{}?page={}&q=red+shoes",
                    (w as u64 * 7919 + i) % 5000,
                    i % 20
                );
                let req = Request::get(uri)
                    .header("user-agent", "Mozilla/5.0 (X11; Linux x86_64) Chrome/130.0")
                    .header(
                        "x-forwarded-for",
                        format!("198.51.{}.{}", w % 250, (i / 50) % 250),
                    )
                    .body(Empty::new())
                    .unwrap();
                let t = Instant::now();
                if let Ok(r) = client.request(req).await {
                    let _ = r.into_body().collect().await;
                    local.push(t.elapsed().as_micros() as u32);
                }
            }
            lat.lock().unwrap().extend(local);
        }));
    }
    for t in tasks {
        let _ = t.await;
    }
    let mut v = lat.lock().unwrap().clone();
    v.sort_unstable();
    let p = |q: f64| v[((v.len() as f64 * q) as usize).min(v.len() - 1)] as f64 / 1000.0;
    println!(
        "{label:<28} {:>9.0} req/s   p50 {:>6.2} ms   p99 {:>6.2} ms   ({} requests)",
        v.len() as f64 / secs as f64,
        p(0.5),
        p(0.99),
        v.len()
    );
}

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let conc: usize = args.first().and_then(|s| s.parse().ok()).unwrap_or(64);
    let secs: u64 = args.get(1).and_then(|s| s.parse().ok()).unwrap_or(5);
    let up = upstream().await;
    let cfg = GatewayConfig::from_toml_str(&format!(
        "upstream = \"http://{up}\"\nmode = \"detect\"\n[client_ip]\ntrusted_proxies = [\"127.0.0.1\"]\n[limits]\nmax_connections_per_ip = 0\n"
    ))
    .unwrap();
    let state = pattern_guard_gateway::build_state(cfg).unwrap();
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let gw = l.local_addr().unwrap();
    tokio::spawn(pattern_guard_gateway::serve(state, l));
    println!(
        "concurrency {conc}, {secs}s each, {} CPU threads shared by client + gateway + upstream",
        std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(0)
    );
    load(up, conc, secs, "upstream directly").await;
    load(gw, conc, secs, "gateway, detect mode").await;
}
