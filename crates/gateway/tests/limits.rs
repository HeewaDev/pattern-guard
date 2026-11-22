//! Resource limits end to end: real upstream + gateway over TCP, raw HTTP/1.1 so a test
//! can trickle, stall or oversize any part of a request.

use std::convert::Infallible;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::Ordering::Relaxed;
use std::time::{Duration, Instant};

use bytes::Bytes;
use http_body_util::Full;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::rt::TokioIo;
use pattern_guard_gateway::config::GatewayConfig;
use pattern_guard_gateway::state::State;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// Upstream app: answers 200 "ok" to everything.
async fn start_upstream() -> SocketAddr {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (s, _) = l.accept().await.unwrap();
            tokio::spawn(async move {
                let svc = service_fn(|_req: Request<hyper::body::Incoming>| async move {
                    Ok::<_, Infallible>(Response::new(Full::new(Bytes::from_static(b"ok"))))
                });
                let _ = http1::Builder::new()
                    .serve_connection(TokioIo::new(s), svc)
                    .await;
            });
        }
    });
    addr
}

/// Gateway with the default limits plus `extra` (TOML placed before any section).
async fn start_gateway(extra: &str) -> (SocketAddr, Arc<State>) {
    let up = start_upstream().await;
    let toml = format!("upstream = \"http://{up}\"\nadmin_listen = \"127.0.0.1:0\"\n{extra}\n");
    let cfg = GatewayConfig::from_toml_str(&toml).unwrap();
    let state = pattern_guard_gateway::build_state(cfg).unwrap();
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    pattern_guard_gateway::start_background(&state, None).unwrap();
    tokio::spawn(pattern_guard_gateway::serve(state.clone(), l));
    (addr, state)
}

/// Reads one HTTP/1.1 response (head + Content-Length body); returns status and head.
async fn read_response(s: &mut TcpStream) -> (u16, String) {
    let mut buf = Vec::with_capacity(4096);
    let mut tmp = [0u8; 4096];
    let head_end = loop {
        let n = s.read(&mut tmp).await.unwrap();
        assert!(n > 0, "connection closed before a response");
        buf.extend_from_slice(&tmp[..n]);
        if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break i + 4;
        }
    };
    let head = String::from_utf8_lossy(&buf[..head_end]).to_ascii_lowercase();
    let status: u16 = head[9..12].parse().unwrap();
    let len: usize = head
        .lines()
        .find_map(|l| l.strip_prefix("content-length:"))
        .map(|v| v.trim().parse().unwrap())
        .unwrap_or(0);
    while buf.len() < head_end + len {
        let n = s.read(&mut tmp).await.unwrap();
        assert!(n > 0);
        buf.extend_from_slice(&tmp[..n]);
    }
    (status, head)
}

/// One request on a keep-alive connection; returns the status.
async fn roundtrip(s: &mut TcpStream, head: &str, body: &[u8]) -> u16 {
    s.write_all(head.as_bytes()).await.unwrap();
    s.write_all(body).await.unwrap();
    read_response(s).await.0
}

fn temp_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("pg-limits-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

async fn wait_for_lines(path: &std::path::Path, n: usize) -> Vec<String> {
    for _ in 0..100 {
        if let Ok(s) = std::fs::read_to_string(path) {
            let lines: Vec<String> = s.lines().map(str::to_string).collect();
            if lines.len() >= n {
                return lines;
            }
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("decision log {} has fewer than {n} lines", path.display());
}

// ---------------------------------------------------------------- decision log

/// A 300 KB Host header used to be copied whole into the decision-log line.
#[tokio::test]
async fn decision_log_truncates_huge_client_values() {
    let dir = temp_dir("huge-host");
    let log = dir.join("decisions.jsonl");
    let (gw, _state) = start_gateway(&format!("[log]\ndecisions = \"{}\"\n", log.display())).await;
    let host = "h".repeat(300_000);
    let ua = "u".repeat(50_000);
    let mut s = TcpStream::connect(gw).await.unwrap();
    let head = format!(
        "GET /?q=%3Cscript%3Ealert(1)%3C/script%3E HTTP/1.1\r\nhost: {host}\r\nuser-agent: {ua}\r\n\r\n"
    );
    // over the protocol header limit: blocked and logged
    assert_eq!(roundtrip(&mut s, &head, b"").await, 431);
    let lines = wait_for_lines(&log, 1).await;
    assert!(
        lines[0].len() < 16 * 1024,
        "decision-log line of {} bytes",
        lines[0].len()
    );
    let v: serde_json::Value = serde_json::from_str(&lines[0]).unwrap();
    let logged = v["http"]["hostname"].as_str().unwrap();
    assert!(
        logged.starts_with("hhhh") && logged.ends_with('…'),
        "{logged}"
    );
    assert!(
        v["http"]["http_user_agent"]
            .as_str()
            .unwrap()
            .ends_with('…')
    );
    assert_eq!(v["pattern_guard"]["layer"], "protocol");
    let _ = std::fs::remove_dir_all(&dir);
}

/// With a stalled writer (a FIFO nobody reads), queued lines are bounded by bytes, not
/// only by their count.
#[cfg(target_os = "linux")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn decision_log_queue_is_bounded_by_bytes() {
    use std::io::Read;
    use std::os::unix::fs::OpenOptionsExt;

    let dir = temp_dir("fifo");
    let fifo = dir.join("decisions.fifo");
    assert!(
        std::process::Command::new("mkfifo")
            .arg(&fifo)
            .status()
            .unwrap()
            .success()
    );
    // If an assertion fails before the reader is opened, the writer would stay blocked
    // in open() and keep the runtime from shutting down: open (and close) it on drop.
    struct Unblock(PathBuf);
    impl Drop for Unblock {
        fn drop(&mut self) {
            let _ = std::fs::OpenOptions::new()
                .read(true)
                .custom_flags(0o4000)
                .open(&self.0);
        }
    }
    let _unblock = Unblock(fifo.clone());
    let budget = 64 * 1024;
    let (gw, state) = start_gateway(&format!(
        "mode = \"detect\"\n[limits]\ndecision_log_queue_bytes = {budget}\n[log]\ndecisions = \"{}\"\n",
        fifo.display()
    ))
    .await;
    // ~8 KB URL with one XSS finding: every request is logged with a ~9 KB line
    let pad = "a".repeat(8000);
    let mut s = TcpStream::connect(gw).await.unwrap();
    let n = 40;
    for _ in 0..n {
        let head = format!(
            "GET /?q=%3Cscript%3Ealert(1)%3C/script%3E&pad={pad} HTTP/1.1\r\nhost: x\r\n\r\n"
        );
        assert_eq!(roundtrip(&mut s, &head, b"").await, 200);
    }
    let queued = state.log.as_ref().unwrap().queued_bytes();
    let dropped = state.metrics.decision_log_dropped.load(Relaxed);

    // Let the writer through (before any assertion: a writer blocked in open() would
    // keep the runtime from shutting down) and count what it had queued.
    let mut f = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(0o4000) // O_NONBLOCK
        .open(&fifo)
        .unwrap();
    let (mut total, mut lines) = (0usize, 0usize);
    let mut buf = vec![0u8; 64 * 1024];
    let mut idle = Instant::now();
    while idle.elapsed() < Duration::from_secs(1) {
        match f.read(&mut buf) {
            Ok(n) if n > 0 => {
                total += n;
                lines += buf[..n].iter().filter(|b| **b == b'\n').count();
                idle = Instant::now();
            }
            _ => tokio::time::sleep(Duration::from_millis(20)).await,
        }
    }
    println!(
        "{n} logged requests, writer stalled: {lines} lines ({total} bytes) queued, {dropped} dropped"
    );
    assert!(queued <= budget, "{queued} bytes queued");
    assert!(dropped > 0, "nothing dropped");
    assert!(lines >= 1);
    assert!(total <= budget + lines, "{total} bytes were queued");
    assert_eq!(lines as u64 + dropped, n as u64);
    let _ = std::fs::remove_dir_all(&dir);
}
