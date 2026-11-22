//! End-to-end: client identity (the client IP and the forwarded headers the upstream
//! receives) and the identifiers of `[[operations]]` / `[[logins]]`.

use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::client::legacy::Client;
use hyper_util::rt::{TokioExecutor, TokioIo};
use pattern_guard_gateway::config::GatewayConfig;
use pattern_guard_gateway::state::State;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// Upstream app: echoes the identity headers it received. `/signin` rejects the
/// credentials (401) unless the query contains `ok`.
async fn start_upstream() -> SocketAddr {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (s, _) = l.accept().await.unwrap();
            tokio::spawn(async move {
                let svc = service_fn(|req: Request<hyper::body::Incoming>| async move {
                    let q = req.uri().query().unwrap_or("").to_string();
                    let deny = |p: &str| req.uri().path().starts_with(p) && !q.contains("ok");
                    if deny("/signin") || deny("/denied") {
                        let mut r = Response::new(Full::new(Bytes::from("bad credentials")));
                        *r.status_mut() = StatusCode::UNAUTHORIZED;
                        return Ok::<_, Infallible>(r);
                    }
                    let h = |n: &str| {
                        let all: Vec<&str> = req
                            .headers()
                            .get_all(n)
                            .iter()
                            .filter_map(|v| v.to_str().ok())
                            .collect();
                        if all.is_empty() {
                            "<none>".to_string()
                        } else {
                            all.join(" | ")
                        }
                    };
                    let body = format!(
                        "XFF=[{}] XRI=[{}] CIP=[{}]",
                        h("x-forwarded-for"),
                        h("x-real-ip"),
                        h("cf-connecting-ip")
                    );
                    Ok::<_, Infallible>(Response::new(Full::new(Bytes::from(body))))
                });
                let _ = http1::Builder::new()
                    .serve_connection(TokioIo::new(s), svc)
                    .await;
            });
        }
    });
    addr
}

/// A gateway in prevent mode with `extra` config; no trusted proxy unless `extra` sets
/// one. Behavioural delays are not slept (these test clients send no User-Agent).
async fn start_gateway(extra: &str) -> (SocketAddr, Arc<State>) {
    let up = start_upstream().await;
    let toml = format!(
        "upstream = \"http://{up}\"\nmax_body_bytes = 100000\ndelay_max_secs = 0.0\n{extra}\n"
    );
    let cfg = GatewayConfig::from_toml_str(&toml).unwrap();
    let state = pattern_guard_gateway::build_state(cfg).unwrap();
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    pattern_guard_gateway::start_background(&state, None).unwrap();
    tokio::spawn(pattern_guard_gateway::serve(state.clone(), l));
    (addr, state)
}

struct Resp {
    status: StatusCode,
    body: String,
}

async fn send(
    addr: SocketAddr,
    method: &str,
    path: &str,
    headers: &[(&str, &str)],
    body: &str,
) -> Resp {
    let client = Client::builder(TokioExecutor::new()).build_http::<Full<Bytes>>();
    let mut b = Request::builder()
        .method(method)
        .uri(format!("http://{addr}{path}"));
    for (k, v) in headers {
        b = b.header(*k, *v);
    }
    let resp = client
        .request(b.body(Full::new(Bytes::from(body.to_string()))).unwrap())
        .await
        .unwrap();
    let status = resp.status();
    let body =
        String::from_utf8_lossy(&resp.into_body().collect().await.unwrap().to_bytes()).into_owned();
    Resp { status, body }
}

/// Sends a raw HTTP/1.1 request (`Connection: close`), for repeated header lines.
async fn raw(addr: SocketAddr, head: &str) -> Resp {
    let mut s = TcpStream::connect(addr).await.unwrap();
    s.write_all(head.as_bytes()).await.unwrap();
    let mut buf = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(5), s.read_to_end(&mut buf)).await;
    let text = String::from_utf8_lossy(&buf).into_owned();
    let (head, body) = text.split_once("\r\n\r\n").unwrap_or((&text, ""));
    let code = head
        .split_whitespace()
        .nth(1)
        .and_then(|c| c.parse().ok())
        .unwrap_or(0);
    Resp {
        status: StatusCode::from_u16(code).unwrap_or(StatusCode::IM_A_TEAPOT),
        body: body.to_string(),
    }
}

#[tokio::test]
async fn a_direct_client_cannot_forge_forwarded_identity() {
    // no trusted proxy: the peer (127.0.0.1) is the client, whatever it claims
    let (gw, _) = start_gateway("").await;
    let r = send(
        gw,
        "GET",
        "/",
        &[("x-forwarded-for", "1.2.3.4"), ("x-real-ip", "5.6.7.8")],
        "",
    )
    .await;
    assert_eq!(r.status, StatusCode::OK);
    assert!(
        r.body.contains("XFF=[127.0.0.1] XRI=[127.0.0.1]"),
        "{}",
        r.body
    );

    // a configured client-IP header other than X-Forwarded-For is replaced too
    let (gw, _) = start_gateway("[client_ip]\nheader = \"cf-connecting-ip\"\n").await;
    let r = send(gw, "GET", "/", &[("cf-connecting-ip", "1.2.3.4")], "").await;
    assert!(
        r.body
            .contains("XFF=[127.0.0.1] XRI=[127.0.0.1] CIP=[127.0.0.1]"),
        "{}",
        r.body
    );
}

#[tokio::test]
async fn behind_a_trusted_proxy_only_the_chain_from_the_client_is_forwarded() {
    let (gw, _) =
        start_gateway("[client_ip]\ntrusted_proxies = [\"127.0.0.1\", \"10.0.0.0/8\"]\n").await;
    // a forged left part, the client, then a trusted hop
    let h = [("x-forwarded-for", "6.6.6.6, 203.0.113.7, 10.0.0.2")];
    let r = send(gw, "GET", "/", &h, "").await;
    assert!(
        r.body
            .contains("XFF=[203.0.113.7, 10.0.0.2, 127.0.0.1] XRI=[203.0.113.7]"),
        "{}",
        r.body
    );
    // no header: the proxy itself is the client
    let r = send(gw, "GET", "/", &[], "").await;
    assert!(
        r.body.contains("XFF=[127.0.0.1] XRI=[127.0.0.1]"),
        "{}",
        r.body
    );
    // an unparsable entry: the peer, as for the client IP
    let r = send(
        gw,
        "GET",
        "/",
        &[("x-forwarded-for", "203.0.113.7, junk")],
        "",
    )
    .await;
    assert!(
        r.body.contains("XFF=[127.0.0.1] XRI=[127.0.0.1]"),
        "{}",
        r.body
    );

    // a CDN header: the client from it, then the CDN
    let (gw, _) = start_gateway(
        "[client_ip]\ntrusted_proxies = [\"127.0.0.1\"]\nheader = \"cf-connecting-ip\"\n",
    )
    .await;
    let h = [
        ("cf-connecting-ip", "203.0.113.9"),
        ("x-forwarded-for", "6.6.6.6"),
    ];
    let r = send(gw, "GET", "/", &h, "").await;
    assert!(
        r.body
            .contains("XFF=[203.0.113.9, 127.0.0.1] XRI=[203.0.113.9] CIP=[203.0.113.9]"),
        "{}",
        r.body
    );
}

#[tokio::test]
async fn every_forwarded_for_line_counts_right_to_left() {
    let (gw, _) = start_gateway(
        "[access]\ndeny = [\"9.9.9.9\"]\n[client_ip]\ntrusted_proxies = [\"127.0.0.1\"]\n",
    )
    .await;
    let req = |first: &str, second: &str| {
        format!(
            "GET / HTTP/1.1\r\nHost: {gw}\r\nX-Forwarded-For: {first}\r\nX-Forwarded-For: {second}\r\nConnection: close\r\n\r\n"
        )
    };
    // the first line (written by the client) does not decide who the client is
    let r = raw(gw, &req("9.9.9.9", "203.0.113.7")).await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.body);
    assert!(
        r.body
            .contains("XFF=[203.0.113.7, 127.0.0.1] XRI=[203.0.113.7]"),
        "one joined line: {}",
        r.body
    );
    // the right-most untrusted entry is in the last line
    let r = raw(gw, &req("203.0.113.7", "9.9.9.9")).await;
    assert_eq!(r.status, StatusCode::FORBIDDEN, "{}", r.body);
}

/// Distinct client IPs (behind the trusted 127.0.0.1), so the behavioural engine sees
/// no single client collecting failures.
fn from(n: u32) -> String {
    format!("198.51.100.{n}")
}

#[tokio::test]
async fn login_failures_count_whatever_the_content_type() {
    let (gw, _) = start_gateway(
        r#"
[client_ip]
trusted_proxies = ["127.0.0.1"]
[[logins]]
name = "api login"
path = "/signin"
account = "json:email"
max_failures = 2
action = "block"
[[logins]]
name = "form login"
path = "/denied"
account = "form:username"
max_failures = 2
action = "block"
"#,
    )
    .await;
    // JSON declared as text/plain, which the application parses anyway
    let json = r#"{"email": "victim@example.com", "password": "guess"}"#;
    for (n, ct) in [(1, "text/plain"), (2, "application/octet-stream")] {
        let ip = from(n);
        let h = [("content-type", ct), ("x-forwarded-for", ip.as_str())];
        let r = send(gw, "POST", "/signin", &h, json).await;
        assert_eq!(r.status, StatusCode::UNAUTHORIZED, "{}", r.body);
    }
    let ip = from(3);
    let h = [
        ("content-type", "application/json"),
        ("x-forwarded-for", ip.as_str()),
    ];
    let r = send(gw, "POST", "/signin", &h, json).await;
    assert_eq!(
        r.status,
        StatusCode::TOO_MANY_REQUESTS,
        "locked: {}",
        r.body
    );

    // a form login answered with multipart instead of URL-encoded
    let mp = "--b\r\nContent-Disposition: form-data; name=\"username\"\r\n\r\nalice\r\n--b--\r\n";
    for n in 4..=5 {
        let ip = from(n);
        let h = [
            ("content-type", "multipart/form-data; boundary=b"),
            ("x-forwarded-for", ip.as_str()),
        ];
        let r = send(gw, "POST", "/denied", &h, mp).await;
        assert_eq!(r.status, StatusCode::UNAUTHORIZED, "{}", r.body);
    }
    let ip = from(6);
    let h = [
        ("content-type", "application/x-www-form-urlencoded"),
        ("x-forwarded-for", ip.as_str()),
    ];
    let r = send(gw, "POST", "/denied", &h, "username=alice&password=x").await;
    assert_eq!(
        r.status,
        StatusCode::TOO_MANY_REQUESTS,
        "locked: {}",
        r.body
    );
}

#[tokio::test]
async fn blocked_or_refused_requests_do_not_spend_an_accounts_budget() {
    let (gw, _) = start_gateway(
        r#"
[client_ip]
trusted_proxies = ["127.0.0.1"]
[[operations]]
name = "checkout"
path = "/denied"
account = "query:account"
limit = { requests = 2, per_secs = 3600 }
"#,
    )
    .await;
    // (GET: a fresh client's first request being a write looks risky to the
    // behavioural engine once the route has seen failures)
    let attempt = |n: u32, target: &'static str| async move {
        let ip = from(n);
        send(gw, "GET", target, &[("x-forwarded-for", ip.as_str())], "").await
    };
    // someone who knows the account identifier: blocked by the WAF before reaching
    // the application, or answered 401 by it
    let attack = "/denied?account=victim&ok&q=%3Cscript%3Ealert(1)%3C/script%3E";
    for n in 10..14 {
        let r = attempt(n, attack).await;
        assert_eq!(r.status, StatusCode::FORBIDDEN, "{}", r.body);
    }
    for n in 14..18 {
        let r = attempt(n, "/denied?account=victim").await;
        assert_eq!(r.status, StatusCode::UNAUTHORIZED, "{}", r.body);
    }
    // the owner's budget is intact; what the application accepted is spent
    for n in 18..20 {
        let r = attempt(n, "/denied?account=victim&ok").await;
        assert_eq!(r.status, StatusCode::OK, "{}", r.body);
    }
    let r = attempt(20, "/denied?account=victim&ok").await;
    assert_eq!(r.status, StatusCode::TOO_MANY_REQUESTS, "{}", r.body);
}
