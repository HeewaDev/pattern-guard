//! Memory used to read `[[operations]]` / `[[logins]]` identifiers from a large body.
//! The measurement is process-wide (peak RSS), so this file holds a single test.
#![cfg(target_os = "linux")]

use std::net::IpAddr;

use hyper::Request;
use pattern_guard_gateway::config::GatewayConfig;
use pattern_guard_gateway::policy::operations::Operations;

/// Peak resident memory of this process (`VmHWM`), in MiB.
fn peak_rss_mib() -> f64 {
    let status = std::fs::read_to_string("/proc/self/status").unwrap();
    let kib: f64 = status
        .lines()
        .find_map(|l| l.strip_prefix("VmHWM:"))
        .and_then(|v| v.trim().trim_end_matches("kB").trim().parse().ok())
        .unwrap();
    kib / 1024.0
}

#[test]
fn identifiers_are_read_without_building_the_body_into_a_tree() {
    let cfg = GatewayConfig::from_toml_str(
        r#"
upstream = "http://127.0.0.1:1"
[[operations]]
name = "transfer"
path = "/login"
account = "json:user.id"
unique = "json:id"
[[logins]]
name = "login"
path = "/login"
account = "json:email"
"#,
    )
    .unwrap();
    let ops = Operations::compile(&cfg.operations, &cfg.logins).unwrap();
    // 10 MiB of `[0,0,…]`: as a serde_json::Value, 32 bytes per element
    let mut body = String::with_capacity(10 << 20);
    body.push('[');
    while body.len() < (10 << 20) - 2 {
        body.push_str("0,");
    }
    body.push_str("0]");
    let req = |path: &str| {
        Request::builder()
            .method("POST")
            .uri(path)
            .header("content-type", "application/json")
            .body(())
            .unwrap()
            .into_parts()
            .0
    };
    let ip: IpAddr = "198.51.100.7".parse().unwrap();
    // the same request on a route without operations or logins
    let (hit, ticket) = ops.check(ip, &req("/other"), body.as_bytes());
    assert!(hit.is_none());
    drop(ticket);
    let before = peak_rss_mib();
    let (hit, ticket) = ops.check(ip, &req("/login"), body.as_bytes());
    assert!(hit.is_none());
    drop(ticket);
    let grown = peak_rss_mib() - before;
    // one decoded copy of the text (10 MiB) is expected; a tree is over 160 MiB
    assert!(
        grown < 40.0,
        "peak RSS grew by {grown:.0} MiB reading three identifiers from a 10 MiB body"
    );
}
