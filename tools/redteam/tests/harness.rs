//! The harness end to end over real TCP: the attacker finds every vulnerability without
//! the gateway (the demo app and the oracle work), the gateway run is measured, a trap ban
//! is seen on the admin port, and an external attacker is driven over JSON lines.
//!
//! These tests check the tool, not detection: they assert nothing about how well the
//! gateway does.

use std::time::Duration;

use pattern_guard_redteam::Vuln;
use pattern_guard_redteam::harness::{self, Settings};

fn fast() -> Settings {
    Settings {
        pace: Duration::ZERO,
        budget: 150,
        max_wait: Duration::from_secs(1),
        wait_budget: Duration::from_secs(2),
        ..Settings::default()
    }
}

fn scenario(name: &str) -> harness::Scenario {
    harness::scenarios(7)
        .into_iter()
        .find(|s| s.name == name)
        .unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn without_the_gateway_every_vulnerability_is_found() {
    let r = harness::run(&scenario("targeted"), &fast(), false)
        .await
        .unwrap();
    for v in Vuln::ALL {
        assert!(r.found.contains_key(&v), "{v:?} not found: {r:?}");
    }
    assert_eq!(r.stop, "done");
    assert_eq!(
        r.records_leaked, 20,
        "BOLA reads 20 other customers' orders"
    );
    assert!(r.first_ban.is_none() && r.blocked_by_layer.is_empty());
    // the first injection works at once against the bare app
    assert_eq!(r.found[&Vuln::Sqli].at.request, 2);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn through_the_gateway_bans_and_blocks_are_measured() {
    let r = harness::run(&scenario("scanner"), &fast(), true)
        .await
        .unwrap();
    assert!(r.via_gateway && r.requests > 0);
    let ban = r.first_ban.as_ref().expect("the trap bans the scanner");
    assert!(ban.reason.contains("trap"), "{}", ban.reason);
    assert_eq!(ban.ip, "203.0.113.8");
    assert!(
        r.blocked_by_layer.contains_key("trap"),
        "{:?}",
        r.blocked_by_layer
    );
    assert_eq!(r.banned_ips, 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_external_attacker_speaks_json_lines() {
    // one SQL injection, then done
    let script = r#"read start; echo '{"type":"request","method":"GET","path":"/products?id=1%20OR%201%3D1","headers":[["accept","*/*"]],"goal":"sqli"}'; read resp; echo '{"type":"done","reason":"one shot"}'"#;
    let set = Settings {
        attacker_cmd: Some(script.into()),
        ..fast()
    };
    let r = harness::run(&scenario("targeted"), &set, false)
        .await
        .unwrap();
    assert_eq!(r.requests, 1);
    assert!(r.found.contains_key(&Vuln::Sqli), "{r:?}");
    assert_eq!(r.stop, "done: one shot");
    assert!(r.strategy.starts_with("external"));
}
