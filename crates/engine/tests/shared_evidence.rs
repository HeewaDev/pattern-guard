//! Evidence that innocent clients share (the user agent's or network's failures and new
//! arrivals) or that every first contact has (a first request, a write before any page
//! view) can't block on its own: such requests are challenged. Adapted from the 2026-11
//! security review's proofs of concept, which showed innocent users blocked.

use pattern_guard::{Decision, Event, Guard};
use std::time::{Duration, SystemTime};

fn at(t: f64) -> SystemTime {
    SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000) + Duration::from_secs_f64(t)
}

/// The event the gateway builds: actor `ip:<addr>`, the user agent as the client key.
fn ev(ip: &str, method: &str, path: &str, ua: &str, t: f64) -> Event {
    Event::new(format!("ip:{ip}"), method, path, at(t)).with_user_agent(ua)
}

#[test]
fn a_cold_login_is_challenged_not_blocked() {
    // a password manager or a native app: the first request is the login itself
    let g = Guard::from_toml_str("").unwrap();
    let ua = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Safari/17.0";
    let a = g.assess(&ev("203.0.113.50", "POST", "/login", ua, 0.0));
    assert_eq!(a.decision, Decision::Challenge, "{:?}", a.reasons);
    assert!(a.reasons.iter().any(|r| r.signal == "shared_evidence_only"));
}

#[test]
fn sharing_a_user_agent_with_an_attacker_gets_a_challenge_not_a_block() {
    let g = Guard::from_toml_str("").unwrap();
    let ua = "Mozilla/5.0 (Linux; Android 13; Pixel 7) AppleWebKit/537.36 Chrome/119.0";
    let mut t = 0.0;
    // 400 failed logins from rotating IPs, all with the victim's phone's user agent
    for i in 0..400 {
        let e = ev(
            &format!("45.11.{}.{}", i / 250, i % 250),
            "POST",
            "/login",
            ua,
            t,
        );
        g.assess(&e);
        g.observe_response(&e, 401);
        t += 0.3;
    }
    // an honest shopper with the same phone browses a product page
    let victim = g.assess(&ev("198.51.100.77", "GET", "/products/42", ua, t));
    assert_ne!(victim.decision, Decision::Block, "{:?}", victim.reasons);
}

#[test]
fn a_cooldown_earned_by_shared_evidence_challenges_and_own_behaviour_still_blocks() {
    let g =
        Guard::from_toml_str("[guard]\ncooldown_secs = 120\ncooldown_after_blocks = 3\n").unwrap();
    let ua = "okhttp/4.9.0";
    let mut t = 0.0;
    for i in 0..500 {
        let e = ev(
            &format!("45.80.{}.{}", i / 250, i % 250),
            "POST",
            "/api/login",
            ua,
            t,
        );
        g.assess(&e);
        g.observe_response(&e, 401);
        t += 0.2;
    }
    // the victim's own logins succeed; none of its requests may be blocked, during the
    // attack or a minute after it
    for k in 0..3 {
        let e = ev("198.51.100.5", "POST", "/api/login", ua, t + k as f64);
        let a = g.assess(&e);
        g.observe_response(&e, 200);
        assert_ne!(a.decision, Decision::Block, "during: {:?}", a.reasons);
    }
    let after = g.assess(&ev("198.51.100.5", "POST", "/api/login", ua, t + 63.0));
    assert_ne!(
        after.decision,
        Decision::Block,
        "after: {:?}",
        after.reasons
    );

    // an actor failing on its own still gets blocked
    let attacker = "203.0.113.66";
    let mut last = Decision::Allow;
    for k in 0..40 {
        let e = ev(
            attacker,
            "POST",
            "/login",
            "python-requests/2.32",
            t + 100.0 + k as f64 * 0.5,
        );
        last = g.assess(&e).decision;
        g.observe_response(&e, 401);
    }
    assert_eq!(last, Decision::Block);
}
