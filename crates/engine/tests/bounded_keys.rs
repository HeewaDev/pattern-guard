//! The engine's tables must not keep attacker-sized identifiers as keys (security
//! review H2). The client table was keyed by the whole `ua:<User-Agent>` string, so
//! 50 000 entries with 300 KB user agents could hold ~14 GiB; the actor tables (features,
//! rules, cooldowns) kept a copy of every actor id. Keys are now 64-bit hashes.
//!
//! Linux only: the test reads the resident set size from `/proc/self/status`. It is the
//! only test in this binary, so nothing else allocates while it measures.

#![cfg(target_os = "linux")]

use std::time::{Duration, SystemTime};

use pattern_guard::{Event, Guard};

fn rss_bytes() -> usize {
    let s = std::fs::read_to_string("/proc/self/status").unwrap();
    let kb: usize = s
        .lines()
        .find_map(|l| l.strip_prefix("VmRSS:"))
        .and_then(|v| v.split_whitespace().next())
        .and_then(|v| v.parse().ok())
        .expect("VmRSS in /proc/self/status");
    kb * 1024
}

#[test]
fn huge_actor_ids_and_user_agents_are_not_kept_as_keys() {
    const MIB: usize = 1 << 20;
    const N: usize = 128;
    // A rule is set so the rules tracker records every actor too.
    let g = Guard::from_toml_str("[guard]\nburst_max_events = 1000\n").unwrap();
    let pad = "u".repeat(MIB);
    let at = |i: usize| SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000 + i as u64);
    // Warm up the allocator with one request of the same size.
    let e = Event::new(format!("user:{pad}"), "GET", "/", at(0)).with_user_agent(pad.clone());
    g.assess(&e);
    drop(e);

    let before = rss_bytes();
    for i in 1..=N {
        // A distinct 1 MiB actor id and 1 MiB user agent per request.
        let e = Event::new(format!("user:{i}:{pad}"), "GET", "/", at(i))
            .with_user_agent(format!("{i}{pad}"));
        g.assess(&e);
        g.observe_response(&e, 200);
    }
    let grown = rss_bytes().saturating_sub(before);
    // Keeping the strings as keys retained ≥ 2 × 128 MiB (actor + user agent tables).
    assert!(
        grown < 32 * MIB,
        "resident memory grew by {} MiB for {N} requests",
        grown / MIB
    );
}
