//! Memory regression checks that read the process RSS. This binary holds a single test
//! so nothing else allocates while it measures; keep it that way (add sections to
//! `memory_stays_bounded` rather than new `#[test]`s).

#[cfg(target_os = "linux")]
fn rss_mib() -> f64 {
    let s = std::fs::read_to_string("/proc/self/status").unwrap();
    let kb: f64 = s
        .lines()
        .find(|l| l.starts_with("VmRSS:"))
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|v| v.parse().ok())
        .unwrap();
    kb / 1024.0
}

/// `header:<name>` rate-limit buckets used to be keyed by the whole header value, so
/// unique 256 KB API keys kept 256 KB each (200 000 buckets → ~50 GiB). Keys are a
/// 64-bit hash now.
#[cfg(target_os = "linux")]
fn rate_limit_keys(n: usize, len: usize) {
    use pattern_guard_gateway::config::GatewayConfig;
    use pattern_guard_gateway::policy::rate_limit::{Buckets, Limits};

    let cfg = GatewayConfig::from_toml_str(
        "upstream = \"http://127.0.0.1:1\"\n[[rate_limits]]\nname = \"api\"\npath = \"/api/\"\nkey = \"header:x-api-key\"\nrequests = 100\nper_secs = 60\n",
    )
    .unwrap();
    let rl = Limits::compile(&cfg.rate_limits).unwrap();
    let buckets = Buckets::default();
    let ip = "203.0.113.9".parse().unwrap();
    let pad = "k".repeat(len);
    let req = |i: usize| {
        hyper::Request::get("/api/items")
            .header("x-api-key", format!("{i:08}{pad}"))
            .body(())
            .unwrap()
            .into_parts()
            .0
    };
    // warm up the allocator with one request of the same shape
    assert!(rl.check(&buckets, ip, &req(usize::MAX)).is_none());
    let before = rss_mib();
    for i in 0..n {
        assert!(rl.check(&buckets, ip, &req(i)).is_none());
    }
    let grown = rss_mib() - before;
    println!("{n} unique {len}-byte API keys: RSS +{grown:.1} MiB");
    assert!(
        grown < 16.0,
        "rate-limit buckets keep the key: +{grown:.1} MiB for {n} keys"
    );
}

#[test]
fn memory_stays_bounded() {
    #[cfg(target_os = "linux")]
    {
        rate_limit_keys(200, 256 * 1024);
    }
}
