//! A client sending huge requests must not stall everyone else (security review H3).
//!
//! The guard serialises requests on one state lock. Route templating, probe scanning and
//! hashing the user agent used to run under it, so a 64 KB path with a 400 KB user agent
//! held the lock ~100× longer than a typical request, and one such client capped the
//! whole gateway's throughput. That work now runs before the lock is taken.
//!
//! This is the only test in its binary, so nothing else competes for the CPU.

use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant, SystemTime};

use pattern_guard::{Event, Guard};

#[test]
fn huge_requests_do_not_stall_typical_ones() {
    let g = Guard::from_toml_str("").unwrap();
    let now = SystemTime::now();
    let typical = Event::new("ip:203.0.113.1", "GET", "/api/items/7?page=2", now)
        .with_user_agent("Mozilla/5.0 (Windows NT 10.0) Chrome/130");
    let huge = Event::new(
        "ip:203.0.113.2",
        "GET",
        format!("/{}", "ab/".repeat(21_800)),
        now,
    )
    .with_user_agent("u".repeat(400_000));
    let request = |e: &Event| {
        let t = Instant::now();
        g.assess(e);
        g.observe_response(e, 200);
        t.elapsed()
    };
    // Uncontended cost of one huge request.
    let huge_cost = (0..5).map(|_| request(&huge)).min().unwrap();

    let stop = AtomicBool::new(false);
    let (n, busy) = std::thread::scope(|s| {
        s.spawn(|| {
            while !stop.load(Ordering::Relaxed) {
                request(&huge);
            }
        });
        // Typical requests while the other thread sends huge ones back to back. The pause
        // lets the huge thread take the lock in between, as it would in a gateway.
        let started = Instant::now();
        let (mut n, mut busy) = (0u32, Duration::ZERO);
        while n < 100 && started.elapsed() < Duration::from_secs(2) {
            std::thread::sleep(Duration::from_micros(200));
            busy += request(&typical);
            n += 1;
        }
        stop.store(true, Ordering::Relaxed);
        (n, busy)
    });
    // Waiting behind the lock costs a typical request about 1.5 huge requests (half of
    // one for `assess`, then a whole one for `observe_response`); without the wait it
    // costs a small fraction of one. The mean, not the median: the mutex is not fair, so
    // a few lucky requests may hide the starved ones.
    let mean = busy / n;
    assert!(
        mean < huge_cost / 4,
        "typical requests took {mean:?} on average ({n} done) while huge requests ({huge_cost:?} each) ran"
    );
}
