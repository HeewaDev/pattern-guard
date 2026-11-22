//! Replaying attacker-influenced access logs (security review M2).
//!
//! In the combined format, `$remote_user` comes from the client's `Authorization: Basic`
//! header and is logged with spaces and brackets unescaped. Parsing must never panic,
//! the client must not choose the event time, and one bad timestamp must not freeze the
//! engine's event clock for the rest of the replay.

use pattern_guard::Guard;
use pattern_guard::logs::{LogFormat, LogRecord, Ordered, ReplayOrder, parse_line};

fn line(user: &str, day: &str, t: u32, ip: &str) -> String {
    let (hh, mm, ss) = (10 + t / 3600, (t / 60) % 60, t % 60);
    format!(
        r#"{ip} - {user} [{day}:{hh:02}:{mm:02}:{ss:02} +0000] "GET /api/status HTTP/1.1" 200 512 "-" "Mozilla/5.0 (Windows NT 10.0) Chrome/130""#
    )
}

/// 20 status dashboards on different networks, polling every 10 s for an hour
/// (7 200 requests), with `extra` lines inserted after the first one.
fn dashboards(extra: &[String]) -> Vec<String> {
    let mut lines = Vec::new();
    for tick in 0..360 {
        for v in 0..20 {
            lines.push(line(
                "-",
                "23/Nov/2026",
                tick * 10 + v / 4,
                &format!("203.0.{v}.7"),
            ));
            if tick == 0 && v == 0 {
                lines.extend_from_slice(extra);
            }
        }
    }
    lines
}

/// Replays through a fresh guard; returns (requests replayed, requests stopped).
fn replay(records: impl IntoIterator<Item = LogRecord>) -> (usize, usize) {
    let g = Guard::from_toml_str("").unwrap();
    let (mut n, mut stopped) = (0, 0);
    for r in records {
        let a = g.assess(&r.event);
        if let Some(s) = r.status {
            g.observe_response(&r.event, s);
        }
        n += 1;
        stopped += a.decision.is_mitigation() as usize;
    }
    (n, stopped)
}

fn parsed(lines: &[String]) -> Vec<LogRecord> {
    lines
        .iter()
        .map(|l| parse_line(l, LogFormat::Combined).unwrap().unwrap())
        .collect()
}

fn ordered(records: Vec<LogRecord>) -> Vec<LogRecord> {
    let mut order = ReplayOrder::new();
    let mut out = Vec::new();
    let mut keep = |o: Ordered<LogRecord>| {
        if let Ordered::Keep(r) = o {
            out.push(r);
        }
    };
    for r in records {
        if let Some(o) = order.push(r.event.unix_secs(), r) {
            keep(o);
        }
    }
    while let Some(o) = order.finish() {
        keep(o);
    }
    out
}

#[test]
fn basic_auth_user_cannot_freeze_the_replay() {
    let (n, clean) = replay(parsed(&dashboards(&[])));
    let injected = line(
        "x [01/Jan/2099:00:00:00 +0000]",
        "23/Nov/2026",
        0,
        "198.51.100.9",
    );
    let (n2, poisoned) = replay(parsed(&dashboards(&[injected])));
    assert_eq!((n, n2), (7200, 7201));
    // Was 3 580 of 7 201 when the user name set the time to 2099.
    assert_eq!(clean, 0);
    assert_eq!(
        poisoned, 0,
        "ordinary visitors stopped after one injected line"
    );
}

#[test]
fn far_future_timestamp_is_skipped_before_the_guard() {
    // The server's own time field says 2099 (a clock glitch or a forged JSONL `ts`):
    // `ReplayOrder` drops it because the records after it are back in 2026.
    let bad = line("-", "01/Jan/2099", 0, "198.51.100.9");
    let (n, stopped) = replay(ordered(parsed(&dashboards(&[bad.clone(), bad]))));
    assert_eq!(n, 7200);
    assert_eq!(stopped, 0);
}

#[test]
fn hostile_lines_are_errors_not_panics() {
    for user in [
        "x [01/Jan/999999999999:00:00:00 +0000]",
        "x [01/Jan/400000000000:00:00:00 +0000]",
        "x [01/Jan/2026:00:00:00 +1é2]",
    ] {
        // The user name is no longer read as the time, so these lines parse normally...
        let l = line(user, "23/Nov/2026", 0, "198.51.100.9");
        assert!(parse_line(&l, LogFormat::Combined).unwrap().is_some());
    }
    // ...and the same values in the real time field are rejected without a panic.
    for day in ["01/Jan/999999999999", "01/Jan/400000000000"] {
        let l = line("-", day, 0, "198.51.100.9");
        assert!(parse_line(&l, LogFormat::Combined).is_err(), "{day}");
    }
    let l = r#"198.51.100.9 - - [01/Jan/2026:00:00:00 +1é2] "GET / HTTP/1.1" 200 1 "-" "-""#;
    assert!(parse_line(l, LogFormat::Combined).is_err());
    let l = r#"{"ts": 1e20, "ip": "1.2.3.4", "path": "/"}"#;
    assert!(parse_line(l, LogFormat::Jsonl).is_err());
}
