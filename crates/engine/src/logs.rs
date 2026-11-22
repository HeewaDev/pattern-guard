//! Parse access logs into events for replay, evaluation and training.
//!
//! Supported formats:
//! * **JSONL** — one JSON object per line:
//!   `{"ts": 1700000000.25, "ip": "203.0.113.7", "method": "GET", "path": "/x", "status": 200,
//!     "ua": "...", "fp": "<ja4>", "actor": "user:42", "label": 0, "scenario": "..."}`.
//!   Only `ts` and `path` are required. `actor` defaults to `ip:<ip>`.
//!   `label` (0/1, true/false, "bot"/"human") is needed for training and for accuracy reports.
//! * **combined** — the nginx/Apache default
//!   `$remote_addr - $user [$time_local] "$request" $status $bytes "$referer" "$user_agent"`.
//!
//! Log lines are attacker-influenced (the client chooses the request line, the Basic-auth
//! user name, the referer and the user agent), so parsing never panics: a malformed line
//! is an `Err`. Timestamps must lie between the Unix epoch and the end of year 9999.
//!
//! With the default `time_source = "event"` the engine's clock follows the newest
//! timestamp it has seen, so one far-future record would distort everything replayed
//! after it. Pass records through [`ReplayOrder`] to drop such records first.

use std::collections::VecDeque;
use std::net::IpAddr;
use std::time::{Duration, SystemTime};

use serde::Deserialize;

use crate::event::Event;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogFormat {
    Jsonl,
    Combined,
}

impl LogFormat {
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "jsonl" | "json" => Some(Self::Jsonl),
            "combined" | "nginx" | "apache" => Some(Self::Combined),
            _ => None,
        }
    }

    /// Guess from a sample line.
    pub fn detect(line: &str) -> Self {
        if line.trim_start().starts_with('{') {
            Self::Jsonl
        } else {
            Self::Combined
        }
    }
}

#[derive(Debug, Clone)]
pub struct LogRecord {
    pub event: Event,
    pub status: Option<u16>,
    /// `Some(true)` = known abusive, `Some(false)` = known legitimate.
    pub label: Option<bool>,
    pub scenario: Option<String>,
}

#[derive(Deserialize)]
struct JsonLine {
    ts: f64,
    #[serde(default)]
    actor: Option<String>,
    #[serde(default)]
    ip: Option<String>,
    #[serde(default)]
    method: Option<String>,
    #[serde(alias = "target", alias = "url", alias = "uri")]
    path: String,
    #[serde(default)]
    status: Option<u16>,
    #[serde(default, alias = "user_agent")]
    ua: Option<String>,
    #[serde(default, alias = "fingerprint", alias = "ja4", alias = "ja3")]
    fp: Option<String>,
    #[serde(default)]
    weight: Option<f64>,
    #[serde(default)]
    label: Option<serde_json::Value>,
    #[serde(default)]
    scenario: Option<String>,
}

/// Parses one line. Blank lines and `#` comments yield `Ok(None)`.
pub fn parse_line(line: &str, format: LogFormat) -> Result<Option<LogRecord>, String> {
    let line = line.trim();
    if line.is_empty() || line.starts_with('#') {
        return Ok(None);
    }
    match format {
        LogFormat::Jsonl => parse_json(line).map(Some),
        LogFormat::Combined => parse_combined(line).map(Some),
    }
}

/// The latest accepted timestamp: 9999-12-31T23:59:59Z, the last four-digit-year CLF date.
const MAX_UNIX_SECS: f64 = 253_402_300_799.0;

/// Unix seconds → `SystemTime`. Negative, NaN and out-of-range values are an `Err`, never
/// a panic (`Duration::from_secs_f64` and `SystemTime + Duration` both panic on overflow).
fn to_time(ts: f64) -> Result<SystemTime, String> {
    let err = || format!("timestamp {ts} out of range (1970 to 9999)");
    if !(0.0..=MAX_UNIX_SECS).contains(&ts) {
        return Err(err());
    }
    Duration::try_from_secs_f64(ts)
        .ok()
        .and_then(|d| SystemTime::UNIX_EPOCH.checked_add(d))
        .ok_or_else(err)
}

fn parse_label(v: &serde_json::Value) -> Result<Option<bool>, String> {
    use serde_json::Value;
    Ok(match v {
        Value::Null => None,
        Value::Bool(b) => Some(*b),
        Value::Number(n) => Some(n.as_f64().unwrap_or(0.0) != 0.0),
        Value::String(s) => match s.to_ascii_lowercase().as_str() {
            "1" | "true" | "bad" | "bot" | "attack" | "malicious" | "abuse" => Some(true),
            "0" | "false" | "good" | "human" | "legit" | "benign" => Some(false),
            "" | "unknown" => None,
            other => return Err(format!("unrecognised label {other:?}")),
        },
        _ => return Err("label must be a bool, number or string".into()),
    })
}

fn parse_json(line: &str) -> Result<LogRecord, String> {
    let j: JsonLine = serde_json::from_str(line).map_err(|e| e.to_string())?;
    let ip: Option<IpAddr> = match &j.ip {
        Some(s) => Some(s.parse().map_err(|_| format!("bad ip {s:?}"))?),
        None => None,
    };
    let actor = match (j.actor, ip) {
        (Some(a), _) => a,
        (None, Some(ip)) => format!("ip:{ip}"),
        (None, None) => return Err("need `actor` or `ip`".into()),
    };
    let mut event = Event::new(
        actor,
        j.method.unwrap_or_else(|| "GET".into()),
        j.path,
        to_time(j.ts)?,
    );
    event.ip = ip;
    event.user_agent = j.ua.filter(|s| !s.is_empty() && s != "-");
    event.fingerprint = j.fp.filter(|s| !s.is_empty() && s != "-");
    event.weight = j.weight;
    Ok(LogRecord {
        event,
        status: j.status,
        label: match &j.label {
            Some(v) => parse_label(v)?,
            None => None,
        },
        scenario: j.scenario,
    })
}

/// `$remote_addr - $user [$time_local] "$request" $status $bytes "$referer" "$user_agent"`
///
/// `$user` comes from the client's `Authorization: Basic` header, and nginx and Apache log
/// it with spaces, `[` and `]` unescaped, so the first `[` on the line may be the client's.
/// The timestamp is the `[...]` that ends right before the `"` opening the request: a `"`
/// inside a logged field is always escaped (`\x22` by nginx, `\"` by Apache), so the first
/// `] "` on the line is the server's.
fn parse_combined(line: &str) -> Result<LogRecord, String> {
    let ip_end = line.find(' ').ok_or("missing remote address")?;
    let ip: IpAddr = line[..ip_end]
        .parse()
        .map_err(|_| format!("bad ip {:?}", &line[..ip_end]))?;
    let t1 = line.find("] \"").ok_or("missing [time] \"request\"")?;
    let t0 = line[..t1].rfind('[').ok_or("missing [time]")?;
    let ts = parse_clf_time(&line[t0 + 1..t1])?;
    let mut fields = log_fields(&line[t1 + 1..]);
    let request = fields.next().ok_or("missing \"request\"")?;
    let status = fields.next().and_then(|s| s.parse::<u16>().ok());
    let _bytes = fields.next();
    let _referer = fields.next();
    let ua = fields.next().filter(|s| !s.is_empty() && *s != "-");

    let mut parts = request.split_whitespace();
    let method = parts.next().unwrap_or("-").to_string();
    let path = parts.next().unwrap_or("/").to_string();

    let mut event = Event::new(format!("ip:{ip}"), method, path, to_time(ts)?);
    event.ip = Some(ip);
    event.user_agent = ua.map(str::to_string);
    Ok(LogRecord {
        event,
        status,
        label: None,
        scenario: None,
    })
}

/// Splits the fields after the timestamp into `"quoted"` strings (a backslash escapes the
/// next byte, as Apache writes `\"`) and bare words. Contents are returned as logged.
fn log_fields(s: &str) -> impl Iterator<Item = &str> {
    let b = s.as_bytes();
    let mut i = 0;
    // Every slice index is the position of an ASCII byte or the end, so a char boundary.
    std::iter::from_fn(move || {
        while i < b.len() && b[i].is_ascii_whitespace() {
            i += 1;
        }
        if i >= b.len() {
            return None;
        }
        if b[i] == b'"' {
            let start = i + 1;
            let mut j = start;
            while j < b.len() && b[j] != b'"' {
                j += if b[j] == b'\\' { 2 } else { 1 };
            }
            let end = j.min(b.len());
            i = end + 1;
            Some(&s[start..end])
        } else {
            let start = i;
            while i < b.len() && !b[i].is_ascii_whitespace() {
                i += 1;
            }
            Some(&s[start..i])
        }
    })
}

/// `10/Oct/2000:13:55:36 -0700` → Unix seconds. Every field is range-checked, so a
/// malformed date is an `Err`, never a panic or an absurd timestamp.
fn parse_clf_time(s: &str) -> Result<f64, String> {
    let err = || format!("bad time {s:?}");
    let digits = |v: Option<&str>, max_len: usize| -> Result<i64, String> {
        match v {
            Some(v)
                if (1..=max_len).contains(&v.len()) && v.bytes().all(|b| b.is_ascii_digit()) =>
            {
                v.parse().map_err(|_| err())
            }
            _ => Err(err()),
        }
    };
    let (dt, tz) = s.split_once(' ').unwrap_or((s, "+0000"));
    let mut it = dt.splitn(4, [':', '/']);
    let day = digits(it.next(), 2)?;
    let mon = it.next().ok_or_else(err)?;
    let year = digits(it.next(), 4)?;
    let hms = it.next().ok_or_else(err)?;
    let month = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ]
    .iter()
    .position(|m| *m == mon)
    .ok_or_else(err)? as i64
        + 1;
    let mut hms_it = hms.split(':');
    let h = digits(hms_it.next(), 2)?;
    let m = digits(hms_it.next(), 2)?;
    // Seconds may carry a fraction: digits and at most one '.', so no "inf", "NaN" or "1e9".
    let sec: f64 = match hms_it.next() {
        Some(v)
            if !v.is_empty()
                && v.bytes().all(|b| b.is_ascii_digit() || b == b'.')
                && v.bytes().filter(|&b| b == b'.').count() <= 1 =>
        {
            v.parse().map_err(|_| err())?
        }
        _ => return Err(err()),
    };
    if hms_it.next().is_some()
        || !(1..=31).contains(&day)
        || !(1970..=9999).contains(&year)
        || h > 23
        || m > 59
        || !(0.0..61.0).contains(&sec)
    {
        return Err(err());
    }
    let tz = tz.trim();
    let (sign, tz_digits) = match tz.as_bytes().first() {
        Some(b'-') => (-1, &tz[1..]),
        Some(b'+') => (1, &tz[1..]),
        _ => (1, tz),
    };
    // ASCII-only before slicing: `[..2]` on a multi-byte character would panic.
    if tz_digits.len() != 4 || !tz_digits.bytes().all(|b| b.is_ascii_digit()) {
        return Err(err());
    }
    let tz_h: i64 = tz_digits[..2].parse().map_err(|_| err())?;
    let tz_m: i64 = tz_digits[2..].parse().map_err(|_| err())?;
    if tz_h > 23 || tz_m > 59 {
        return Err(err());
    }
    let offset = sign * (tz_h * 3600 + tz_m * 60);
    let days = days_from_civil(year, month, day);
    Ok((days * 86400 + h * 3600 + m * 60 - offset) as f64 + sec)
}

/// Howard Hinnant's algorithm: days since 1970-01-01 for a proleptic Gregorian date.
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146097 + doe - 719468
}

/// Records [`ReplayOrder`] looks ahead to confirm a jump forward in time.
const LOOKAHEAD: usize = 16;
/// A record further ahead of the newest accepted record than this (seconds) is replayed
/// only if the records after it agree that time has moved on.
const MAX_UNCONFIRMED_JUMP: f64 = 60.0;
/// A record older than the newest accepted record by more than this (seconds) is out of order.
const MAX_LAG: f64 = 3600.0;

/// What [`ReplayOrder`] decided about a record.
#[derive(Debug)]
pub enum Ordered<T> {
    /// Replay it.
    Keep(T),
    /// Skip it; the reason names the timestamp problem.
    Skip(T, String),
}

/// Drops records whose timestamps would corrupt an event-time replay.
///
/// With `time_source = "event"` the engine's clock is the newest timestamp seen so far.
/// A single far-future record (a server clock glitch, a merged log from a misconfigured
/// host, a forged `ts`) would put every later record at that same instant: nothing decays,
/// and ordinary traffic looks like a flood. `ReplayOrder` looks 16 records ahead and, in
/// input order:
///
/// * skips a record more than 60 s ahead of the newest accepted record unless the median
///   of the 16 records after it is ahead too. A real gap in traffic (a quiet night, an
///   outage) is followed by more traffic at the new time, so it is kept however long it
///   is; a lone bad timestamp is followed by records at the old time, so it is skipped.
///   Up to 9 consecutive bad records are skipped this way.
/// * skips a record more than an hour older than the newest accepted record: the log is
///   not in chronological order (e.g. files concatenated newest first), and replaying
///   it at the wrong time would give wrong results.
///
/// `T` is whatever the caller wants back (e.g. a line number and the record).
pub struct ReplayOrder<T> {
    pending: VecDeque<(f64, T)>,
    newest: Option<f64>,
}

impl<T> Default for ReplayOrder<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T> ReplayOrder<T> {
    pub fn new() -> Self {
        Self {
            pending: VecDeque::with_capacity(LOOKAHEAD + 1),
            newest: None,
        }
    }

    /// Adds a record with its Unix timestamp. Returns the oldest buffered record once the
    /// look-ahead is full.
    pub fn push(&mut self, unix_secs: f64, item: T) -> Option<Ordered<T>> {
        self.pending.push_back((unix_secs, item));
        if self.pending.len() > LOOKAHEAD {
            self.release()
        } else {
            None
        }
    }

    /// At the end of the input: returns the remaining records one by one, then `None`.
    pub fn finish(&mut self) -> Option<Ordered<T>> {
        self.release()
    }

    fn release(&mut self) -> Option<Ordered<T>> {
        let (ts, item) = self.pending.pop_front()?;
        let newest = self.newest.unwrap_or(f64::NEG_INFINITY);
        if ts > newest + MAX_UNCONFIRMED_JUMP && !self.pending.is_empty() {
            let mut ahead: Vec<f64> = self.pending.iter().map(|(t, _)| *t).collect();
            ahead.sort_by(f64::total_cmp);
            let median = ahead[(ahead.len() - 1) / 2];
            if median < ts - MAX_UNCONFIRMED_JUMP {
                let reason = format!(
                    "timestamp {ts} is {:.0} s ahead of the records after it (out of order or a bad clock)",
                    ts - median
                );
                return Some(Ordered::Skip(item, reason));
            }
        } else if ts < newest - MAX_LAG {
            let reason = format!(
                "timestamp {ts} is {:.0} s older than an earlier record (sort the log by time)",
                newest - ts
            );
            return Some(Ordered::Skip(item, reason));
        }
        self.newest = Some(newest.max(ts));
        Some(Ordered::Keep(item))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn combined_line() {
        let l = r#"203.0.113.7 - - [10/Oct/2000:13:55:36 -0700] "GET /apache_pb.gif?x=1 HTTP/1.0" 200 2326 "http://www.example.com/start.html" "Mozilla/4.08 [en] (Win98; I ;Nav)""#;
        let r = parse_line(l, LogFormat::Combined).unwrap().unwrap();
        assert_eq!(r.event.actor, "ip:203.0.113.7");
        assert_eq!(r.event.action, "GET");
        assert_eq!(r.event.target, "/apache_pb.gif?x=1");
        assert_eq!(r.status, Some(200));
        assert_eq!(
            r.event.user_agent.as_deref(),
            Some("Mozilla/4.08 [en] (Win98; I ;Nav)")
        );
        // 2000-10-10T20:55:36Z
        assert_eq!(r.event.unix_secs(), 971211336.0);
    }

    #[test]
    fn combined_ipv6_and_dash_ua() {
        let l =
            r#"2001:db8::1 - - [01/Jan/2024:00:00:00 +0000] "POST /login HTTP/2.0" 401 12 "-" "-""#;
        let r = parse_line(l, LogFormat::Combined).unwrap().unwrap();
        assert_eq!(r.status, Some(401));
        assert_eq!(r.event.user_agent, None);
        assert_eq!(r.event.unix_secs(), 1704067200.0);
    }

    fn with_user(user: &str) -> String {
        format!(
            r#"198.51.100.9 - {user} [23/Nov/2026:10:00:00 +0000] "GET / HTTP/1.1" 401 12 "-" "Mozilla/5.0""#
        )
    }

    #[test]
    fn remote_user_cannot_set_the_time() {
        // nginx logs the Basic-auth user name with spaces and brackets unescaped.
        let server_time = 1_795_428_000.0; // 2026-11-23T10:00:00Z
        for user in [
            "x [01/Jan/2099:00:00:00 +0000]",
            "[01/Jan/2099:00:00:00 +0000]",
            "a] [b [01/Jan/2099:00:00:00 +0000] c",
            r"x [01/Jan/2099:00:00:00 +0000]\x22",
            "\"\"", // Apache logs an empty user name as ""
        ] {
            let r = parse_line(&with_user(user), LogFormat::Combined)
                .unwrap()
                .unwrap();
            assert_eq!(r.event.unix_secs(), server_time, "user {user:?}");
            assert_eq!(r.status, Some(401), "user {user:?}");
            assert_eq!(r.event.target, "/");
        }
    }

    #[test]
    fn escaped_quotes_stay_inside_their_field() {
        // Apache escapes `"` as `\"`; the client must not be able to forge the status.
        let l = r#"198.51.100.9 - - [23/Nov/2026:10:00:00 +0000] "GET /x\" 200 1 \"-\" \"ua HTTP/1.1" 401 12 "-" "Mozilla/5.0 \"quoted\"""#;
        let r = parse_line(l, LogFormat::Combined).unwrap().unwrap();
        assert_eq!(r.status, Some(401));
        assert_eq!(r.event.target, r#"/x\""#);
        assert_eq!(
            r.event.user_agent.as_deref(),
            Some(r#"Mozilla/5.0 \"quoted\""#)
        );
    }

    #[test]
    fn hostile_timestamps_are_errors_not_panics() {
        for user_time in [
            "01/Jan/999999999999:00:00:00 +0000", // ≈ 3e19 s: Duration overflow
            "01/Jan/400000000000:00:00:00 +0000", // ≈ 1e19 s: SystemTime overflow
            "01/Jan/9223372036854775807:00:00:00 +0000",
            "01/Jan/2026:00:00:00 +1é2", // byte 2 inside a multi-byte character
            "01/Jan/2026:00:00:00 +é",
            "01/Jan/2026:00:00:inf +0000",
            "01/Jan/2026:00:00:NaN +0000",
            "01/Jan/2026:00:00:1e300 +0000",
            "01/Jan/2026:99:00:00 +0000",
            "01/Jan/2026:00:00:00:00 +0000",
            "00/Jan/2026:00:00:00 +0000",
            "01/Jan/1969:00:00:00 +0000",
            "01/Jan/2026:00:00:00 +9999",
            "01/Jan/-2026:00:00:00 +0000",
            "01/Jan/+2026:00:00:00 +0000",
            "",
        ] {
            let l = format!(
                r#"198.51.100.9 - - [{user_time}] "GET / HTTP/1.1" 200 12 "-" "Mozilla/5.0""#
            );
            assert!(
                parse_line(&l, LogFormat::Combined).is_err(),
                "{user_time:?} should be rejected"
            );
        }
        for ts in ["1e20", "-1", "1e300", "253402300800", "-0.5"] {
            let l = format!(r#"{{"ts": {ts}, "ip": "1.2.3.4", "path": "/"}}"#);
            assert!(parse_line(&l, LogFormat::Jsonl).is_err(), "ts {ts}");
        }
        let l = r#"{"ts": 253402300799, "ip": "1.2.3.4", "path": "/"}"#;
        assert!(parse_line(l, LogFormat::Jsonl).unwrap().is_some());
        // Fractional seconds still parse.
        let l = r#"198.51.100.9 - - [01/Jan/2024:00:00:01.5 +0000] "GET / HTTP/1.1" 200 1"#;
        let r = parse_line(l, LogFormat::Combined).unwrap().unwrap();
        assert_eq!(r.event.unix_secs(), 1704067201.5);
        assert_eq!(r.event.user_agent, None);
    }

    #[test]
    fn jsonl_line() {
        let l = r#"{"ts": 1700000000.5, "ip": "198.51.100.4", "method": "POST", "path": "/login", "status": 401, "ua": "python-requests/2.32", "fp": "t13d", "label": "bot", "scenario": "stuffing"}"#;
        let r = parse_line(l, LogFormat::Jsonl).unwrap().unwrap();
        assert_eq!(r.event.actor, "ip:198.51.100.4");
        assert_eq!(r.event.fingerprint.as_deref(), Some("t13d"));
        assert_eq!(r.label, Some(true));
        assert_eq!(r.scenario.as_deref(), Some("stuffing"));
        assert!(parse_line(r#"{"ts": 1, "path": "/"}"#, LogFormat::Jsonl).is_err());
        assert!(parse_line("   ", LogFormat::Jsonl).unwrap().is_none());
    }

    #[test]
    fn detect_format() {
        assert_eq!(LogFormat::detect("{\"ts\":1}"), LogFormat::Jsonl);
        assert_eq!(LogFormat::detect("1.2.3.4 - - [..."), LogFormat::Combined);
    }

    /// Runs timestamps through `ReplayOrder`; returns the indices it keeps.
    fn kept(ts: &[f64]) -> Vec<usize> {
        let mut o = ReplayOrder::new();
        let mut out = Vec::new();
        let mut take = |r: Ordered<usize>| {
            if let Ordered::Keep(i) = r {
                out.push(i);
            }
        };
        for (i, &t) in ts.iter().enumerate() {
            if let Some(r) = o.push(t, i) {
                take(r);
            }
        }
        while let Some(r) = o.finish() {
            take(r);
        }
        out
    }

    #[test]
    fn replay_order_skips_a_lone_future_timestamp() {
        let t0 = 1_795_428_000.0;
        let mut ts: Vec<f64> = (0..100).map(|i| t0 + i as f64).collect();
        ts[50] = 4_070_908_800.0; // 2099
        ts[0] = t0 + 86_400.0; // also as the very first record
        let k = kept(&ts);
        assert_eq!(k.len(), 98);
        assert!(!k.contains(&50) && !k.contains(&0));
        // Several consecutive bad lines (fewer than half the look-ahead) are skipped too.
        ts[60..69].fill(t0 + 1e6);
        assert_eq!(kept(&ts).len(), 89);
    }

    #[test]
    fn replay_order_keeps_real_gaps_and_sparse_logs() {
        let t0 = 1_795_428_000.0;
        // Busy hour, an eight-hour silence, another busy hour.
        let mut ts: Vec<f64> = (0..3600).map(|i| t0 + i as f64).collect();
        ts.extend((0..3600).map(|i| t0 + 9.0 * 3600.0 + i as f64));
        assert_eq!(kept(&ts).len(), ts.len());
        // One request every ten minutes; a three-line log; a single line.
        let sparse: Vec<f64> = (0..50).map(|i| t0 + 600.0 * i as f64).collect();
        assert_eq!(kept(&sparse).len(), 50);
        assert_eq!(kept(&[t0, t0 + 7200.0, t0 + 7201.0]).len(), 3);
        assert_eq!(kept(&[t0]), vec![0]);
        // Small disorder (Apache logs the request start time at completion).
        let jitter: Vec<f64> = (0..200)
            .map(|i| t0 + i as f64 - if i % 7 == 0 { 30.0 } else { 0.0 })
            .collect();
        assert_eq!(kept(&jitter).len(), 200);
    }

    #[test]
    fn replay_order_skips_records_far_in_the_past() {
        let t0 = 1_795_428_000.0;
        // Today's log followed by yesterday's (concatenated in the wrong order).
        let mut ts: Vec<f64> = (0..100).map(|i| t0 + i as f64).collect();
        ts.extend((0..100).map(|i| t0 - 86_400.0 + i as f64));
        assert_eq!(kept(&ts), (0..100).collect::<Vec<_>>());
    }
}
