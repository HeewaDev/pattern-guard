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

fn to_time(ts: f64) -> Result<SystemTime, String> {
    if !ts.is_finite() || ts < 0.0 {
        return Err(format!("bad timestamp {ts}"));
    }
    Ok(SystemTime::UNIX_EPOCH + Duration::from_secs_f64(ts))
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
fn parse_combined(line: &str) -> Result<LogRecord, String> {
    let ip_end = line.find(' ').ok_or("missing remote address")?;
    let ip: IpAddr = line[..ip_end]
        .parse()
        .map_err(|_| format!("bad ip {:?}", &line[..ip_end]))?;
    let t0 = line.find('[').ok_or("missing [time]")?;
    let t1 = line[t0..].find(']').ok_or("missing ]")? + t0;
    let ts = parse_clf_time(&line[t0 + 1..t1])?;
    let rest = &line[t1 + 1..];
    let mut quoted = rest.split('"');
    let _ = quoted.next();
    let request = quoted.next().ok_or("missing \"request\"")?;
    let after_request = quoted.next().unwrap_or("");
    let _referer = quoted.next();
    let _ = quoted.next();
    let ua = quoted.next().filter(|s| !s.is_empty() && *s != "-");

    let mut parts = request.split_whitespace();
    let method = parts.next().unwrap_or("-").to_string();
    let path = parts.next().unwrap_or("/").to_string();
    let status = after_request
        .split_whitespace()
        .next()
        .and_then(|s| s.parse::<u16>().ok());

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

/// `10/Oct/2000:13:55:36 -0700` → Unix seconds.
fn parse_clf_time(s: &str) -> Result<f64, String> {
    let err = || format!("bad time {s:?}");
    let (dt, tz) = s.split_once(' ').unwrap_or((s, "+0000"));
    let mut it = dt.splitn(4, [':', '/']);
    let day: i64 = it.next().and_then(|v| v.parse().ok()).ok_or_else(err)?;
    let mon = it.next().ok_or_else(err)?;
    let year: i64 = it.next().and_then(|v| v.parse().ok()).ok_or_else(err)?;
    let hms = it.next().ok_or_else(err)?;
    let month = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ]
    .iter()
    .position(|m| *m == mon)
    .ok_or_else(err)? as i64
        + 1;
    let mut hms_it = hms.split(':');
    let h: f64 = hms_it.next().and_then(|v| v.parse().ok()).ok_or_else(err)?;
    let m: f64 = hms_it.next().and_then(|v| v.parse().ok()).ok_or_else(err)?;
    let sec: f64 = hms_it.next().and_then(|v| v.parse().ok()).ok_or_else(err)?;
    let tz = tz.trim();
    let (sign, digits) = match tz.as_bytes().first() {
        Some(b'-') => (-1.0, &tz[1..]),
        Some(b'+') => (1.0, &tz[1..]),
        _ => (1.0, tz),
    };
    if digits.len() != 4 {
        return Err(err());
    }
    let tz_h: f64 = digits[..2].parse().map_err(|_| err())?;
    let tz_m: f64 = digits[2..].parse().map_err(|_| err())?;
    let offset = sign * (tz_h * 3600.0 + tz_m * 60.0);
    let days = days_from_civil(year, month, day) as f64;
    Ok(days * 86400.0 + h * 3600.0 + m * 60.0 + sec - offset)
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
}
