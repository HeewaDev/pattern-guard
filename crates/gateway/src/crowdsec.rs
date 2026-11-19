//! CrowdSec bouncer: pulls decisions (community blocklist + local detections) from the
//! CrowdSec Local API stream and mirrors them into the intel store.
//!
//! `GET {url}/v1/decisions/stream?startup=true|false` with header `X-Api-Key`.

use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;
use http_body_util::{BodyExt, Empty};
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use serde::Deserialize;

use crate::config::CrowdSecConfig;
use crate::intel::{IntelAction, IntelEntry, IntelStore};
use crate::ipnet::Cidr;
use crate::metrics::Metrics;

#[derive(Deserialize)]
struct Stream {
    #[serde(default)]
    new: Option<Vec<Decision>>,
    #[serde(default)]
    deleted: Option<Vec<Decision>>,
}

#[derive(Deserialize)]
struct Decision {
    scope: String,
    value: String,
    #[serde(rename = "type", default)]
    kind: String,
    #[serde(default)]
    origin: String,
    #[serde(default)]
    scenario: String,
    #[serde(default)]
    duration: String,
}

/// Go duration string (`3h59m5.123s`, `10m`, `500ms`) → seconds.
pub fn parse_go_duration(s: &str) -> Option<f64> {
    let s = s.trim().trim_start_matches('-');
    if s.is_empty() {
        return None;
    }
    let mut total = 0.0;
    let mut num = String::new();
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c.is_ascii_digit() || c == '.' {
            num.push(c);
            continue;
        }
        let mut unit = c.to_string();
        if (c == 'm' || c == 'u' || c == 'n' || c == 'µ') && chars.peek() == Some(&'s') {
            unit.push(chars.next().unwrap());
        }
        let v: f64 = num.parse().ok()?;
        num.clear();
        total += v * match unit.as_str() {
            "h" => 3600.0,
            "m" => 60.0,
            "s" => 1.0,
            "ms" => 1e-3,
            "us" | "µs" => 1e-6,
            "ns" => 1e-9,
            _ => return None,
        };
    }
    if !num.is_empty() {
        return None;
    }
    Some(total)
}

/// Applies one stream response. Returns (added, removed).
pub fn apply_stream(
    json: &[u8],
    store: &IntelStore,
    startup: bool,
) -> Result<(usize, usize), String> {
    let s: Stream = serde_json::from_slice(json).map_err(|e| format!("bad stream JSON: {e}"))?;
    if startup {
        store.clear_source("crowdsec");
    }
    let (mut added, mut removed) = (0, 0);
    for d in s.deleted.unwrap_or_default() {
        if let Some(c) = cidr_for(&d) {
            store.remove(c, "crowdsec");
            removed += 1;
        }
    }
    for d in s.new.unwrap_or_default() {
        let Some(c) = cidr_for(&d) else { continue };
        let action = match d.kind.to_ascii_lowercase().as_str() {
            "ban" => IntelAction::Ban,
            "captcha" | "challenge" => IntelAction::Challenge,
            _ => continue,
        };
        let expires = parse_go_duration(&d.duration)
            .filter(|s| *s > 0.0)
            .map(|s| Instant::now() + Duration::from_secs_f64(s.min(365.0 * 86400.0)));
        store.add(
            c,
            IntelEntry {
                action,
                source: format!(
                    "crowdsec:{}",
                    if d.origin.is_empty() {
                        "local"
                    } else {
                        &d.origin
                    }
                ),
                reason: d.scenario,
                expires,
            },
        );
        added += 1;
    }
    Ok((added, removed))
}

fn cidr_for(d: &Decision) -> Option<Cidr> {
    match d.scope.to_ascii_lowercase().as_str() {
        "ip" | "range" => Cidr::parse(&d.value),
        _ => None,
    }
}

pub fn api_key(cfg: &CrowdSecConfig) -> Result<String, String> {
    if let Some(var) = &cfg.api_key_env {
        return std::env::var(var)
            .map_err(|_| format!("crowdsec: environment variable {var} is not set"));
    }
    cfg.api_key
        .clone()
        .ok_or_else(|| "crowdsec: no API key".into())
}

pub async fn run(cfg: CrowdSecConfig, key: String, store: Arc<IntelStore>, metrics: Arc<Metrics>) {
    let client = Client::builder(TokioExecutor::new()).build_http::<Empty<Bytes>>();
    let base = cfg.url.trim_end_matches('/').to_string();
    let mut startup = true;
    loop {
        let uri = format!("{base}/v1/decisions/stream?startup={startup}");
        let req = hyper::Request::get(&uri)
            .header("x-api-key", &key)
            .header(
                "user-agent",
                concat!("pattern-guard-gateway/", env!("CARGO_PKG_VERSION")),
            )
            .body(Empty::new());
        let result = match req {
            Ok(req) => {
                match tokio::time::timeout(Duration::from_secs(15), client.request(req)).await {
                    Ok(Ok(resp)) if resp.status().is_success() => resp
                        .into_body()
                        .collect()
                        .await
                        .map_err(|e| e.to_string())
                        .and_then(|b| apply_stream(&b.to_bytes(), &store, startup)),
                    Ok(Ok(resp)) => Err(format!("HTTP {}", resp.status())),
                    Ok(Err(e)) => Err(e.to_string()),
                    Err(_) => Err("timeout".into()),
                }
            }
            Err(e) => Err(e.to_string()),
        };
        match result {
            Ok((a, r)) => {
                if startup || a + r > 0 {
                    eprintln!(
                        "pattern-guard-gateway: crowdsec +{a} -{r} decisions ({} active)",
                        store.len()
                    );
                }
                startup = false;
                metrics
                    .crowdsec_ok
                    .store(1, std::sync::atomic::Ordering::Relaxed);
            }
            Err(e) => {
                eprintln!("pattern-guard-gateway: crowdsec poll failed: {e}");
                metrics
                    .crowdsec_ok
                    .store(0, std::sync::atomic::Ordering::Relaxed);
            }
        }
        tokio::time::sleep(Duration::from_secs(cfg.poll_secs.max(1))).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn go_durations() {
        assert_eq!(parse_go_duration("1h"), Some(3600.0));
        assert!((parse_go_duration("3h59m5.5s").unwrap() - 14345.5).abs() < 1e-9);
        assert_eq!(parse_go_duration("500ms"), Some(0.5));
        assert_eq!(parse_go_duration("bogus"), None);
        assert_eq!(parse_go_duration("10"), None);
    }

    #[test]
    fn stream_updates_store() {
        let store = IntelStore::default();
        let startup = br#"{"new":[
            {"scope":"Ip","value":"192.0.2.10","type":"ban","origin":"CAPI","scenario":"crowdsecurity/http-bf","duration":"4h"},
            {"scope":"Range","value":"198.51.100.0/24","type":"captcha","origin":"cscli","scenario":"manual","duration":"1h"},
            {"scope":"Country","value":"XX","type":"ban","origin":"cscli","scenario":"x","duration":"1h"}
        ],"deleted":null}"#;
        assert_eq!(apply_stream(startup, &store, true).unwrap(), (2, 0));
        let e = store.lookup("192.0.2.10".parse().unwrap()).unwrap();
        assert_eq!(e.action, IntelAction::Ban);
        assert_eq!(e.source, "crowdsec:CAPI");
        assert_eq!(
            store
                .lookup("198.51.100.9".parse().unwrap())
                .unwrap()
                .action,
            IntelAction::Challenge
        );
        let delta = br#"{"new":null,"deleted":[{"scope":"Ip","value":"192.0.2.10","type":"ban","duration":"0s"}]}"#;
        assert_eq!(apply_stream(delta, &store, false).unwrap(), (0, 1));
        assert!(store.lookup("192.0.2.10".parse().unwrap()).is_none());
    }
}
