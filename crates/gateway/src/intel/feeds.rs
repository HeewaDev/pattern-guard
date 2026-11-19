//! Tails Suricata EVE and Wazuh alert files and turns alerts into temporary IP blocks, so
//! network-layer (Suricata) and host-layer (Wazuh) detections are enforced at the gateway.

use std::io::SeekFrom;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use serde_json::Value;
use tokio::io::{AsyncReadExt, AsyncSeekExt};

use crate::config::{FeedAction, FeedConfig, FeedKind};
use crate::intel::{IntelAction, IntelEntry, IntelStore};
use crate::ipnet::Cidr;
use crate::observability::metrics::Metrics;

/// Extracts (attacker IP, reason) from one alert line, if it qualifies.
pub fn parse_alert(
    kind: FeedKind,
    line: &str,
    min_severity: Option<u32>,
) -> Option<(IpAddr, String)> {
    let v: Value = serde_json::from_str(line).ok()?;
    let (ip, reason) = match kind {
        FeedKind::Suricata => {
            if v.get("event_type")?.as_str()? != "alert" {
                return None;
            }
            let alert = v.get("alert")?;
            let severity = alert.get("severity").and_then(Value::as_u64).unwrap_or(3) as u32;
            if severity > min_severity.unwrap_or(2) {
                return None;
            }
            // For alerts on traffic towards the client, the attacker is the destination.
            let field = match v.get("direction").and_then(Value::as_str) {
                Some("to_client") => "dest_ip",
                _ => "src_ip",
            };
            let sig = alert
                .get("signature")
                .and_then(Value::as_str)
                .unwrap_or("alert");
            (
                v.get(field)?.as_str()?.parse::<IpAddr>().ok()?,
                format!("suricata: {sig}"),
            )
        }
        FeedKind::Wazuh => {
            let rule = v.get("rule")?;
            let level = rule.get("level").and_then(Value::as_u64).unwrap_or(0) as u32;
            if level < min_severity.unwrap_or(10) {
                return None;
            }
            let ip = v
                .pointer("/data/srcip")
                .or_else(|| v.get("srcip"))
                .and_then(Value::as_str)?
                .parse::<IpAddr>()
                .ok()?;
            let desc = rule
                .get("description")
                .and_then(Value::as_str)
                .unwrap_or("alert");
            (ip, format!("wazuh: {desc}"))
        }
    };
    if ip.is_loopback() || ip.is_unspecified() {
        return None;
    }
    Some((ip, reason))
}

pub async fn run(feed: FeedConfig, store: Arc<IntelStore>, metrics: Arc<Metrics>) {
    let source = match feed.kind {
        FeedKind::Suricata => "suricata",
        FeedKind::Wazuh => "wazuh",
    };
    // Start at the end: act on new alerts, don't replay history.
    let mut pos = tokio::fs::metadata(&feed.path)
        .await
        .map(|m| m.len())
        .unwrap_or(0);
    let mut partial = String::new();
    loop {
        tokio::time::sleep(Duration::from_secs(1)).await;
        let Ok(meta) = tokio::fs::metadata(&feed.path).await else {
            continue;
        };
        let len = meta.len();
        if len < pos {
            pos = 0; // rotated / truncated
            partial.clear();
        }
        if len == pos {
            continue;
        }
        let Ok(mut f) = tokio::fs::File::open(&feed.path).await else {
            continue;
        };
        if f.seek(SeekFrom::Start(pos)).await.is_err() {
            continue;
        }
        let mut buf = Vec::new();
        let max = (len - pos).min(8 * 1024 * 1024);
        if f.take(max).read_to_end(&mut buf).await.is_err() {
            continue;
        }
        pos += buf.len() as u64;
        partial.push_str(&String::from_utf8_lossy(&buf));
        let complete = match partial.rfind('\n') {
            Some(i) => {
                let rest = partial.split_off(i + 1);
                std::mem::replace(&mut partial, rest)
            }
            None => continue,
        };
        for line in complete.lines() {
            if let Some((ip, reason)) = parse_alert(feed.kind, line, feed.min_severity) {
                let action = match feed.action {
                    FeedAction::Ban => IntelAction::Ban,
                    FeedAction::Challenge => IntelAction::Challenge,
                };
                store.add(
                    Cidr::parse(&ip.to_string()).expect("ip parses as cidr"),
                    IntelEntry {
                        action,
                        source: source.into(),
                        reason,
                        expires: Some(Instant::now() + Duration::from_secs(feed.block_secs)),
                    },
                );
                metrics.inc_feed(source);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn suricata_alerts() {
        let l = r#"{"timestamp":"2024-01-01T00:00:00.000000+0000","event_type":"alert","src_ip":"203.0.113.5","dest_ip":"10.0.0.2","alert":{"signature":"ET SCAN Nmap","severity":2}}"#;
        let (ip, why) = parse_alert(FeedKind::Suricata, l, None).unwrap();
        assert_eq!(ip.to_string(), "203.0.113.5");
        assert!(why.contains("Nmap"));
        let low = l.replace("\"severity\":2", "\"severity\":3");
        assert!(parse_alert(FeedKind::Suricata, &low, None).is_none());
        let to_client = l.replace(
            "\"event_type\"",
            "\"direction\":\"to_client\",\"event_type\"",
        );
        assert_eq!(
            parse_alert(FeedKind::Suricata, &to_client, None)
                .unwrap()
                .0
                .to_string(),
            "10.0.0.2"
        );
        assert!(parse_alert(FeedKind::Suricata, r#"{"event_type":"flow"}"#, None).is_none());
    }

    #[test]
    fn wazuh_alerts() {
        let l = r#"{"rule":{"level":12,"description":"sshd: brute force"},"data":{"srcip":"198.51.100.7"}}"#;
        assert_eq!(
            parse_alert(FeedKind::Wazuh, l, None).unwrap().0.to_string(),
            "198.51.100.7"
        );
        assert!(parse_alert(FeedKind::Wazuh, &l.replace("12", "5"), None).is_none());
        assert!(parse_alert(FeedKind::Wazuh, "not json", None).is_none());
    }
}
