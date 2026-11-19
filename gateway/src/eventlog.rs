//! Asynchronous JSON-lines decision log (EVE/ECS-like field names, `srcip` for Wazuh).

use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use tokio::io::AsyncWriteExt;
use tokio::sync::mpsc;

#[derive(Clone)]
pub struct EventLog {
    tx: mpsc::Sender<String>,
}

impl EventLog {
    pub fn start(path: PathBuf) -> Self {
        let (tx, mut rx) = mpsc::channel::<String>(10_000);
        tokio::spawn(async move {
            let file = tokio::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&path)
                .await;
            let mut file = match file {
                Ok(f) => f,
                Err(e) => {
                    eprintln!(
                        "pattern-guard-gateway: cannot open decision log {}: {e}",
                        path.display()
                    );
                    return;
                }
            };
            while let Some(mut line) = rx.recv().await {
                line.push('\n');
                if file.write_all(line.as_bytes()).await.is_err() {
                    eprintln!("pattern-guard-gateway: decision log write failed");
                }
            }
        });
        Self { tx }
    }

    /// Never blocks the request path; drops lines if the writer falls behind.
    pub fn log(&self, line: String) {
        let _ = self.tx.try_send(line);
    }
}

/// RFC 3339 UTC timestamp with milliseconds.
pub fn rfc3339_now() -> String {
    let d = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let secs = d.as_secs() as i64;
    let (days, rem) = (secs.div_euclid(86400), secs.rem_euclid(86400));
    let (y, m, day) = civil_from_days(days);
    format!(
        "{y:04}-{m:02}-{day:02}T{:02}:{:02}:{:02}.{:03}Z",
        rem / 3600,
        rem % 3600 / 60,
        rem % 60,
        d.subsec_millis()
    )
}

/// Howard Hinnant's days → (year, month, day).
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn civil_dates() {
        assert_eq!(civil_from_days(0), (1970, 1, 1));
        assert_eq!(civil_from_days(19723), (2024, 1, 1));
        assert_eq!(civil_from_days(11016), (2000, 2, 29));
        assert!(rfc3339_now().ends_with('Z'));
    }
}
