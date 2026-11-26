//! Asynchronous JSON-lines decision log (EVE/ECS-like field names, `srcip` for Wazuh).
//!
//! The queue between the request path and the writer is bounded twice: by line count
//! and by bytes (`limits.decision_log_queue_bytes`). A stalled disk therefore costs at
//! most that much memory; lines beyond it are dropped and counted in
//! `pattern_guard_decision_log_dropped_total`. At shutdown, [`EventLog::flush`] waits
//! until the queued lines are written.

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering::Relaxed};
use std::time::{SystemTime, UNIX_EPOCH};

use tokio::io::AsyncWriteExt;
use tokio::sync::{mpsc, oneshot};

use crate::observability::metrics::Metrics;

/// Most lines queued for the writer, whatever their size.
const MAX_QUEUED_LINES: usize = 10_000;

enum Msg {
    Line(String),
    /// Answered once every line queued before it has been written.
    Flush(oneshot::Sender<()>),
}

#[derive(Clone)]
pub struct EventLog {
    tx: mpsc::Sender<Msg>,
    /// Bytes (allocated capacity) of the lines queued for the writer.
    queued: Arc<AtomicUsize>,
    max_bytes: usize,
    metrics: Arc<Metrics>,
}

impl EventLog {
    /// Starts the writer task appending to `path`; at most `max_bytes` of lines wait
    /// in memory for it.
    pub fn start(path: PathBuf, max_bytes: usize, metrics: Arc<Metrics>) -> Self {
        let (log, mut rx) = Self::queue(max_bytes, metrics);
        let queued = log.queued.clone();
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
            while let Some(msg) = rx.recv().await {
                let mut line = match msg {
                    Msg::Line(line) => line,
                    Msg::Flush(done) => {
                        // tokio's `File` may still be writing the last line in the background
                        let _ = file.flush().await;
                        let _ = done.send(());
                        continue;
                    }
                };
                let size = line.capacity();
                line.push('\n');
                if file.write_all(line.as_bytes()).await.is_err() {
                    eprintln!("pattern-guard-gateway: decision log write failed");
                }
                drop(line);
                queued.fetch_sub(size, Relaxed);
            }
        });
        log
    }

    /// The bounded queue without its writer (whoever drains the receiver must
    /// subtract each line's capacity from `queued`).
    fn queue(max_bytes: usize, metrics: Arc<Metrics>) -> (Self, mpsc::Receiver<Msg>) {
        let (tx, rx) = mpsc::channel::<Msg>(MAX_QUEUED_LINES);
        let log = Self {
            tx,
            queued: Arc::new(AtomicUsize::new(0)),
            max_bytes,
            metrics,
        };
        (log, rx)
    }

    /// Never blocks the request path: the line is dropped (and counted) when the
    /// writer is `max_bytes` or `MAX_QUEUED_LINES` lines behind.
    pub fn log(&self, line: String) {
        let size = line.capacity();
        let before = self.queued.fetch_add(size, Relaxed);
        if before.saturating_add(size) > self.max_bytes
            || self.tx.try_send(Msg::Line(line)).is_err()
        {
            self.queued.fetch_sub(size, Relaxed);
            self.metrics.decision_log_dropped.fetch_add(1, Relaxed);
        }
    }

    /// Waits until every line queued before the call has been written (returns at once
    /// when the writer has stopped, e.g. because the file couldn't be opened). Used at
    /// shutdown, under a timeout: it waits for room in the queue and for the disk.
    pub async fn flush(&self) {
        let (done, written) = oneshot::channel();
        if self.tx.send(Msg::Flush(done)).await.is_ok() {
            let _ = written.await;
        }
    }

    /// Bytes currently queued for the writer.
    pub fn queued_bytes(&self) -> usize {
        self.queued.load(Relaxed)
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

    #[test]
    fn queue_is_bounded_by_bytes() {
        let metrics = Arc::new(Metrics::default());
        let (log, mut rx) = EventLog::queue(10_000, metrics.clone());
        let line = |n: usize| {
            let mut s = String::with_capacity(n);
            s.push_str(&"x".repeat(n));
            s
        };
        log.log(line(4_000));
        log.log(line(4_000));
        assert_eq!(log.queued_bytes(), 8_000);
        // the writer is stalled: a third line would exceed 10 000 bytes
        log.log(line(4_000));
        assert_eq!(log.queued_bytes(), 8_000);
        assert_eq!(metrics.decision_log_dropped.load(Relaxed), 1);
        // small lines still fit
        log.log(line(1_000));
        assert_eq!(log.queued_bytes(), 9_000);
        // draining releases the budget
        let Ok(Msg::Line(first)) = rx.try_recv() else {
            panic!("a line was queued first")
        };
        log.queued.fetch_sub(first.capacity(), Relaxed);
        log.log(line(4_000));
        assert_eq!(log.queued_bytes(), 9_000);
        assert_eq!(metrics.decision_log_dropped.load(Relaxed), 1);
    }

    #[tokio::test]
    async fn flush_waits_for_queued_lines() {
        let path =
            std::env::temp_dir().join(format!("pg-eventlog-flush-{}.jsonl", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let log = EventLog::start(path.clone(), 1 << 20, Arc::new(Metrics::default()));
        for i in 0..500 {
            log.log(format!("{{\"n\":{i}}}"));
        }
        log.flush().await;
        let written = std::fs::read_to_string(&path).unwrap();
        assert_eq!(written.lines().count(), 500);
        assert!(written.ends_with("{\"n\":499}\n"));
        assert_eq!(log.queued_bytes(), 0);
        let _ = std::fs::remove_file(&path);

        // a writer that couldn't open its file doesn't hold the shutdown up
        let nowhere = std::env::temp_dir().join("pg-no-such-dir/decisions.jsonl");
        let dead = EventLog::start(nowhere, 1 << 20, Arc::new(Metrics::default()));
        dead.log("x".into());
        tokio::time::timeout(std::time::Duration::from_secs(5), dead.flush())
            .await
            .unwrap();
    }
}
