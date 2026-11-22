//! Prometheus text metrics.

use std::collections::HashMap;
use std::fmt::Write;
use std::sync::atomic::{AtomicU64, Ordering::Relaxed};
use std::sync::{Arc, Mutex};

#[derive(Default)]
pub struct Metrics {
    pub allow: AtomicU64,
    pub warn: AtomicU64,
    pub delay: AtomicU64,
    pub challenge: AtomicU64,
    pub block: AtomicU64,
    /// Detect mode: requests that would have been delayed/challenged/blocked.
    pub would_mitigate: AtomicU64,
    pub challenges_passed: AtomicU64,
    pub challenges_failed: AtomicU64,
    pub upstream_errors: AtomicU64,
    pub body_too_large: AtomicU64,
    pub connections_rejected: AtomicU64,
    /// Decision-log lines dropped because the writer was too far behind.
    pub decision_log_dropped: AtomicU64,
    /// Reputation entries evicted because their source was at its cap (shared with
    /// the `IntelStore`).
    pub intel_evicted: Arc<AtomicU64>,
    /// Request-body bytes buffered right now. This is also the counter the
    /// `limits.max_buffered_body_bytes` budget is enforced on (`server::read_body`).
    pub buffered_body_bytes: AtomicU64,
    /// Requests refused with 408: the body arrived too slowly or stalled.
    pub rejected_body_timeout: AtomicU64,
    /// Requests refused with 503: buffering the body would exceed the budget.
    pub rejected_body_budget: AtomicU64,
    /// Requests refused with 429: the client already had `limits.max_requests_in_flight_per_ip`
    /// requests in progress.
    pub rejected_in_flight: AtomicU64,
    pub crowdsec_ok: AtomicU64,
    pub duration_us_sum: AtomicU64,
    pub requests: AtomicU64,
    waf: Mutex<HashMap<&'static str, u64>>,
    blocked_by: Mutex<HashMap<String, u64>>,
    feeds: Mutex<HashMap<&'static str, u64>>,
}

impl Metrics {
    pub fn inc_waf(&self, class: &'static str) {
        *self
            .waf
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .entry(class)
            .or_default() += 1;
    }

    pub fn inc_blocked_by(&self, layer: &str) {
        *self
            .blocked_by
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .entry(layer.to_string())
            .or_default() += 1;
    }

    pub fn inc_feed(&self, source: &'static str) {
        *self
            .feeds
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .entry(source)
            .or_default() += 1;
    }

    pub fn render(&self, intel_entries: usize) -> String {
        let mut s = String::new();
        let c = |s: &mut String, name: &str, help: &str| {
            let _ = writeln!(s, "# HELP {name} {help}\n# TYPE {name} counter");
        };
        c(
            &mut s,
            "pattern_guard_requests_total",
            "Requests by final action.",
        );
        for (a, v) in [
            ("allow", &self.allow),
            ("warn", &self.warn),
            ("delay", &self.delay),
            ("challenge", &self.challenge),
            ("block", &self.block),
        ] {
            let _ = writeln!(
                s,
                "pattern_guard_requests_total{{action=\"{a}\"}} {}",
                v.load(Relaxed)
            );
        }
        for (name, help, v) in [
            (
                "pattern_guard_would_mitigate_total",
                "Detect mode: requests that would have been mitigated.",
                &self.would_mitigate,
            ),
            (
                "pattern_guard_challenges_passed_total",
                "Proof-of-work challenges solved.",
                &self.challenges_passed,
            ),
            (
                "pattern_guard_challenges_failed_total",
                "Invalid challenge solutions.",
                &self.challenges_failed,
            ),
            (
                "pattern_guard_upstream_errors_total",
                "Upstream connection errors / timeouts.",
                &self.upstream_errors,
            ),
            (
                "pattern_guard_body_too_large_total",
                "Requests rejected with 413.",
                &self.body_too_large,
            ),
            (
                "pattern_guard_connections_rejected_total",
                "Connections over the per-IP limit.",
                &self.connections_rejected,
            ),
            (
                "pattern_guard_decision_log_dropped_total",
                "Decision-log lines dropped because the writer fell behind (queue full by lines or bytes).",
                &self.decision_log_dropped,
            ),
            (
                "pattern_guard_intel_evicted_total",
                "Reputation entries dropped because their source was at its cap (soonest-expiring first).",
                &*self.intel_evicted,
            ),
        ] {
            c(&mut s, name, help);
            let _ = writeln!(s, "{name} {}", v.load(Relaxed));
        }
        c(
            &mut s,
            "pattern_guard_waf_findings_total",
            "WAF findings at or above log_score, by class.",
        );
        for (k, v) in self.waf.lock().unwrap_or_else(|e| e.into_inner()).iter() {
            let _ = writeln!(s, "pattern_guard_waf_findings_total{{class=\"{k}\"}} {v}");
        }
        c(
            &mut s,
            "pattern_guard_blocked_total",
            "Blocked requests by deciding layer.",
        );
        for (k, v) in self
            .blocked_by
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
        {
            let _ = writeln!(s, "pattern_guard_blocked_total{{layer=\"{k}\"}} {v}");
        }
        c(
            &mut s,
            "pattern_guard_feed_alerts_total",
            "Suricata/Wazuh alerts turned into blocks.",
        );
        for (k, v) in self.feeds.lock().unwrap_or_else(|e| e.into_inner()).iter() {
            let _ = writeln!(s, "pattern_guard_feed_alerts_total{{source=\"{k}\"}} {v}");
        }
        c(
            &mut s,
            "pattern_guard_requests_rejected_total",
            "Requests refused by a connection-level limit before inspection, by reason.",
        );
        for (reason, v) in [
            ("body_timeout", &self.rejected_body_timeout),
            ("body_budget", &self.rejected_body_budget),
            ("in_flight_per_ip", &self.rejected_in_flight),
        ] {
            let _ = writeln!(
                s,
                "pattern_guard_requests_rejected_total{{reason=\"{reason}\"}} {}",
                v.load(Relaxed)
            );
        }
        let _ = writeln!(
            s,
            "# HELP pattern_guard_buffered_body_bytes Request-body bytes buffered right now.\n# TYPE pattern_guard_buffered_body_bytes gauge\npattern_guard_buffered_body_bytes {}",
            self.buffered_body_bytes.load(Relaxed)
        );
        let _ = writeln!(
            s,
            "# HELP pattern_guard_intel_entries Active reputation entries.\n# TYPE pattern_guard_intel_entries gauge\npattern_guard_intel_entries {intel_entries}"
        );
        let _ = writeln!(
            s,
            "# HELP pattern_guard_crowdsec_up Last CrowdSec poll succeeded.\n# TYPE pattern_guard_crowdsec_up gauge\npattern_guard_crowdsec_up {}",
            self.crowdsec_ok.load(Relaxed)
        );
        let _ = writeln!(
            s,
            "# HELP pattern_guard_decision_seconds Time spent deciding (excl. upstream).\n# TYPE pattern_guard_decision_seconds summary\npattern_guard_decision_seconds_sum {}\npattern_guard_decision_seconds_count {}",
            self.duration_us_sum.load(Relaxed) as f64 / 1e6,
            self.requests.load(Relaxed)
        );
        s
    }
}
