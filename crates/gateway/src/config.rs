//! `gateway.toml`. See docs/GATEWAY.md.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use serde::Deserialize;

use crate::ipnet::Cidr;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum Mode {
    /// Log what would happen, never interfere (shadow mode).
    Detect,
    /// Enforce: block, challenge, delay.
    #[default]
    Prevent,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GatewayConfig {
    #[serde(default = "d_listen")]
    pub listen: SocketAddr,
    /// `http://host:port` of the protected application.
    pub upstream: String,
    #[serde(default)]
    pub mode: Mode,
    /// Metrics, health and API inventory. Keep it on loopback or a private network.
    #[serde(default = "d_admin")]
    pub admin_listen: Option<SocketAddr>,
    /// Pattern-Guard engine config (behavioural ML). Relative to this file.
    #[serde(default)]
    pub guard_config: Option<PathBuf>,
    /// Largest request body accepted (bytes); larger → 413.
    #[serde(default = "d_max_body")]
    pub max_body_bytes: usize,
    #[serde(default = "d_upstream_timeout")]
    pub upstream_timeout_secs: u64,
    /// Upper bound for `Delay` decisions.
    #[serde(default = "d_delay_max")]
    pub delay_max_secs: f64,
    /// Forward the client's Host header (true) or the upstream's authority (false).
    #[serde(default = "d_true")]
    pub preserve_host: bool,
    /// Add `x-pattern-guard-*` headers (risk, bot score, decision) to upstream requests.
    #[serde(default = "d_true")]
    pub forward_scores: bool,
    #[serde(default)]
    pub client_ip: ClientIpConfig,
    #[serde(default)]
    pub limits: LimitsConfig,
    #[serde(default)]
    pub waf: WafConfig,
    #[serde(default)]
    pub challenge: ChallengeConfig,
    #[serde(default)]
    pub access: AccessConfig,
    #[serde(default)]
    pub crowdsec: CrowdSecConfig,
    #[serde(default)]
    pub feeds: Vec<FeedConfig>,
    #[serde(default)]
    pub log: LogConfig,
    /// Custom firewall rules, evaluated in order (see docs/GATEWAY.md#custom-rules).
    #[serde(default)]
    pub rules: Vec<RuleConfig>,
    /// Rate limits per route and key (see docs/GATEWAY.md#rate-limits).
    #[serde(default)]
    pub rate_limits: Vec<RateLimitConfig>,
    /// Automatic bans for repeat offenders (fail2ban-style).
    #[serde(default)]
    pub bans: BanConfig,
    /// Honeypot paths: requesting one bans the client immediately.
    #[serde(default)]
    pub traps: TrapConfig,
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct ClientIpConfig {
    /// Peers allowed to set the client-IP header (your load balancer / CDN).
    #[serde(default)]
    pub trusted_proxies: Vec<String>,
    /// Header carrying the client IP when the peer is trusted.
    #[serde(default = "d_xff")]
    pub header: String,
    /// Header carrying a TLS fingerprint (e.g. JA4) set by your TLS terminator.
    #[serde(default)]
    pub fingerprint_header: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LimitsConfig {
    /// Concurrent connections per client IP (0 = unlimited). Not applied to trusted proxies.
    #[serde(default = "d_conn")]
    pub max_connections_per_ip: u32,
    /// Seconds a client has to send complete request headers (slowloris protection).
    #[serde(default = "d_header_timeout")]
    pub header_read_timeout_secs: u64,
}

impl Default for LimitsConfig {
    fn default() -> Self {
        Self {
            max_connections_per_ip: d_conn(),
            header_read_timeout_secs: d_header_timeout(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WafConfig {
    #[serde(default = "d_true")]
    pub enabled: bool,
    #[serde(default = "d_block_score")]
    pub block_score: f64,
    #[serde(default = "d_log_score")]
    pub log_score: f64,
    /// Body bytes inspected (the full body is still forwarded).
    #[serde(default = "d_inspect_body")]
    pub inspect_body_bytes: usize,
    /// Path prefixes not inspected.
    #[serde(default)]
    pub exclude_paths: Vec<String>,
    /// Parameter / field names whose values are not inspected (e.g. `password`, `html_body`).
    #[serde(default)]
    pub exclude_params: Vec<String>,
}

impl Default for WafConfig {
    fn default() -> Self {
        toml::from_str("").unwrap()
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChallengeConfig {
    #[serde(default = "d_true")]
    pub enabled: bool,
    /// Leading zero bits required (16 ≈ 65k hashes, well under a second in a browser).
    #[serde(default = "d_difficulty")]
    pub difficulty: u32,
    /// How long a solved challenge (clearance cookie) is valid.
    #[serde(default = "d_ttl")]
    pub ttl_secs: u64,
    /// Hex HMAC key (≥ 32 hex chars). Empty = random per process (clearances reset on restart;
    /// set it when running several gateway instances).
    #[serde(default)]
    pub secret: String,
}

impl Default for ChallengeConfig {
    fn default() -> Self {
        toml::from_str("").unwrap()
    }
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct AccessConfig {
    /// Always allowed, no inspection (CIDRs or IPs).
    #[serde(default)]
    pub allow: Vec<String>,
    /// Always blocked.
    #[serde(default)]
    pub deny: Vec<String>,
    /// Always challenged (until they hold a clearance cookie).
    #[serde(default)]
    pub challenge: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CrowdSecConfig {
    #[serde(default)]
    pub enabled: bool,
    /// Local API base URL (http only).
    #[serde(default = "d_crowdsec_url")]
    pub url: String,
    /// Bouncer API key (`cscli bouncers add pattern-guard`). Prefer `api_key_env`.
    #[serde(default)]
    pub api_key: Option<String>,
    /// Environment variable holding the bouncer API key.
    #[serde(default)]
    pub api_key_env: Option<String>,
    #[serde(default = "d_poll")]
    pub poll_secs: u64,
}

impl Default for CrowdSecConfig {
    fn default() -> Self {
        toml::from_str("").unwrap()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FeedKind {
    /// Suricata EVE JSON (`event_type: alert`, `src_ip`, `alert.severity` 1 = highest).
    Suricata,
    /// Wazuh `alerts.json` (`rule.level`, `data.srcip`).
    Wazuh,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum FeedAction {
    #[default]
    Ban,
    Challenge,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FeedConfig {
    pub kind: FeedKind,
    pub path: PathBuf,
    /// Suricata: act on alerts with severity ≤ this (1 = highest). Wazuh: rule level ≥ this.
    pub min_severity: Option<u32>,
    #[serde(default = "d_feed_block")]
    pub block_secs: u64,
    #[serde(default)]
    pub action: FeedAction,
}

/// What a matching rule does.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuleAction {
    /// Forward without any further inspection (terminal).
    Allow,
    /// Refuse with 403 (terminal).
    Block,
    /// Proof-of-work challenge unless the client holds a clearance (terminal).
    Challenge,
    /// Slow the request down, then continue (terminal).
    Delay,
    /// Record the match in the decision log and keep evaluating.
    Log,
    /// Skip WAF payload inspection for this request and keep evaluating.
    SkipWaf,
}

/// A header condition: present (optionally matching `regex`) or `absent`.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HeaderMatch {
    pub name: String,
    #[serde(default)]
    pub regex: Option<String>,
    #[serde(default)]
    pub absent: bool,
}

/// One custom rule. Every condition that is set must match (AND); unset conditions are ignored.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuleConfig {
    pub name: String,
    /// Path prefix, e.g. `/admin`.
    #[serde(default)]
    pub path: Option<String>,
    /// Regex on the path (without the query string).
    #[serde(default)]
    pub path_regex: Option<String>,
    /// HTTP methods (case-insensitive); empty = any.
    #[serde(default)]
    pub methods: Vec<String>,
    /// Host names; `*.example.com` matches subdomains. Empty = any.
    #[serde(default)]
    pub hosts: Vec<String>,
    /// Client IP must be in one of these CIDRs.
    #[serde(default)]
    pub ips: Vec<String>,
    /// Client IP must be in none of these CIDRs.
    #[serde(default)]
    pub not_ips: Vec<String>,
    /// Regex on the User-Agent (missing UA = empty string).
    #[serde(default)]
    pub user_agent_regex: Option<String>,
    /// Regex on the raw query string (missing query = empty string).
    #[serde(default)]
    pub query_regex: Option<String>,
    #[serde(default)]
    pub headers: Vec<HeaderMatch>,
    pub action: RuleAction,
}

/// Escalating bans: `threshold` blocks within `window_secs` ban the IP for `ban_secs`,
/// multiplied by `escalation` for every previous ban (capped at `max_ban_secs`).
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BanConfig {
    #[serde(default = "d_true")]
    pub enabled: bool,
    #[serde(default = "d_ban_threshold")]
    pub threshold: u32,
    #[serde(default = "d_ban_window")]
    pub window_secs: u64,
    #[serde(default = "d_ban_secs")]
    pub ban_secs: u64,
    #[serde(default = "d_ban_escalation")]
    pub escalation: f64,
    #[serde(default = "d_ban_max")]
    pub max_ban_secs: u64,
}

impl Default for BanConfig {
    fn default() -> Self {
        toml::from_str("").unwrap()
    }
}

/// Honeypot paths (prefixes) that legitimate visitors never request on this site.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrapConfig {
    #[serde(default)]
    pub paths: Vec<String>,
    #[serde(default = "d_trap_ban")]
    pub ban_secs: u64,
}

impl Default for TrapConfig {
    fn default() -> Self {
        toml::from_str("").unwrap()
    }
}

fn d_ban_threshold() -> u32 {
    10
}
fn d_ban_window() -> u64 {
    60
}
fn d_ban_secs() -> u64 {
    600
}
fn d_ban_escalation() -> f64 {
    2.0
}
fn d_ban_max() -> u64 {
    86_400
}
fn d_trap_ban() -> u64 {
    3_600
}

/// What happens when a rate limit is exceeded.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum LimitAction {
    /// 429 Too Many Requests with Retry-After.
    #[default]
    Block,
    Challenge,
    Delay,
}

/// A token-bucket rate limit: `requests` per `per_secs`, bursts up to `requests`.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RateLimitConfig {
    pub name: String,
    #[serde(default)]
    pub path: Option<String>,
    #[serde(default)]
    pub path_regex: Option<String>,
    #[serde(default)]
    pub methods: Vec<String>,
    /// `ip` (default), `ip_route` (per IP and route template), or `header:<name>`
    /// (e.g. `header:x-api-key`; falls back to the IP when the header is missing).
    #[serde(default = "d_limit_key")]
    pub key: String,
    pub requests: u32,
    pub per_secs: f64,
    #[serde(default)]
    pub action: LimitAction,
}

fn d_limit_key() -> String {
    "ip".into()
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct LogConfig {
    /// JSON-lines decision log (EVE/ECS-like). Unset = stderr summary only.
    #[serde(default)]
    pub decisions: Option<PathBuf>,
    /// Also log allowed requests (verbose).
    #[serde(default)]
    pub include_allowed: bool,
}

fn d_listen() -> SocketAddr {
    "0.0.0.0:8080".parse().unwrap()
}
fn d_admin() -> Option<SocketAddr> {
    Some("127.0.0.1:9901".parse().unwrap())
}
fn d_max_body() -> usize {
    10 * 1024 * 1024
}
fn d_upstream_timeout() -> u64 {
    30
}
fn d_delay_max() -> f64 {
    5.0
}
fn d_true() -> bool {
    true
}
fn d_xff() -> String {
    "x-forwarded-for".into()
}
fn d_conn() -> u32 {
    256
}
fn d_header_timeout() -> u64 {
    10
}
fn d_block_score() -> f64 {
    7.0
}
fn d_log_score() -> f64 {
    4.0
}
fn d_inspect_body() -> usize {
    64 * 1024
}
fn d_difficulty() -> u32 {
    16
}
fn d_ttl() -> u64 {
    3600
}
fn d_crowdsec_url() -> String {
    "http://127.0.0.1:8080".into()
}
fn d_poll() -> u64 {
    10
}
fn d_feed_block() -> u64 {
    3600
}

impl GatewayConfig {
    pub fn load(path: impl AsRef<Path>) -> Result<Self, String> {
        let path = path.as_ref();
        let s = std::fs::read_to_string(path)
            .map_err(|e| format!("cannot read {}: {e}", path.display()))?;
        let mut c = Self::from_toml_str(&s)?;
        if let (Some(g), Some(dir)) = (&c.guard_config, path.parent()) {
            if g.is_relative() {
                c.guard_config = Some(dir.join(g));
            }
        }
        Ok(c)
    }

    pub fn from_toml_str(s: &str) -> Result<Self, String> {
        let c: Self = toml::from_str(s).map_err(|e| format!("invalid gateway config: {e}"))?;
        c.validate()?;
        Ok(c)
    }

    fn validate(&self) -> Result<(), String> {
        if !self.upstream.starts_with("http://") {
            return Err("upstream must be an http:// URL (terminate TLS in front of the gateway or use a local upstream)".into());
        }
        self.upstream
            .parse::<hyper::Uri>()
            .map_err(|e| format!("bad upstream URL: {e}"))?;
        for list in [
            &self.client_ip.trusted_proxies,
            &self.access.allow,
            &self.access.deny,
            &self.access.challenge,
        ] {
            for c in list {
                Cidr::parse(c).ok_or_else(|| format!("bad IP/CIDR {c:?}"))?;
            }
        }
        if !(0.0..=10.0).contains(&self.waf.block_score)
            || self.waf.log_score > self.waf.block_score
        {
            return Err("waf: need 0 ≤ log_score ≤ block_score ≤ 10".into());
        }
        if self.bans.threshold == 0
            || self.bans.escalation < 1.0
            || !self.bans.escalation.is_finite()
        {
            return Err("bans: need threshold ≥ 1 and escalation ≥ 1".into());
        }
        if self.challenge.difficulty > 28 {
            return Err(
                "challenge.difficulty above 28 bits would take minutes in a browser".into(),
            );
        }
        if !self.challenge.secret.is_empty() && self.challenge.secret.len() < 32 {
            return Err("challenge.secret must be at least 32 hex characters".into());
        }
        if self.crowdsec.enabled {
            if !self.crowdsec.url.starts_with("http://") {
                return Err("crowdsec.url must be http:// (local API)".into());
            }
            if self.crowdsec.api_key.is_none() && self.crowdsec.api_key_env.is_none() {
                return Err("crowdsec: set api_key_env (or api_key)".into());
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn minimal_config() {
        let c = GatewayConfig::from_toml_str("upstream = \"http://127.0.0.1:3000\"\n").unwrap();
        assert_eq!(c.mode, Mode::Prevent);
        assert!(c.waf.enabled);
        assert_eq!(c.challenge.difficulty, 16);
    }

    #[test]
    fn rejects_bad_values() {
        assert!(GatewayConfig::from_toml_str("upstream = \"https://x\"\n").is_err());
        assert!(
            GatewayConfig::from_toml_str("upstream = \"http://x\"\nmode = \"magic\"\n").is_err()
        );
        assert!(
            GatewayConfig::from_toml_str("upstream = \"http://x\"\n[access]\ndeny = [\"nope\"]\n")
                .is_err()
        );
        assert!(GatewayConfig::from_toml_str("upstream = \"http://x\"\ntypo = 1\n").is_err());
        assert!(
            GatewayConfig::from_toml_str("upstream = \"http://x\"\n[crowdsec]\nenabled = true\n")
                .is_err()
        );
    }
}
