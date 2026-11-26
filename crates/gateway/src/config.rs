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
    /// Business operations: per-account limits, allowed sources, replay protection
    /// (see docs/GATEWAY.md#business-operations).
    #[serde(default)]
    pub operations: Vec<OperationConfig>,
    /// Login protection: failures per account across IPs, accounts tried per IP.
    #[serde(default)]
    pub logins: Vec<LoginConfig>,
    /// Automatic bans for repeat offenders (fail2ban-style).
    #[serde(default)]
    pub bans: BanConfig,
    /// Honeypot paths: requesting one bans the client immediately.
    #[serde(default)]
    pub traps: TrapConfig,
    /// HTTP protocol enforcement (methods, sizes, null bytes, restricted extensions).
    #[serde(default)]
    pub protocol: ProtocolConfig,
    /// Security headers added to (and fingerprinting headers removed from) responses.
    #[serde(default)]
    pub response_headers: ResponseHeadersConfig,
    /// Block responses that leak errors, stack traces, directory listings or keys.
    #[serde(default)]
    pub response_inspection: ResponseInspectionConfig,
    /// Country-based access control from an IP-to-country CSV.
    #[serde(default)]
    pub geo: GeoConfig,
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
    /// Requests in progress per client IP *after* `client_ip.trusted_proxies` (so it also
    /// applies behind a CDN or load balancer); more get 429. 0 = unlimited. The allow list
    /// is exempt.
    #[serde(default = "d_conn")]
    pub max_requests_in_flight_per_ip: u32,
    /// Seconds a client has to send complete request headers (slowloris protection).
    #[serde(default = "d_header_timeout")]
    pub header_read_timeout_secs: u64,
    /// A request body must keep arriving: within every period of this many seconds, at
    /// least `body_min_bytes_per_sec × body_read_timeout_secs` bytes (or the rest of the
    /// body). Otherwise 408 and the connection is closed (slow-body / stalled-upload
    /// protection).
    #[serde(default = "d_body_timeout")]
    pub body_read_timeout_secs: u64,
    /// Minimum average body rate over each `body_read_timeout_secs` period. 0 = only
    /// a stall of a whole period times out.
    #[serde(default = "d_body_min_rate")]
    pub body_min_bytes_per_sec: u64,
    /// Request-body bytes buffered at once across all requests (0 = unlimited). A
    /// request that would go over it gets 503. Never less than `max_body_bytes`.
    #[serde(default = "d_buffered_bodies")]
    pub max_buffered_body_bytes: usize,
    /// Bytes of decision-log lines that may wait in memory for a slow or stalled disk;
    /// further lines are dropped and counted.
    #[serde(default = "d_log_queue_bytes")]
    pub decision_log_queue_bytes: usize,
    /// Bans the gateway issues itself (repeat offenders, traps) kept at once. Over the
    /// cap, the ban closest to expiry is dropped.
    #[serde(default = "d_max_bans")]
    pub max_bans: usize,
    /// Reputation entries kept per external source (each CrowdSec origin, Suricata,
    /// Wazuh). Over the cap, that source's entry closest to expiry is dropped.
    #[serde(default = "d_max_intel_per_source")]
    pub max_intel_entries_per_source: usize,
}

impl Default for LimitsConfig {
    fn default() -> Self {
        toml::from_str("").unwrap()
    }
}

impl GatewayConfig {
    /// The effective `limits.max_buffered_body_bytes`: `None` = unlimited, and never
    /// below `max_body_bytes`, so one body of the largest accepted size always fits.
    pub fn body_budget(&self) -> Option<usize> {
        match self.limits.max_buffered_body_bytes {
            0 => None,
            b => Some(b.max(self.max_body_bytes)),
        }
    }
}

/// Smallest `limits.decision_log_queue_bytes`: room for the largest line (values and
/// findings are truncated, see `proxy/decision_log.rs`).
pub const MIN_LOG_QUEUE_BYTES: usize = 64 * 1024;

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

#[derive(Debug, Clone, PartialEq, Deserialize)]
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

#[derive(Debug, Clone, PartialEq, Deserialize)]
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
    /// Client country (needs `[geo] database`); empty = any.
    #[serde(default)]
    pub countries: Vec<String>,
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

/// Requests violating these limits are refused with the matching HTTP status.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProtocolConfig {
    #[serde(default = "d_true")]
    pub enabled: bool,
    /// Allowed methods (405 otherwise).
    #[serde(default = "d_methods")]
    pub allowed_methods: Vec<String>,
    /// Longest request target, path + query (414 otherwise).
    #[serde(default = "d_max_url")]
    pub max_url_bytes: usize,
    /// Most header fields (431 otherwise).
    #[serde(default = "d_max_headers")]
    pub max_headers: usize,
    /// Largest total of header names + values (431 otherwise).
    #[serde(default = "d_max_header_bytes")]
    pub max_header_bytes: usize,
    /// Most query-string arguments (400 otherwise).
    #[serde(default = "d_max_args")]
    pub max_query_args: usize,
    /// Refuse NUL bytes (raw or `%00`) in the request target (400).
    #[serde(default = "d_true")]
    pub block_null_bytes: bool,
    /// Refuse requests without a Host header (400).
    #[serde(default = "d_true")]
    pub require_host: bool,
    /// Refuse paths ending in these extensions, e.g. `.bak`, `.sql` (403).
    #[serde(default)]
    pub restricted_extensions: Vec<String>,
}

impl Default for ProtocolConfig {
    fn default() -> Self {
        toml::from_str("").unwrap()
    }
}

/// Security headers set on upstream responses when the app hasn't set them itself.
/// An empty string disables a default.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResponseHeadersConfig {
    #[serde(default = "d_true")]
    pub enabled: bool,
    #[serde(default = "d_nosniff")]
    pub content_type_options: String,
    #[serde(default = "d_frame")]
    pub frame_options: String,
    #[serde(default = "d_referrer")]
    pub referrer_policy: String,
    /// e.g. `max-age=31536000; includeSubDomains` (only when the site is served over HTTPS).
    #[serde(default)]
    pub strict_transport_security: String,
    #[serde(default)]
    pub content_security_policy: String,
    #[serde(default)]
    pub permissions_policy: String,
    #[serde(default)]
    pub cross_origin_opener_policy: String,
    /// Response headers to strip (server fingerprinting).
    #[serde(default = "d_remove_headers")]
    pub remove: Vec<String>,
}

impl Default for ResponseHeadersConfig {
    fn default() -> Self {
        toml::from_str("").unwrap()
    }
}

/// Country access control. `database` is a CSV of `start_ip,end_ip,country_code`
/// (e.g. DB-IP "IP to Country Lite", CC BY 4.0). Relative to this config file.
#[derive(Debug, Clone, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct GeoConfig {
    #[serde(default)]
    pub database: Option<PathBuf>,
    /// ISO 3166-1 alpha-2 codes that are blocked.
    #[serde(default)]
    pub deny_countries: Vec<String>,
    /// Codes that are challenged.
    #[serde(default)]
    pub challenge_countries: Vec<String>,
    /// If non-empty, only these countries are allowed (unknown/private IPs are not blocked).
    #[serde(default)]
    pub allow_countries: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum LeakAction {
    /// Replace the response with a generic 500 page.
    #[default]
    Block,
    /// Pass it through and record it in the decision log.
    Log,
}

/// Data-leak inspection of upstream responses (opt-in: it buffers text responses).
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResponseInspectionConfig {
    #[serde(default)]
    pub enabled: bool,
    /// Bytes of each response inspected; longer bodies are inspected at the start and
    /// the rest is streamed unchanged.
    #[serde(default = "d_leak_bytes")]
    pub max_bytes: usize,
    /// Content-type prefixes to inspect.
    #[serde(default = "d_leak_types")]
    pub content_types: Vec<String>,
    #[serde(default)]
    pub action: LeakAction,
}

impl Default for ResponseInspectionConfig {
    fn default() -> Self {
        toml::from_str("").unwrap()
    }
}

fn d_leak_bytes() -> usize {
    256 * 1024
}
fn d_leak_types() -> Vec<String> {
    [
        "text/html",
        "text/plain",
        "application/json",
        "application/xml",
        "text/xml",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect()
}

fn d_nosniff() -> String {
    "nosniff".into()
}
fn d_frame() -> String {
    "SAMEORIGIN".into()
}
fn d_referrer() -> String {
    "strict-origin-when-cross-origin".into()
}
fn d_remove_headers() -> Vec<String> {
    [
        "server",
        "x-powered-by",
        "x-aspnet-version",
        "x-aspnetmvc-version",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect()
}

fn d_methods() -> Vec<String> {
    ["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"]
        .iter()
        .map(|s| s.to_string())
        .collect()
}
fn d_max_url() -> usize {
    8192
}
fn d_max_headers() -> usize {
    100
}
fn d_max_header_bytes() -> usize {
    32 * 1024
}
fn d_max_args() -> usize {
    512
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

/// What an operation does when one of its checks fails.
#[derive(Debug, Clone, Copy, Deserialize, Default, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum OperationAction {
    #[default]
    Block,
    Challenge,
    Delay,
    /// Only record the hit in the decision log.
    Log,
}

/// A per-account budget: `requests` per `per_secs`, bursts up to `requests`.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccountLimit {
    pub requests: u32,
    pub per_secs: f64,
}

/// A business operation such as checkout, a transfer or a payment callback.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OperationConfig {
    pub name: String,
    #[serde(default)]
    pub path: Option<String>,
    #[serde(default)]
    pub path_regex: Option<String>,
    #[serde(default)]
    pub methods: Vec<String>,
    /// Who performs it: `header:<name>`, `cookie:<name>`, `query:<name>`,
    /// `form:<name>` or `json:<dotted.path>`. Values are hashed, never stored.
    #[serde(default)]
    pub account: Option<String>,
    /// Refuse requests that don't carry the account identifier.
    #[serde(default)]
    pub require_account: bool,
    /// Budget per account (falls back to the client IP when there is no account).
    #[serde(default)]
    pub limit: Option<AccountLimit>,
    /// If set, only these sources may call the operation (e.g. a payment provider).
    #[serde(default)]
    pub allowed_ips: Vec<String>,
    /// A value that must be unique (e.g. `json:transaction_id`): a second request with
    /// the same value is refused while the first is in flight or after it succeeded.
    #[serde(default)]
    pub unique: Option<String>,
    #[serde(default = "d_unique_ttl")]
    pub unique_ttl_secs: u64,
    #[serde(default)]
    pub action: OperationAction,
}

fn d_unique_ttl() -> u64 {
    86_400
}

/// A login endpoint to protect against brute force and credential stuffing.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LoginConfig {
    pub name: String,
    #[serde(default)]
    pub path: Option<String>,
    #[serde(default)]
    pub path_regex: Option<String>,
    #[serde(default = "d_login_methods")]
    pub methods: Vec<String>,
    /// Where the user name is: `form:<name>`, `json:<dotted.path>`, `header:<name>`, …
    pub account: String,
    /// Upstream statuses that mean a failed login.
    #[serde(default = "d_failure_statuses")]
    pub failure_statuses: Vec<u16>,
    /// Failed logins per account (from any IP) within `window_secs` before the account
    /// is protected with `action`. 0 disables.
    #[serde(default = "d_max_failures")]
    pub max_failures: u32,
    /// Distinct accounts one IP may try within `window_secs` (credential stuffing).
    /// 0 disables.
    #[serde(default = "d_max_accounts_per_ip")]
    pub max_accounts_per_ip: u32,
    #[serde(default = "d_login_window")]
    pub window_secs: u64,
    #[serde(default = "d_login_action")]
    pub action: OperationAction,
}

fn d_login_methods() -> Vec<String> {
    vec!["POST".into()]
}
fn d_failure_statuses() -> Vec<u16> {
    vec![401, 403]
}
fn d_max_failures() -> u32 {
    5
}
fn d_max_accounts_per_ip() -> u32 {
    10
}
fn d_login_window() -> u64 {
    900
}
fn d_login_action() -> OperationAction {
    OperationAction::Challenge
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
fn d_body_timeout() -> u64 {
    30
}
fn d_body_min_rate() -> u64 {
    1024
}
fn d_buffered_bodies() -> usize {
    256 * 1024 * 1024
}
fn d_log_queue_bytes() -> usize {
    16 * 1024 * 1024
}
fn d_max_bans() -> usize {
    100_000
}
fn d_max_intel_per_source() -> usize {
    500_000 // = intel::store::DEFAULT_MAX_PER_SOURCE
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
        if let (Some(g), Some(dir)) = (&c.geo.database, path.parent()) {
            if g.is_relative() {
                c.geo.database = Some(dir.join(g));
            }
        }
        Ok(c)
    }

    pub fn from_toml_str(s: &str) -> Result<Self, String> {
        let c: Self = toml::from_str(s).map_err(|e| format!("invalid gateway config: {e}"))?;
        c.validate()?;
        Ok(c)
    }

    /// Checks the values serde can't (ranges, URLs, CIDRs). `load` and `from_toml_str`
    /// call it; so does `Compiled::compile`, for configs built or changed in code.
    pub fn validate(&self) -> Result<(), String> {
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
        if self.limits.decision_log_queue_bytes < MIN_LOG_QUEUE_BYTES {
            return Err(format!(
                "limits.decision_log_queue_bytes must be at least {MIN_LOG_QUEUE_BYTES}"
            ));
        }
        if self.limits.body_read_timeout_secs == 0 {
            return Err("limits.body_read_timeout_secs must be at least 1".into());
        }
        if self.limits.max_bans == 0 || self.limits.max_intel_entries_per_source == 0 {
            return Err(
                "limits.max_bans and limits.max_intel_entries_per_source must be at least 1".into(),
            );
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

    #[test]
    fn limits() {
        let c = GatewayConfig::from_toml_str("upstream = \"http://x\"\n").unwrap();
        assert_eq!(c.limits.decision_log_queue_bytes, 16 * 1024 * 1024);
        let bad = |l: &str| {
            GatewayConfig::from_toml_str(&format!("upstream = \"http://x\"\n[limits]\n{l}\n"))
                .is_err()
        };
        assert!(bad("decision_log_queue_bytes = 1000"));
        assert!(!bad("decision_log_queue_bytes = 65536"));
        assert_eq!(
            (c.limits.max_bans, c.limits.max_intel_entries_per_source),
            (100_000, 500_000)
        );
        assert!(bad("max_bans = 0"));
        assert!(bad("max_intel_entries_per_source = 0"));
        assert_eq!(
            (
                c.limits.body_read_timeout_secs,
                c.limits.body_min_bytes_per_sec,
                c.limits.max_buffered_body_bytes
            ),
            (30, 1024, 256 * 1024 * 1024)
        );
        assert!(bad("body_read_timeout_secs = 0"));
        assert_eq!(c.limits.max_requests_in_flight_per_ip, 256);
        assert!(!bad("max_requests_in_flight_per_ip = 0"));
        assert!(!bad(
            "body_min_bytes_per_sec = 0\nmax_buffered_body_bytes = 0"
        ));
    }
}
