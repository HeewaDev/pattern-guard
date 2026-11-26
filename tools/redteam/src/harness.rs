//! Runs a scenario: the demo app, optionally the gateway in front of it (in process, on
//! 127.0.0.1), an attacker, and the measurements.

use std::collections::{BTreeMap, BTreeSet};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::{Duration, Instant};

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::Request;
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::TokioExecutor;
use pattern_guard_gateway::config::GatewayConfig;
use tokio::net::TcpListener;

use crate::Vuln;
use crate::attack::adaptive::{Adaptive, Capabilities};
use crate::attack::external::External;
use crate::attack::{Observation, Probe, Strategy, classify};
use crate::oracle;
use crate::rng::Rng;

/// The gateway config the harness uses unless told otherwise.
pub const DEFAULT_CONFIG: &str = include_str!("../gateway.toml");

/// Who attacks, from where, with which abilities.
#[derive(Debug, Clone)]
pub struct Scenario {
    pub name: &'static str,
    pub about: &'static str,
    pub ips: Vec<IpAddr>,
    pub rotate: bool,
    pub solve_pow: bool,
    pub recon: bool,
}

/// Addresses that look like residential customers of many providers (one per /16). They
/// are only ever written into `X-Forwarded-For` in process; nothing contacts them.
fn residential_pool(seed: u64, n: usize) -> Vec<IpAddr> {
    const FIRST: &[u8] = &[
        24, 31, 37, 46, 62, 68, 73, 77, 78, 81, 82, 86, 88, 89, 90, 92, 93, 95, 98, 109, 151, 176,
        178, 185, 188, 189, 201, 212,
    ];
    let mut rng = Rng::new(seed ^ 0x5eed);
    let mut seen = BTreeSet::new();
    let mut out = Vec::new();
    while out.len() < n {
        let a = *rng.pick(FIRST);
        let b = rng.below(256) as u8;
        if !seen.insert((a, b)) {
            continue;
        }
        let ip = Ipv4Addr::new(a, b, rng.below(256) as u8, 1 + rng.below(254) as u8);
        out.push(IpAddr::V4(ip));
    }
    out
}

pub fn scenarios(seed: u64) -> Vec<Scenario> {
    let one = |last: u8| vec![IpAddr::V4(Ipv4Addr::new(203, 0, 113, last))];
    vec![
        Scenario {
            name: "targeted",
            about: "one client IP, knows the endpoints, mutates payloads when blocked",
            ips: one(7),
            rotate: false,
            solve_pow: false,
            recon: false,
        },
        Scenario {
            name: "scanner",
            about: "one client IP, probes common paths (/.env, /.git/config, …) first",
            ips: one(8),
            rotate: false,
            solve_pow: false,
            recon: true,
        },
        Scenario {
            name: "rotating",
            about: "residential-proxy rotation: a new client IP per request (256 addresses)",
            ips: residential_pool(seed, 256),
            rotate: true,
            solve_pow: false,
            recon: false,
        },
        Scenario {
            name: "pow-solver",
            about: "one client IP that solves proof-of-work challenges like a bot can",
            ips: one(9),
            rotate: false,
            solve_pow: true,
            recon: false,
        },
    ]
}

#[derive(Debug, Clone)]
pub struct Settings {
    pub seed: u64,
    pub pace: Duration,
    /// Most requests per run.
    pub budget: usize,
    pub max_wait: Duration,
    pub wait_budget: Duration,
    /// Gateway config; `{{UPSTREAM}}` is replaced with the demo app's address.
    pub gateway_config: String,
    /// Run this program as the attacker instead of the built-in one (JSON lines).
    pub attacker_cmd: Option<String>,
    /// Vulnerabilities the built-in attacker goes after (empty: all).
    pub vulns: Vec<Vuln>,
    /// One line per request on stderr.
    pub verbose: bool,
}

impl Default for Settings {
    fn default() -> Self {
        Settings {
            seed: 7,
            pace: Duration::from_millis(50),
            budget: 400,
            max_wait: Duration::from_secs(10),
            wait_budget: Duration::from_secs(30),
            gateway_config: DEFAULT_CONFIG.to_string(),
            attacker_cmd: None,
            vulns: Vec::new(),
            verbose: false,
        }
    }
}

/// When something happened: the request number (1-based) and seconds since the first.
#[derive(Debug, Clone)]
pub struct At {
    pub request: usize,
    pub secs: f64,
}

#[derive(Debug, Clone)]
pub struct Found {
    pub at: At,
    pub evidence: String,
}

#[derive(Debug, Clone)]
pub struct Ban {
    pub at: At,
    pub ip: String,
    pub reason: String,
}

/// One run of one scenario, through the gateway or directly against the app.
#[derive(Debug, Clone, Default)]
pub struct RunResult {
    pub via_gateway: bool,
    pub strategy: String,
    pub requests: usize,
    pub secs: f64,
    pub stop: String,
    /// Responses by [`Verdict`](crate::attack::Verdict) name.
    pub verdicts: BTreeMap<&'static str, usize>,
    pub found: BTreeMap<Vuln, Found>,
    /// Requests sent to each vulnerable endpoint.
    pub attempts: BTreeMap<Vuln, usize>,
    pub first_ban: Option<Ban>,
    pub banned_ips: usize,
    /// `pattern_guard_blocked_total` by layer at the end of the run.
    pub blocked_by_layer: BTreeMap<String, u64>,
    /// Challenges the gateway issued (`pattern_guard_requests_total{action="challenge"}`).
    pub challenges: u64,
    pub pow_solved: usize,
    /// Responses that took a second or more (the gateway's `delay` action).
    pub slow_responses: usize,
    /// Distinct orders of other customers read through BOLA.
    pub records_leaked: usize,
}

impl RunResult {
    pub fn first_bypass(&self) -> Option<(Vuln, &Found)> {
        self.found
            .iter()
            .min_by_key(|(_, f)| f.at.request)
            .map(|(v, f)| (*v, f))
    }
}

struct Gateway {
    addr: SocketAddr,
    admin: SocketAddr,
}

async fn start_gateway(config: &str, upstream: SocketAddr) -> Result<Gateway, String> {
    let toml = config.replace("{{UPSTREAM}}", &format!("http://{upstream}"));
    let cfg = GatewayConfig::from_toml_str(&toml).map_err(|e| format!("gateway config: {e}"))?;
    let state = pattern_guard_gateway::build_state(cfg)?;
    let l = TcpListener::bind("127.0.0.1:0")
        .await
        .map_err(|e| e.to_string())?;
    let al = TcpListener::bind("127.0.0.1:0")
        .await
        .map_err(|e| e.to_string())?;
    let addr = l.local_addr().map_err(|e| e.to_string())?;
    let admin = al.local_addr().map_err(|e| e.to_string())?;
    pattern_guard_gateway::start_background(&state, Some(al))?;
    tokio::spawn(pattern_guard_gateway::serve(state, l));
    Ok(Gateway { addr, admin })
}

type HttpClient = Client<HttpConnector, Full<Bytes>>;

async fn send(client: &HttpClient, addr: SocketAddr, p: &Probe, xff: bool) -> Observation {
    let started = Instant::now();
    let mut b = Request::builder()
        .method(p.method.as_str())
        .uri(format!("http://{addr}{}", p.target));
    for (k, v) in &p.headers {
        b = b.header(k.as_str(), v.as_str());
    }
    if xff {
        if let Some(ip) = p.client_ip {
            b = b.header("x-forwarded-for", ip.to_string());
        }
    }
    let Ok(req) = b.body(Full::new(Bytes::from(p.body.clone()))) else {
        return Observation::default();
    };
    let resp = match tokio::time::timeout(Duration::from_secs(30), client.request(req)).await {
        Ok(Ok(r)) => r,
        _ => return Observation::default(),
    };
    let status = resp.status().as_u16();
    let headers = resp
        .headers()
        .iter()
        .map(|(k, v)| {
            (
                k.as_str().to_string(),
                String::from_utf8_lossy(v.as_bytes()).into_owned(),
            )
        })
        .collect();
    let body = match tokio::time::timeout(Duration::from_secs(30), resp.into_body().collect()).await
    {
        Ok(Ok(b)) => String::from_utf8_lossy(&b.to_bytes()).into_owned(),
        _ => String::new(),
    };
    Observation {
        status,
        headers,
        body,
        elapsed: started.elapsed(),
        confirmed: None,
    }
}

async fn get_text(client: &HttpClient, url: String) -> Option<String> {
    let req = Request::get(url).body(Full::new(Bytes::new())).ok()?;
    let resp = client.request(req).await.ok()?;
    let b = resp.into_body().collect().await.ok()?.to_bytes();
    Some(String::from_utf8_lossy(&b).into_owned())
}

/// `(ip, reason)` of every ban on the admin port.
async fn bans(client: &HttpClient, admin: SocketAddr) -> Vec<(String, String)> {
    let Some(text) = get_text(client, format!("http://{admin}/bans")).await else {
        return Vec::new();
    };
    let v: serde_json::Value = serde_json::from_str(&text).unwrap_or_default();
    v["bans"]
        .as_array()
        .map(|a| {
            a.iter()
                .map(|b| {
                    (
                        b["ip"].as_str().unwrap_or("").to_string(),
                        b["reason"].as_str().unwrap_or("").to_string(),
                    )
                })
                .collect()
        })
        .unwrap_or_default()
}

/// Blocks by layer and the challenge count from `/metrics`.
async fn metrics(client: &HttpClient, admin: SocketAddr) -> (BTreeMap<String, u64>, u64) {
    let text = get_text(client, format!("http://{admin}/metrics"))
        .await
        .unwrap_or_default();
    let mut layers = BTreeMap::new();
    let mut challenges = 0;
    for line in text.lines() {
        let Some((key, value)) = line.rsplit_once(' ') else {
            continue;
        };
        let Ok(n) = value.parse::<f64>() else {
            continue;
        };
        if let Some(rest) = key.strip_prefix("pattern_guard_blocked_total{layer=\"") {
            layers.insert(rest.trim_end_matches("\"}").to_string(), n as u64);
        } else if key == "pattern_guard_requests_total{action=\"challenge\"}" {
            challenges = n as u64;
        }
    }
    (layers, challenges)
}

fn strategy_for(s: &Scenario, set: &Settings) -> Result<Box<dyn Strategy>, String> {
    Ok(match &set.attacker_cmd {
        Some(cmd) => Box::new(External::spawn(
            cmd,
            External::start_message(s.name, set.seed, &s.ips, s.rotate, s.solve_pow),
        )?),
        None => Box::new(Adaptive::new(
            Capabilities {
                ips: s.ips.clone(),
                rotate: s.rotate,
                solve_pow: s.solve_pow,
                recon: s.recon,
                pace: set.pace,
                max_wait: set.max_wait,
                wait_budget: set.wait_budget,
                vulns: set.vulns.clone(),
            },
            set.seed,
        )),
    })
}

/// Runs `scenario` through the gateway (`via_gateway`) or directly against the app. Needs
/// a multi-threaded runtime (an external attacker is read with blocking I/O).
pub async fn run(
    scenario: &Scenario,
    set: &Settings,
    via_gateway: bool,
) -> Result<RunResult, String> {
    let app = crate::app::start().await.map_err(|e| e.to_string())?;
    let gw = if via_gateway {
        Some(start_gateway(&set.gateway_config, app).await?)
    } else {
        None
    };
    let target = gw.as_ref().map_or(app, |g| g.addr);
    let client: HttpClient = Client::builder(TokioExecutor::new()).build_http();
    let mut strategy = strategy_for(scenario, set)?;
    let external = set.attacker_cmd.is_some();
    let mut r = RunResult {
        via_gateway,
        strategy: strategy.name(),
        ..Default::default()
    };
    let mut leaked = BTreeSet::new();
    let mut started: Option<Instant> = None;
    let mut stop = None;
    loop {
        if r.requests >= set.budget {
            stop = Some("budget".to_string());
            break;
        }
        let next = if external {
            tokio::task::block_in_place(|| strategy.next())
        } else {
            strategy.next()
        };
        let Some(mut probe) = next else { break };
        if probe.client_ip.is_none() {
            probe.client_ip = scenario.ips.first().copied();
        }
        tokio::time::sleep(probe.wait).await;
        let t0 = *started.get_or_insert_with(Instant::now);
        let mut obs = send(&client, target, &probe, via_gateway).await;
        r.requests += 1;
        let at = At {
            request: r.requests,
            secs: t0.elapsed().as_secs_f64(),
        };
        let content_type = probe
            .headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("content-type"))
            .map(|(_, v)| v.as_str())
            .unwrap_or("");
        obs.confirmed = oracle::confirm_request(
            &oracle::Request {
                target: &probe.target,
                content_type,
                body: &probe.body,
            },
            obs.status,
            &obs.body,
        );
        let verdict = classify(&obs);
        *r.verdicts.entry(verdict.as_str()).or_default() += 1;
        if let Some(v) = oracle::endpoint(&probe.target) {
            *r.attempts.entry(v).or_default() += 1;
        }
        if obs.elapsed >= Duration::from_secs(1) {
            r.slow_responses += 1;
        }
        if probe.target.starts_with("/.pattern-guard/verify") && obs.status / 100 == 2 {
            r.pow_solved += 1;
        }
        if let Some(c) = &obs.confirmed {
            if let Some(id) = c.record {
                leaked.insert(id);
            }
            r.found.entry(c.vuln).or_insert_with(|| Found {
                at: at.clone(),
                evidence: c.evidence.clone(),
            });
        }
        if let Some(g) = &gw {
            if r.first_ban.is_none() {
                if let Some((ip, reason)) = bans(&client, g.admin).await.into_iter().next() {
                    r.first_ban = Some(Ban {
                        at: at.clone(),
                        ip,
                        reason,
                    });
                }
            }
        }
        if set.verbose {
            eprintln!(
                "{:>4} {:>7.2}s {:<15} {:>3} {:<12} {}",
                at.request,
                at.secs,
                probe.client_ip.map(|i| i.to_string()).unwrap_or_default(),
                obs.status,
                verdict.as_str(),
                probe.label
            );
        }
        if external {
            tokio::task::block_in_place(|| strategy.observe(&probe, &obs));
        } else {
            strategy.observe(&probe, &obs);
        }
        r.secs = at.secs;
    }
    r.stop = stop.unwrap_or_else(|| strategy.stop_reason());
    r.records_leaked = leaked.len();
    if let Some(g) = &gw {
        r.banned_ips = bans(&client, g.admin).await.len();
        let (layers, challenges) = metrics(&client, g.admin).await;
        r.blocked_by_layer = layers;
        r.challenges = challenges;
    }
    Ok(r)
}

/// Both runs of a scenario.
#[derive(Debug, Clone)]
pub struct ScenarioResult {
    pub scenario: Scenario,
    pub gateway: RunResult,
    pub direct: RunResult,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_residential_pool_is_diverse_and_public() {
        let pool = residential_pool(7, 256);
        assert_eq!(pool.len(), 256);
        let nets: BTreeSet<_> = pool
            .iter()
            .map(|ip| match ip {
                IpAddr::V4(v) => (v.octets()[0], v.octets()[1]),
                IpAddr::V6(_) => (0, 0),
            })
            .collect();
        assert_eq!(nets.len(), 256, "one address per /16");
        assert!(pool.iter().all(|ip| match ip {
            IpAddr::V4(v) =>
                !v.is_private() && !v.is_loopback() && ![192, 198, 203].contains(&v.octets()[0]),
            IpAddr::V6(_) => false,
        }));
        assert_eq!(pool, residential_pool(7, 256), "deterministic");
    }

    #[test]
    fn the_default_config_parses() {
        let toml = DEFAULT_CONFIG.replace("{{UPSTREAM}}", "http://127.0.0.1:9");
        GatewayConfig::from_toml_str(&toml).unwrap();
    }
}
