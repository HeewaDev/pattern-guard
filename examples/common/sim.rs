//! Synthetic but realistic labelled web traffic for one site.
//!
//! Legitimate background traffic runs for the whole period; attacks start at staggered
//! times. `unseen: true` adds attack variants (and a legitimate flash-sale surge) that
//! are never used for training, to measure how the model generalises.
#![allow(dead_code)]

pub struct Rec {
    pub t: f64,
    pub actor: String,
    pub ip: String,
    pub method: &'static str,
    pub path: String,
    pub status: u16,
    pub ua: &'static str,
    pub fp: &'static str,
    pub label: bool,
    pub scenario: &'static str,
}

#[derive(Clone, Copy)]
pub struct Profile {
    pub fp: &'static str,
    pub ua: &'static str,
}

const BROWSERS: [(Profile, u32); 7] = [
    (
        Profile {
            fp: "t13d1516h2_8daaf6152771_chrome_win",
            ua: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0 Safari/537.36",
        },
        30,
    ),
    (
        Profile {
            fp: "t13d1516h2_8daaf6152771_chrome_mac",
            ua: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0 Safari/537.36",
        },
        15,
    ),
    (
        Profile {
            fp: "t13d2014h2_a09f3c656075_safari_ios",
            ua: "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1",
        },
        20,
    ),
    (
        Profile {
            fp: "t13d1516h2_8daaf6152771_chrome_android",
            ua: "Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0 Mobile Safari/537.36",
        },
        15,
    ),
    (
        Profile {
            fp: "t13d1715h2_5b57614c22b0_firefox",
            ua: "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:132.0) Gecko/20100101 Firefox/132.0",
        },
        6,
    ),
    (
        Profile {
            fp: "t13d2014h2_a09f3c656075_safari_mac",
            ua: "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15",
        },
        7,
    ),
    (
        Profile {
            fp: "t13d1516h2_8daaf6152771_edge_win",
            ua: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0 Safari/537.36 Edg/130.0",
        },
        7,
    ),
];

const CHROME_WIN: Profile = BROWSERS[0].0;
const CHROME_MAC: Profile = BROWSERS[1].0;
const SAFARI_IOS: Profile = BROWSERS[2].0;
const EDGE_WIN: Profile = BROWSERS[6].0;
const PYTHON: Profile = Profile {
    fp: "t13d1812h1_python_requests",
    ua: "python-requests/2.32.3",
};
const GO_HTTP: Profile = Profile {
    fp: "t13d1311h1_go_http",
    ua: "Go-http-client/1.1",
};
const NODE: Profile = Profile {
    fp: "t13d1714h1_node_fetch",
    ua: "node-fetch/3.3",
};
const CURL: Profile = Profile {
    fp: "t13d3112h1_curl",
    ua: "curl/8.5.0",
};
const HEADLESS: Profile = Profile {
    fp: "t13d1516h2_8daaf6152771_headless",
    ua: "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/130.0 Safari/537.36",
};
const ZGRAB: Profile = Profile {
    fp: "t12d1009h1_zgrab",
    ua: "Mozilla/5.0 zgrab/0.x",
};
const OKHTTP: Profile = Profile {
    fp: "t13d1714h2_okhttp",
    ua: "okhttp/4.12.0",
};
const UPTIME: Profile = Profile {
    fp: "t13d1311h1_uptime",
    ua: "UptimeRobot/2.0",
};

pub struct Rng(u64);
impl Rng {
    pub fn new(seed: u64) -> Self {
        Rng(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1)
    }
    pub fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    pub fn f(&mut self) -> f64 {
        (self.next() >> 11) as f64 / (1u64 << 53) as f64
    }
    pub fn range(&mut self, lo: f64, hi: f64) -> f64 {
        lo + (hi - lo) * self.f()
    }
    pub fn int(&mut self, lo: u64, hi: u64) -> u64 {
        lo + self.next() % (hi - lo + 1)
    }
    pub fn chance(&mut self, p: f64) -> bool {
        self.f() < p
    }
    pub fn exp(&mut self, mean: f64) -> f64 {
        -mean * (1.0 - self.f()).ln()
    }
    fn browser(&mut self) -> Profile {
        let total: u32 = BROWSERS.iter().map(|b| b.1).sum();
        let mut x = self.int(0, total as u64 - 1) as u32;
        for (p, w) in BROWSERS {
            if x < w {
                return p;
            }
            x -= w;
        }
        CHROME_WIN
    }
    fn public_ip(&mut self) -> String {
        loop {
            let a = self.int(1, 223);
            if a != 10 && a != 127 && a != 100 && a != 203 && a != 198 && a != 192 {
                return format!(
                    "{}.{}.{}.{}",
                    a,
                    self.int(0, 255),
                    self.int(0, 255),
                    self.int(1, 254)
                );
            }
        }
    }
    fn carrier_ip(&mut self) -> String {
        format!("100.70.12.{}", self.int(1, 254))
    }
    fn word(&mut self) -> String {
        const W: [&str; 12] = [
            "shoes",
            "red+dress",
            "laptop",
            "usb+c+cable",
            "coffee",
            "lamp",
            "desk",
            "phone+case",
            "jacket",
            "headphones",
            "book",
            "watch",
        ];
        W[self.int(0, 11) as usize].to_string()
    }
}

pub struct Sim {
    pub rng: Rng,
    pub dur: f64,
    pub out: Vec<Rec>,
}

struct Who<'a> {
    actor: &'a str,
    ip: &'a str,
    p: Profile,
    label: bool,
    scenario: &'static str,
}

impl Sim {
    fn push(
        &mut self,
        w: &Who,
        t: f64,
        method: &'static str,
        path: impl Into<String>,
        status: u16,
    ) {
        if t >= 0.0 && t < self.dur {
            self.out.push(Rec {
                t,
                actor: w.actor.to_string(),
                ip: w.ip.to_string(),
                method,
                path: path.into(),
                status,
                ua: w.p.ua,
                fp: w.p.fp,
                label: w.label,
                scenario: w.scenario,
            });
        }
    }

    /// Browser page view: html + XHR + images. Returns time after the last request.
    fn page_view(&mut self, w: &Who, mut t: f64, n_images: u64) -> f64 {
        let id = self.rng.int(1, 5000);
        let html_status = if self.rng.chance(0.03) { 404 } else { 200 };
        let reqs: [(&'static str, String); 5] = [
            ("GET", format!("/product/{id}")),
            ("GET", format!("/api/product/{id}")),
            ("GET", format!("/api/reviews/{id}")),
            ("GET", format!("/api/recommendations?for={id}")),
            ("GET", "/api/cart".to_string()),
        ];
        for (i, (m, p)) in reqs.into_iter().enumerate() {
            self.push(w, t, m, p, if i == 0 { html_status } else { 200 });
            t += self.rng.range(0.02, 0.3);
        }
        for k in 0..n_images {
            let s = if self.rng.chance(0.02) { 404 } else { 200 };
            self.push(w, t, "GET", format!("/img/{id}_{k}.jpg"), s);
            t += self.rng.range(0.01, 0.15);
        }
        if self.rng.chance(0.1) {
            t += self.rng.range(2.0, 10.0);
            self.push(w, t, "POST", "/api/cart", 200);
        }
        t
    }

    fn shopping_session(&mut self, w: &Who, mut t: f64, pages: u64) {
        let mut logged_in = false;
        for i in 0..pages {
            let imgs = if i == 0 { 8 } else { self.rng.int(0, 3) };
            t = self.page_view(w, t, imgs);
            if self.rng.chance(0.15) {
                t += self.rng.range(3.0, 10.0);
                let q = self.rng.word();
                self.push(w, t, "GET", format!("/search?q={q}"), 200);
            }
            if !logged_in && self.rng.chance(0.06) {
                logged_in = true;
                t += self.rng.range(1.0, 4.0);
                self.push(w, t, "GET", "/login", 200);
                t += self.rng.range(4.0, 15.0);
                if self.rng.chance(0.15) {
                    self.push(w, t, "POST", "/login", 401);
                    t += self.rng.range(5.0, 12.0);
                }
                self.push(w, t, "POST", "/login", 302);
                t += self.rng.range(0.1, 0.5);
                self.push(w, t, "GET", "/account", 200);
            }
            t += self.rng.range(10.0, 60.0);
        }
    }
}

// ------------------------------------------------------------------ legitimate

fn shoppers(s: &mut Sim, scenario: &'static str, from: f64, to: f64, mean_gap: f64) {
    let mut t = from + s.rng.exp(mean_gap);
    while t < to {
        let p = s.rng.browser();
        let ip = if s.rng.chance(0.25) {
            s.rng.carrier_ip()
        } else {
            s.rng.public_ip()
        };
        let actor = format!("ip:{ip}");
        let w = Who {
            actor: &actor,
            ip: &ip,
            p,
            label: false,
            scenario,
        };
        let pages = s.rng.int(3, 20);
        s.shopping_session(&w, t, pages);
        t += s.rng.exp(mean_gap);
    }
}

fn office_nat(s: &mut Sim) {
    let ip = "203.0.113.5";
    let actor = "ip:203.0.113.5";
    for u in 0..25 {
        let p = if u % 3 == 0 { EDGE_WIN } else { CHROME_WIN };
        let w = Who {
            actor,
            ip,
            p,
            label: false,
            scenario: "legit: office NAT (25 users, 1 IP)",
        };
        let mut t = s.rng.range(0.0, 300.0);
        while t < s.dur {
            let pages = s.rng.int(2, 8);
            s.shopping_session(&w, t, pages);
            t += pages as f64 * 40.0 + s.rng.range(120.0, 900.0);
        }
    }
}

fn casual(s: &mut Sim) {
    for _ in 0..(300.0 * s.dur / 3600.0) as usize {
        let p = s.rng.browser();
        let ip = s.rng.public_ip();
        let actor = format!("ip:{ip}");
        let w = Who {
            actor: &actor,
            ip: &ip,
            p,
            label: false,
            scenario: "legit: casual visitors",
        };
        let mut t = s.rng.range(0.0, s.dur);
        let pages = ["/", "/pricing", "/docs", "/blog/how-we-ship", "/signup"];
        let n = s.rng.int(2, 4) as usize;
        for (i, page) in pages.iter().take(n).enumerate() {
            s.push(&w, t, "GET", *page, 200);
            if i == 0 {
                s.push(&w, t + 0.05, "GET", "/static/app.js", 200);
                s.push(&w, t + 0.08, "GET", "/static/style.css", 200);
            }
            t += s.rng.range(0.5, 8.0);
        }
    }
}

fn dashboard(s: &mut Sim) {
    let w = Who {
        actor: "user:ops-dashboard",
        ip: "198.51.100.20",
        p: CHROME_MAC,
        label: false,
        scenario: "legit: ops dashboard (2s polling)",
    };
    let mut t = 0.0;
    let mut i = 0u64;
    while t < s.dur {
        s.push(&w, t, "GET", "/api/metrics", 200);
        if i % 5 == 0 {
            s.push(&w, t + 0.03, "GET", "/api/alerts", 200);
        }
        t += 2.0;
        i += 1;
    }
}

fn partner_api(s: &mut Sim) {
    let w = Who {
        actor: "ip:198.51.100.200",
        ip: "198.51.100.200",
        p: GO_HTTP,
        label: false,
        scenario: "legit: partner API sync (non-browser)",
    };
    let mut start = 30.0;
    while start < s.dur {
        for page in 1..=100 {
            s.push(
                &w,
                start + page as f64 * 0.5,
                "GET",
                format!("/api/items?page={page}"),
                200,
            );
        }
        start += 600.0;
    }
}

fn mobile_app(s: &mut Sim) {
    for _ in 0..(40.0 * s.dur / 3600.0).max(1.0) as usize {
        let ip = if s.rng.chance(0.5) {
            s.rng.carrier_ip()
        } else {
            s.rng.public_ip()
        };
        let actor = format!("ip:{ip}");
        let w = Who {
            actor: &actor,
            ip: &ip,
            p: OKHTTP,
            label: false,
            scenario: "legit: mobile app (okhttp)",
        };
        let start = s.rng.range(0.0, s.dur);
        let end = start + s.rng.range(300.0, 1800.0);
        let mut t = start;
        let mut next_feed = start;
        while t < end {
            s.push(&w, t, "GET", "/api/notifications", 200);
            if t >= next_feed {
                s.push(&w, t + 0.2, "GET", "/api/feed", 200);
                if s.rng.chance(0.3) {
                    let tl = t + s.rng.range(2.0, 10.0);
                    s.push(&w, tl, "POST", "/api/like", 200);
                }
                next_feed = t + s.rng.range(20.0, 120.0);
            }
            t += s.rng.range(28.0, 32.0);
        }
    }
}

fn uptime(s: &mut Sim) {
    for i in 0..3 {
        let ip = format!("198.51.100.{}", 50 + i);
        let actor = format!("ip:{ip}");
        let w = Who {
            actor: &actor,
            ip: &ip,
            p: UPTIME,
            label: false,
            scenario: "legit: uptime monitors",
        };
        let mut t = i as f64 * 7.0;
        while t < s.dur {
            s.push(&w, t, "GET", "/health", 200);
            t += 60.0;
        }
    }
}

/// A link goes viral: lots of brand-new (mostly mobile) visitors land on one product.
fn viral_link(s: &mut Sim, from: f64, to: f64) {
    let id = s.rng.int(1, 5000);
    let mut t = from;
    while t < to {
        let p = if s.rng.chance(0.6) {
            SAFARI_IOS
        } else {
            s.rng.browser()
        };
        let ip = if s.rng.chance(0.4) {
            s.rng.carrier_ip()
        } else {
            s.rng.public_ip()
        };
        let actor = format!("ip:{ip}");
        let w = Who {
            actor: &actor,
            ip: &ip,
            p,
            label: false,
            scenario: "legit: viral link spike",
        };
        let mut tt = t;
        s.push(&w, tt, "GET", format!("/product/{id}"), 200);
        for k in 0..6 {
            tt += s.rng.range(0.01, 0.15);
            s.push(&w, tt, "GET", format!("/img/{id}_{k}.jpg"), 200);
        }
        tt += s.rng.range(0.1, 0.4);
        s.push(&w, tt, "GET", format!("/api/product/{id}"), 200);
        if s.rng.chance(0.35) {
            tt += s.rng.range(5.0, 40.0);
            let pages = s.rng.int(1, 4);
            s.shopping_session(&w, tt, pages);
        }
        t += s.rng.exp(0.4);
    }
}

/// Start of the work day: many users log in within minutes; some mistype passwords.
fn login_rush(s: &mut Sim, from: f64, to: f64) {
    let mut t = from;
    while t < to {
        let p = s.rng.browser();
        let ip = s.rng.public_ip();
        let actor = format!("ip:{ip}");
        let w = Who {
            actor: &actor,
            ip: &ip,
            p,
            label: false,
            scenario: "legit: morning login rush",
        };
        let mut tt = t;
        s.push(&w, tt, "GET", "/login", 200);
        tt += s.rng.range(3.0, 12.0);
        let mut tries = 0;
        while tries < 3 && s.rng.chance(0.2) {
            s.push(&w, tt, "POST", "/login", 401);
            tt += s.rng.range(4.0, 15.0);
            tries += 1;
        }
        s.push(&w, tt, "POST", "/login", 302);
        tt += s.rng.range(0.1, 0.4);
        s.push(&w, tt, "GET", "/account", 200);
        tt += s.rng.range(5.0, 30.0);
        let pages = s.rng.int(1, 5);
        s.shopping_session(&w, tt, pages);
        t += s.rng.exp(1.0);
    }
}

// ------------------------------------------------------------------ attacks

fn cred_stuffing(s: &mut Sim, from: f64, to: f64) {
    for i in 0..300 {
        let ip = s.rng.public_ip();
        let actor = format!("ip:{ip}");
        let p = [PYTHON, HEADLESS, NODE][i % 3];
        let w = Who {
            actor: &actor,
            ip: &ip,
            p,
            label: true,
            scenario: "attack: credential stuffing (300 IPs)",
        };
        let mut t = from + s.rng.range(0.0, 60.0);
        while t < to {
            let st = if s.rng.chance(0.01) { 302 } else { 401 };
            s.push(&w, t, "POST", "/login", st);
            t += s.rng.range(45.0, 90.0);
        }
    }
}

fn slow_scraper(s: &mut Sim, from: f64, to: f64) {
    let ip = s.rng.public_ip();
    let actor = format!("ip:{ip}");
    let w = Who {
        actor: &actor,
        ip: &ip,
        p: HEADLESS,
        label: true,
        scenario: "attack: slow sequential scraper (1 IP)",
    };
    let (mut t, mut id) = (from, s.rng.int(1000, 2000));
    while t < to {
        let st = if s.rng.chance(0.05) { 404 } else { 200 };
        s.push(&w, t, "GET", format!("/product/{id}"), st);
        id += 1;
        t += s.rng.range(6.5, 9.0);
    }
}

fn rotating_scraper(s: &mut Sim, from: f64, to: f64) {
    let ips: Vec<String> = (0..10).map(|_| s.rng.public_ip()).collect();
    let (mut t, mut id) = (from, s.rng.int(1000, 2000));
    while t < to {
        let ip = ips[s.rng.int(0, 9) as usize].clone();
        let actor = format!("ip:{ip}");
        let w = Who {
            actor: &actor,
            ip: &ip,
            p: GO_HTTP,
            label: true,
            scenario: "attack: scraper rotating 10 IPs",
        };
        s.push(&w, t, "GET", format!("/api/product/{id}"), 200);
        id += 1;
        t += s.rng.range(0.7, 1.3);
    }
}

fn single_flood(s: &mut Sim, from: f64, to: f64) {
    let ip = s.rng.public_ip();
    let actor = format!("ip:{ip}");
    let w = Who {
        actor: &actor,
        ip: &ip,
        p: CURL,
        label: true,
        scenario: "attack: single-IP flood (50 rps)",
    };
    let mut t = from;
    while t < to {
        let q = s.rng.next() % 100_000;
        s.push(&w, t, "GET", format!("/search?q={q}"), 200);
        t += 0.02;
    }
}

/// Flood on an endpoint with no history yet (no route baseline to compare against).
fn fresh_endpoint_flood(s: &mut Sim, from: f64, to: f64) {
    let ip = s.rng.public_ip();
    let actor = format!("ip:{ip}");
    let p = if s.rng.chance(0.5) { PYTHON } else { GO_HTTP };
    let w = Who {
        actor: &actor,
        ip: &ip,
        p,
        label: true,
        scenario: "attack: flood on a fresh endpoint",
    };
    let rate = s.rng.range(10.0, 40.0);
    let mut t = from;
    while t < to {
        let id = s.rng.next() % 1_000_000;
        s.push(&w, t, "GET", format!("/api/reports/export?id={id}"), 200);
        t += 1.0 / rate;
    }
}

fn distributed_flood(s: &mut Sim, from: f64, to: f64) {
    for i in 0..500 {
        let ip = s.rng.public_ip();
        let actor = format!("ip:{ip}");
        let p = [GO_HTTP, PYTHON, NODE][i % 3];
        let w = Who {
            actor: &actor,
            ip: &ip,
            p,
            label: true,
            scenario: "attack: L7 flood (500 IPs)",
        };
        let mut t = from + s.rng.range(0.0, 4.0);
        while t < to {
            let q = s.rng.next() % 100_000;
            s.push(&w, t, "GET", format!("/search?q={q}"), 200);
            t += s.rng.range(3.0, 5.0);
        }
    }
}

const SCAN_PATHS: [&str; 45] = [
    "/.env",
    "/.git/config",
    "/wp-admin",
    "/wp-login.php",
    "/phpmyadmin",
    "/admin",
    "/config.php",
    "/backup.zip",
    "/.aws/credentials",
    "/server-status",
    "/actuator/env",
    "/api/v1/users",
    "/debug",
    "/console",
    "/.DS_Store",
    "/xmlrpc.php",
    "/cgi-bin/test",
    "/etc/passwd",
    "/.htaccess",
    "/web.config",
    "/swagger.json",
    "/graphql",
    "/.svn/entries",
    "/db.sql",
    "/dump.sql",
    "/old",
    "/test",
    "/staging",
    "/vendor/phpunit",
    "/solr",
    "/jenkins",
    "/manager/html",
    "/owa",
    "/autodiscover.xml",
    "/.well-known/security.txt",
    "/api/swagger",
    "/api/docs",
    "/info.php",
    "/install.php",
    "/setup.php",
    "/shell.php",
    "/upload.php",
    "/login.action",
    "/struts",
    "/HNAP1",
];

fn vuln_scan(s: &mut Sim, from: f64) {
    let ip = s.rng.public_ip();
    let actor = format!("ip:{ip}");
    let w = Who {
        actor: &actor,
        ip: &ip,
        p: ZGRAB,
        label: true,
        scenario: "attack: vulnerability scanner (45 paths)",
    };
    let mut t = from;
    for path in SCAN_PATHS {
        let st = if s.rng.chance(0.15) { 403 } else { 404 };
        s.push(&w, t, "GET", path, st);
        t += s.rng.range(0.5, 2.0);
    }
}

/// Stuffing through residential proxies with real-browser fingerprints, posting directly.
fn browser_stuffing(s: &mut Sim, from: f64, to: f64) {
    for _ in 0..250 {
        let ip = s.rng.public_ip();
        let actor = format!("ip:{ip}");
        let p = s.rng.browser();
        let w = Who {
            actor: &actor,
            ip: &ip,
            p,
            label: true,
            scenario: "attack: stuffing via browser fps (250 IPs)",
        };
        let mut t = from + s.rng.range(0.0, 90.0);
        while t < to {
            let st = if s.rng.chance(0.02) { 302 } else { 401 };
            s.push(&w, t, "POST", "/login", st);
            t += s.rng.range(60.0, 120.0);
        }
    }
}

/// Directory brute-forcing with a generic wordlist (no well-known probe paths).
fn dirbuster(s: &mut Sim, from: f64) {
    const WORDS: [&str; 20] = [
        "admin", "backup", "old", "new", "test", "dev", "staging", "private", "secret", "tmp",
        "files", "uploads", "download", "data", "db", "logs", "conf", "portal", "internal", "beta",
    ];
    const SUFFIX: [&str; 6] = ["", "1", "2", "_old", "-dev", "/"];
    let ip = s.rng.public_ip();
    let actor = format!("ip:{ip}");
    let w = Who {
        actor: &actor,
        ip: &ip,
        p: CURL,
        label: true,
        scenario: "attack: directory brute-force (120 paths)",
    };
    let mut t = from;
    for word in WORDS {
        for suf in SUFFIX {
            s.push(&w, t, "GET", format!("/{word}{suf}"), 404);
            t += s.rng.range(0.2, 1.0);
        }
    }
}

// ------------------------------------------------------------------ unseen variants

fn stealth_stuffing(s: &mut Sim, from: f64, to: f64) {
    for _ in 0..400 {
        let ip = if s.rng.chance(0.3) {
            s.rng.carrier_ip()
        } else {
            s.rng.public_ip()
        };
        let actor = format!("ip:{ip}");
        let w = Who {
            actor: &actor,
            ip: &ip,
            p: CHROME_WIN,
            label: true,
            scenario: "attack: stealth stuffing, Chrome fp [unseen]",
        };
        let mut t = from + s.rng.range(0.0, 240.0);
        while t < to {
            s.push(&w, t, "GET", "/login", 200);
            t += s.rng.range(3.0, 8.0);
            let st = if s.rng.chance(0.03) { 302 } else { 401 };
            s.push(&w, t, "POST", "/login", st);
            t += s.rng.range(120.0, 240.0);
        }
    }
}

fn browser_flood(s: &mut Sim, from: f64, to: f64) {
    for i in 0..800 {
        let ip = s.rng.public_ip();
        let actor = format!("ip:{ip}");
        let p = [CHROME_WIN, CHROME_MAC, SAFARI_IOS][i % 3];
        let w = Who {
            actor: &actor,
            ip: &ip,
            p,
            label: true,
            scenario: "attack: L7 flood on /, browser fp [unseen]",
        };
        let mut t = from + s.rng.range(0.0, 3.0);
        while t < to {
            s.push(&w, t, "GET", "/", 200);
            t += s.rng.range(1.5, 2.5);
        }
    }
}

fn random_scraper(s: &mut Sim, from: f64, to: f64) {
    let ip = s.rng.public_ip();
    let actor = format!("ip:{ip}");
    let w = Who {
        actor: &actor,
        ip: &ip,
        p: CHROME_WIN,
        label: true,
        scenario: "attack: random-order scraper, Chrome fp [unseen]",
    };
    let mut t = from;
    while t < to {
        let id = s.rng.int(1, 50_000);
        let st = if id > 5000 || s.rng.chance(0.03) {
            404
        } else {
            200
        };
        s.push(&w, t, "GET", format!("/product/{id}"), st);
        t += s.rng.range(2.5, 4.0);
    }
}

const SCAN2_PATHS: [&str; 30] = [
    "/admin/config.json",
    "/.git/HEAD",
    "/api/.env",
    "/wp-content/debug.log",
    "/storage/logs/laravel.log",
    "/.vscode/sftp.json",
    "/config/database.yml",
    "/.npmrc",
    "/docker-compose.yml",
    "/api/v1/admin",
    "/backup.sql",
    "/.env.production",
    "/phpinfo.php",
    "/admin.php",
    "/administrator/",
    "/user/login",
    "/wp-json/wp/v2/users",
    "/.well-known/openid-configuration",
    "/api/graphql",
    "/metrics",
    "/v2/_catalog",
    "/containers/json",
    "/_cat/indices",
    "/solr/admin/cores",
    "/druid/index.html",
    "/nacos/",
    "/geoserver/web/",
    "/remote/login",
    "/cgi-bin/luci",
    "/dana-na/",
];

fn scanner2(s: &mut Sim, from: f64) {
    let ip = s.rng.public_ip();
    let actor = format!("ip:{ip}");
    let w = Who {
        actor: &actor,
        ip: &ip,
        p: PYTHON,
        label: true,
        scenario: "attack: different scanner, 30 paths [unseen]",
    };
    let mut t = from;
    for path in SCAN2_PATHS {
        s.push(&w, t, "GET", path, 404);
        t += s.rng.range(0.3, 3.0);
    }
}

/// Generates `hours` consecutive hours of traffic, sorted by time (seconds from 0).
pub fn generate(seed: u64, hours: u32, unseen: bool) -> Vec<Rec> {
    let mut all = Vec::new();
    for h in 0..hours {
        let mut s = Sim {
            rng: Rng::new(seed.wrapping_add(h as u64 * 7919)),
            dur: 3600.0,
            out: Vec::new(),
        };
        let d = s.dur;
        shoppers(&mut s, "legit: shoppers", 0.0, d, 20.0);
        office_nat(&mut s);
        casual(&mut s);
        dashboard(&mut s);
        partner_api(&mut s);
        mobile_app(&mut s);
        uptime(&mut s);

        // Attack and spike windows shift each hour so the model doesn't learn clock times.
        let j = s.rng.range(-0.05, 0.05);
        let k = s.rng.range(0.0, 0.8);
        viral_link(&mut s, k * d, (k + 0.1) * d);
        let k2 = s.rng.range(0.0, 0.85);
        login_rush(&mut s, k2 * d, (k2 + 0.08) * d);
        cred_stuffing(&mut s, (0.17 + j) * d, (0.37 + j) * d);
        slow_scraper(&mut s, (0.25 + j) * d, d);
        rotating_scraper(&mut s, (0.33 + j) * d, (0.53 + j) * d);
        single_flood(&mut s, (0.50 + j) * d, (0.517 + j) * d);
        distributed_flood(&mut s, (0.58 + j) * d, (0.75 + j) * d);
        vuln_scan(&mut s, (0.67 + j) * d);
        browser_stuffing(&mut s, (0.78 + j) * d, (0.95 + j) * d);
        dirbuster(&mut s, (0.12 + j) * d);
        let k3 = s.rng.range(0.05, 0.9);
        fresh_endpoint_flood(&mut s, k3 * d, (k3 + 0.015) * d);

        if unseen {
            shoppers(
                &mut s,
                "legit: flash-sale traffic spike [unseen]",
                0.45 * d,
                0.55 * d,
                2.0,
            );
            stealth_stuffing(&mut s, 0.40 * d, 0.65 * d);
            browser_flood(&mut s, 0.80 * d, 0.87 * d);
            random_scraper(&mut s, 0.08 * d, 0.92 * d);
            scanner2(&mut s, 0.85 * d);
        }
        for r in &mut s.out {
            r.t += h as f64 * 3600.0;
        }
        all.append(&mut s.out);
    }
    all.sort_by(|a, b| a.t.total_cmp(&b.t));
    all
}

pub const EPOCH: f64 = 1_700_000_000.0;

pub fn to_event(r: &Rec) -> pattern_guard::Event {
    use std::time::{Duration, SystemTime};
    pattern_guard::Event::new(
        r.actor.clone(),
        r.method,
        r.path.clone(),
        SystemTime::UNIX_EPOCH + Duration::from_secs_f64(EPOCH + r.t),
    )
    .with_ip(r.ip.parse().unwrap())
    .with_user_agent(r.ua)
    .with_fingerprint(r.fp)
}

pub fn to_json(r: &Rec) -> String {
    serde_json::json!({
        "ts": EPOCH + r.t,
        "actor": r.actor,
        "ip": r.ip,
        "method": r.method,
        "path": r.path,
        "status": r.status,
        "ua": r.ua,
        "fp": r.fp,
        "label": r.label as u8,
        "scenario": r.scenario,
    })
    .to_string()
}
