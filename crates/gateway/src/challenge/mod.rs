//! Proof-of-work bot challenge with HMAC-signed, IP-bound clearance cookies.
//!
//! 1. The gateway serves a page containing a signed challenge `(nonce, expiry, difficulty)`.
//! 2. The browser finds `counter` such that `sha256(nonce ":" counter)` starts with
//!    `difficulty` zero bits (pure-JS SHA-256, so it also works on plain HTTP).
//! 3. `GET /.pattern-guard/verify` checks the signature, expiry and work, then sets
//!    `pg_clearance=<expiry>.<hmac(ip, expiry)>` and redirects back.
//!
//! Costs a browser a fraction of a second once per `ttl_secs`; costs a bot farm CPU on
//! every IP, and headless clients without JavaScript cannot pass at all.

use std::collections::hash_map::RandomState;
use std::hash::{BuildHasher, Hasher};
use std::net::IpAddr;
use std::sync::OnceLock;
use std::time::{SystemTime, UNIX_EPOCH};

use hmac::{Hmac, Mac};
use hyper::header::HeaderMap;
use sha2::{Digest, Sha256};

use crate::util::now_secs;

type HmacSha256 = Hmac<Sha256>;

pub const COOKIE: &str = "pg_clearance";
pub const VERIFY_PATH: &str = "/.pattern-guard/verify";
/// How long a served challenge may take to solve.
const CHALLENGE_TTL: u64 = 300;

pub struct Challenger {
    /// The HMAC key: `challenge.secret`, else 32 random bytes made on first use, unless
    /// persisted state supplied the previous run's key first (`restore_secret`).
    secret: OnceLock<Vec<u8>>,
    /// The key is `challenge.secret` (and is never persisted).
    configured: bool,
    pub difficulty: u32,
    pub ttl_secs: u64,
}

/// 32 bytes from the OS-seeded `RandomState` hasher plus time — no extra dependency.
fn random_bytes() -> [u8; 32] {
    let mut out = [0u8; 32];
    for chunk in out.chunks_mut(8) {
        let mut h = RandomState::new().build_hasher();
        h.write_u128(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0),
        );
        h.write_usize(chunk.as_ptr() as usize);
        chunk.copy_from_slice(&h.finish().to_le_bytes());
    }
    out
}

pub fn hex(b: &[u8]) -> String {
    use std::fmt::Write;
    b.iter()
        .fold(String::with_capacity(b.len() * 2), |mut s, x| {
            let _ = write!(s, "{x:02x}");
            s
        })
}

pub(crate) fn unhex(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(s.get(i..i + 2)?, 16).ok())
        .collect()
}

pub fn leading_zero_bits(hash: &[u8]) -> u32 {
    let mut bits = 0;
    for b in hash {
        if *b == 0 {
            bits += 8;
        } else {
            bits += b.leading_zeros();
            break;
        }
    }
    bits
}

pub struct Issued {
    pub nonce: String,
    pub expires: u64,
    pub difficulty: u32,
    pub sig: String,
}

impl Challenger {
    pub fn new(secret_hex: &str, difficulty: u32, ttl_secs: u64) -> Self {
        let secret = OnceLock::new();
        let configured = match unhex(secret_hex).filter(|s| s.len() >= 16) {
            Some(key) => secret.set(key).is_ok(),
            None => false,
        };
        Self {
            secret,
            configured,
            difficulty,
            ttl_secs,
        }
    }

    /// This challenger with `other`'s key, so the challenges and clearance cookies `other`
    /// issued stay valid (a reload that keeps `challenge.secret`, including an empty one,
    /// whose generated or restored key carries over).
    pub fn with_key_of(mut self, other: &Challenger) -> Self {
        self.secret = OnceLock::from(other.key().to_vec());
        self.configured = other.configured;
        self
    }

    fn key(&self) -> &[u8] {
        self.secret.get_or_init(|| random_bytes().to_vec())
    }

    /// The key when it was generated (no usable `challenge.secret`), for persistence; a
    /// configured key is `None`, so it is never written anywhere.
    pub fn generated_secret(&self) -> Option<&[u8]> {
        (!self.configured).then(|| self.key())
    }

    /// Uses `key` (the previous run's generated key, from persisted state) instead of
    /// generating one, so clearance cookies survive a restart. Refused (`false`) when
    /// the key is configured, already in use, or shorter than 16 bytes.
    pub fn restore_secret(&self, key: &[u8]) -> bool {
        !self.configured && key.len() >= 16 && self.secret.set(key.to_vec()).is_ok()
    }

    fn mac(&self, parts: &[&str]) -> HmacSha256 {
        let mut m = HmacSha256::new_from_slice(self.key()).expect("any key length");
        for (i, p) in parts.iter().enumerate() {
            if i > 0 {
                m.update(b"|");
            }
            m.update(p.as_bytes());
        }
        m
    }

    pub fn issue(&self, ip: IpAddr) -> Issued {
        let nonce = hex(&random_bytes()[..16]);
        let expires = now_secs() + CHALLENGE_TTL;
        let difficulty = self.difficulty;
        let sig = hex(&self
            .mac(&[
                "c",
                &ip.to_string(),
                &nonce,
                &expires.to_string(),
                &difficulty.to_string(),
            ])
            .finalize()
            .into_bytes());
        Issued {
            nonce,
            expires,
            difficulty,
            sig,
        }
    }

    /// Verifies a solution; returns the `Set-Cookie` value on success.
    pub fn verify(
        &self,
        ip: IpAddr,
        nonce: &str,
        expires: u64,
        difficulty: u32,
        sig: &str,
        counter: &str,
    ) -> Option<String> {
        if expires < now_secs() || difficulty < self.difficulty || counter.len() > 20 {
            return None;
        }
        let sig = unhex(sig)?;
        self.mac(&[
            "c",
            &ip.to_string(),
            nonce,
            &expires.to_string(),
            &difficulty.to_string(),
        ])
        .verify_slice(&sig)
        .ok()?;
        let hash = Sha256::digest(format!("{nonce}:{counter}").as_bytes());
        if leading_zero_bits(&hash) < difficulty {
            return None;
        }
        Some(self.clearance_cookie(ip))
    }

    pub fn clearance_cookie(&self, ip: IpAddr) -> String {
        let exp = now_secs() + self.ttl_secs;
        let tag = hex(&self
            .mac(&["k", &ip.to_string(), &exp.to_string()])
            .finalize()
            .into_bytes());
        format!(
            "{COOKIE}={exp}.{tag}; Path=/; Max-Age={}; HttpOnly; SameSite=Lax",
            self.ttl_secs
        )
    }

    /// True if the request's Cookie header carries a valid clearance for `ip`.
    pub fn has_clearance(&self, ip: IpAddr, cookie_header: Option<&str>) -> bool {
        let Some(h) = cookie_header else { return false };
        h.split(';').any(|c| {
            let Some(v) = c
                .trim()
                .strip_prefix(COOKIE)
                .and_then(|r| r.strip_prefix('='))
            else {
                return false;
            };
            let Some((exp, tag)) = v.split_once('.') else {
                return false;
            };
            let (Ok(exp_n), Some(tag)) = (exp.parse::<u64>(), unhex(tag)) else {
                return false;
            };
            exp_n >= now_secs()
                && self
                    .mac(&["k", &ip.to_string(), exp])
                    .verify_slice(&tag)
                    .is_ok()
        })
    }

    pub fn page(&self, ip: IpAddr, return_to: &str) -> String {
        self.render(ip, return_to, "")
    }

    /// The challenge page for a challenged browser form POST (see [`resubmission`]): once
    /// solved, it fetches the clearance cookie and sends the form again, so the user is not
    /// stuck. Field names and values are HTML-escaped.
    pub fn page_resubmit(&self, ip: IpAddr, action: &str, fields: &[(String, String)]) -> String {
        let mut form = format!(
            "<form id=\"pg-resubmit\" method=\"post\" action=\"{}\" hidden>",
            html_escape(safe_return(action))
        );
        for (name, value) in fields {
            form.push_str(&format!(
                "<input type=\"hidden\" name=\"{}\" value=\"{}\">",
                html_escape(name),
                html_escape(value)
            ));
        }
        form.push_str("</form>");
        self.render(ip, action, &form)
    }

    fn render(&self, ip: IpAddr, return_to: &str, form: &str) -> String {
        let c = self.issue(ip);
        // JSON string literal, with <, >, & escaped so it can't close the <script> element.
        let rt = serde_json::to_string(safe_return(return_to))
            .unwrap_or_else(|_| "\"/\"".into())
            .replace('<', "\\u003c")
            .replace('>', "\\u003e")
            .replace('&', "\\u0026");
        CHALLENGE_HTML
            .replace("__NONCE__", &c.nonce)
            .replace("__EXPIRES__", &c.expires.to_string())
            .replace("__DIFFICULTY__", &c.difficulty.to_string())
            .replace("__SIG__", &c.sig)
            .replace("__RETURN__", &rt)
            .replace("__VERIFY__", VERIFY_PATH)
            // last, so placeholder-like text in a reflected field is never substituted
            .replace("__FORM__", form)
    }
}

/// Only same-site relative paths, so `r=` can't be used as an open redirect.
pub fn safe_return(r: &str) -> &str {
    if r.starts_with('/')
        && !r.starts_with("//")
        && !r.starts_with("/\\")
        && !r.contains(['\r', '\n'])
    {
        r
    } else {
        "/"
    }
}

/// The fields of a challenged browser POST that may be sent again after the proof of work:
/// a same-origin `application/x-www-form-urlencoded` form of at most 16 KiB and 200
/// fields. A cross-site POST is never re-sent from this origin: that would turn it into a
/// same-site request and defeat `SameSite` cookies and `Origin` checks (CSRF).
pub fn resubmission(
    headers: &HeaderMap,
    method: &hyper::Method,
    body: &[u8],
) -> Option<Vec<(String, String)>> {
    let ct = headers
        .get("content-type")?
        .to_str()
        .ok()?
        .to_ascii_lowercase();
    if method != hyper::Method::POST
        || !ct.starts_with("application/x-www-form-urlencoded")
        || body.len() > 16 * 1024
        || !same_origin(headers)
    {
        return None;
    }
    let text = std::str::from_utf8(body).ok()?;
    let fields: Vec<(String, String)> = text
        .split('&')
        .filter(|p| !p.is_empty())
        .map(|p| {
            let (k, v) = p.split_once('=').unwrap_or((p, ""));
            (crate::util::form_decode(k), crate::util::form_decode(v))
        })
        .collect();
    (fields.len() <= 200).then_some(fields)
}

/// Where a challenged browser POST that can't be re-sent returns after the proof of work:
/// the page it came from when that page is on this origin (the user submits again), else `/`.
pub fn return_after_post(headers: &HeaderMap) -> String {
    let referer = headers.get("referer").and_then(|v| v.to_str().ok());
    match referer.filter(|_| same_origin(headers)) {
        Some(r) => {
            let rest = r.split_once("://").map_or("", |(_, rest)| rest);
            let path = rest.find('/').map_or("/", |i| &rest[i..]);
            safe_return(path).to_string()
        }
        None => "/".to_string(),
    }
}

/// Whether the browser says the request came from this origin: `Sec-Fetch-Site:
/// same-origin`, else an `Origin`, else a `Referer`, whose host equals `Host`.
pub fn same_origin(headers: &HeaderMap) -> bool {
    let get = |n: &str| headers.get(n).and_then(|v| v.to_str().ok());
    if let Some(site) = get("sec-fetch-site") {
        return site.eq_ignore_ascii_case("same-origin");
    }
    let Some(host) = get("host").map(str::to_ascii_lowercase) else {
        return false;
    };
    let host_of = |u: &str| {
        u.split_once("://").map(|(_, rest)| {
            rest.split(['/', '?', '#'])
                .next()
                .unwrap_or("")
                .to_ascii_lowercase()
        })
    };
    match get("origin") {
        Some(o) => host_of(o).as_deref() == Some(host.as_str()),
        None => get("referer").and_then(host_of).as_deref() == Some(host.as_str()),
    }
}

fn html_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            c => out.push(c),
        }
    }
    out
}

/// The challenge page; `__NONCE__`-style placeholders are filled per request.
const CHALLENGE_HTML: &str = include_str!("page.html");

#[cfg(test)]
mod tests {
    use super::*;

    fn headers(pairs: &[(&str, &str)]) -> HeaderMap {
        let mut h = HeaderMap::new();
        for (k, v) in pairs {
            h.append(
                hyper::header::HeaderName::from_bytes(k.as_bytes()).unwrap(),
                v.parse().unwrap(),
            );
        }
        h
    }

    #[test]
    fn generated_keys_can_be_restored_configured_ones_never_leave() {
        let ip: IpAddr = "192.0.2.60".parse().unwrap();
        let first = Challenger::new("", 8, 3600);
        let cookie = first.clearance_cookie(ip);
        let key = first.generated_secret().unwrap().to_vec();
        assert_eq!(key.len(), 32);
        let header = cookie.split(';').next().unwrap().to_string(); // pg_clearance=<exp>.<tag>
        // the next run: a fresh random key would reject the cookie, the restored one accepts it
        let fresh = Challenger::new("", 8, 3600);
        assert!(!fresh.has_clearance(ip, Some(&header)));
        let next = Challenger::new("", 8, 3600);
        assert!(next.restore_secret(&key));
        assert!(next.has_clearance(ip, Some(&header)));
        assert!(!next.restore_secret(&key), "only before the key is in use");
        assert!(
            !Challenger::new("", 8, 3600).restore_secret(&key[..8]),
            "too short"
        );

        let configured = Challenger::new(&"ab".repeat(32), 8, 3600);
        assert!(configured.generated_secret().is_none());
        assert!(!configured.restore_secret(&key));
        assert!(!configured.has_clearance(ip, Some(&header)));
    }

    #[test]
    fn only_same_origin_form_posts_are_sent_again() {
        let form = ("content-type", "application/x-www-form-urlencoded");
        let post = hyper::Method::POST;
        let body = b"user=anna&pass=p%40ss+word";
        let same = headers(&[form, ("sec-fetch-site", "same-origin")]);
        assert_eq!(
            resubmission(&same, &post, body),
            Some(vec![
                ("user".into(), "anna".into()),
                ("pass".into(), "p@ss word".into())
            ])
        );
        // origin / referer fallbacks for browsers without Sec-Fetch-Site
        let by_origin = headers(&[
            form,
            ("host", "shop.example"),
            ("origin", "https://shop.example"),
        ]);
        assert!(resubmission(&by_origin, &post, body).is_some());
        let by_referer = headers(&[
            form,
            ("host", "shop.example"),
            ("referer", "https://shop.example/login"),
        ]);
        assert!(resubmission(&by_referer, &post, body).is_some());
        // cross-site, same-site subdomains, no evidence, other methods / types / sizes: never
        for h in [
            headers(&[form, ("sec-fetch-site", "cross-site")]),
            headers(&[form, ("sec-fetch-site", "same-site")]),
            headers(&[
                form,
                ("host", "shop.example"),
                ("origin", "https://evil.example"),
            ]),
            headers(&[form, ("host", "shop.example"), ("origin", "null")]),
            headers(&[form, ("host", "shop.example")]),
        ] {
            assert!(resubmission(&h, &post, body).is_none());
        }
        assert!(resubmission(&same, &hyper::Method::PUT, body).is_none());
        let json = headers(&[
            ("content-type", "application/json"),
            ("sec-fetch-site", "same-origin"),
        ]);
        assert!(resubmission(&json, &post, b"{}").is_none());
        assert!(resubmission(&same, &post, &vec![b'a'; 17 * 1024]).is_none());
    }

    #[test]
    fn a_post_that_is_not_sent_again_returns_to_its_form_page() {
        let h = headers(&[
            ("host", "shop.example"),
            ("referer", "https://shop.example/login?next=%2Fcart"),
        ]);
        assert_eq!(return_after_post(&h), "/login?next=%2Fcart");
        let cross = headers(&[
            ("host", "shop.example"),
            ("referer", "https://evil.example/x"),
        ]);
        assert_eq!(return_after_post(&cross), "/");
    }

    #[test]
    fn reflected_fields_are_escaped_and_never_substituted() {
        let c = Challenger::new("", 4, 60);
        let fields = vec![
            ("q".to_string(), "\"><script>alert(1)</script>".to_string()),
            (
                "x\"onfocus=\"a".to_string(),
                "__RETURN__ __NONCE__ __VERIFY__".to_string(),
            ),
        ];
        let page = c.page_resubmit("203.0.113.9".parse().unwrap(), "/login?a=1&b=\"2", &fields);
        assert!(page.contains("id=\"pg-resubmit\""));
        assert!(page.contains("value=\"&quot;&gt;&lt;script&gt;alert(1)&lt;/script&gt;\""));
        assert!(page.contains("name=\"x&quot;onfocus=&quot;a\""));
        assert!(page.contains("value=\"__RETURN__ __NONCE__ __VERIFY__\""));
        assert!(page.contains("action=\"/login?a=1&amp;b=&quot;2\""));
        assert!(!page.contains("<script>alert(1)"));
        // the plain page has no form
        assert!(
            !c.page("203.0.113.9".parse().unwrap(), "/")
                .contains("id=\"pg-resubmit\"")
        );
    }

    fn solve(nonce: &str, d: u32) -> String {
        (0u64..)
            .find(|c| leading_zero_bits(&Sha256::digest(format!("{nonce}:{c}").as_bytes())) >= d)
            .unwrap()
            .to_string()
    }

    #[test]
    fn full_flow() {
        let ch = Challenger::new("", 8, 60);
        let ip: IpAddr = "203.0.113.7".parse().unwrap();
        let c = ch.issue(ip);
        let counter = solve(&c.nonce, c.difficulty);
        let cookie = ch
            .verify(ip, &c.nonce, c.expires, c.difficulty, &c.sig, &counter)
            .expect("valid solution");
        let value = cookie.split(';').next().unwrap();
        assert!(ch.has_clearance(ip, Some(&format!("a=b; {value}"))));
        // bound to the IP
        assert!(!ch.has_clearance("203.0.113.8".parse().unwrap(), Some(value)));
        // tampered signature / wrong work / other IP
        assert!(
            ch.verify(ip, &c.nonce, c.expires, c.difficulty, "00", &counter)
                .is_none()
        );
        assert!(
            ch.verify(
                "1.1.1.1".parse().unwrap(),
                &c.nonce,
                c.expires,
                c.difficulty,
                &c.sig,
                &counter
            )
            .is_none()
        );
        assert!(
            ch.verify(ip, &c.nonce, c.expires, 0, &c.sig, "0").is_none(),
            "difficulty downgrade"
        );
        assert!(!ch.has_clearance(ip, Some("pg_clearance=99999999999.00ff")));
    }

    #[test]
    fn return_path_is_sanitised() {
        assert_eq!(safe_return("/cart?x=1"), "/cart?x=1");
        assert_eq!(safe_return("//evil.example"), "/");
        assert_eq!(safe_return("https://evil.example"), "/");
        assert_eq!(safe_return("/\\evil"), "/");
    }

    #[test]
    fn zero_bits() {
        assert_eq!(leading_zero_bits(&[0, 0x0f, 0xff]), 12);
        assert_eq!(leading_zero_bits(&[0x80]), 0);
    }
}
