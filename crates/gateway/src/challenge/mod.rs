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
use std::time::{SystemTime, UNIX_EPOCH};

use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};

type HmacSha256 = Hmac<Sha256>;

pub const COOKIE: &str = "pg_clearance";
pub const VERIFY_PATH: &str = "/.pattern-guard/verify";
/// How long a served challenge may take to solve.
const CHALLENGE_TTL: u64 = 300;

pub struct Challenger {
    secret: Vec<u8>,
    pub difficulty: u32,
    pub ttl_secs: u64,
}

pub fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
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

fn unhex(s: &str) -> Option<Vec<u8>> {
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
        let secret = unhex(secret_hex)
            .filter(|s| s.len() >= 16)
            .unwrap_or_else(|| random_bytes().to_vec());
        Self {
            secret,
            difficulty,
            ttl_secs,
        }
    }

    fn mac(&self, parts: &[&str]) -> HmacSha256 {
        let mut m = HmacSha256::new_from_slice(&self.secret).expect("any key length");
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

/// The challenge page; `__NONCE__`-style placeholders are filled per request.
const CHALLENGE_HTML: &str = include_str!("page.html");

#[cfg(test)]
mod tests {
    use super::*;

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
