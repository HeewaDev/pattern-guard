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

const CHALLENGE_HTML: &str = r#"<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex"><title>Checking your browser…</title>
<style>
:root{color-scheme:light dark;--bg:#f6f7f9;--fg:#1d2330;--muted:#5b6475;--bar:#3b82f6}
@media (prefers-color-scheme:dark){:root{--bg:#11141a;--fg:#e6e9ef;--muted:#9aa3b2}}
body{margin:0;min-height:100vh;display:grid;place-items:center;background:var(--bg);color:var(--fg);font:16px/1.5 system-ui,-apple-system,Segoe UI,Roboto,sans-serif}
main{max-width:28rem;padding:2rem 1rem;text-align:center}
h1{font-size:1.25rem;margin:0 0 .5rem}p{color:var(--muted);margin:.25rem 0}
.track{height:6px;border-radius:3px;background:rgba(127,127,127,.25);overflow:hidden;margin:1.25rem 0 .5rem}
.fill{height:100%;width:0;background:var(--bar);transition:width .2s}
</style></head><body><main>
<h1>Checking that you're not a bot</h1>
<p>This takes a moment and happens once. Please keep this page open.</p>
<div class="track"><div class="fill" id="f"></div></div>
<p id="s">Working…</p>
<noscript><p>JavaScript is required to continue.</p></noscript>
</main><script>
function sha256(a){function r(v,n){return(v>>>n)|(v<<(32-n))}var p=Math.pow,M=p(2,32),o='',w=[],L=a.length*8,h=sha256.h=sha256.h||[],k=sha256.k=sha256.k||[],K=k.length,c={},i,j;for(var x=2;K<64;x++){if(!c[x]){for(i=0;i<313;i+=x)c[i]=x;h[K]=(p(x,.5)*M)|0;k[K++]=(p(x,1/3)*M)|0}}a+='\x80';while(a.length%64-56)a+='\x00';for(i=0;i<a.length;i++){j=a.charCodeAt(i);w[i>>2]|=j<<((3-i)%4)*8}w[w.length]=((L/M)|0);w[w.length]=L;for(j=0;j<w.length;){var W=w.slice(j,j+=16),O=h;h=h.slice(0,8);for(i=0;i<64;i++){var a15=W[i-15],a2=W[i-2],A=h[0],E=h[4],t1=h[7]+(r(E,6)^r(E,11)^r(E,25))+((E&h[5])^((~E)&h[6]))+k[i]+(W[i]=(i<16)?W[i]:(W[i-16]+(r(a15,7)^r(a15,18)^(a15>>>3))+W[i-7]+(r(a2,17)^r(a2,19)^(a2>>>10)))|0),t2=(r(A,2)^r(A,13)^r(A,22))+((A&h[1])^(A&h[2])^(h[1]&h[2]));h=[(t1+t2)|0].concat(h);h[4]=(h[4]+t1)|0}for(i=0;i<8;i++)h[i]=(h[i]+O[i])|0}for(i=0;i<8;i++){for(j=3;j+1;j--){var b=(h[i]>>(j*8))&255;o+=((b<16)?0:'')+b.toString(16)}}return o}
function zeros(hx){var n=0;for(var i=0;i<hx.length;i++){var v=parseInt(hx[i],16);if(v===0){n+=4;continue}n+=Math.clz32(v)-28;break}return n}
var N="__NONCE__",E=__EXPIRES__,D=__DIFFICULTY__,S="__SIG__",R=__RETURN__,c=0,exp=Math.pow(2,D),f=document.getElementById('f'),s=document.getElementById('s');
function step(){var t=Date.now();while(Date.now()-t<50){if(zeros(sha256(N+':'+c))>=D){s.textContent='Done — redirecting…';f.style.width='100%';location.replace("__VERIFY__?n="+N+"&e="+E+"&d="+D+"&s="+S+"&c="+c+"&r="+encodeURIComponent(R));return}c++}f.style.width=Math.min(95,100*c/exp)+'%';setTimeout(step,0)}
step();
</script></body></html>"#;

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
