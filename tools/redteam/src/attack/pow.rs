//! Solving the gateway's proof-of-work challenge the way a bot would: read the puzzle from
//! the challenge page, find a counter whose SHA-256 has enough leading zero bits, and
//! fetch the clearance cookie from the verify endpoint.

use sha2::{Digest, Sha256};

/// The puzzle in a challenge page: `var N="…",E=…,D=…,S="…"`.
#[derive(Debug, Clone, PartialEq)]
pub struct Puzzle {
    pub nonce: String,
    pub expires: String,
    pub difficulty: u32,
    pub sig: String,
}

fn between<'a>(s: &'a str, start: &str, end: &str) -> Option<&'a str> {
    let i = s.find(start)? + start.len();
    let j = s[i..].find(end)? + i;
    Some(&s[i..j])
}

pub fn parse(page: &str) -> Option<Puzzle> {
    let vars = &page[page.find("var N=\"")?..];
    Some(Puzzle {
        nonce: between(vars, "var N=\"", "\"")?.to_string(),
        expires: between(vars, ",E=", ",")?.to_string(),
        difficulty: between(vars, ",D=", ",")?.parse().ok()?,
        sig: between(vars, ",S=\"", "\"")?.to_string(),
    })
}

fn leading_zero_bits(h: &[u8]) -> u32 {
    let mut n = 0;
    for b in h {
        if *b == 0 {
            n += 8;
        } else {
            return n + b.leading_zeros();
        }
    }
    n
}

/// The first counter that solves the puzzle (2^difficulty hashes on average). Gives up
/// after 2^28 tries (difficulty is at most a few dozen bits in practice).
pub fn solve(p: &Puzzle) -> Option<u64> {
    (0u64..1 << 28).find(|c| {
        let h = Sha256::digest(format!("{}:{c}", p.nonce).as_bytes());
        leading_zero_bits(&h) >= p.difficulty
    })
}

/// The verify request that returns the clearance cookie (`j=1`: 204 instead of a redirect).
pub fn verify_target(p: &Puzzle, counter: u64) -> String {
    format!(
        "/.pattern-guard/verify?n={}&e={}&d={}&s={}&c={counter}&j=1",
        p.nonce, p.expires, p.difficulty, p.sig
    )
}

/// `name=value` from a `Set-Cookie` header.
pub fn cookie_pair(set_cookie: &str) -> Option<String> {
    let pair = set_cookie.split(';').next()?.trim();
    pair.contains('=').then(|| pair.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_and_solves_a_page() {
        let page = "<script>…var N=\"abc123\",E=1700000000,D=8,S=\"ff00\",R=\"/\",c=0;</script>";
        let p = parse(page).unwrap();
        assert_eq!(p.nonce, "abc123");
        assert_eq!(p.difficulty, 8);
        let c = solve(&p).unwrap();
        let h = Sha256::digest(format!("abc123:{c}").as_bytes());
        assert!(leading_zero_bits(&h) >= 8);
        assert!(
            verify_target(&p, c)
                .starts_with("/.pattern-guard/verify?n=abc123&e=1700000000&d=8&s=ff00&c=")
        );
        assert_eq!(parse("<html>no puzzle</html>"), None);
        assert_eq!(
            cookie_pair("pg_clearance=1.2.3; Path=/; HttpOnly").as_deref(),
            Some("pg_clearance=1.2.3")
        );
    }
}
