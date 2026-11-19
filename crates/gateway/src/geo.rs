//! IP → country lookup from a `start_ip,end_ip,country_code` CSV (DB-IP Lite format,
//! IPv4 and IPv6), and the country access policy.

use std::net::IpAddr;
use std::path::Path;

use crate::config::GeoConfig;
use crate::ipnet::normalize;

pub struct GeoDb {
    v4: Vec<(u32, u32, [u8; 2])>,
    v6: Vec<(u128, u128, [u8; 2])>,
}

fn code(s: &str) -> Option<[u8; 2]> {
    let b = s.trim().trim_matches('"').as_bytes();
    (b.len() == 2 && b.iter().all(u8::is_ascii_alphabetic))
        .then(|| [b[0].to_ascii_uppercase(), b[1].to_ascii_uppercase()])
}

impl GeoDb {
    pub fn load(path: &Path) -> Result<Self, String> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| format!("geo: cannot read {}: {e}", path.display()))?;
        Self::parse(&text)
    }

    pub fn parse(text: &str) -> Result<Self, String> {
        let mut db = GeoDb {
            v4: Vec::new(),
            v6: Vec::new(),
        };
        for (n, line) in text.lines().enumerate() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let mut f = line.split(',');
            let (Some(a), Some(b), Some(c)) = (f.next(), f.next(), f.next()) else {
                return Err(format!("geo: line {}: expected start,end,country", n + 1));
            };
            let parse = |s: &str| s.trim().trim_matches('"').parse::<IpAddr>().ok();
            let (Some(start), Some(end), Some(cc)) = (parse(a), parse(b), code(c)) else {
                if n == 0 {
                    continue; // header row
                }
                return Err(format!("geo: line {}: bad entry", n + 1));
            };
            match (start, end) {
                (IpAddr::V4(s), IpAddr::V4(e)) => db.v4.push((s.into(), e.into(), cc)),
                (IpAddr::V6(s), IpAddr::V6(e)) => db.v6.push((s.into(), e.into(), cc)),
                _ => return Err(format!("geo: line {}: mixed IP versions", n + 1)),
            }
        }
        db.v4.sort_unstable_by_key(|r| r.0);
        db.v6.sort_unstable_by_key(|r| r.0);
        Ok(db)
    }

    pub fn len(&self) -> usize {
        self.v4.len() + self.v6.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Two-letter country code, if the IP is in a known range.
    pub fn lookup(&self, ip: IpAddr) -> Option<&str> {
        fn find<T: Ord + Copy>(ranges: &[(T, T, [u8; 2])], x: T) -> Option<&[u8; 2]> {
            let i = ranges.partition_point(|r| r.0 <= x);
            let r = ranges.get(i.checked_sub(1)?)?;
            (x <= r.1).then_some(&r.2)
        }
        let cc = match normalize(ip) {
            IpAddr::V4(v) => find(&self.v4, u32::from(v)),
            IpAddr::V6(v) => find(&self.v6, u128::from(v)),
        }?;
        std::str::from_utf8(cc).ok()
    }
}

/// What the country policy says about a request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GeoVerdict {
    Block,
    Challenge,
}

pub struct GeoPolicy {
    deny: Vec<String>,
    challenge: Vec<String>,
    allow: Vec<String>,
}

impl GeoPolicy {
    pub fn new(cfg: &GeoConfig) -> Self {
        let up = |l: &[String]| l.iter().map(|c| c.to_ascii_uppercase()).collect();
        Self {
            deny: up(&cfg.deny_countries),
            challenge: up(&cfg.challenge_countries),
            allow: up(&cfg.allow_countries),
        }
    }

    pub fn verdict(&self, country: Option<&str>) -> Option<GeoVerdict> {
        let c = country?;
        if self.deny.iter().any(|d| d == c)
            || (!self.allow.is_empty() && !self.allow.iter().any(|a| a == c))
        {
            Some(GeoVerdict::Block)
        } else if self.challenge.iter().any(|d| d == c) {
            Some(GeoVerdict::Challenge)
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CSV: &str = "\"ip_start\",\"ip_end\",\"country\"\n1.0.0.0,1.0.0.255,AU\n5.0.0.0,5.255.255.255,de\n203.0.113.0,203.0.113.255,XX\n2001:db8::,2001:db8:ffff:ffff:ffff:ffff:ffff:ffff,NL\n";

    #[test]
    fn lookups() {
        let db = GeoDb::parse(CSV).unwrap();
        assert_eq!(db.len(), 4);
        let l = |s: &str| db.lookup(s.parse().unwrap());
        assert_eq!(l("1.0.0.7"), Some("AU"));
        assert_eq!(l("5.9.1.1"), Some("DE"));
        assert_eq!(l("1.0.1.0"), None);
        assert_eq!(l("0.0.0.1"), None);
        assert_eq!(l("2001:db8::5"), Some("NL"));
        assert_eq!(l("::ffff:5.1.2.3"), Some("DE"), "IPv4-mapped");
        assert!(GeoDb::parse("1.0.0.0,1.0.0.255\n").is_err());
    }

    #[test]
    fn policy() {
        let cfg = |toml: &str| {
            crate::config::GatewayConfig::from_toml_str(&format!(
                "upstream = \"http://127.0.0.1:1\"\n[geo]\n{toml}"
            ))
            .unwrap()
            .geo
        };
        let p = GeoPolicy::new(&cfg(
            "deny_countries = [\"xx\"]\nchallenge_countries = [\"DE\"]\n",
        ));
        assert_eq!(p.verdict(Some("XX")), Some(GeoVerdict::Block));
        assert_eq!(p.verdict(Some("DE")), Some(GeoVerdict::Challenge));
        assert_eq!(p.verdict(Some("AU")), None);
        let only = GeoPolicy::new(&cfg("allow_countries = [\"AU\", \"NL\"]\n"));
        assert_eq!(only.verdict(Some("DE")), Some(GeoVerdict::Block));
        assert_eq!(only.verdict(Some("AU")), None);
        assert_eq!(
            only.verdict(None),
            None,
            "unknown / private IPs are not blocked"
        );
    }
}
