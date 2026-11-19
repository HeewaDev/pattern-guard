//! Minimal IPv4/IPv6 CIDR matching.

use std::net::IpAddr;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cidr {
    addr: IpAddr,
    prefix: u8,
}

impl Cidr {
    /// Parses `1.2.3.0/24`, `2001:db8::/32` or a bare address.
    pub fn parse(s: &str) -> Option<Self> {
        let s = s.trim();
        let (a, p) = match s.split_once('/') {
            Some((a, p)) => (a, Some(p)),
            None => (s, None),
        };
        let addr: IpAddr = a.parse().ok()?;
        let max = if addr.is_ipv4() { 32 } else { 128 };
        let prefix = match p {
            Some(p) => p.parse::<u8>().ok().filter(|p| *p <= max)?,
            None => max,
        };
        Some(Self { addr, prefix })
    }

    pub fn contains(&self, ip: IpAddr) -> bool {
        match (self.addr, normalize(ip)) {
            (IpAddr::V4(n), IpAddr::V4(i)) => {
                let mask = if self.prefix == 0 {
                    0
                } else {
                    u32::MAX << (32 - self.prefix)
                };
                u32::from(n) & mask == u32::from(i) & mask
            }
            (IpAddr::V6(n), IpAddr::V6(i)) => {
                let mask = if self.prefix == 0 {
                    0
                } else {
                    u128::MAX << (128 - self.prefix)
                };
                u128::from(n) & mask == u128::from(i) & mask
            }
            _ => false,
        }
    }

    pub fn is_single(&self) -> bool {
        self.prefix == if self.addr.is_ipv4() { 32 } else { 128 }
    }

    pub fn addr(&self) -> IpAddr {
        self.addr
    }
}

/// Maps IPv4-mapped IPv6 (`::ffff:1.2.3.4`) to IPv4.
pub fn normalize(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(ip),
        v4 => v4,
    }
}

pub fn any_contains(list: &[Cidr], ip: IpAddr) -> bool {
    list.iter().any(|c| c.contains(ip))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matching() {
        let c = Cidr::parse("10.1.0.0/16").unwrap();
        assert!(c.contains("10.1.200.3".parse().unwrap()));
        assert!(!c.contains("10.2.0.1".parse().unwrap()));
        assert!(c.contains("::ffff:10.1.2.3".parse().unwrap()));
        let v6 = Cidr::parse("2001:db8::/32").unwrap();
        assert!(v6.contains("2001:db8:1::9".parse().unwrap()));
        assert!(Cidr::parse("1.2.3.4").unwrap().is_single());
        assert!(Cidr::parse("1.2.3.4/33").is_none());
        assert!(Cidr::parse("nope").is_none());
        assert!(
            Cidr::parse("0.0.0.0/0")
                .unwrap()
                .contains("8.8.8.8".parse().unwrap())
        );
    }
}
