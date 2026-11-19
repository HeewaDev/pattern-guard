//! URL analysis for server-side request forgery and remote file inclusion.
//!
//! Finds URLs (and bare host names) in a value, normalises the host the way URL
//! parsers and `inet_aton` would (Unicode look-alike digits, decimal / hex / octal
//! and shortened IPv4 forms, IPv4-mapped IPv6), then classifies the address.
//! Obfuscated IP notation is never typed by legitimate users; internal addresses
//! and names are what SSRF targets.

use std::net::{Ipv4Addr, Ipv6Addr};

use regex::Regex;

/// Parameter names that PHP applications have historically used to include files
/// (CRS 931110).
const RFI_PARAMS: &[&str] = &[
    "mosconfig_absolute_path",
    "_conf[path]",
    "_server[document_root]",
    "gallery_basedir",
    "path[docroot]",
    "appserv_root",
    "config[root_dir]",
];

/// Host names that resolve to the local machine, a container host or a cluster.
const INTERNAL_SUFFIXES: &[&str] = &[
    ".localdomain",
    ".localdomain4",
    ".localdomain6",
    ".internal",
    ".cluster.local",
    ".localtest.me",
    ".lvh.me",
    ".localhost",
];
const INTERNAL_NAMES: &[&str] = &[
    "localhost",
    "localhost4",
    "localhost6",
    "ip6-localhost",
    "ipv6-localhost",
    "ip6-loopback",
    "ipv6-loopback",
    "localtest.me",
    "lvh.me",
];
const METADATA_NAMES: &[&str] = &[
    "metadata.google.internal",
    "metadata.packet.net",
    "metadata.azure.com",
    "instance-data",
    "instance-data.ec2.internal",
];

pub(crate) struct Ssrf {
    url: Regex,
    bare_host: Regex,
    script: Regex,
}

impl Ssrf {
    pub(crate) fn new() -> Self {
        Self {
            // scheme, optional slashes, authority (bracketed IPv6 or up to / ? # space)
            url: Regex::new(r"(?:^|[^a-z0-9+.\-])([a-z][a-z0-9+.\-_]{1,20}):(/{0,3})(\[[^\]\s]{1,80}\][^/?#\s]*|[^/?#\s\[]{1,255})([^\s]*)").unwrap(),
            // a value that is only a host (optionally :port and path): `localhost/`
            bare_host: Regex::new(r"^([a-z0-9][a-z0-9.\-]{0,252})(:\d{1,5})?(/\S*)?$").unwrap(),
            script: Regex::new(r"\.(php\d?|phtml|txt|sh|pl|py|asp|aspx|jsp|cgi|inc)(\?.*)?$").unwrap(),
        }
    }

    /// Indicators for one decoded, lowercased value. `param` is the parameter name
    /// when known.
    pub(crate) fn scan(&self, value: &str, param: Option<&str>) -> Vec<(&'static str, f64)> {
        let mut out = Vec::new();
        let mut push = |name: &'static str, w: f64| {
            if !out.iter().any(|(n, _)| *n == name) {
                out.push((name, w));
            }
        };
        let v = fold_lookalikes(value);
        let v = v.trim();
        let whole_value_is_url = !v.contains(' ');
        let mut found_url = false;
        // `http://good.com &@good.com# @127.0.0.1/`: parsers disagree on which host
        // is meant when the authority holds `@` together with spaces or `#`
        if let Some(i) = v.find("://") {
            let authority = v[i + 3..].split('/').next().unwrap_or("");
            // (e-mail addresses in user agents have a word right before their `@`)
            let b = authority.as_bytes();
            if b.windows(2)
                .any(|w| w[1] == b'@' && matches!(w[0], b' ' | b'&' | b'#'))
            {
                push("url_parser_confusion", 7.0);
            }
        }

        for c in self.url.captures_iter(v) {
            let scheme = &c[1];
            let slashes = c[2].len();
            if !is_url_scheme(scheme) {
                continue;
            }
            // `http:2852039166` and `http:/x` are accepted by lenient parsers;
            // other schemes need `//` to be URLs rather than prose ("note:").
            if slashes < 2 && !matches!(scheme, "http" | "https" | "ftp") {
                continue;
            }
            found_url = true;
            let mut authority = c[3].replace('\\', "");
            let rest = &c[4];
            // parser confusion: several `@`, or a fragment / space before the user part
            if authority.matches('@').count() > 1 || (authority.contains('@') && rest.contains('@'))
            {
                push("url_parser_confusion", 7.0);
            }
            if let Some(i) = authority.rfind('@') {
                authority = authority[i + 1..].to_string();
            }
            let host = strip_port(&authority);
            self.classify_host(host, true, whole_value_is_url, &mut push);

            // remote file inclusion: URL to a raw IP that ends in a script, or with a
            // trailing `?` that cuts off the suffix the application appends
            if matches!(scheme, "http" | "https" | "ftp" | "ftps") {
                let raw_ip = host.parse::<Ipv4Addr>().is_ok() || host.starts_with('[');
                if raw_ip && whole_value_is_url {
                    push("rfi_ip_url", 5.0);
                }
                if raw_ip && self.script.is_match(rest) {
                    push("rfi_remote_script", 3.0);
                }
                if whole_value_is_url && rest.ends_with('?') && rest.len() > 1 {
                    push("rfi_trailing_question_mark", 4.0);
                }
                if let Some(p) = param {
                    if RFI_PARAMS.contains(&p) {
                        push("rfi_known_parameter", 7.0);
                    }
                }
            }
        }
        // a bare host name as the whole value (`url=localhost/`)
        if !found_url {
            // A bare number may be an order id: numeric IP notations need a scheme.
            // A bare name needs a port or path (`localhost/`), not just `localhost`.
            if let Some(c) = self.bare_host.captures(v) {
                let host = &c[1];
                let plain_ip = host.parse::<Ipv4Addr>().is_ok();
                let numeric = host
                    .chars()
                    .all(|c| c.is_ascii_hexdigit() || c == '.' || c == 'x');
                let has_tail = c.get(2).is_some() || c.get(3).is_some();
                if has_tail && (plain_ip || !numeric) {
                    self.classify_host(host, false, true, &mut push);
                }
            }
        }
        out
    }

    fn classify_host(
        &self,
        host: &str,
        is_url: bool,
        whole_value: bool,
        push: &mut impl FnMut(&'static str, f64),
    ) {
        let host = host.trim_end_matches('.');
        if host.is_empty() {
            return;
        }
        // where the request would go, and whether the notation is unusual
        let (addr, obfuscated) = if let Some(inner) = host.strip_prefix('[') {
            let inner = inner.split(']').next().unwrap_or("");
            let inner = inner.split('%').next().unwrap_or(""); // zone id
            match inner.parse::<Ipv6Addr>() {
                Ok(a6) => match a6.to_ipv4_mapped() {
                    Some(a4) => (Some(a4), true),
                    None => {
                        let seg = a6.segments();
                        // loopback, unspecified, link-local (fe80::/10), unique local (fc00::/7)
                        if a6.is_loopback()
                            || a6.is_unspecified()
                            || (seg[0] & 0xffc0) == 0xfe80
                            || (seg[0] & 0xfe00) == 0xfc00
                        {
                            push("ssrf_internal_address", 7.0);
                        } else if whole_value {
                            push("ssrf_ipv6_literal", 4.0);
                        }
                        return;
                    }
                },
                Err(_) => return,
            }
        } else {
            match parse_ipv4_lenient(host) {
                Some((a, unusual)) => (Some(a), unusual),
                None => (None, false),
            }
        };
        if let Some(a) = addr {
            if obfuscated {
                push("ssrf_obfuscated_ip", 7.0);
            }
            if is_metadata(a) {
                push("ssrf_cloud_metadata", 8.0);
            } else if is_internal(a) && (whole_value || obfuscated) {
                push("ssrf_internal_address", 7.0);
            }
            return;
        }
        // names
        if !host.contains('.') && !INTERNAL_NAMES.contains(&host) && !is_url {
            return;
        }
        if METADATA_NAMES.contains(&host) {
            push("ssrf_cloud_metadata", 8.0);
        } else if INTERNAL_NAMES.contains(&host)
            || host.starts_with("localhost")
            || INTERNAL_SUFFIXES.iter().any(|s| host.ends_with(s))
        {
            push("ssrf_internal_name", if whole_value { 7.0 } else { 4.0 });
        }
    }
}

fn is_url_scheme(s: &str) -> bool {
    matches!(
        s,
        "http"
            | "https"
            | "ftp"
            | "ftps"
            | "sftp"
            | "ssh"
            | "telnet"
            | "gopher"
            | "dict"
            | "ldap"
            | "ldaps"
            | "tftp"
            | "imap"
            | "imaps"
            | "pop3"
            | "pop3s"
            | "smtp"
            | "irc"
            | "rtmp"
            | "rtsp"
            | "acap"
            | "ws"
            | "wss"
            | "jar"
            | "netdoc"
            | "local_file"
            | "redis"
            | "mysql"
            | "smb"
    )
}

fn strip_port(authority: &str) -> &str {
    if authority.starts_with('[') {
        return authority;
    }
    match authority.rsplit_once(':') {
        Some((h, p)) if p.chars().all(|c| c.is_ascii_digit()) => h,
        _ => authority,
    }
}

/// `inet_aton` rules: 1–4 parts, each decimal, `0x` hex or `0` octal; the last part
/// fills the remaining bytes. Returns the address and whether the notation is
/// anything other than plain dotted decimal.
fn parse_ipv4_lenient(host: &str) -> Option<(Ipv4Addr, bool)> {
    if host.parse::<Ipv4Addr>().is_ok() {
        return host.parse().ok().map(|a| (a, false));
    }
    let parts: Vec<&str> = host.split('.').collect();
    if parts.is_empty() || parts.len() > 4 || parts.iter().any(|p| p.is_empty()) {
        return None;
    }
    let mut nums = Vec::with_capacity(4);
    for p in &parts {
        let n = if let Some(h) = p.strip_prefix("0x") {
            // `0x41414141a9fea9fe`: some parsers keep only the low 32 bits
            let h = if h.len() > 8 { &h[h.len() - 8..] } else { h };
            u64::from_str_radix(h, 16).ok()?
        } else if p.len() > 1 && p.starts_with('0') {
            u64::from_str_radix(p, 8).ok()?
        } else {
            p.parse::<u64>().ok()?
        };
        nums.push(n);
    }
    let last = *nums.last()?;
    let head = &nums[..nums.len() - 1];
    if head.iter().any(|&n| n > 255) {
        return None;
    }
    let shift = 8 * (4 - head.len() as u32);
    if shift < 32 && last >= (1u64 << shift) {
        return None;
    }
    if last > u32::MAX as u64 {
        return None;
    }
    let mut v: u32 = 0;
    for (i, &n) in head.iter().enumerate() {
        v |= (n as u32) << (24 - 8 * i as u32);
    }
    v |= last as u32;
    // a single small decimal number is just a number, not an address
    if parts.len() == 1 && last < (1 << 24) {
        return None;
    }
    Some((Ipv4Addr::from(v), true))
}

fn is_metadata(a: Ipv4Addr) -> bool {
    let o = a.octets();
    a == Ipv4Addr::new(169, 254, 169, 254)
        || a == Ipv4Addr::new(100, 100, 100, 200)
        || a == Ipv4Addr::new(192, 0, 0, 192)
        || (o[0] == 169 && o[1] == 254 && o[2] == 170 && o[3] == 2)
}

fn is_internal(a: Ipv4Addr) -> bool {
    let o = a.octets();
    a.is_loopback()
        || a.is_private()
        || a.is_link_local()
        || a.is_unspecified()
        || o[0] == 0
        || (o[0] == 100 && (64..128).contains(&o[1]))
        || (o[0] == 192 && o[1] == 0 && o[2] == 0)
}

/// Maps characters that URL parsers fold to ASCII (IDNA / NFKC): circled and
/// full-width digits and letters, ideographic and full-width dots.
fn fold_lookalikes(s: &str) -> String {
    if s.is_ascii() {
        return s.to_string();
    }
    s.chars()
        .map(|c| {
            let u = c as u32;
            match u {
                0x2460..=0x2468 => char::from(b'1' + (u - 0x2460) as u8),
                0x24ea => '0',
                0x24d0..=0x24e9 => char::from(b'a' + (u - 0x24d0) as u8),
                0x24b6..=0x24cf => char::from(b'a' + (u - 0x24b6) as u8),
                0xff10..=0xff19 => char::from(b'0' + (u - 0xff10) as u8),
                0xff41..=0xff5a => char::from(b'a' + (u - 0xff41) as u8),
                0xff21..=0xff3a => char::from(b'a' + (u - 0xff21) as u8),
                0x3002 | 0xff0e | 0xff61 => '.',
                _ => c,
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn score(s: &Ssrf, v: &str) -> f64 {
        s.scan(v, None).iter().map(|(_, w)| w).sum()
    }

    #[test]
    fn obfuscated_and_internal_targets_score_high() {
        let s = Ssrf::new();
        for v in [
            "http://2852039166/",
            "http://0xa9.0xfe.0xa9.0xfe/",
            "http://0xa9fea9fe/",
            "http://0x41414141a9fea9fe/",
            "http://0251.0376.0251.0376/",
            "http://169.254.43518/",
            "http://169.16689662/",
            "http://[::ffff:a9fe:a9fe]",
            "http://[0:0:0:0:0:ffff:a9fe:a9fe]",
            "ssh://0177.00.00.01",
            "rtmp://017700000001",
            "http:2852039166",
            "http:/2852039166",
            "http://169。254。169。254/",
            "acap://①②⑦.⓪.⓪.①",
            "irc://ⓛⓞⓒⓐⓛⓗⓞⓢⓣ",
            "http://[::]/",
            "http://[fe80::%zone1]",
            "http://localhost/",
            "http://127.0.0.1:8080/admin",
            "localhost/",
            "host.docker.internal/",
            "kubernetes.default.svc.cluster.local/",
            "lvh.me/",
            "https://metadata.packet.net/userdata",
            "http://192.0.0.192/latest/user-data/",
            "http:127.0.0.1",
            "http://google.com:80 &@google.com:80# @127.88.23.245:22/",
            "http://\\l\\o\\c\\a\\l\\h\\o\\s\\t/",
            "http://66.240.183.75/crash.php",
        ] {
            assert!(score(&s, v) >= 7.0, "{v}: {:?}", s.scan(v, None));
        }
        assert!(
            s.scan("https://foo.bar", Some("_conf[path]"))
                .iter()
                .any(|(n, _)| *n == "rfi_known_parameter")
        );
    }

    #[test]
    fn ordinary_urls_and_text_stay_low() {
        let s = Ssrf::new();
        for v in [
            "https://example.com/page?id=1",
            "http://www.google.com/search?q=rust",
            "note: call me at 12345678",
            "see http://127.0.0.1:7878 in your browser to test the server",
            "mailto:someone@example.com",
            "localhost is where i test",
            "https://8.8.8.8",
            "http://user@example.com/",
            "version 1.2.3.4 released",
            "12345678901",
            "2852039166",
            "0x41414141a9fea9fe",
            "localhost",
            "https://[2001:db8::1]:443/x is documented",
            "buzzbot/1.0 (buzzbot; http://www.buzzstream.com; buzzbot@buzzstream.com)",
            "amibot - http://www.amidalla.de - tech@amidalla.com libwww-perl/5.831",
        ] {
            assert!(score(&s, v) < 7.0, "{v}: {:?}", s.scan(v, None));
        }
    }
}
