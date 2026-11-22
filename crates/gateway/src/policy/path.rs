//! The request path as the gateway and as the application may read it.
//!
//! Servers decode the path before routing: `%61dmin` is `admin`, `/a/../b` is `/b`,
//! `//admin` is `/admin`, `/health/..;/app` is `/app` on Tomcat and Spring, and `\` is `/`
//! on IIS. A policy that only matched the raw path could be walked around that way, while
//! the request is forwarded unchanged and the application serves the protected resource.
//!
//! Every path match therefore looks at two views, the raw path and a canonical one:
//! * a **protection** (block / challenge / delay rules, traps, rate limits, operations,
//!   logins, restricted extensions) applies when **either** view matches, ignoring ASCII
//!   case;
//! * an **exemption** (`allow` and `skip_waf` rules, `waf.exclude_paths`) applies only when
//!   **both** views match exactly, so no encoding can move a request into an exemption.
//!
//! The request is still forwarded with its original target.

use std::borrow::Cow;

use regex::Regex;

pub struct PathView<'a> {
    raw: &'a str,
    canonical: Cow<'a, str>,
}

impl<'a> PathView<'a> {
    pub fn new(raw: &'a str) -> Self {
        Self {
            raw,
            canonical: canonicalize(raw),
        }
    }

    pub fn raw(&self) -> &str {
        self.raw
    }

    pub fn canonical(&self) -> &str {
        &self.canonical
    }

    /// Protection: either view starts with `prefix`, ignoring ASCII case.
    pub fn protects_prefix(&self, prefix: &str) -> bool {
        starts_with_ci(self.raw, prefix) || starts_with_ci(&self.canonical, prefix)
    }

    /// Exemption: both views start with `prefix`, exactly.
    pub fn exempts_prefix(&self, prefix: &str) -> bool {
        self.raw.starts_with(prefix) && self.canonical.starts_with(prefix)
    }

    /// Protection: `re` matches either view (also the lower-cased canonical one).
    pub fn protects_regex(&self, re: &Regex) -> bool {
        re.is_match(self.raw)
            || re.is_match(&self.canonical)
            || (self.canonical.bytes().any(|b| b.is_ascii_uppercase())
                && re.is_match(&self.canonical.to_ascii_lowercase()))
    }

    /// Exemption: `re` matches both views.
    pub fn exempts_regex(&self, re: &Regex) -> bool {
        re.is_match(self.raw) && re.is_match(&self.canonical)
    }

    /// Protection: either view ends with `suffix`, ignoring ASCII case.
    pub fn protects_suffix(&self, suffix: &str) -> bool {
        ends_with_ci(self.raw, suffix) || ends_with_ci(&self.canonical, suffix)
    }
}

fn starts_with_ci(s: &str, p: &str) -> bool {
    s.len() >= p.len() && s.as_bytes()[..p.len()].eq_ignore_ascii_case(p.as_bytes())
}

fn ends_with_ci(s: &str, p: &str) -> bool {
    s.len() >= p.len() && s.as_bytes()[s.len() - p.len()..].eq_ignore_ascii_case(p.as_bytes())
}

/// The path a typical server routes on: percent-encoded unreserved characters decoded
/// (RFC 3986 §6.2.2.2; reserved ones such as `%2F` keep their meaning and stay encoded),
/// `\` and `%5C` as `/`, `;parameters` removed from each segment, empty and `.` segments
/// dropped, `..` resolved (RFC 3986 §5.2.4, never above the root). Ordinary paths are
/// returned as they are, without allocating.
pub fn canonicalize(raw: &str) -> Cow<'_, str> {
    let unusual = raw.bytes().any(|b| matches!(b, b'%' | b';' | b'\\'))
        || raw.contains("//")
        || raw.contains("/.");
    if !unusual || !raw.starts_with('/') {
        return Cow::Borrowed(raw);
    }
    let b = raw.as_bytes();
    let mut decoded: Vec<u8> = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'%' if i + 2 < b.len() => match (hex(b[i + 1]), hex(b[i + 2])) {
                (Some(h), Some(l)) => {
                    let c = (h << 4) | l;
                    if c.is_ascii_alphanumeric() || matches!(c, b'-' | b'.' | b'_' | b'~') {
                        decoded.push(c);
                    } else if c == b'\\' {
                        decoded.push(b'/');
                    } else {
                        decoded.extend_from_slice(&b[i..i + 3]);
                    }
                    i += 3;
                }
                _ => {
                    decoded.push(b'%');
                    i += 1;
                }
            },
            b'\\' => {
                decoded.push(b'/');
                i += 1;
            }
            c => {
                decoded.push(c);
                i += 1;
            }
        }
    }
    // Only ASCII bytes were decoded and everything else copied, so this stays UTF-8.
    let decoded = String::from_utf8_lossy(&decoded);
    let mut segments: Vec<&str> = Vec::new();
    for segment in decoded.split('/') {
        match segment.split(';').next().unwrap_or("") {
            "" | "." => {}
            ".." => {
                segments.pop();
            }
            s => segments.push(s),
        }
    }
    let mut out = String::with_capacity(decoded.len());
    for s in &segments {
        out.push('/');
        out.push_str(s);
    }
    let directory = decoded.ends_with('/') || decoded.ends_with("/.") || decoded.ends_with("/..");
    if out.is_empty() || directory {
        out.push('/');
    }
    Cow::Owned(out)
}

fn hex(c: u8) -> Option<u8> {
    (c as char).to_digit(16).map(|d| d as u8)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_paths() {
        for (raw, canonical) in [
            ("/admin/secret", "/admin/secret"),
            ("/%61dmin/secret", "/admin/secret"),
            ("/dump%2Esql", "/dump.sql"),
            ("/health/..;/app", "/app"),
            ("/health/%2e%2e/app", "/app"),
            ("//admin", "/admin"),
            ("/./admin/./x", "/admin/x"),
            ("/a/b/../../../admin", "/admin"),
            ("/admin\\secret", "/admin/secret"),
            ("/admin%5csecret", "/admin/secret"),
            ("/app;jsessionid=ABC/page", "/app/page"),
            ("/files/a%2Fb", "/files/a%2Fb"), // an encoded slash keeps its meaning
            ("/admin/", "/admin/"),
            ("/admin/.", "/admin/"),
            ("/%7Euser", "/~user"),
            ("/caf%C3%A9", "/caf%C3%A9"),
            ("/100%", "/100%"),
            ("/", "/"),
            ("*", "*"),
        ] {
            assert_eq!(canonicalize(raw), canonical, "{raw}");
        }
        assert!(matches!(
            canonicalize("/plain/path-1.html"),
            Cow::Borrowed(_)
        ));
    }

    #[test]
    fn protections_match_either_view_and_exemptions_need_both() {
        let p = PathView::new("/%61dmin/secret");
        assert!(p.protects_prefix("/admin"));
        assert!(!p.exempts_prefix("/admin"));
        let p = PathView::new("/ADMIN/secret");
        assert!(p.protects_prefix("/admin"));
        assert!(!p.exempts_prefix("/admin"));
        let p = PathView::new("/health/..;/app");
        assert!(p.protects_prefix("/health")); // raw view
        assert!(!p.exempts_prefix("/health")); // canonical is /app
        let p = PathView::new("/health/live");
        assert!(p.exempts_prefix("/health"));
        let re = Regex::new(r"^/admin(/|$)").unwrap();
        assert!(PathView::new("//Admin/x").protects_regex(&re));
        assert!(!PathView::new("/%61dmin/x").exempts_regex(&re));
        assert!(PathView::new("/dump%2ESQL").protects_suffix(".sql"));
        assert!(PathView::new("/dump.sql;x=1").protects_suffix(".sql"));
        assert!(!PathView::new("/dump.sqlite").protects_suffix(".sql"));
    }
}
