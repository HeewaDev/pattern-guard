//! Path → route template (`/product/123?x=1` → `/product/{n}`), object-id extraction,
//! and a small list of well-known vulnerability-scanner probe paths.

use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Normalized {
    /// Route template with ids replaced by placeholders and the query string removed.
    pub template: String,
    /// Last fully numeric path segment, if any (used for enumeration / novelty signals).
    pub id: Option<u64>,
}

pub fn normalize_path(path: &str) -> Normalized {
    let path = path.split(['?', '#']).next().unwrap_or("");
    let mut template = String::with_capacity(path.len());
    let mut id = None;
    for (i, seg) in path.split('/').enumerate() {
        if i > 0 {
            template.push('/');
        }
        if seg.is_empty() {
            continue;
        }
        if seg.len() <= 19 && seg.bytes().all(|b| b.is_ascii_digit()) {
            template.push_str("{n}");
            id = seg.parse().ok();
        } else if is_uuid(seg) {
            template.push_str("{uuid}");
        } else if seg.len() >= 16 && seg.bytes().all(|b| b.is_ascii_hexdigit()) {
            template.push_str("{hex}");
        } else if seg.len() >= 24 && seg.bytes().any(|b| b.is_ascii_digit()) {
            template.push_str("{token}");
        } else if seg.bytes().any(|b| b.is_ascii_digit()) {
            let mut in_digits = false;
            for c in seg.chars() {
                if c.is_ascii_digit() {
                    if !in_digits {
                        template.push_str("{n}");
                    }
                    in_digits = true;
                } else {
                    in_digits = false;
                    template.push(c);
                }
            }
        } else {
            template.push_str(seg);
        }
    }
    if template.is_empty() {
        template.push('/');
    }
    Normalized { template, id }
}

fn is_uuid(s: &str) -> bool {
    s.len() == 36
        && s.bytes().enumerate().all(|(i, b)| match i {
            8 | 13 | 18 | 23 => b == b'-',
            _ => b.is_ascii_hexdigit(),
        })
}

pub fn hash_str(parts: &[&str]) -> u64 {
    let mut h = DefaultHasher::new();
    for p in parts {
        p.hash(&mut h);
    }
    h.finish()
}

/// Substrings that legitimate users essentially never request but scanners always do.
const PROBE_PATTERNS: &[&str] = &[
    "/.env",
    "/.git/",
    "/.git",
    "/.svn",
    "/.hg/",
    "/.aws/",
    "/.ssh/",
    "/.ds_store",
    "/.htaccess",
    "/.htpasswd",
    "/wp-admin",
    "/wp-login",
    "/wp-content/",
    "/wp-includes/",
    "/xmlrpc.php",
    "/phpmyadmin",
    "/pma/",
    "/phpinfo",
    "/info.php",
    "/shell.php",
    "/cmd.php",
    "/eval-stdin.php",
    "/phpunit",
    "/cgi-bin/",
    "/etc/passwd",
    "/proc/self",
    "../",
    "..%2f",
    "%2e%2e",
    "/web.config",
    "/server-status",
    "/actuator/",
    "/manager/html",
    "/hnap1",
    "/boaform",
    "/owa/",
    "/autodiscover",
    "/solr/",
    "/jenkins",
    "/console/",
    "/druid/",
    "/telescope/",
    "/_profiler",
    ".sql",
    ".bak",
    "/backup.zip",
    "/backup.tar",
    "/config.json",
    "/config.php",
    "/setup.php",
    "/install.php",
    "/laravel.log",
    "/debug.log",
];

pub fn is_probe_path(path: &str, extra: &[String]) -> bool {
    let lower = path.to_ascii_lowercase();
    PROBE_PATTERNS.iter().any(|p| lower.contains(p))
        || extra
            .iter()
            .any(|p| lower.contains(&p.to_ascii_lowercase()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn templates_numeric_ids_and_strips_query() {
        let n = normalize_path("/product/123?ref=home");
        assert_eq!(n.template, "/product/{n}");
        assert_eq!(n.id, Some(123));
        assert_eq!(normalize_path("/search?q=shoes").template, "/search");
        assert_eq!(normalize_path("/").template, "/");
        assert_eq!(normalize_path("").template, "/");
    }

    #[test]
    fn templates_uuid_hex_and_mixed() {
        assert_eq!(
            normalize_path("/u/123e4567-e89b-12d3-a456-426614174000/x").template,
            "/u/{uuid}/x"
        );
        assert_eq!(normalize_path("/f/deadbeefdeadbeef00").template, "/f/{hex}");
        assert_eq!(
            normalize_path("/img/1001_3.jpg").template,
            "/img/{n}_{n}.jpg"
        );
        assert_eq!(normalize_path("/api/v2/items").template, "/api/v{n}/items");
    }

    #[test]
    fn probe_paths() {
        assert!(is_probe_path("/.env", &[]));
        assert!(is_probe_path("/WP-ADMIN/install", &[]));
        assert!(is_probe_path("/static/../../etc/passwd", &[]));
        assert!(!is_probe_path("/product/12", &[]));
        assert!(is_probe_path("/secret-admin", &["/secret-admin".into()]));
    }
}
