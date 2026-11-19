//! Data-leak inspection of upstream responses (the ideas of OWASP CRS 95x and
//! open-appsec's error-disclosure checks): database errors, stack traces, verbose
//! framework error pages, directory listings and private keys.

use hyper::header::HeaderMap;
use regex::RegexSet;

use crate::config::{LeakAction, ResponseInspectionConfig};

const SIGNATURES: &[(&str, &str)] = &[
    (
        "sql_error",
        r"(?i)you have an error in your sql syntax|warning:\s*mysqli?_|mysqli_sql_exception|sqlstate\[\w+\]|\bora-\d{5}\b|pg::\w+error|psycopg2\.(errors|operationalerror)|org\.postgresql\.util\.psqlexception|unclosed quotation mark after the character string|microsoft ole db provider for|sqlite3?[:.](sqlexception|operationalerror)|com\.mysql\.jdbc|activerecord::statementinvalid",
    ),
    (
        "php_error",
        r"(?i)<b>(fatal error|parse error|warning|notice)</b>:.{0,300}? on line <b>\d+</b>|php (fatal error|parse error|warning):|stack trace:\s*#0 ",
    ),
    (
        "java_stacktrace",
        r"\bat (java|javax|jakarta|org\.springframework|org\.apache|org\.hibernate)\.[\w.$]+\([\w$]+\.java:\d+\)",
    ),
    ("python_traceback", r"Traceback \(most recent call last\):"),
    (
        "dotnet_error",
        r"(?i)server error in '/[^']*' application|asp\.net is configured to show verbose error messages|system\.(nullreferenceexception|invalidoperationexception|data\.sqlclient\.sqlexception)",
    ),
    (
        "node_stacktrace",
        r"\n\s+at [\w.<>$\[\] ]+ \((/|[A-Za-z]:\\)[^)]+\.(js|mjs|cjs|ts):\d+:\d+\)",
    ),
    (
        "directory_listing",
        r"(?i)<title>index of /|<h1>directory listing for /",
    ),
    (
        "private_key",
        r"-----BEGIN (RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----",
    ),
    ("aws_access_key", r"\b(AKIA|ASIA)[0-9A-Z]{16}\b"),
];

pub struct LeakInspector {
    set: RegexSet,
    pub max_bytes: usize,
    content_types: Vec<String>,
    pub action: LeakAction,
}

impl LeakInspector {
    /// `None` when inspection is disabled.
    pub fn new(cfg: &ResponseInspectionConfig) -> Option<Self> {
        if !cfg.enabled {
            return None;
        }
        Some(Self {
            set: RegexSet::new(SIGNATURES.iter().map(|(_, p)| *p))
                .expect("leak signatures compile"),
            max_bytes: cfg.max_bytes.max(1024),
            content_types: cfg
                .content_types
                .iter()
                .map(|c| c.to_ascii_lowercase())
                .collect(),
            action: cfg.action,
        })
    }

    /// Inspect this response? (text-like content type, not compressed)
    pub fn should_inspect(&self, h: &HeaderMap) -> bool {
        let ct = h
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_ascii_lowercase();
        let encoded = h
            .get("content-encoding")
            .and_then(|v| v.to_str().ok())
            .is_some_and(|e| !e.eq_ignore_ascii_case("identity"));
        !encoded
            && self
                .content_types
                .iter()
                .any(|t| ct.starts_with(t.as_str()))
    }

    /// Name of the first matching leak signature.
    pub fn scan(&self, body: &[u8]) -> Option<&'static str> {
        let text = String::from_utf8_lossy(body);
        self.set
            .matches(&text)
            .into_iter()
            .next()
            .map(|i| SIGNATURES[i].0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyper::header::HeaderValue;

    fn inspector() -> LeakInspector {
        let cfg = crate::config::GatewayConfig::from_toml_str(
            "upstream = \"http://127.0.0.1:1\"\n[response_inspection]\nenabled = true\n",
        )
        .unwrap();
        LeakInspector::new(&cfg.response_inspection).unwrap()
    }

    #[test]
    fn detects_real_world_leaks() {
        let i = inspector();
        let cases = [
            (
                "sql_error",
                "<p>You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version</p>",
            ),
            (
                "sql_error",
                "SQLSTATE[42S22]: Column not found: 1054 Unknown column",
            ),
            ("sql_error", "ORA-00933: SQL command not properly ended"),
            (
                "php_error",
                "<b>Fatal error</b>:  Uncaught Error: Call to undefined function foo() in /var/www/index.php on line <b>12</b>",
            ),
            (
                "java_stacktrace",
                "java.lang.NullPointerException\n\tat org.springframework.web.servlet.DispatcherServlet.doDispatch(DispatcherServlet.java:1067)",
            ),
            (
                "python_traceback",
                "Traceback (most recent call last):\n  File \"app.py\", line 3",
            ),
            ("dotnet_error", "<h1>Server Error in '/' Application.</h1>"),
            (
                "node_stacktrace",
                "TypeError: x is undefined\n    at Object.handler (/srv/app/routes/user.js:42:13)",
            ),
            (
                "directory_listing",
                "<html><head><title>Index of /backups</title>",
            ),
            ("private_key", "-----BEGIN RSA PRIVATE KEY-----\nMIIE..."),
            ("aws_access_key", "aws_access_key_id = AKIAIOSFODNN7EXAMPLE"),
        ];
        for (want, body) in cases {
            assert_eq!(i.scan(body.as_bytes()), Some(want), "{body}");
        }
    }

    #[test]
    fn ordinary_pages_pass() {
        let i = inspector();
        for body in [
            "<html><title>Shop</title><p>Welcome back! Your order #4512 shipped.</p>",
            "{\"items\":[{\"id\":1,\"name\":\"Index of products\"}]}",
            "<p>Learn SQL: SELECT * FROM users WHERE id = 1</p>",
            "<p>Our Java tutorial covers exceptions and stack traces.</p>",
        ] {
            assert_eq!(i.scan(body.as_bytes()), None, "{body}");
        }
    }

    #[test]
    fn only_uncompressed_text_is_inspected() {
        let i = inspector();
        let mut h = HeaderMap::new();
        h.insert(
            "content-type",
            HeaderValue::from_static("text/html; charset=utf-8"),
        );
        assert!(i.should_inspect(&h));
        h.insert("content-encoding", HeaderValue::from_static("gzip"));
        assert!(!i.should_inspect(&h));
        let mut img = HeaderMap::new();
        img.insert("content-type", HeaderValue::from_static("image/png"));
        assert!(!i.should_inspect(&img));
    }
}
