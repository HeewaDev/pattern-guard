//! Walks a request (path, query, headers, cookies, body) and scores every value.

use std::collections::BTreeMap;

use regex::{Regex, RegexSet};

use crate::decode::{decode, percent_decode};
use crate::indicators::AttackClass::{self, *};
use crate::indicators::indicators;

/// One suspicious value.
#[derive(Debug, Clone)]
pub struct Finding {
    pub class: AttackClass,
    /// 0–10.
    pub score: f64,
    /// Where it was found: `path`, `query:id`, `body:comment`, `json:user.name`, `header:user-agent`, `cookie:sid`.
    pub location: String,
    pub indicators: Vec<&'static str>,
    /// Decoded value (truncated) for the log.
    pub sample: String,
}

#[derive(Debug, Clone, Default)]
pub struct Inspection {
    pub findings: Vec<Finding>,
}

impl Inspection {
    pub fn max_score(&self) -> f64 {
        self.findings.iter().map(|f| f.score).fold(0.0, f64::max)
    }

    pub fn top(&self) -> Option<&Finding> {
        self.findings
            .iter()
            .max_by(|a, b| a.score.total_cmp(&b.score))
    }
}

/// What the inspector needs from a request.
pub struct HttpRequest<'a> {
    pub path_and_query: &'a str,
    pub headers: &'a [(String, String)],
    pub content_type: Option<&'a str>,
    pub body: &'a [u8],
}

pub struct Inspector {
    set: RegexSet,
    meta: Vec<(AttackClass, &'static str, f64)>,
    jndi_only: Vec<bool>,
    comments: Regex,
    lookups: Regex,
    /// Findings below this score are dropped.
    pub min_score: f64,
    /// Longest value inspected (bytes); longer values are truncated.
    pub max_value_len: usize,
}

impl Default for Inspector {
    fn default() -> Self {
        Self::new()
    }
}

impl Inspector {
    pub fn new() -> Self {
        let ind = indicators();
        let set = RegexSet::new(ind.iter().map(|i| format!("(?s){}", i.pattern)))
            .expect("WAF patterns compile");
        Self {
            set,
            meta: ind.iter().map(|i| (i.class, i.name, i.weight)).collect(),
            jndi_only: ind.iter().map(|i| i.class == JndiInjection).collect(),
            comments: Regex::new(r"(?s)/\*.*?\*/").unwrap(),
            // Log4j lookup obfuscation: ${lower:j} ${upper:j} ${::-j} ${env:X:-j} → j
            lookups: Regex::new(r"\$\{\s*(?:lower|upper|::-|[a-z]*:[^:}$]*:-)\s*:?([^}$]*)\}")
                .unwrap(),
            min_score: 3.0,
            max_value_len: 8192,
        }
    }

    /// Scores one value. `form` = `+` means space (query strings, form bodies).
    /// Returns the strongest finding, if any reaches `min_score`.
    pub fn inspect_value(&self, location: &str, raw: &str, form: bool) -> Option<Finding> {
        self.inspect_value_filtered(location, raw, form, false)
    }

    fn inspect_value_filtered(
        &self,
        location: &str,
        raw: &str,
        form: bool,
        jndi_only: bool,
    ) -> Option<Finding> {
        if raw.is_empty() {
            return None;
        }
        let raw = truncate(raw, self.max_value_len);
        let decoded = decode(raw, form);
        let mut scores: BTreeMap<AttackClass, (f64, Vec<&'static str>)> = BTreeMap::new();
        let mut add = |class, name, w| {
            let e = scores.entry(class).or_insert((0.0, Vec::new()));
            if !e.1.contains(&name) {
                e.0 += w;
                e.1.push(name);
            }
        };

        let mut resolved = decoded.clone();
        for _ in 0..3 {
            let next = self.lookups.replace_all(&resolved, "$1").into_owned();
            if next == resolved {
                break;
            }
            resolved = next;
        }
        let variants = [
            self.comments.replace_all(&decoded, "").into_owned(),
            self.comments.replace_all(&decoded, " ").into_owned(),
            resolved,
            decoded.clone(),
        ];
        for v in &variants {
            for idx in self.set.matches(v).into_iter() {
                if jndi_only && !self.jndi_only[idx] {
                    continue;
                }
                let (class, name, w) = self.meta[idx];
                add(class, name, w);
            }
        }
        if !jndi_only {
            // Binary upload bodies legitimately contain NUL bytes; parameters never should.
            if location != "body"
                && (decoded.contains('\0') || raw.to_ascii_lowercase().contains("%00"))
            {
                add(PathTraversal, "null_byte", 7.0);
            }
            let lower_raw = raw.to_ascii_lowercase();
            if [
                "%2e%2e", "%252e", "..%2f", "..%5c", "%c0%ae", "%c0%af", ".%2e", "%2e.",
            ]
            .iter()
            .any(|p| lower_raw.contains(p))
            {
                add(PathTraversal, "encoded_traversal", 3.0);
            }
            if decoded.contains("/*!") {
                add(SqlInjection, "versioned_comment", 4.0);
            } else if decoded.contains("/*") && decoded.contains("*/") {
                add(SqlInjection, "inline_comment", 2.0);
            }
        }

        let (class, (score, inds)) = scores.into_iter().max_by(|a, b| a.1.0.total_cmp(&b.1.0))?;
        let score = score.min(10.0);
        if score < self.min_score {
            return None;
        }
        Some(Finding {
            class,
            score,
            location: location.to_string(),
            indicators: inds,
            sample: truncate(&decoded, 160).to_string(),
        })
    }

    /// Inspects path, query parameters, cookies, user agent, referer, other headers
    /// (Log4Shell lookups only) and the body (form, JSON, XML, text, multipart).
    pub fn inspect(&self, req: &HttpRequest) -> Inspection {
        let mut out = Inspection::default();
        let mut push = |f: Option<Finding>| {
            if let Some(f) = f {
                out.findings.push(f);
            }
        };
        let (path, query) = match req.path_and_query.split_once('?') {
            Some((p, q)) => (p, Some(q)),
            None => (req.path_and_query, None),
        };
        push(self.inspect_value("path", path, false));
        if let Some(q) = query {
            for (k, v) in form_pairs(q) {
                push(self.inspect_value("query-name", k, true));
                push(self.inspect_value(&format!("query:{}", decode_name(k)), v, true));
            }
        }
        for (name, value) in req.headers {
            let n = name.to_ascii_lowercase();
            match n.as_str() {
                "user-agent" | "referer" | "x-forwarded-host" | "x-original-url"
                | "x-rewrite-url" => push(self.inspect_value(&format!("header:{n}"), value, false)),
                "cookie" => {
                    for part in value.split(';') {
                        let (k, v) = part.split_once('=').unwrap_or(("", part));
                        push(self.inspect_value(&format!("cookie:{}", k.trim()), v.trim(), true));
                    }
                }
                _ => push(self.inspect_value_filtered(&format!("header:{n}"), value, false, true)),
            }
        }
        if !req.body.is_empty() {
            let ct = req.content_type.unwrap_or("").to_ascii_lowercase();
            let text = String::from_utf8_lossy(req.body);
            if ct.starts_with("application/x-www-form-urlencoded") {
                for (k, v) in form_pairs(&text) {
                    push(self.inspect_value("body-name", k, true));
                    push(self.inspect_value(&format!("body:{}", decode_name(k)), v, true));
                }
            } else if ct.contains("json") {
                match serde_json::from_str::<serde_json::Value>(&text) {
                    Ok(v) => self.walk_json(&v, "json", &mut out.findings, 0),
                    Err(_) => push(self.inspect_value("body", &text, false)),
                }
            } else if ct.contains("xml")
                || ct.starts_with("text/")
                || ct.starts_with("multipart/")
                || ct.is_empty()
            {
                push(self.inspect_value("body", &text, false));
            }
        }
        out
    }

    fn walk_json(&self, v: &serde_json::Value, path: &str, out: &mut Vec<Finding>, depth: usize) {
        if depth > 32 {
            return;
        }
        match v {
            serde_json::Value::String(s) => {
                if let Some(f) = self.inspect_value(path, s, false) {
                    out.push(f);
                }
            }
            serde_json::Value::Array(a) => {
                for (i, x) in a.iter().enumerate().take(1000) {
                    self.walk_json(x, &format!("{path}[{i}]"), out, depth + 1);
                }
            }
            serde_json::Value::Object(m) => {
                for (k, x) in m.iter().take(1000) {
                    if let Some(f) = self.inspect_value(&format!("{path}-key"), k, false) {
                        out.push(f);
                    }
                    self.walk_json(x, &format!("{path}.{k}"), out, depth + 1);
                }
            }
            _ => {}
        }
    }
}

fn truncate(s: &str, max: usize) -> &str {
    if s.len() <= max {
        return s;
    }
    let mut end = max;
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
}

fn form_pairs(s: &str) -> impl Iterator<Item = (&str, &str)> {
    s.split('&')
        .filter(|p| !p.is_empty())
        .map(|p| p.split_once('=').unwrap_or((p, "")))
}

fn decode_name(k: &str) -> String {
    let d = percent_decode(k, true);
    truncate(&d, 64).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn locations_and_body_types() {
        let w = Inspector::new();
        let headers = vec![
            ("User-Agent".to_string(), "Mozilla/5.0".to_string()),
            (
                "X-Api-Version".to_string(),
                "${jndi:ldap://x/a}".to_string(),
            ),
            (
                "Cookie".to_string(),
                "sid=abc; pref=%27%20OR%20%271%27%3D%271".to_string(),
            ),
        ];
        let body = br#"{"user": {"name": "<script>alert(1)</script>", "$where": "1"}}"#;
        let r = w.inspect(&HttpRequest {
            path_and_query: "/search?q=shoes&id=1%20UNION%20SELECT%201,2--",
            headers: &headers,
            content_type: Some("application/json"),
            body,
        });
        let locs: Vec<(&str, &str)> = r
            .findings
            .iter()
            .filter(|f| f.score >= 7.0)
            .map(|f| (f.location.as_str(), f.class.as_str()))
            .collect();
        assert!(locs.contains(&("query:id", "sql_injection")), "{locs:?}");
        assert!(
            locs.contains(&("header:x-api-version", "jndi_injection")),
            "{locs:?}"
        );
        assert!(locs.contains(&("cookie:pref", "sql_injection")), "{locs:?}");
        assert!(locs.contains(&("json.user.name", "xss")), "{locs:?}");
        assert!(
            locs.contains(&("json.user-key", "nosql_injection")),
            "{locs:?}"
        );
        assert!(!locs.iter().any(|(l, _)| *l == "query:q"));
    }

    #[test]
    fn other_headers_only_checked_for_jndi() {
        let w = Inspector::new();
        let headers = vec![(
            "Accept".to_string(),
            "text/html,*/*;q=0.8' or '1'='1".to_string(),
        )];
        let r = w.inspect(&HttpRequest {
            path_and_query: "/",
            headers: &headers,
            content_type: None,
            body: b"",
        });
        assert!(r.findings.is_empty());
    }
}
