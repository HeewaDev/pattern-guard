//! Walks a request (path, query, headers, cookies, body) and scores every value.

use std::collections::BTreeMap;

use regex::{Regex, RegexSet, RegexSetBuilder};

use crate::decode::{base64_variants, decode, decode_keep_case, percent_decode};
use crate::indicators::AttackClass::{self, *};
use crate::indicators::indicators;
use crate::lexicon::Lexicons;
use crate::shell::Shell;
use crate::sql::Sql;
use crate::ssrf::Ssrf;

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
    session_names: Regex,
    lexicons: Lexicons,
    shell: Shell,
    sql: Sql,
    ssrf: Ssrf,
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
        // The set holds every indicator. With the default 2 MiB lazy-DFA cache it
        // thrashes and the regex crate falls back to its PikeVM, ~60x slower
        // (1.4 ms instead of ~20 µs per request). 16 MiB per thread leaves headroom
        // for the extra states that varied attack traffic creates.
        let set = RegexSetBuilder::new(ind.iter().map(|i| format!("(?s){}", i.pattern)))
            .dfa_size_limit(16 << 20)
            .build()
            .expect("WAF patterns compile");
        Self {
            set,
            meta: ind.iter().map(|i| (i.class, i.name, i.weight)).collect(),
            jndi_only: ind
                .iter()
                .map(|i| matches!(i.class, JndiInjection | JavaInjection))
                .collect(),
            lexicons: Lexicons::new(),
            shell: Shell::new(),
            sql: Sql::new(),
            ssrf: Ssrf::new(),
            comments: Regex::new(r"(?s)/\*.*?\*/").unwrap(),
            // session-id parameter names of common frameworks (CRS 943110 / 943120)
            session_names: Regex::new(
                r"^(jsessionid|jservsession|jwsession|aspsessionid|asp\.net_sessionid|zend_session_id|phpsessid|phpsession|play_session|weblogicsession|wlsession|rack\.session|laravel_session|next-auth\.session-token|meteor_login_token|session[-_]?id|sails\.sid|shiny-token|_session_id|_flask_session|_rails_session|cfid|cfsid|cftoken|connect\.sid|cakephp|ci_session|koa[.:]sess)$",
            )
            .unwrap(),
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
        let mut variants = vec![
            self.comments.replace_all(&decoded, "").into_owned(),
            self.comments.replace_all(&decoded, " ").into_owned(),
            resolved,
            decoded.clone(),
        ];
        // Payloads hidden in base64 (whole values or fragments).
        let kept_case = decode_keep_case(raw, form);
        variants.extend(base64_variants(&kept_case));
        for v in &variants {
            for idx in self.set.matches(v).into_iter() {
                if jndi_only && !self.jndi_only[idx] {
                    continue;
                }
                let (class, name, w) = self.meta[idx];
                add(class, name, w);
            }
        }
        // Word lists: decoded value, comment-stripped value and base64 decodings.
        let mut lexicon_inputs: Vec<&String> = vec![&decoded, &variants[0]];
        lexicon_inputs.extend(variants.iter().skip(4));
        for v in lexicon_inputs {
            for (class, name, w) in self.lexicons.scan(location, v) {
                // other headers: only header-safe classes (Log4Shell, Java)
                if !jndi_only || class == JavaInjection {
                    add(class, name, w);
                }
            }
        }
        if !jndi_only {
            // SQL structure: string / numeric breakout, whole-value expressions,
            // database functions.
            for (name, w) in self.sql.scan(&decoded) {
                add(SqlInjection, name, w);
            }
            // Shell commands: newlines kept, they separate commands.
            if location != "path" {
                for (name, w) in self.shell.scan(&kept_case.to_lowercase()) {
                    add(CommandInjection, name, w);
                }
            }
            // URLs and host names: SSRF targets and remote file inclusion.
            // (the Referer is set by browsers; `http://localhost` there is development)
            if location != "path" && location != "header:referer" {
                let param = location
                    .split_once(':')
                    .map(|(_, n)| n.rsplit('.').next().unwrap_or(n));
                for (name, w) in self.ssrf.scan(&decoded, param) {
                    let class = if name.starts_with("rfi_") {
                        RemoteFileInclusion
                    } else {
                        Ssrf
                    };
                    add(class, name, w);
                }
            }
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
        let mut names: Vec<String> = Vec::new();
        if let Some(q) = query {
            for (k, v) in form_pairs(q) {
                names.push(decode_name(k).to_ascii_lowercase());
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
                    names.push(decode_name(k).to_ascii_lowercase());
                    push(self.inspect_value("body-name", k, true));
                    push(self.inspect_value(&format!("body:{}", decode_name(k)), v, true));
                }
            } else if ct.contains("json") {
                match serde_json::from_str::<serde_json::Value>(&text) {
                    Ok(v) => {
                        if let Some(m) = v.as_object() {
                            names.extend(m.keys().take(1000).map(|k| k.to_ascii_lowercase()));
                        }
                        self.walk_json(&v, "json", &mut out.findings, 0)
                    }
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
        if let Some(f) = self.session_fixation(&names, req.headers) {
            out.findings.push(f);
        }
        out
    }

    /// A session-id parameter is how an attacker plants a known session on a victim
    /// (session fixation). Legitimate URL-rewritten sessions come from links on the
    /// same site, so the request is flagged only without a Referer or with one from
    /// another site.
    fn session_fixation(&self, names: &[String], headers: &[(String, String)]) -> Option<Finding> {
        let name = names.iter().find(|n| self.session_names.is_match(n))?;
        let header = |h: &str| {
            headers
                .iter()
                .find(|(k, _)| k.eq_ignore_ascii_case(h))
                .map(|(_, v)| v.as_str())
        };
        let host = header("host").unwrap_or("").to_ascii_lowercase();
        let host = host.split(':').next().unwrap_or("");
        let indicator = match header("referer") {
            None => "session_id_parameter_without_referer",
            Some(r) => {
                let r = r.to_ascii_lowercase();
                let referer_host = r
                    .split_once("://")
                    .map(|(_, rest)| rest.split(['/', '?', '#']).next().unwrap_or(""))
                    .unwrap_or("");
                let referer_host = referer_host.rsplit('@').next().unwrap_or("");
                let referer_host = referer_host.split(':').next().unwrap_or("");
                if host.is_empty() || referer_host.ends_with(host) {
                    return None;
                }
                "session_id_parameter_foreign_referer"
            }
        };
        Some(Finding {
            class: SessionFixation,
            score: 8.0,
            location: format!("param-name:{name}"),
            indicators: vec![indicator],
            sample: name.clone(),
        })
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
    fn server_side_code_injection_classes() {
        let w = Inspector::new();
        for (v, class) in [
            (
                "_$$ND_FUNC$$_function(){require('child_process').exec('id')}()",
                "code_injection",
            ),
            (
                "#{require.main.constructor._load('child_process').spawn('id')}",
                "code_injection",
            ),
            (
                "this.constructor.constructor('return process')()",
                "code_injection",
            ),
            ("while(!false){}", "code_injection"),
            ("@{[system 'whoami']}", "code_injection"),
            (
                "{\"then\":\"$1:__proto__:then\",\"status\":\"resolved_model\"}",
                "code_injection",
            ),
            ("__proto__[isAdmin]", "prototype_pollution"),
            ("x.constructor.prototype.polluted", "prototype_pollution"),
            (
                "#set($c=$x.class.forName('a'+'b'))#set($m=$c.getMethod('ex'+'ec'))",
                "template_injection",
            ),
        ] {
            let f = w.inspect_value("query:x", v, false).expect(v);
            assert!(f.score >= 7.0, "{v}: {f:?}");
            assert_eq!(f.class.as_str(), class, "{v}: {f:?}");
        }
    }

    #[test]
    fn session_fixation_needs_missing_or_foreign_referer() {
        let w = Inspector::new();
        let run = |referer: Option<&str>| {
            let mut headers = vec![("Host".to_string(), "shop.example.com".to_string())];
            if let Some(r) = referer {
                headers.push(("Referer".to_string(), r.to_string()));
            }
            w.inspect(&HttpRequest {
                path_and_query: "/login.php?JSESSIONID=74B0CB414BD77D17",
                headers: &headers,
                content_type: None,
                body: b"",
            })
            .findings
            .iter()
            .any(|f| f.class == SessionFixation && f.score >= 7.0)
        };
        assert!(run(None));
        assert!(run(Some("http://attacker.example.net/x")));
        assert!(!run(Some("https://shop.example.com/cart")));
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
