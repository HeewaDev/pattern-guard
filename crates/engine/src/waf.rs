//! Payload inspection (web application firewall).
//!
//! Every inspected value (path, query/body parameters, JSON strings and keys, cookies,
//! selected headers) is **decoded** the way a server or browser would decode it
//! (repeated URL-decoding, `%uXXXX`, HTML entities, `\uXXXX`/`\xHH`, SQL comments,
//! case, whitespace) and then **scored**: each attack class sums the weights of the
//! indicators that matched, capped at 10. A single weak signal (an apostrophe in
//! "O'Brien", the word "select" in a sentence) stays low; combinations that only
//! appear in attacks (`' OR '1'='1`, `<img src=x onerror=…>`) score high.
//!
//! Suggested thresholds: log ≥ 4, block ≥ 7.

use std::collections::BTreeMap;

use regex::{Regex, RegexSet};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum AttackClass {
    SqlInjection,
    CrossSiteScripting,
    PathTraversal,
    CommandInjection,
    Ssrf,
    JndiInjection,
    Xxe,
    TemplateInjection,
    NoSqlInjection,
}

impl AttackClass {
    pub fn as_str(&self) -> &'static str {
        match self {
            AttackClass::SqlInjection => "sql_injection",
            AttackClass::CrossSiteScripting => "xss",
            AttackClass::PathTraversal => "path_traversal",
            AttackClass::CommandInjection => "command_injection",
            AttackClass::Ssrf => "ssrf",
            AttackClass::JndiInjection => "jndi_injection",
            AttackClass::Xxe => "xxe",
            AttackClass::TemplateInjection => "template_injection",
            AttackClass::NoSqlInjection => "nosql_injection",
        }
    }
}

use AttackClass::*;

struct Indicator {
    class: AttackClass,
    name: &'static str,
    weight: f64,
    pattern: &'static str,
}

const CMDS: &str = r"(cat|ls|id|whoami|uname|wget|curl|nc|ncat|netcat|bash|sh|zsh|ksh|powershell|pwsh|cmd|ping|nslookup|dig|python[23]?|perl|ruby|php|rm|chmod|chown|echo|printenv|env|ifconfig|ipconfig|systeminfo|tasklist|base64|telnet|ssh|scp)";
const MONGO_OPS: &str =
    r"(ne|eq|gt|gte|lt|lte|in|nin|regex|exists|where|expr|or|and|not|nor|elemmatch|function)";

fn indicators() -> Vec<Indicator> {
    let i = |class, name, weight, pattern: &'static str| Indicator {
        class,
        name,
        weight,
        pattern,
    };
    let cmd_chain: &'static str = Box::leak(
        format!(r"([;&|\n]|\$\()\s*{CMDS}(\s*$|\s*[;&|`)]|\s+[-/]|\s+(https?|ftp)://|\s+\$)")
            .into_boxed_str(),
    );
    let backtick_args: &'static str = Box::leak(format!(r"`\s*{CMDS}\s+[^`]+`").into_boxed_str());
    let backtick_bare: &'static str = Box::leak(format!(r"`\s*{CMDS}\s*`").into_boxed_str());
    let abs_cmd: &'static str =
        Box::leak(format!(r"(^|[;&|(\s])/(usr/)?s?bin/{CMDS}\b").into_boxed_str());
    let mongo_bracket: &'static str = Box::leak(
        format!(r#"\[\s*\${MONGO_OPS}\s*\]|"\${MONGO_OPS}"\s*:|^\${MONGO_OPS}$"#).into_boxed_str(),
    );
    vec![
        // ---- SQL injection ----
        i(
            SqlInjection,
            "union_select",
            8.0,
            r"\bunion(\s+(all|distinct))?\s*\(?\s*select\b",
        ),
        i(
            SqlInjection,
            "quote_tautology",
            7.0,
            r#"['"]\s*\)*\s*(or|and|\|\||&&)\s*\(*\s*['"]?\w*['"]?\s*\)*\s*(=|<>|!=|<|>|\blike\b|\bis\s+(not\s+)?(null|true|false)\b|[-*^&|+/%])"#,
        ),
        i(
            SqlInjection,
            "quote_boolean",
            4.0,
            r#"['"]\s*\)*\s*(or|and)\s+(true|false|not|\d+)\b"#,
        ),
        i(
            SqlInjection,
            "quote_block_comment",
            3.0,
            r#"['"]\s*\)*\s*/\*"#,
        ),
        i(
            SqlInjection,
            "numeric_tautology",
            7.0,
            r"\b(or|and)\s+\(*\s*(\d+|'\d+')\s*(=|<>|!=)\s*(\d+|'\d+')",
        ),
        i(
            SqlInjection,
            "quote_and_function",
            5.0,
            r#"['"]\s*\)?\s*(or|and)\s+\w+\s*\("#,
        ),
        i(
            SqlInjection,
            "quote_comment",
            4.0,
            r#"['"]\s*\)*\s*(--|#|;|/\*)"#,
        ),
        i(
            SqlInjection,
            "quote_line_comment_end",
            3.0,
            r#"['"]\s*\)*\s*(--(\s|-|$)|#\s*$)"#,
        ),
        i(
            SqlInjection,
            "paren_comment_end",
            2.0,
            r"\)\s*(--(\s|-|$)|#\s*$)",
        ),
        i(
            SqlInjection,
            "operator_time_function",
            3.0,
            r"(\bor\b|\band\b|\|\||&&|,|\(|=)\s*(sleep|pg_sleep|benchmark)\s*\(",
        ),
        i(
            SqlInjection,
            "order_by_injection",
            3.0,
            r"\border\s+by\s+[\d,\s]*(sleep|benchmark|if|case|select|\()",
        ),
        i(
            SqlInjection,
            "ddl_statement",
            3.0,
            r"\b(drop|truncate|alter)\s+(table|database|schema|column|user)\b|\bdelete\s+from\b|\binsert\s+into\b",
        ),
        i(
            SqlInjection,
            "stacked_query",
            6.0,
            r";\s*(drop|delete|insert|update|alter|create|truncate|exec(ute)?|declare|shutdown|grant|revoke)\b",
        ),
        i(
            SqlInjection,
            "time_based",
            6.0,
            r"\b(sleep|pg_sleep)\s*\(\s*\d|\bbenchmark\s*\(\s*\d|\bwaitfor\s+delay\b|\bdbms_lock\.sleep",
        ),
        i(
            SqlInjection,
            "schema_probe",
            6.0,
            r"\b(information_schema|sysobjects|syscolumns|pg_catalog|sqlite_master|mysql\.user|all_tables|sys\.tables)\b",
        ),
        i(
            SqlInjection,
            "dangerous_function",
            7.0,
            r"\b(load_file|xp_cmdshell|utl_http|sp_oacreate)\b|\binto\s+(out|dump)file\b",
        ),
        i(
            SqlInjection,
            "select_from",
            3.0,
            r"\bselect\b[\s\S]{1,100}?\bfrom\b",
        ),
        i(
            SqlInjection,
            "sql_function",
            2.0,
            r"\b(concat|concat_ws|group_concat|char|chr|ascii|substring|substr|mid|hex|unhex|extractvalue|updatexml|cast|convert|md5|sha1|if|ifnull|iif|nullif)\s*\(",
        ),
        i(
            SqlInjection,
            "fingerprint_function",
            4.0,
            r"@@version|@@datadir|\bversion\s*\(\s*\)|\b(current_user|database|user|schema)\s*\(\s*\)",
        ),
        i(
            SqlInjection,
            "boolean_literal",
            3.0,
            r"\b(or|and)\s+(true|false|null)\b",
        ),
        i(
            SqlInjection,
            "order_by_probe",
            7.0,
            r"\border\s+by\s+\d+\s*(--|#)",
        ),
        i(
            SqlInjection,
            "having_probe",
            6.0,
            r"\bhaving\s+\d+\s*=\s*\d+",
        ),
        // ---- cross-site scripting ----
        i(CrossSiteScripting, "script_tag", 8.0, r"<\s*/?\s*script\b"),
        i(
            CrossSiteScripting,
            "js_uri",
            3.0,
            r"\b(java|vb|live)script\s*:",
        ),
        i(
            CrossSiteScripting,
            "js_uri_call",
            7.0,
            r"\b(java|vb)script\s*:\s*[\w.\[\]]+\s*[(`]",
        ),
        i(
            CrossSiteScripting,
            "tag_event_handler",
            8.0,
            r"<[a-z][\w-]*[^>]*?[\s/]on[a-z]{3,}\s*=",
        ),
        i(
            CrossSiteScripting,
            "event_handler",
            4.0,
            r"\bon(error|load|mouseover|mouseenter|focus|blur|click|toggle|animationstart|transitionend|pointerover|begin|start|unload|beforeunload|message|hashchange|input|change|submit|keydown|keyup|wheel)\s*=",
        ),
        i(
            CrossSiteScripting,
            "dangerous_tag",
            4.0,
            r"<\s*(iframe|frame|object|embed|svg|math|base|meta|link|form|img|video|audio|body|details|marquee|isindex|applet|style|template)\b",
        ),
        i(
            CrossSiteScripting,
            "dom_sink",
            4.0,
            r"\b(document\s*\.\s*(cookie|domain|write|location)|window\s*\.\s*location|localstorage|sessionstorage|innerhtml|outerhtml)\b",
        ),
        i(
            CrossSiteScripting,
            "js_string_breakout",
            5.0,
            r#"['"]\s*[-+*/;,|&]\s*(alert|prompt|confirm|eval)\s*[(`]"#,
        ),
        i(
            CrossSiteScripting,
            "js_exec_call",
            3.0,
            r"\b(alert|prompt|confirm|eval|settimeout|setinterval|atob)\s*(\(|`)",
        ),
        i(
            CrossSiteScripting,
            "srcdoc",
            5.0,
            r"\b(srcdoc|formaction|xlink:href)\s*=",
        ),
        i(
            CrossSiteScripting,
            "css_expression",
            4.0,
            r"expression\s*\(|-moz-binding|\bbehavior\s*:",
        ),
        i(
            CrossSiteScripting,
            "data_uri_html",
            5.0,
            r"data\s*:\s*(text/html|text/javascript|application/javascript)",
        ),
        i(
            CrossSiteScripting,
            "html_breakout",
            4.0,
            r#"['"]\s*/?>\s*<"#,
        ),
        // ---- path traversal ----
        i(PathTraversal, "dotdot", 3.0, r"\.\.[/\\]"),
        i(PathTraversal, "dotdot_multi", 3.0, r"(\.\.[/\\]){2,}"),
        i(PathTraversal, "dotdot_deep", 2.0, r"(\.\.[/\\]){4,}"),
        i(
            PathTraversal,
            "sensitive_file",
            7.0,
            r"/etc/(passwd|shadow|group|hosts|issue)\b|/proc/(self|\d+)/|\bc:\\\\?windows\\|\bboot\.ini\b|\bwin\.ini\b|/\.ssh/|\bweb-inf/web\.xml|/\.env\b|/\.git/|/\.aws/",
        ),
        // ---- command injection ----
        i(CommandInjection, "shell_chain", 7.0, cmd_chain),
        i(
            CommandInjection,
            "command_substitution",
            4.0,
            r"\$\(\s*[a-z]+[^)]*\)",
        ),
        i(
            CommandInjection,
            "backtick_command_args",
            7.0,
            backtick_args,
        ),
        // `ls` is also how people write code in Markdown: log, don't block, on its own.
        i(CommandInjection, "backtick_command", 4.0, backtick_bare),
        i(CommandInjection, "absolute_path_command", 7.0, abs_cmd),
        i(
            CommandInjection,
            "ssi_directive",
            8.0,
            r"<!--\s*#\s*(exec|include|echo|config|printenv)\b",
        ),
        i(
            CommandInjection,
            "shell_path",
            6.0,
            r"(/bin/(ba|z|da)?sh\b|/usr/bin/(env|python|perl)\b|\bcmd(\.exe)?\s+/c\b|powershell(\.exe)?\s+-)",
        ),
        i(
            CommandInjection,
            "reverse_shell",
            6.0,
            r"/dev/(tcp|udp)/|>\s*/dev/null|\bnc\s+-[elvnp]",
        ),
        i(CommandInjection, "ifs_evasion", 5.0, r"\$\{?ifs\}?"),
        // ---- server-side request forgery ----
        i(
            Ssrf,
            "cloud_metadata",
            8.0,
            r"\b169\.254\.169\.254\b|\bmetadata\.google\.internal\b|\b100\.100\.100\.200\b|\bfd00:ec2::254\b|/latest/meta-data",
        ),
        i(
            Ssrf,
            "dangerous_scheme",
            7.0,
            r"\b(gopher|dict|ldap|tftp|jar|netdoc|expect|phar)://",
        ),
        i(Ssrf, "file_scheme", 6.0, r"\bfile://"),
        i(
            Ssrf,
            "internal_url",
            5.0,
            r"\bhttps?://(localhost|127\.\d+\.\d+\.\d+|0\.0\.0\.0|0x7f\w*|2130706433|\[::1?\]|10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+|172\.(1[6-9]|2\d|3[01])\.\d+\.\d+)",
        ),
        // ---- JNDI / Log4Shell ----
        i(JndiInjection, "jndi_lookup", 10.0, r"\$\{\s*jndi\s*:"),
        i(
            JndiInjection,
            "nested_lookup",
            6.0,
            r"\$\{[^}]{0,40}\$\{|\$\{\s*(lower|upper|env|sys|date|main|ctx|base64|::-)",
        ),
        i(
            JndiInjection,
            "jndi_protocol",
            3.0,
            r"\b(ldaps?|rmi|iiop|corba|nds|nis)://",
        ),
        // ---- XML external entities ----
        i(Xxe, "entity_declaration", 6.0, r"<!entity\b"),
        i(
            Xxe,
            "external_entity",
            4.0,
            r"<!entity[^>]*\b(system|public)\b",
        ),
        i(Xxe, "doctype_subset", 3.0, r"<!doctype[^>]*\["),
        i(Xxe, "xinclude", 5.0, r"xi:include|xmlns:xi\s*="),
        // ---- server-side template injection ----
        i(
            TemplateInjection,
            "template_math",
            7.0,
            r#"\{\{\s*\d+\s*[*+\-/]\s*['"]?\d+['"]?\s*\}\}|\$\{\s*\d+\s*[*+\-/]\s*['"]?\d+['"]?\s*\}|<%=\s*\d+\s*[*+]\s*\d+\s*%>|#\{\s*\d+\s*[*+]\s*\d+\s*\}"#,
        ),
        i(
            TemplateInjection,
            "template_dangerous_name",
            7.0,
            r"(\{\{|\{%|\$\{|<%|#\{)[^}%>]{0,300}(\bself\b|\brequest\b|\bconfig\b|\bapp\.|getclass\s*\(|\|\s*attr\b|\bos\.(system|popen)|\bpopen\b|subprocess|forname\s*\(|newinstance\s*\(|scriptengine|\.iteritems\s*\(|\bimport\s+os\b|\bsystem\s*\()",
        ),
        i(
            TemplateInjection,
            "template_object_access",
            8.0,
            r"(\{\{|\{%|\$\{|<%)[^}%>]{0,200}(__class__|__globals__|__builtins__|__mro__|__subclasses__|config\.items|request\.application|self\._|lipsum|cycler|joiner|getruntime|processbuilder|freemarker\.template|\bexec\s*\()",
        ),
        // ---- NoSQL injection ----
        i(NoSqlInjection, "mongo_operator", 7.0, mongo_bracket),
        i(NoSqlInjection, "mongo_where", 8.0, r#"\$where\b"#),
    ]
}

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

/// Decodes like a permissive server/browser would, then lowercases and collapses whitespace.
pub fn decode(raw: &str, form: bool) -> String {
    let mut s = raw.to_string();
    for _ in 0..4 {
        let next = percent_decode(&s, form);
        let next = html_entities(&next);
        let next = js_escapes(&next);
        if next == s {
            break;
        }
        s = next;
    }
    let lower = s.to_lowercase();
    let mut out = String::with_capacity(lower.len());
    let mut prev_space = false;
    for c in lower.chars() {
        let space = c.is_whitespace() || c == '\u{0b}' || c == '\u{0c}';
        if space {
            if !prev_space {
                out.push(' ');
            }
        } else {
            out.push(c);
        }
        prev_space = space;
    }
    out.trim().to_string()
}

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

fn percent_decode(s: &str, form: bool) -> String {
    let b = s.as_bytes();
    let hex_at = |i: usize| b.get(i).copied().and_then(hex_val);
    let mut out: Vec<u8> = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'%' if matches!(b.get(i + 1), Some(b'u') | Some(b'U')) => {
                // IIS-style %uXXXX
                let code = (0..4).try_fold(0u32, |acc, k| {
                    hex_at(i + 2 + k).map(|v| acc * 16 + v as u32)
                });
                match code.and_then(char::from_u32) {
                    Some(c) => {
                        let mut buf = [0u8; 4];
                        out.extend_from_slice(c.encode_utf8(&mut buf).as_bytes());
                        i += 6;
                    }
                    None => {
                        out.push(b'%');
                        i += 1;
                    }
                }
            }
            b'%' => match (hex_at(i + 1), hex_at(i + 2)) {
                (Some(h), Some(l)) => {
                    out.push(h * 16 + l);
                    i += 3;
                }
                _ => {
                    out.push(b'%');
                    i += 1;
                }
            },
            b'+' if form => {
                out.push(b' ');
                i += 1;
            }
            c => {
                out.push(c);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn html_entities(s: &str) -> String {
    if !s.contains('&') {
        return s.to_string();
    }
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(pos) = rest.find('&') {
        out.push_str(&rest[..pos]);
        let tail = &rest[pos..];
        let (decoded, used) = decode_entity(tail);
        match decoded {
            Some(c) => {
                out.push(c);
                rest = &tail[used..];
            }
            None => {
                out.push('&');
                rest = &tail[1..];
            }
        }
    }
    out.push_str(rest);
    out
}

fn decode_entity(t: &str) -> (Option<char>, usize) {
    const NAMED: [(&str, char); 9] = [
        ("&lt", '<'),
        ("&gt", '>'),
        ("&quot", '"'),
        ("&apos", '\''),
        ("&amp", '&'),
        ("&sol", '/'),
        ("&colon", ':'),
        ("&lpar", '('),
        ("&rpar", ')'),
    ];
    let lower: String = t.chars().take(12).collect::<String>().to_ascii_lowercase();
    for (name, c) in NAMED {
        if lower.starts_with(name) {
            let mut used = name.len();
            if t[used..].starts_with(';') {
                used += 1;
            }
            return (Some(c), used);
        }
    }
    if let Some(num) = lower.strip_prefix("&#") {
        let (digits, radix, skip) = match num.strip_prefix('x') {
            Some(h) => (h, 16, 3),
            None => (num, 10, 2),
        };
        let len = digits
            .chars()
            .take_while(|c| c.is_digit(radix))
            .count()
            .min(7);
        if len > 0 {
            if let Some(c) = u32::from_str_radix(&digits[..len], radix)
                .ok()
                .and_then(char::from_u32)
            {
                let mut used = skip + len;
                if t[used..].starts_with(';') {
                    used += 1;
                }
                return (Some(c), used);
            }
        }
    }
    (None, 0)
}

fn js_escapes(s: &str) -> String {
    if !s.contains('\\') {
        return s.to_string();
    }
    let b = s.as_bytes();
    let mut out = String::with_capacity(s.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'\\' && i + 1 < b.len() {
            let (n, len) = match b[i + 1] {
                b'u' | b'U' if i + 5 < b.len() => (
                    (0..4).try_fold(0u32, |acc, k| {
                        hex_val(b[i + 2 + k]).map(|v| acc * 16 + v as u32)
                    }),
                    6,
                ),
                b'x' | b'X' if i + 3 < b.len() => (
                    (0..2).try_fold(0u32, |acc, k| {
                        hex_val(b[i + 2 + k]).map(|v| acc * 16 + v as u32)
                    }),
                    4,
                ),
                _ => (None, 0),
            };
            if let Some(c) = n.and_then(char::from_u32) {
                out.push(c);
                i += len;
                continue;
            }
        }
        let ch = s[i..].chars().next().unwrap();
        out.push(ch);
        i += ch.len_utf8();
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decoding() {
        assert_eq!(decode("%3Cscript%3E", false), "<script>");
        assert_eq!(decode("%253Cscript%253E", false), "<script>");
        assert_eq!(decode("&lt;img&#x20;src=x&#62;", false), "<img src=x>");
        assert_eq!(decode("\\u003cscript\\x3e", false), "<script>");
        assert_eq!(decode("a+b", true), "a b");
        assert_eq!(decode("a+b", false), "a+b");
        assert_eq!(decode("%u003Csvg", false), "<svg");
        assert_eq!(decode("A \t\n B", false), "a b");
        assert_eq!(decode("100%", false), "100%");
        assert_eq!(decode("%zz%4", false), "%zz%4");
    }

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
