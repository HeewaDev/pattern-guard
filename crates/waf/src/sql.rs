//! SQL analysis: tokenizes a value the way a SQL parser would and scores structure,
//! in the spirit of libinjection (our own implementation, no fingerprint table).
//!
//! Three questions are asked of each value:
//! * Does a quote **break out of a string** into SQL (`' or 1=1`, `" and sleep(5)#`)?
//! * Is the **whole value a SQL expression** (`sleep(5000)`, `select char(`)?
//! * Does it **call a database function**, especially one attackers use to probe or
//!   delay (`current_user()`, `benchmark(`, `pg_sleep(`)?
//!
//! Prose fails these tests: it has runs of plain words, and a quote in "O'Brien" is
//! followed by a word, not by an operator or keyword.

use std::collections::HashSet;

use regex::Regex;

/// Functions attackers call to fingerprint, delay, read files or exfiltrate.
const DANGEROUS_FUNCTIONS: &[&str] = &[
    "sleep",
    "pg_sleep",
    "benchmark",
    "load_file",
    "current_user",
    "session_user",
    "system_user",
    "user",
    "database",
    "db_name",
    "schema",
    "version",
    "extractvalue",
    "updatexml",
    "xp_cmdshell",
    "sys_eval",
    "sys_exec",
    "utl_http.request",
    "utl_inaddr.get_host_address",
    "dbms_pipe.receive_message",
    "dbms_lock.sleep",
    "sqlite_version",
    "sqlite_compileoption_get",
    "sqlite_compileoption_used",
    "pg_read_file",
    "pg_ls_dir",
    "pg_read_binary_file",
    "lo_import",
    "lo_export",
    "group_concat",
    "string_agg",
    "make_set",
    "export_set",
    "name_const",
    "geometrycollection",
    "multipoint",
    "polygon",
    "linestring",
    "exp",
    "is_srvrolemember",
    "has_dbaccess",
    "openrowset",
    "opendatasource",
    "current_database",
    "current_schema",
    "inet_server_addr",
    "connection_id",
    "last_insert_id",
    "row_count",
    "found_rows",
    "uuid",
    "lo_get",
    "lo_put",
    "lo_from_bytea",
    "pg_stat_file",
    "dblink",
    "dblink_exec",
];

/// Other common SQL functions (MySQL, PostgreSQL, SQL Server, Oracle, SQLite).
const FUNCTIONS: &[&str] = &[
    "abs",
    "acos",
    "ascii",
    "asin",
    "atan",
    "avg",
    "bin",
    "bit_length",
    "cast",
    "ceil",
    "ceiling",
    "char",
    "char_length",
    "character_length",
    "charindex",
    "chr",
    "coalesce",
    "collation",
    "compress",
    "concat",
    "concat_ws",
    "conv",
    "convert",
    "cos",
    "cot",
    "count",
    "crc32",
    "curdate",
    "current_date",
    "current_time",
    "current_timestamp",
    "curtime",
    "date_format",
    "datediff",
    "dayname",
    "decode",
    "default",
    "degrees",
    "des_encrypt",
    "elt",
    "encode",
    "encrypt",
    "field",
    "find_in_set",
    "floor",
    "format",
    "from_base64",
    "from_unixtime",
    "greatest",
    "hex",
    "ifnull",
    "iif",
    "inet_aton",
    "inet_ntoa",
    "insert",
    "instr",
    "isnull",
    "json_extract",
    "json_keys",
    "json_value",
    "json_query",
    "jsonb_pretty",
    "jsonb_extract_path",
    "json_array",
    "json_object",
    "lcase",
    "least",
    "left",
    "len",
    "length",
    "ln",
    "locate",
    "log",
    "log10",
    "lower",
    "lpad",
    "ltrim",
    "max",
    "md5",
    "mid",
    "min",
    "mod",
    "now",
    "nullif",
    "nvl",
    "oct",
    "octet_length",
    "ord",
    "password",
    "pi",
    "position",
    "pow",
    "power",
    "quote",
    "quotename",
    "radians",
    "rand",
    "random",
    "regexp_like",
    "regexp_replace",
    "regexp_substr",
    "repeat",
    "replace",
    "reverse",
    "right",
    "round",
    "rpad",
    "rtrim",
    "sha",
    "sha1",
    "sha2",
    "sign",
    "sin",
    "soundex",
    "space",
    "sqrt",
    "starts_with",
    "std",
    "stddev",
    "strcmp",
    "substr",
    "substring",
    "substring_index",
    "sum",
    "sysdate",
    "tan",
    "to_base64",
    "to_char",
    "to_number",
    "trim",
    "ucase",
    "uncompress",
    "unhex",
    "upper",
    "utc_date",
    "utc_time",
    "variance",
    "weight_string",
    "xmltype",
    "if",
    "elt",
    "chr",
    "nchar",
    "unicode",
    "unistr",
    "json_build_object",
    "json_build_array",
    "to_json",
    "to_jsonb",
    "array_to_string",
    "div",
];

/// Keywords that start a statement.
const STATEMENTS: &[&str] = &[
    "select",
    "union",
    "insert",
    "update",
    "delete",
    "drop",
    "create",
    "alter",
    "truncate",
    "exec",
    "execute",
    "declare",
    "waitfor",
    "shutdown",
    "grant",
    "revoke",
    "procedure",
    "handler",
    "merge",
    "call",
    "load",
    "replace",
    "rename",
];

/// Other SQL keywords.
const KEYWORDS: &[&str] = &[
    "from",
    "where",
    "having",
    "group",
    "order",
    "by",
    "limit",
    "offset",
    "into",
    "values",
    "join",
    "inner",
    "outer",
    "left",
    "right",
    "on",
    "case",
    "when",
    "then",
    "else",
    "end",
    "as",
    "top",
    "delay",
    "analyse",
    "distinct",
    "all",
    "any",
    "exists",
    "null",
    "true",
    "false",
    "is",
    "in",
    "between",
    "like",
    "rlike",
    "regexp",
    "sounds",
    "collate",
    "div",
    "set",
    "table",
    "column",
    "database",
    "schema",
    "outfile",
    "dumpfile",
    "information_schema",
    "asc",
    "desc",
    "procedure",
    "with",
    "returning",
    "nocase",
    "binary",
];

const LOGIC: &[&str] = &["and", "or", "xor", "not"];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Tok {
    Str,
    Num,
    Word,
    Keyword,
    Statement,
    Logic,
    /// known SQL function followed by `(`
    Func,
    /// dangerous SQL function followed by `(`
    DangerousFunc,
    /// unknown word followed by `(`
    Call,
    Var,
    Op,
    LParen,
    RParen,
    Comma,
    Semi,
    Comment,
    Other,
}

pub(crate) struct Sql {
    dangerous: HashSet<&'static str>,
    functions: HashSet<&'static str>,
    statements: HashSet<&'static str>,
    keywords: HashSet<&'static str>,
    column_breakout: Regex,
}

impl Sql {
    pub(crate) fn new() -> Self {
        Self {
            dangerous: DANGEROUS_FUNCTIONS.iter().copied().collect(),
            functions: FUNCTIONS.iter().copied().collect(),
            statements: STATEMENTS.iter().copied().collect(),
            keywords: KEYWORDS.iter().copied().collect(),
            // `1 or username='admin'` · `1) or (role='x'` · `-1 or is_admin=true`
            // · `5 or email like '%'` · `0 or id in (select` · `1 or name is not null`:
            // a number, a logic operator, then a comparison on a column. The token
            // rules don't take bare words as operands because English is full of
            // them; this shape needs a real comparison right after the word.
            column_breakout: Regex::new(concat!(
                r"^\s*(?:[-+]?\d+(?:\.\d+)?\)*\s*)?(?:(?:or|and|xor)\s|\|\||&&)[\s(]*",
                r"[a-z_][a-z0-9_$.]*",
                r"(?:\s*(?:<=>|<>|!=|<=|>=|=|<|>)\s*\S",
                r"|\s+(?:not\s+)?(?:like|rlike|regexp|in|between)\s*['\x22(\d-]",
                r"|\s+is\s+(?:not\s+)?(?:null|true|false)\b)",
            ))
            .expect("column breakout pattern compiles"),
        }
    }

    /// SQL indicators for one decoded, lowercased value.
    pub(crate) fn scan(&self, value: &str) -> Vec<(&'static str, f64)> {
        let mut out: Vec<(&'static str, f64)> = Vec::new();
        let mut push = |name: &'static str, w: f64| {
            if !out.iter().any(|(n, _)| *n == name) {
                out.push((name, w));
            }
        };
        if value.len() < 2 || !value.bytes().any(|b| !b.is_ascii_alphanumeric()) {
            return out;
        }
        let toks = self.tokenize(value);

        // database functions anywhere in the value
        if toks.contains(&Tok::DangerousFunc) {
            push("sql_dangerous_function", 5.0);
        } else if toks.contains(&Tok::Func) {
            push("sql_known_function", 3.0);
        }

        // the whole value is a SQL expression
        if self.is_expression(&toks) {
            let statement_with_call = toks.contains(&Tok::Statement)
                && toks
                    .iter()
                    .any(|t| matches!(t, Tok::Func | Tok::DangerousFunc));
            // `select char(` · `select group_concat(`
            push(
                "sql_expression",
                if statement_with_call { 4.0 } else { 3.0 },
            );
        }

        // a quote breaks out of a string context into SQL
        // (backticks are Markdown inline code far more often than MySQL identifiers)
        for q in ['\'', '"'] {
            if let Some(i) = value.find(q) {
                let after = &value[i + q.len_utf8()..];
                let t = self.tokenize(after);
                if breaks_out(&t) {
                    push("sql_string_breakout", 7.0);
                    break;
                }
            }
        }
        // a value starting with an operator or `)` continues a numeric context:
        // `1) or (1=1`, `1 and sleep(5)`
        if let Some(w) = numeric_breakout(&toks) {
            push("sql_numeric_breakout", w);
        } else if self.column_breakout.is_match(value) {
            push("sql_column_breakout", 7.0);
        }
        out
    }

    /// A value is a SQL expression when every token is SQL, it contains a function
    /// call or statement keyword, it has SQL syntax (parenthesis, operator, quote,
    /// variable, semicolon or comment) and no run of three plain words (prose).
    fn is_expression(&self, toks: &[Tok]) -> bool {
        if toks.len() < 2 || toks.contains(&Tok::Other) {
            return false;
        }
        let anchor = toks
            .iter()
            .any(|t| matches!(t, Tok::Func | Tok::DangerousFunc | Tok::Statement));
        let syntax = toks.iter().any(|t| {
            matches!(
                t,
                Tok::LParen | Tok::Op | Tok::Str | Tok::Var | Tok::Semi | Tok::Comment
            )
        });
        let mut run = 0;
        for t in toks {
            if *t == Tok::Word || *t == Tok::Call {
                run += 1;
                if run >= 3 {
                    return false;
                }
            } else {
                run = 0;
            }
        }
        anchor && syntax
    }

    fn tokenize(&self, s: &str) -> Vec<Tok> {
        let b = s.as_bytes();
        let mut out = Vec::new();
        let mut i = 0;
        while i < b.len() && out.len() < 64 {
            let c = b[i];
            match c {
                b' ' | b'\t' | b'\n' | b'\r' | 0x0b | 0x0c => i += 1,
                b'/' if b.get(i + 1) == Some(&b'*') => {
                    if b.get(i + 2) == Some(&b'!') {
                        // MySQL versioned comment: its content is code
                        i += 3;
                        while i < b.len() && b[i].is_ascii_digit() {
                            i += 1;
                        }
                    } else {
                        match s[i + 2..].find("*/") {
                            Some(e) => i += e + 4,
                            None => {
                                out.push(Tok::Comment);
                                break;
                            }
                        }
                    }
                }
                b'*' if b.get(i + 1) == Some(&b'/') => i += 2,
                b'-' if b.get(i + 1) == Some(&b'-')
                    && matches!(b.get(i + 2), None | Some(b' ' | b'-' | b'\t' | b'\n')) =>
                {
                    out.push(Tok::Comment);
                    break;
                }
                b'#' => {
                    out.push(Tok::Comment);
                    break;
                }
                b'\'' | b'"' | b'`' => {
                    let mut j = i + 1;
                    while j < b.len() {
                        if b[j] == c {
                            if b.get(j + 1) == Some(&c) {
                                j += 2; // doubled quote inside the string
                                continue;
                            }
                            break;
                        }
                        if b[j] == b'\\' {
                            j += 1;
                        }
                        j += 1;
                    }
                    out.push(if c == b'`' { Tok::Word } else { Tok::Str });
                    i = (j + 1).min(b.len());
                }
                b'0'..=b'9' => {
                    let mut j = i + 1;
                    if c == b'0' && matches!(b.get(j), Some(b'x' | b'b')) {
                        j += 1;
                        while j < b.len() && b[j].is_ascii_hexdigit() {
                            j += 1;
                        }
                    } else {
                        while j < b.len()
                            && (b[j].is_ascii_digit()
                                || b[j] == b'.'
                                || (b[j] == b'e'
                                    && matches!(b.get(j + 1), Some(b'0'..=b'9' | b'-' | b'+'))))
                        {
                            j += if b[j] == b'e' { 2 } else { 1 };
                        }
                    }
                    // `1abc` is a word, not a number
                    if j < b.len() && (b[j].is_ascii_alphabetic() || b[j] == b'_') {
                        while j < b.len() && is_word_byte(b[j]) {
                            j += 1;
                        }
                        out.push(Tok::Word);
                    } else {
                        out.push(Tok::Num);
                    }
                    i = j;
                }
                b'@' => {
                    let mut j = i + 1;
                    while j < b.len() && (b[j] == b'@' || is_word_byte(b[j])) {
                        j += 1;
                    }
                    out.push(Tok::Var);
                    i = j;
                }
                b'(' => {
                    out.push(Tok::LParen);
                    i += 1;
                }
                b')' => {
                    out.push(Tok::RParen);
                    i += 1;
                }
                b',' => {
                    out.push(Tok::Comma);
                    i += 1;
                }
                b';' => {
                    out.push(Tok::Semi);
                    i += 1;
                }
                b'=' | b'<' | b'>' | b'!' | b'|' | b'&' | b'+' | b'-' | b'*' | b'/' | b'%'
                | b'^' | b'~' | b':' | b'?' => {
                    let mut j = i + 1;
                    while j < b.len()
                        && matches!(b[j], b'=' | b'<' | b'>' | b'|' | b'&' | b':' | b'@')
                        && j - i < 3
                    {
                        j += 1;
                    }
                    let op = &s[i..j];
                    out.push(if op == "||" || op == "&&" {
                        Tok::Logic
                    } else if op == ":" {
                        // a lone colon is punctuation ("Update: …"); only `::` is SQL
                        Tok::Other
                    } else {
                        Tok::Op
                    });
                    i = j;
                }
                c if c.is_ascii_alphabetic() || c == b'_' || c == b'$' => {
                    let mut j = i + 1;
                    while j < b.len() && (is_word_byte(b[j]) || b[j] == b'.') {
                        j += 1;
                    }
                    let word = s[i..j].trim_end_matches('.');
                    // is it called? (whitespace or comments before `(`)
                    let mut k = j;
                    loop {
                        while k < b.len() && b[k].is_ascii_whitespace() {
                            k += 1;
                        }
                        if b.get(k) == Some(&b'/') && b.get(k + 1) == Some(&b'*') {
                            match s[k + 2..].find("*/") {
                                Some(e) => k += e + 4,
                                None => break,
                            }
                        } else {
                            break;
                        }
                    }
                    let called = b.get(k) == Some(&b'(');
                    // dotted names match only in full (`dbms_lock.sleep`), so method
                    // calls such as `guess.trim()` are not SQL functions
                    out.push(if called && self.dangerous.contains(word) {
                        Tok::DangerousFunc
                    } else if called && self.functions.contains(word) {
                        Tok::Func
                    } else if LOGIC.contains(&word) {
                        Tok::Logic
                    } else if self.statements.contains(word) {
                        Tok::Statement
                    } else if self.keywords.contains(word) {
                        Tok::Keyword
                    } else if called {
                        Tok::Call
                    } else {
                        Tok::Word
                    });
                    i = j;
                }
                _ => {
                    out.push(Tok::Other);
                    // skip the whole UTF-8 character
                    i += 1;
                    while i < b.len() && (b[i] & 0xc0) == 0x80 {
                        i += 1;
                    }
                }
            }
        }
        out
    }
}

fn is_word_byte(c: u8) -> bool {
    c.is_ascii_alphanumeric() || c == b'_' || c == b'$'
}

fn is_operand(t: Tok) -> bool {
    matches!(
        t,
        Tok::Num | Tok::Str | Tok::Var | Tok::Func | Tok::DangerousFunc | Tok::LParen
    ) || t == Tok::Keyword // true / false / null
}

/// Token sequence after a closing quote that only makes sense as SQL.
fn breaks_out(t: &[Tok]) -> bool {
    let mut t = t;
    // `')` closes parentheses first
    while let Some(Tok::RParen) = t.first() {
        t = &t[1..];
    }
    // `' and not x` · `' or not (x)`: keep one logic token, drop the rest
    let chained: Vec<Tok>;
    if t.first() == Some(&Tok::Logic) {
        let skip = t[1..]
            .iter()
            .take_while(|x| matches!(x, Tok::Logic))
            .count();
        if skip > 0 {
            chained = std::iter::once(Tok::Logic)
                .chain(t[1 + skip..].iter().copied())
                .collect();
            t = &chained;
        }
    }
    match t {
        // ' or 1=1 · ' and sleep(5) · ' or true-- · ' || 'a'='a
        [Tok::Logic, a, rest @ ..] if is_operand(*a) => match rest.first() {
            None => matches!(a, Tok::Num | Tok::Var | Tok::Func | Tok::DangerousFunc),
            Some(Tok::Op | Tok::Comment | Tok::Semi | Tok::Keyword | Tok::RParen) => true,
            Some(Tok::LParen) => matches!(a, Tok::Func | Tok::DangerousFunc),
            _ => matches!(a, Tok::Func | Tok::DangerousFunc | Tok::LParen),
        },
        // ' = 1 or ' · '+sleep(5)+' · '||(select
        [Tok::Op, a, ..] if is_operand(*a) => matches!(
            a,
            Tok::Func | Tok::DangerousFunc | Tok::LParen | Tok::Num | Tok::Var
        ),
        // '; drop table · ' union select · ' order by 1
        [Tok::Semi, Tok::Statement, ..] => true,
        [
            Tok::Statement,
            Tok::Statement | Tok::Keyword | Tok::Num | Tok::Op,
            ..,
        ] => true,
        [Tok::Keyword, Tok::Keyword, Tok::Num, ..] => true, // order by 1
        // '-- · '# · '; (end of the query)
        [Tok::Comment] | [Tok::Semi] | [Tok::Semi, Tok::Comment] => true,
        _ => false,
    }
}

/// `1 and 1=1` · `1) or (1=1` · `1 or sleep(5)` · `-1 union select`. Returns the
/// weight: a comparison, function or statement after the breakout is strong.
fn numeric_breakout(t: &[Tok]) -> Option<f64> {
    let mut t = t;
    if let Some(Tok::Op) = t.first() {
        t = &t[1..]; // leading minus
    }
    if t.first() != Some(&Tok::Num) {
        return None;
    }
    let mut rest = &t[1..];
    while let Some(Tok::RParen) = rest.first() {
        rest = &rest[1..];
    }
    match rest {
        [Tok::Logic, after @ ..] => {
            let mut x = after;
            while let Some(Tok::LParen) = x.first() {
                x = &x[1..];
            }
            match x {
                [Tok::Func | Tok::DangerousFunc, ..] => Some(7.0),
                [a, Tok::Op, b, ..] if is_operand(*a) && is_operand(*b) => Some(7.0),
                [a, Tok::Comment] if is_operand(*a) => Some(5.0),
                [Tok::Keyword, ..] => Some(4.0), // 1 or true
                _ => None,
            }
        }
        [
            Tok::Statement,
            Tok::Statement | Tok::Keyword | Tok::Num | Tok::Op,
            ..,
        ] => Some(7.0),
        [Tok::Semi, Tok::Statement, ..] => Some(7.0),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn score(s: &Sql, v: &str) -> f64 {
        s.scan(v).iter().map(|(_, w)| w).sum()
    }

    #[test]
    fn injections_score_high() {
        let s = Sql::new();
        for v in [
            "' or 1=1--",
            "admin'/**/or/**/'1'='1",
            "\" and sleep(5)#",
            "') or ('a'='a",
            "x' || (select 1)",
            "'+sleep(20)+'",
            "1' order by 3--",
            "'; drop table users--",
            "1 and 1=1",
            "1) or (1=1",
            "-1 union select 1,2",
            "sleep(5000)",
            "current_user(",
            "select char(",
            "1 or benchmark(1000000,md5(1))",
            "email=admin@example.com'and not sqlite_compileoption_get (id)--",
        ] {
            assert!(score(&s, v) >= 7.0, "{v}: {:?}", s.scan(v));
        }
    }

    #[test]
    fn prose_names_and_code_stay_low() {
        let s = Sql::new();
        for v in [
            "o'brien",
            "it's or not",
            "the 'or' operator",
            "rock 'n' roll",
            "please select the best option from the list",
            "sort by price",
            "max(3)",
            "if (x > 3) { y }",
            "let count = items.len();",
            "i'd like to order by phone",
            "\"hello\" she said",
            "1 and 2 are numbers",
            "call me at 555-1234",
            "1 or 2 tickets",
            "update: new features; update your app",
            "shorthand for `^0.10.1`, which means any version",
            "let guess: u32 = guess.trim().parse().expect(\"please type a number!\");",
            "add an `#[unsafe(no_mangle)]` annotation",
        ] {
            assert!(score(&s, v) < 7.0, "{v}: {:?}", s.scan(v));
        }
    }
}
