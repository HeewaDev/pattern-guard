//! A small POSIX `sh` (dash-like: no brace expansion) for the ping tool's command
//! injection. It runs nothing: a handful of commands are simulated against the fake file
//! system.
//!
//! Covered: `;` `&` `&&` `||` `|` newline, single and double quotes, backslashes,
//! `$VAR` / `${VAR}` (`IFS` is space, tab, newline; unset variables and `$@`, `$*`, `$1`…
//! are empty), `$(…)` and backticks, field splitting of unquoted expansions, pathname
//! globbing (`*`, `?`, `[…]`), redirections (`> file`, `2>&1`, `2>/dev/null`, `< file`) and
//! `#` comments. Anything else (unterminated quotes, `$((…))`, here-documents, `{a,b}`) is a
//! syntax error or a literal, so the simulation errs towards "not exploited".

use super::fs;

/// What the PHP page shows: stdout (and stderr where the command line merges it).
#[derive(Debug, Default)]
pub struct Output {
    pub stdout: String,
    pub status: i32,
}

#[derive(Debug, Clone, PartialEq)]
enum Piece {
    /// quoted or escaped text: never split or globbed
    Quoted(String),
    /// unquoted literal text: globbed, not split
    Plain(String),
    /// result of an unquoted expansion: split on IFS and globbed
    Expanded(String),
}

#[derive(Debug, Clone, PartialEq)]
enum Token {
    Word(Vec<Piece>),
    /// `;` `&` `&&` `||` `|` or newline
    Op(&'static str),
    /// `[fd]>` `[fd]>>` `<` `[fd]>&fd`
    Redirect {
        fd: u32,
        kind: &'static str,
    },
}

#[derive(Debug)]
pub struct SyntaxError(pub String);

struct Lexer<'a> {
    s: &'a [u8],
    i: usize,
    depth: usize,
}

const MAX_DEPTH: usize = 4;

impl Lexer<'_> {
    fn tokens(&mut self, until: Option<u8>) -> Result<Vec<Token>, SyntaxError> {
        let mut out = Vec::new();
        loop {
            // skip blanks
            while self.i < self.s.len() && matches!(self.s[self.i], b' ' | b'\t') {
                self.i += 1;
            }
            let Some(&c) = self.s.get(self.i) else {
                if until.is_some() {
                    return Err(SyntaxError(
                        "end of file unexpected (expecting \")\")".into(),
                    ));
                }
                return Ok(out);
            };
            if Some(c) == until {
                self.i += 1;
                return Ok(out);
            }
            match c {
                b'#' => {
                    while self.i < self.s.len() && self.s[self.i] != b'\n' {
                        self.i += 1;
                    }
                }
                b'\n' => {
                    self.i += 1;
                    out.push(Token::Op("\n"));
                }
                b';' => {
                    self.i += 1;
                    if self.s.get(self.i) == Some(&b';') {
                        return Err(SyntaxError("\";;\" unexpected".into()));
                    }
                    out.push(Token::Op(";"));
                }
                b'&' | b'|' => {
                    let double = self.s.get(self.i + 1) == Some(&c);
                    self.i += if double { 2 } else { 1 };
                    out.push(Token::Op(match (c, double) {
                        (b'&', true) => "&&",
                        (b'&', false) => "&",
                        (_, true) => "||",
                        _ => "|",
                    }));
                }
                b'<' | b'>' => out.push(self.redirect(1)?),
                b'(' | b')' => {
                    return Err(SyntaxError(format!(
                        "Syntax error: \"{}\" unexpected",
                        c as char
                    )));
                }
                b'0'..=b'9'
                    if matches!(self.s.get(self.i + 1), Some(b'>' | b'<')) && self.word_start() =>
                {
                    let fd = (c - b'0') as u32;
                    self.i += 1;
                    out.push(self.redirect(fd)?);
                }
                _ => out.push(Token::Word(self.word()?)),
            }
        }
    }

    fn word_start(&self) -> bool {
        self.i == 0
            || matches!(
                self.s[self.i - 1],
                b' ' | b'\t' | b'\n' | b';' | b'&' | b'|'
            )
    }

    fn redirect(&mut self, default_fd: u32) -> Result<Token, SyntaxError> {
        let c = self.s[self.i];
        self.i += 1;
        if c == b'<' {
            return Ok(Token::Redirect { fd: 0, kind: "<" });
        }
        let kind = if self.s.get(self.i) == Some(&b'>') {
            self.i += 1;
            ">>"
        } else if self.s.get(self.i) == Some(&b'&') {
            self.i += 1;
            ">&"
        } else {
            ">"
        };
        Ok(Token::Redirect {
            fd: default_fd,
            kind,
        })
    }

    fn word(&mut self) -> Result<Vec<Piece>, SyntaxError> {
        let mut pieces = Vec::new();
        let mut plain = String::new();
        let flush = |plain: &mut String, pieces: &mut Vec<Piece>| {
            if !plain.is_empty() {
                pieces.push(Piece::Plain(std::mem::take(plain)));
            }
        };
        while let Some(&c) = self.s.get(self.i) {
            match c {
                b' ' | b'\t' | b'\n' | b';' | b'&' | b'|' | b'<' | b'>' | b'(' | b')' => break,
                b'#' if plain.is_empty() && pieces.is_empty() => break,
                b'\\' => {
                    self.i += 1;
                    match self.s.get(self.i) {
                        Some(b'\n') => self.i += 1, // line continuation
                        Some(&e) => {
                            flush(&mut plain, &mut pieces);
                            pieces.push(Piece::Quoted((e as char).to_string()));
                            self.i += 1;
                        }
                        None => {}
                    }
                }
                b'\'' => {
                    flush(&mut plain, &mut pieces);
                    self.i += 1;
                    let start = self.i;
                    while self.s.get(self.i).is_some_and(|&x| x != b'\'') {
                        self.i += 1;
                    }
                    if self.i >= self.s.len() {
                        return Err(SyntaxError(
                            "Syntax error: Unterminated quoted string".into(),
                        ));
                    }
                    pieces.push(Piece::Quoted(
                        String::from_utf8_lossy(&self.s[start..self.i]).into_owned(),
                    ));
                    self.i += 1;
                }
                b'"' => {
                    flush(&mut plain, &mut pieces);
                    self.i += 1;
                    let mut q = String::new();
                    loop {
                        match self.s.get(self.i) {
                            None => {
                                return Err(SyntaxError(
                                    "Syntax error: Unterminated quoted string".into(),
                                ));
                            }
                            Some(b'"') => {
                                self.i += 1;
                                break;
                            }
                            Some(b'\\')
                                if matches!(
                                    self.s.get(self.i + 1),
                                    Some(b'$' | b'`' | b'"' | b'\\' | b'\n')
                                ) =>
                            {
                                q.push(self.s[self.i + 1] as char);
                                self.i += 2;
                            }
                            Some(b'$') | Some(b'`') => q.push_str(&self.expansion()?),
                            Some(&x) => {
                                q.push(x as char);
                                self.i += 1;
                            }
                        }
                    }
                    pieces.push(Piece::Quoted(q));
                }
                b'$' | b'`' => {
                    flush(&mut plain, &mut pieces);
                    let e = self.expansion()?;
                    pieces.push(Piece::Expanded(e));
                }
                _ => {
                    // keep multi-byte characters intact
                    let len = utf8_len(c);
                    let end = (self.i + len).min(self.s.len());
                    plain.push_str(&String::from_utf8_lossy(&self.s[self.i..end]));
                    self.i = end;
                }
            }
        }
        flush(&mut plain, &mut pieces);
        Ok(pieces)
    }

    /// `$NAME`, `${NAME}`, `$(…)`, `` `…` ``: the expanded text.
    fn expansion(&mut self) -> Result<String, SyntaxError> {
        let c = self.s[self.i];
        if c == b'`' {
            self.i += 1;
            let start = self.i;
            while self.s.get(self.i).is_some_and(|&x| x != b'`') {
                self.i += 1;
            }
            if self.i >= self.s.len() {
                return Err(SyntaxError(
                    "Syntax error: EOF in backquote substitution".into(),
                ));
            }
            let inner = String::from_utf8_lossy(&self.s[start..self.i]).into_owned();
            self.i += 1;
            return self.substitute(&inner);
        }
        self.i += 1; // `$`
        match self.s.get(self.i) {
            Some(b'(') => {
                if self.s.get(self.i + 1) == Some(&b'(') {
                    return Err(SyntaxError("arithmetic expansion is not simulated".into()));
                }
                self.i += 1;
                // find the matching `)` while respecting quotes
                let start = self.i;
                let mut depth = 1;
                let mut quote = None;
                while let Some(&x) = self.s.get(self.i) {
                    match (quote, x) {
                        (None, b'\'' | b'"') => quote = Some(x),
                        (Some(q), _) if x == q => quote = None,
                        (None, b'(') => depth += 1,
                        (None, b')') => {
                            depth -= 1;
                            if depth == 0 {
                                break;
                            }
                        }
                        _ => {}
                    }
                    self.i += 1;
                }
                if self.i >= self.s.len() {
                    return Err(SyntaxError("Syntax error: end of file unexpected".into()));
                }
                let inner = String::from_utf8_lossy(&self.s[start..self.i]).into_owned();
                self.i += 1;
                self.substitute(&inner)
            }
            Some(b'{') => {
                let start = self.i + 1;
                let end = self.s[start..]
                    .iter()
                    .position(|&x| x == b'}')
                    .ok_or_else(|| SyntaxError("Syntax error: Missing '}'".into()))?;
                let name = String::from_utf8_lossy(&self.s[start..start + end]).into_owned();
                self.i = start + end + 1;
                if !name
                    .chars()
                    .all(|ch| ch.is_ascii_alphanumeric() || ch == '_' || "@*#?".contains(ch))
                {
                    return Err(SyntaxError(format!("${{{name}}}: Bad substitution")));
                }
                Ok(variable(&name))
            }
            Some(&x) if x.is_ascii_alphabetic() || x == b'_' => {
                let start = self.i;
                while self
                    .s
                    .get(self.i)
                    .is_some_and(|&y| y.is_ascii_alphanumeric() || y == b'_')
                {
                    self.i += 1;
                }
                Ok(variable(&String::from_utf8_lossy(&self.s[start..self.i])))
            }
            Some(&x) if x.is_ascii_digit() || b"@*#?$!-".contains(&x) => {
                self.i += 1;
                Ok(variable(&(x as char).to_string()))
            }
            _ => Ok("$".into()),
        }
    }

    fn substitute(&mut self, inner: &str) -> Result<String, SyntaxError> {
        if self.depth >= MAX_DEPTH {
            return Ok(String::new());
        }
        let out = run_nested(inner, self.depth + 1)?;
        // trailing newlines are removed by command substitution
        Ok(out.stdout.trim_end_matches('\n').to_string())
    }
}

fn utf8_len(first: u8) -> usize {
    match first {
        0xf0..=0xff => 4,
        0xe0..=0xef => 3,
        0xc0..=0xdf => 2,
        _ => 1,
    }
}

fn variable(name: &str) -> String {
    match name {
        "IFS" => " \t\n".into(),
        "HOME" => "/var/www".into(),
        "PATH" => "/usr/bin:/bin".into(),
        "PWD" => "/srv/app".into(),
        "USER" | "LOGNAME" => "www-data".into(),
        "SHELL" => "/bin/sh".into(),
        "?" => "0".into(),
        "$" => "4242".into(),
        "#" => "0".into(),
        "0" => "sh".into(),
        _ => String::new(),
    }
}

/// Glob match of one path component (`*`, `?`, `[…]`).
fn glob_match(pat: &[char], s: &[char]) -> bool {
    match pat.first() {
        None => s.is_empty(),
        Some('*') => (0..=s.len()).any(|k| glob_match(&pat[1..], &s[k..])),
        Some('?') => !s.is_empty() && glob_match(&pat[1..], &s[1..]),
        Some('[') => {
            let Some(close) = pat.iter().skip(1).position(|&c| c == ']').map(|p| p + 1) else {
                return s.first() == Some(&'[') && glob_match(&pat[1..], &s[1..]);
            };
            let set = &pat[1..close];
            let (neg, set) = match set.first() {
                Some('!') | Some('^') => (true, &set[1..]),
                _ => (false, set),
            };
            let Some(&ch) = s.first() else { return false };
            let mut hit = false;
            let mut k = 0;
            while k < set.len() {
                if k + 2 < set.len() && set[k + 1] == '-' {
                    hit |= set[k] <= ch && ch <= set[k + 2];
                    k += 3;
                } else {
                    hit |= set[k] == ch;
                    k += 1;
                }
            }
            hit != neg && glob_match(&pat[close + 1..], &s[1..])
        }
        Some(c) => s.first() == Some(c) && glob_match(&pat[1..], &s[1..]),
    }
}

/// Pathname expansion of an absolute or cwd-relative pattern against the fake file system.
fn glob(pattern: &str) -> Vec<String> {
    let abs = if pattern.starts_with('/') {
        pattern.to_string()
    } else {
        format!("/srv/app/{pattern}")
    };
    let pat: Vec<&str> = abs.split('/').skip(1).collect();
    let mut hits: Vec<String> = fs::all_paths()
        .filter(|p| {
            let comps: Vec<&str> = p.split('/').skip(1).collect();
            comps.len() == pat.len()
                && comps.iter().zip(&pat).all(|(c, q)| {
                    // `*` doesn't match a leading dot
                    (!c.starts_with('.') || q.starts_with('.'))
                        && glob_match(
                            &q.chars().collect::<Vec<_>>(),
                            &c.chars().collect::<Vec<_>>(),
                        )
                })
        })
        .map(|p| {
            if pattern.starts_with('/') {
                p.to_string()
            } else {
                p.trim_start_matches("/srv/app/").to_string()
            }
        })
        .collect();
    hits.sort();
    hits
}

/// Field splitting and globbing: the words a token becomes.
fn fields(pieces: &[Piece]) -> Vec<String> {
    let mut words: Vec<(String, bool)> = Vec::new(); // (text, has unquoted glob chars)
    let mut cur = String::new();
    let mut cur_glob = false;
    let mut have = false;
    for p in pieces {
        match p {
            Piece::Quoted(s) => {
                cur.push_str(s);
                have = true;
            }
            Piece::Plain(s) => {
                cur_glob |= s.contains(['*', '?', '[']);
                cur.push_str(s);
                have = true;
            }
            Piece::Expanded(s) => {
                let mut parts = s.split([' ', '\t', '\n']).peekable();
                let mut first = true;
                while let Some(part) = parts.next() {
                    if !first {
                        if have || !cur.is_empty() {
                            words.push((std::mem::take(&mut cur), cur_glob));
                        }
                        cur_glob = false;
                        have = false;
                    }
                    first = false;
                    if !part.is_empty() {
                        cur_glob |= part.contains(['*', '?', '[']);
                        cur.push_str(part);
                        have = true;
                    }
                    let _ = parts.peek();
                }
            }
        }
    }
    if have || !cur.is_empty() {
        words.push((cur, cur_glob));
    }
    let mut out = Vec::new();
    for (w, g) in words {
        if g {
            let hits = glob(&w);
            if hits.is_empty() {
                out.push(w);
            } else {
                out.extend(hits);
            }
        } else {
            out.push(w);
        }
    }
    out
}

const BINARIES: &[(&str, &str)] = &[
    ("cat", "/bin/cat"),
    ("echo", "/bin/echo"),
    ("ls", "/bin/ls"),
    ("ping", "/bin/ping"),
    ("sh", "/bin/sh"),
    ("sleep", "/bin/sleep"),
    ("uname", "/bin/uname"),
    ("head", "/usr/bin/head"),
    ("id", "/usr/bin/id"),
    ("whoami", "/usr/bin/whoami"),
];

pub const ID_OUTPUT: &str = "uid=33(www-data) gid=33(www-data) groups=33(www-data)";
pub const UNAME_A: &str =
    "Linux demo-shop 6.1.0-18-amd64 #1 SMP PREEMPT_DYNAMIC Debian 6.1.76-1 x86_64 GNU/Linux";

/// One simple command. Returns (stdout, stderr, status).
fn exec(argv: &[String], stdin: &str, depth: usize) -> (String, String, i32) {
    let name = argv[0].as_str();
    // merged /usr (Debian 12): /bin and /usr/bin are the same directory
    let base = if name.contains('/') {
        fs::resolve("/srv/app", name).ok().and_then(|r| {
            r.strip_prefix("/usr/bin/")
                .or_else(|| r.strip_prefix("/bin/"))
                .map(str::to_string)
        })
    } else {
        Some(name.to_string())
    };
    let cmd = base.and_then(|b| BINARIES.iter().find(|(n, _)| *n == b).map(|(n, _)| *n));
    let args = &argv[1..];
    let Some(cmd) = cmd else {
        return (String::new(), format!("sh: 1: {name}: not found\n"), 127);
    };
    match cmd {
        "id" => (format!("{ID_OUTPUT}\n"), String::new(), 0),
        "whoami" => ("www-data\n".into(), String::new(), 0),
        "uname" => {
            let all = args.iter().any(|a| a == "-a");
            (
                format!("{}\n", if all { UNAME_A } else { "Linux" }),
                String::new(),
                0,
            )
        }
        "echo" => (format!("{}\n", args.join(" ")), String::new(), 0),
        "sleep" | "sh" => (String::new(), String::new(), 0),
        "ls" => {
            let dir = args
                .iter()
                .find(|a| !a.starts_with('-'))
                .map(String::as_str)
                .unwrap_or(".");
            match fs::resolve("/srv/app", dir) {
                Ok(d) if fs::is_dir(&d) => (fs::list(&d).join("\n") + "\n", String::new(), 0),
                Ok(f) if fs::read("/", &f).is_ok() => (format!("{dir}\n"), String::new(), 0),
                _ => (
                    String::new(),
                    format!("ls: cannot access '{dir}': No such file or directory\n"),
                    2,
                ),
            }
        }
        "cat" | "head" => {
            let files: Vec<&String> = args.iter().filter(|a| !a.starts_with('-')).collect();
            if files.is_empty() {
                let text = if cmd == "head" {
                    stdin.lines().take(10).flat_map(|l| [l, "\n"]).collect()
                } else {
                    stdin.to_string()
                };
                return (text, String::new(), 0);
            }
            let (mut out, mut err, mut status) = (String::new(), String::new(), 0);
            for f in files {
                match fs::read("/srv/app", f) {
                    Ok(c) if cmd == "head" => {
                        out.extend(c.lines().take(10).map(|l| format!("{l}\n")));
                    }
                    Ok(c) => out.push_str(c),
                    Err(e) => {
                        err.push_str(&format!("{cmd}: {f}: {}\n", e.message()));
                        status = 1;
                    }
                }
            }
            (out, err, status)
        }
        "ping" => ping(args, depth),
        _ => (String::new(), String::new(), 0),
    }
}

fn ping(args: &[String], _depth: usize) -> (String, String, i32) {
    // `-c 1` and other options; the last operand is the host
    let mut hosts = Vec::new();
    let mut skip = false;
    for a in args {
        if skip {
            skip = false;
            continue;
        }
        if a == "-c" || a == "-W" || a == "-i" {
            skip = true;
        } else if !a.starts_with('-') {
            hosts.push(a.as_str());
        }
    }
    let Some(host) = hosts.last() else {
        return (
            String::new(),
            "ping: usage error: Destination address required\n".into(),
            1,
        );
    };
    let ip = match *host {
        "localhost" | "127.0.0.1" => Some("127.0.0.1"),
        "example.com" | "shop.example" => Some("93.184.215.14"),
        h if h.split('.').count() == 4 && h.split('.').all(|o| o.parse::<u8>().is_ok()) => Some(h),
        _ => None,
    };
    match ip {
        Some(ip) => (
            format!(
                "PING {host} ({ip}) 56(84) bytes of data.\n64 bytes from {ip}: icmp_seq=1 ttl=64 time=0.042 ms\n\n--- {host} ping statistics ---\n1 packets transmitted, 1 received, 0% packet loss, time 0ms\n"
            ),
            String::new(),
            0,
        ),
        None => (
            String::new(),
            format!("ping: {host}: Name or service not known\n"),
            2,
        ),
    }
}

fn run_nested(script: &str, depth: usize) -> Result<Output, SyntaxError> {
    let mut lx = Lexer {
        s: script.as_bytes(),
        i: 0,
        depth,
    };
    let toks = lx.tokens(None)?;
    Ok(execute(&toks, depth))
}

/// Runs a script and returns what `shell_exec` captures: stdout, plus the stderr of
/// commands that redirect it there (`2>&1`). A syntax error runs nothing; `sh` reports it
/// on its own stderr, which is not captured.
pub fn run(script: &str) -> Output {
    run_nested(script, 0).unwrap_or(Output {
        stdout: String::new(),
        status: 2,
    })
}

struct Simple {
    argv: Vec<String>,
    redirects: Vec<(u32, &'static str, String)>,
}

fn execute(toks: &[Token], depth: usize) -> Output {
    // split into and-or lists of pipelines
    let mut out = String::new();
    let mut status = 0;
    let mut i = 0;
    let mut skip_next = false; // && / || short-circuit
    while i < toks.len() {
        // one pipeline
        let mut pipeline: Vec<Simple> = Vec::new();
        let mut cur = Simple {
            argv: Vec::new(),
            redirects: Vec::new(),
        };
        let mut sep = ";";
        while i < toks.len() {
            match &toks[i] {
                Token::Word(p) => cur.argv.extend(fields(p)),
                Token::Redirect { fd, kind } => {
                    let target = match toks.get(i + 1) {
                        Some(Token::Word(p)) => fields(p).join(" "),
                        _ => {
                            return Output {
                                stdout: out,
                                status: 2,
                            };
                        }
                    };
                    cur.redirects.push((*fd, kind, target));
                    i += 1;
                }
                Token::Op("|") => {
                    pipeline.push(std::mem::replace(
                        &mut cur,
                        Simple {
                            argv: Vec::new(),
                            redirects: Vec::new(),
                        },
                    ));
                }
                Token::Op(op) => {
                    sep = op;
                    i += 1;
                    break;
                }
            }
            i += 1;
        }
        pipeline.push(cur);
        if !skip_next {
            let mut stdin = String::new();
            for (k, cmd) in pipeline.iter().enumerate() {
                let last = k + 1 == pipeline.len();
                let mut input = std::mem::take(&mut stdin);
                for (fd, kind, target) in &cmd.redirects {
                    if *fd == 0 && *kind == "<" {
                        input = fs::read("/srv/app", target).unwrap_or("").to_string();
                    }
                }
                let (so, se, st) = if cmd.argv.is_empty() {
                    (String::new(), String::new(), 0)
                } else {
                    exec(&cmd.argv, &input, depth)
                };
                status = st;
                let (mut so, mut se) = (so, se);
                for (fd, kind, target) in &cmd.redirects {
                    match (*fd, *kind, target.as_str()) {
                        (2, ">&", "1") => {
                            so.push_str(&se);
                            se.clear();
                        }
                        (1, ">&", "2") => {
                            se.push_str(&so);
                            so.clear();
                        }
                        (1, ">" | ">>", _) => so.clear(),
                        (2, ">" | ">>", _) => se.clear(),
                        _ => {}
                    }
                }
                // what is left on stderr is not captured
                drop(se);
                if last {
                    out.push_str(&so);
                } else {
                    stdin = so;
                }
            }
        }
        skip_next = match sep {
            "&&" => skip_next || status != 0,
            "||" => !skip_next && status == 0,
            _ => false,
        };
    }
    Output {
        stdout: out,
        status,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn page(host: &str) -> String {
        run(&format!("ping -c 1 {host} 2>&1")).stdout
    }

    fn pwned(host: &str) -> bool {
        let o = page(host);
        o.contains("33(www-data)") || o.contains(fs::PASSWD_MARKER) || o.contains(UNAME_A)
    }

    #[test]
    fn plain_ping_works() {
        let o = page("127.0.0.1");
        assert!(o.contains("1 packets transmitted"), "{o}");
        assert!(page("no.such.host").contains("Name or service not known"));
        assert!(!pwned("127.0.0.1"));
    }

    #[test]
    fn injections_run_commands() {
        for p in [
            "127.0.0.1; id",
            "127.0.0.1;id",
            "127.0.0.1 && id",
            "x || id",
            "127.0.0.1 | id",
            "127.0.0.1 & id",
            "127.0.0.1\nid",
            "$(id)",
            "`id`",
            "127.0.0.1; cat /etc/passwd",
            "127.0.0.1;cat${IFS}/etc/passwd",
            "127.0.0.1;cat$IFS/etc/passwd",
            "127.0.0.1;c'a't /etc/passwd",
            "127.0.0.1;c\"a\"t /etc/passwd",
            "127.0.0.1;c\\at /etc/passwd",
            "127.0.0.1;/bin/cat /etc/passwd",
            "127.0.0.1;/usr/bin/cat /etc/passwd",
            "127.0.0.1;/bin/id",
            "127.0.0.1;/???/c?t /e??/p?ss??",
            "127.0.0.1;cat</etc/passwd",
            "127.0.0.1;i$@d",
            "127.0.0.1;w${u}hoami;id",
            "127.0.0.1;uname -a",
            "127.0.0.1;head /etc/passwd #",
            "127.0.0.1;$(echo id)",
            "127.0.0.1;cat /srv/app/../../etc/passwd",
        ] {
            assert!(pwned(p), "{p}: {}", page(p));
        }
    }

    #[test]
    fn broken_or_harmless_injections_do_not() {
        for p in [
            "127.0.0.1 && id'",
            "127.0.0.1 || id",
            "127.0.0.1; ID",
            "127.0.0.1; {cat,/etc/passwd}",
            "127.0.0.1; cat /etc/shadow",
            "127.0.0.1; id > /tmp/x",
            "'127.0.0.1; id'",
            "127.0.0.1\\; id",
            "127.0.0.1 # ; id",
            "$((1+1))",
            "127.0.0.1; echo uid",
        ] {
            assert!(!pwned(p), "{p}: {}", page(p));
        }
    }

    #[test]
    fn command_substitution_in_ping_leaks_via_stderr() {
        // `2>&1` at the end of the page's command line shows ping's error
        let o = page("$(whoami)");
        assert!(
            o.contains("ping: www-data: Name or service not known"),
            "{o}"
        );
        // with the trailing `2>&1` commented out, the error is not shown
        let o = run("ping -c 1 $(id) # 2>&1").stdout;
        assert!(o.is_empty(), "{o}");
        assert!(
            run("ping -c 1 'x").stdout.is_empty(),
            "syntax errors run nothing"
        );
    }
}
