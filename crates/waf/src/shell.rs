//! Shell command analysis: undoes common shell evasions, splits a value into the
//! commands a shell would run and recognises Unix command names from the OWASP CRS
//! `unix-shell.data` list (Apache-2.0, see `data/crs/README.md`).
//!
//! A command word on its own is weak evidence ("Hello; find attached"). What scores
//! high is a command word in a position a shell would execute it (after `;`, `|`, `&`,
//! a newline, a backtick or `$(`) together with shell-shaped arguments (`-x` flags,
//! paths, `$variables`, redirections).

use std::collections::HashSet;

use regex::Regex;

/// Commands that give an attacker a shell, the network or code execution.
const DANGEROUS: &[&str] = &[
    "sh", "bash", "dash", "zsh", "ksh", "csh", "tcsh", "ash", "fish", "busybox", "nc", "ncat",
    "netcat", "socat", "telnet", "curl", "wget", "lynx", "ftp", "tftp", "python", "perl", "ruby",
    "php", "lua", "node", "irb", "chmod", "chown", "rm", "mkfifo", "base64", "xxd", "gcc", "cc",
    "c89", "c99", "awk", "gawk", "nawk", "mawk", "nohup", "crontab", "sudo", "su", "eval", "exec",
    "dd", "nmap", "ssh", "scp",
];

/// Extra command names not in the CRS list.
const EXTRA: &[&str] = &[
    "cd", "whoami", "uname", "ifconfig", "busybox", "column", "bridge", "mkfifo", "chmod", "chown",
    "netcat", "socat", "python", "python2", "python3", "base32", "hostname", "printenv", "crontab",
    "nohup", "xargs", "touch", "mkdir", "chgrp", "wget", "zstdcat", "gunzip",
];

/// Separators after which a shell starts a new command. Backticks are left to the
/// regex indicators: Markdown uses them for inline code.
const SEPARATORS: &[char] = &[';', '\n', '|', '&', '(', ')', '{', '}'];

pub(crate) struct Shell {
    commands: HashSet<String>,
    dangerous: HashSet<&'static str>,
    ifs: Regex,
    brace: Regex,
    class: Regex,
    empty_expansion: Regex,
    windows_for: Regex,
    windows_if: Regex,
    windows_if_weak: Regex,
}

impl Shell {
    pub(crate) fn new() -> Self {
        let mut commands: HashSet<String> = include_str!("../data/crs/unix-shell.data")
            .lines()
            .filter_map(|l| l.trim().strip_prefix("bin/"))
            .map(str::to_ascii_lowercase)
            .collect();
        commands.extend(
            include_str!("../data/crs/unix-shell-builtins.data")
                .lines()
                .map(str::trim)
                .filter(|l| !l.is_empty() && !l.starts_with('#'))
                .map(str::to_ascii_lowercase),
        );
        commands.extend(EXTRA.iter().map(|s| s.to_string()));
        Self {
            commands,
            dangerous: DANGEROUS.iter().copied().collect(),
            ifs: Regex::new(r"\$\{ifs[^}]*\}|\$ifs\b").unwrap(),
            // {cat,/etc/passwd} → cat /etc/passwd
            brace: Regex::new(r"\{([^{}\s,]*,[^{}\s]*)\}").unwrap(),
            // pa[s]swd → passwd
            class: Regex::new(r"\[(\w)\]").unwrap(),
            // c$()at, c${u}at, c$@at → cat (empty or unset expansions)
            empty_expansion: Regex::new(r"\$\(\s*\)|\$\{\w?\}|\$[@*]").unwrap(),
            windows_for: Regex::new(
                r#"\bfor(\s*/[dflr]\b[^%]*)?\s*%%?[^\s]+\s+in\s*\(.*\)\s*do\b"#,
            )
            .unwrap(),
            windows_if: Regex::new(
                r#"\bif(\s+/i)?(\s+not)?\s+(exist\s|errorlevel\s|defined\s|cmdextversion\s|[^&|;]*\s(equ|neq|lss|leq|gtr|geq)\s|[^&|;]*%[^%\s]*%?[^&|;]*==|\S+\s*==\s*\S+\s+(echo|goto|call|exit|set|cmd)\b)"#,
            )
            .unwrap(),
            windows_if_weak: Regex::new(r#"\bif\s+(\(|"|%)"#).unwrap(),
        }
    }

    /// Undoes quote, backslash, `${IFS}`, brace-expansion, character-class and
    /// empty-expansion tricks. Input is decoded and lowercased.
    pub(crate) fn normalize(&self, v: &str) -> String {
        let s: String = v
            .chars()
            .filter(|c| !matches!(c, '\\' | '\'' | '"' | '^'))
            .collect();
        let s = self.ifs.replace_all(&s, " ");
        let s = self.empty_expansion.replace_all(&s, "");
        let s = self.class.replace_all(&s, "$1");
        self.brace
            .replace_all(&s, |c: &regex::Captures| c[1].replace(',', " "))
            .into_owned()
    }

    /// Shell indicators for one decoded, lowercased value.
    pub(crate) fn scan(&self, value: &str) -> Vec<(&'static str, f64)> {
        let mut out = Vec::new();
        if self.windows_for.is_match(value) {
            out.push(("windows_for_loop", 7.0));
        }
        if self.windows_if.is_match(value) {
            out.push(("windows_if_command", 7.0));
        } else if self.windows_if_weak.is_match(value) {
            out.push(("windows_if_weak", 2.0));
        }

        let norm = self.normalize(value);
        let mut chained = false;
        let mut at_start = false;
        let mut args = false;
        let mut dangerous = false;
        let mut commands = 0;
        let mut rest = norm.as_str();
        let mut first = true;
        loop {
            let (segment, next) = match rest.find(SEPARATORS) {
                Some(i) => {
                    let sep_len = rest[i..].chars().next().map_or(1, char::len_utf8);
                    (&rest[..i], Some(&rest[i + sep_len..]))
                }
                None => (rest, None),
            };
            // `$(` opens a command like `(`: drop the `$` left at the end of the segment
            let segment = segment.strip_suffix('$').unwrap_or(segment);
            if let Some((cmd, has_args, bare)) = self.command(segment) {
                commands += 1;
                if first {
                    at_start = true;
                } else {
                    chained = true;
                }
                args |= has_args;
                // A sentence may start with a command word ("rm -rf is dangerous") and
                // user agents list "; java 1.8.0": only a command after a separator,
                // with shell arguments or on its own (`;sh`), counts as dangerous.
                dangerous |= !first && (has_args || bare) && self.dangerous.contains(cmd.as_str());
            }
            first = false;
            match next {
                Some(n) => rest = n,
                None => break,
            }
        }
        if commands == 0 {
            return out;
        }
        if chained {
            out.push(("shell_chained_command", 5.0));
        } else if at_start {
            out.push(("shell_command_word", 3.0));
        }
        if args {
            out.push(("shell_command_args", 3.0));
        }
        if dangerous {
            out.push(("shell_dangerous_command", 2.0));
        }
        if commands >= 3 {
            out.push(("shell_command_sequence", 2.0));
        }
        out
    }

    /// The command a shell segment starts with, and whether its arguments look like a
    /// shell's (flags, paths, variables, redirections), and whether it has no
    /// arguments at all.
    fn command(&self, segment: &str) -> Option<(String, bool, bool)> {
        let mut words = segment.split_whitespace().peekable();
        // skip `!`, variable assignments (a=b cmd) and redirections before the command
        while let Some(w) = words.peek() {
            if *w == "!" || (w.contains('=') && !w.starts_with('=')) || w.starts_with('>') {
                words.next();
            } else {
                break;
            }
        }
        let word = words.next()?;
        // /usr/bin/id → id, python3.10 → python
        let base = word.rsplit('/').next().unwrap_or(word);
        let name = base.trim_end_matches(|c: char| c.is_ascii_digit() || c == '.');
        let name = if self.commands.contains(base) {
            base
        } else {
            name
        };
        if name.is_empty() || !self.commands.contains(name) {
            return None;
        }
        // a bare word inside a sentence ("I like cat videos") has no shell syntax around it
        let rest: Vec<&str> = words.collect();
        let has_args = rest.iter().any(|a| {
            (a.len() > 1
                && (a.starts_with('-') || a.starts_with('+'))
                && !a[1..].starts_with('-')
                && a[1..2].chars().all(|c| c.is_ascii_alphanumeric()))
                || a.starts_with('/')
                || a.starts_with("~")
                || a.starts_with("./")
                || a.starts_with('$')
                || a.starts_with('>')
                || a.starts_with('<')
                || a.contains("/etc/")
                || a.contains("/tmp/")
                || a.contains("/var/")
        }) || segment.contains('>')
            || segment.contains("&&");
        Some((name.to_string(), has_args, rest.is_empty()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn score(s: &Shell, v: &str) -> f64 {
        s.scan(v).iter().map(|(_, w)| w).sum()
    }

    #[test]
    fn chained_commands_with_arguments_score_high() {
        let s = Shell::new();
        for v in [
            ";cp /var/log/apache2/error.log evil.php",
            "cd /;cd etc;column passwd",
            ";c89 -wrapper sh,-c,id .",
            ";chmod +x evil.php",
            ";find /etc -name passwd -exec cat {} +",
            "a;{cat,/etc/passwd}",
            "x|c$()at /et$@c/pa[s]swd",
            "x;cat${ifs}/etc/passwd",
        ] {
            assert!(score(&s, v) >= 7.0, "{v}: {:?}", s.scan(v));
        }
    }

    #[test]
    fn prose_and_bare_words_stay_low() {
        let s = Shell::new();
        for v in [
            "hello; find attached the report",
            "i like cat videos",
            "tom & jerry",
            "rock|paper|scissors",
            "sort by date",
            "if you want, (call me)",
            "for each item in (list) we do nothing",
            "see /about for more",
            "rm -rf is dangerous, don't run it",
            "entering the `ls` command in your shell:",
            "yacybot (/global; amd64 linux 3.12.1; java 1.7.0_65; europe/en) http://yacy.net/bot.html",
            "busybox -c \"echo hi\"",
        ] {
            assert!(score(&s, v) < 7.0, "{v}: {:?}", s.scan(v));
        }
    }

    #[test]
    fn windows_batch_syntax() {
        let s = Shell::new();
        for v in [
            "for /f \"usebackq\" %variable in (`command`) do command",
            "for %%g in (sun mon) do echo %%g",
            "if exist c:\\pagefile.sys (cmd) else (cmd)",
            "if not errorlevel 0 cmd",
            "if %n1% lss %n2% echo less",
            "if \"%~1\"==\"/?\" goto help",
        ] {
            assert!(score(&s, v) >= 7.0, "{v}: {:?}", s.scan(v));
        }
    }
}
