//! Large phrase lists from the OWASP Core Rule Set (Apache-2.0, see `data/crs/README.md`),
//! matched case-insensitively with Aho-Corasick and scored as WAF indicators.

use aho_corasick::{AhoCorasick, AhoCorasickBuilder, MatchKind};

use crate::indicators::AttackClass;

/// Where a list applies and what a hit must look like.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Scope {
    /// Any inspected value except the URL path.
    Values,
    /// Only the URL path.
    Path,
    /// Any value; the phrase must start at a word boundary and be followed by `(`
    /// (a function call), so English words that are also function names don't count.
    Call,
}

struct Lexicon {
    name: &'static str,
    class: AttackClass,
    weight: f64,
    scope: Scope,
    ac: AhoCorasick,
}

pub(crate) struct Lexicons {
    lists: Vec<Lexicon>,
}

fn phrases(data: &str) -> Vec<String> {
    data.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(|l| l.to_ascii_lowercase())
        .collect()
}

impl Lexicons {
    pub(crate) fn new() -> Self {
        let lists = [
            (
                "lfi_os_file",
                AttackClass::PathTraversal,
                3.0,
                Scope::Values,
                include_str!("../data/crs/lfi-os-files.data"),
            ),
            (
                "restricted_file",
                AttackClass::PathTraversal,
                7.0,
                Scope::Path,
                include_str!("../data/crs/restricted-files.data"),
            ),
            (
                "unix_shell",
                AttackClass::CommandInjection,
                4.0,
                Scope::Values,
                include_str!("../data/crs/unix-shell.data"),
            ),
            (
                "php_function_call",
                AttackClass::PhpInjection,
                5.0,
                Scope::Call,
                include_str!("../data/crs/php-function-names-933150.data"),
            ),
            (
                "java_class",
                AttackClass::JavaInjection,
                6.0,
                Scope::Values,
                include_str!("../data/crs/java-classes.data"),
            ),
        ]
        .into_iter()
        .map(|(name, class, weight, scope, data)| Lexicon {
            name,
            class,
            weight,
            scope,
            ac: AhoCorasickBuilder::new()
                .ascii_case_insensitive(true)
                .match_kind(MatchKind::LeftmostLongest)
                .build(phrases(data))
                .expect("CRS phrase lists build"),
        })
        .collect();
        Self { lists }
    }

    /// Indicators hit by `value` (already decoded and lowercased) at `location`.
    pub(crate) fn scan(
        &self,
        location: &str,
        value: &str,
    ) -> Vec<(AttackClass, &'static str, f64)> {
        let is_path = location == "path";
        let bytes = value.as_bytes();
        let mut out = Vec::new();
        for l in &self.lists {
            let applies = match l.scope {
                Scope::Path => is_path,
                Scope::Values => !is_path,
                Scope::Call => true,
            };
            if !applies {
                continue;
            }
            let hit = l.ac.find_iter(value).any(|m| match l.scope {
                Scope::Call => {
                    let before_ok = m.start() == 0
                        || !(bytes[m.start() - 1].is_ascii_alphanumeric()
                            || bytes[m.start() - 1] == b'_');
                    let after = value[m.end()..].trim_start();
                    before_ok && after.starts_with('(')
                }
                _ => true,
            });
            if hit {
                out.push((l.class, l.name, l.weight));
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn names(l: &Lexicons, loc: &str, v: &str) -> Vec<&'static str> {
        l.scan(loc, v).into_iter().map(|(_, n, _)| n).collect()
    }

    #[test]
    fn lists_load_and_match() {
        let l = Lexicons::new();
        assert!(
            l.lists.iter().all(|x| x.ac.patterns_len() > 50),
            "every list loaded"
        );
        assert!(names(&l, "query:f", "../../etc/passwd").contains(&"lfi_os_file"));
        assert!(names(&l, "path", "/.git/config").contains(&"restricted_file"));
        assert!(
            !names(&l, "query:f", ".git/config").contains(&"restricted_file"),
            "path-only list"
        );
        assert!(names(&l, "body:cmd", "; /bin/bash -c id").contains(&"unix_shell"));
        assert!(names(&l, "body:x", "java.lang.Runtime").contains(&"java_class"));
    }

    #[test]
    fn php_functions_need_a_call() {
        let l = Lexicons::new();
        assert!(
            names(&l, "query:x", "file_get_contents('/etc/passwd')").contains(&"php_function_call")
        );
        assert!(names(&l, "query:x", "file_get_contents ( $f )").contains(&"php_function_call"));
        assert!(
            !names(&l, "query:x", "please file_get_contents later").contains(&"php_function_call")
        );
        assert!(
            !names(&l, "query:x", "my_file_get_contents(1)").contains(&"php_function_call"),
            "word boundary"
        );
    }
}
