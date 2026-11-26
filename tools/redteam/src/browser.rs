//! A tiny HTML tokenizer that answers one question: would a browser run script from this
//! page? It follows the HTML tokenizer where reflected XSS depends on it: tag names end at
//! whitespace, `/` or `>`; attributes may be unquoted, quoted with `"` or `'`, or separated
//! by `/`; character references are decoded in attribute values; `<script>`, `<style>`,
//! `<textarea>` and `<title>` contents are raw text; comments are skipped.
//!
//! Script runs from: a `<script>` element with a `src` or non-empty content (closed by
//! `</script`), any `on…` event-handler attribute with a non-empty value, and `href`,
//! `src`, `action`, `formaction`, `data` or `xlink:href` whose value is a `javascript:`
//! URL (after decoding and stripping what browsers strip). The JavaScript itself is not
//! evaluated.

fn decode_entities(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(i) = rest.find('&') {
        out.push_str(&rest[..i]);
        rest = &rest[i..];
        let body = &rest[1..];
        let (ch, used) = if let Some(num) = body.strip_prefix('#') {
            let (hex, digits) = match num.strip_prefix(['x', 'X']) {
                Some(h) => (true, h),
                None => (false, num),
            };
            let n = digits
                .chars()
                .take_while(|c| {
                    if hex {
                        c.is_ascii_hexdigit()
                    } else {
                        c.is_ascii_digit()
                    }
                })
                .count();
            let value = if hex {
                u32::from_str_radix(&digits[..n], 16).ok()
            } else {
                digits[..n].parse().ok()
            };
            match value.and_then(char::from_u32) {
                Some(c) if n > 0 => {
                    let mut used = 1 + 1 + usize::from(hex) + n;
                    if rest[used..].starts_with(';') {
                        used += 1;
                    }
                    (Some(c), used)
                }
                _ => (None, 1),
            }
        } else {
            const NAMED: &[(&str, char)] = &[
                ("lt;", '<'),
                ("gt;", '>'),
                ("amp;", '&'),
                ("quot;", '"'),
                ("apos;", '\''),
                ("colon;", ':'),
                ("Tab;", '\t'),
                ("NewLine;", '\n'),
                ("lpar;", '('),
                ("rpar;", ')'),
                ("sol;", '/'),
                ("lt", '<'),
                ("gt", '>'),
                ("amp", '&'),
                ("quot", '"'),
            ];
            match NAMED.iter().find(|(n, _)| body.starts_with(n)) {
                Some((n, c)) => (Some(*c), 1 + n.len()),
                None => (None, 1),
            }
        };
        match ch {
            Some(c) => out.push(c),
            None => out.push('&'),
        }
        rest = &rest[used..];
    }
    out.push_str(rest);
    out
}

fn is_js_url(v: &str) -> bool {
    // browsers drop leading/trailing C0 controls and spaces, and tabs / newlines anywhere
    let cleaned: String = v
        .trim_matches(|c: char| c <= ' ')
        .chars()
        .filter(|c| !matches!(c, '\t' | '\n' | '\r'))
        .collect();
    cleaned.to_ascii_lowercase().starts_with("javascript:")
}

const URL_ATTRS: &[&str] = &["href", "src", "action", "formaction", "data", "xlink:href"];
const RAW_TEXT: &[&str] = &["script", "style", "textarea", "title", "xmp", "noscript"];

/// The first construct in `html` that runs script, described (`"<img onerror>"`), if any.
pub fn script_runs(html: &str) -> Option<String> {
    let b = html.as_bytes();
    let mut i = 0;
    while i < b.len() {
        if b[i] != b'<' {
            i += 1;
            continue;
        }
        if html[i..].starts_with("<!--") {
            i = html[i + 4..].find("-->").map_or(b.len(), |e| i + 4 + e + 3);
            continue;
        }
        if matches!(b.get(i + 1), Some(b'!' | b'?' | b'/')) {
            // doctype, bogus comment or end tag: skip to `>`
            i = html[i..].find('>').map_or(b.len(), |e| i + e + 1);
            continue;
        }
        if !b.get(i + 1).is_some_and(u8::is_ascii_alphabetic) {
            i += 1;
            continue;
        }
        // tag name
        let mut j = i + 1;
        while j < b.len() && !matches!(b[j], b' ' | b'\t' | b'\n' | b'\r' | 0x0c | b'/' | b'>') {
            j += 1;
        }
        let name = html[i + 1..j].to_ascii_lowercase();
        // attributes
        let mut attrs: Vec<(String, String)> = Vec::new();
        loop {
            while j < b.len() && matches!(b[j], b' ' | b'\t' | b'\n' | b'\r' | 0x0c | b'/') {
                j += 1;
            }
            if j >= b.len() {
                break;
            }
            if b[j] == b'>' {
                j += 1;
                break;
            }
            let ns = j;
            j += 1; // an attribute name may start with `=` or a quote: take one byte
            while j < b.len()
                && !matches!(
                    b[j],
                    b' ' | b'\t' | b'\n' | b'\r' | 0x0c | b'/' | b'>' | b'='
                )
            {
                j += 1;
            }
            let aname = html[ns..j].to_ascii_lowercase();
            while j < b.len() && matches!(b[j], b' ' | b'\t' | b'\n' | b'\r' | 0x0c) {
                j += 1;
            }
            let mut value = String::new();
            if j < b.len() && b[j] == b'=' {
                j += 1;
                while j < b.len() && matches!(b[j], b' ' | b'\t' | b'\n' | b'\r' | 0x0c) {
                    j += 1;
                }
                if j < b.len() && (b[j] == b'"' || b[j] == b'\'') {
                    let q = b[j];
                    let vs = j + 1;
                    let ve = b[vs..]
                        .iter()
                        .position(|&x| x == q)
                        .map_or(b.len(), |p| vs + p);
                    value = decode_entities(&html[vs..ve]);
                    j = (ve + 1).min(b.len());
                } else {
                    let vs = j;
                    while j < b.len() && !matches!(b[j], b' ' | b'\t' | b'\n' | b'\r' | 0x0c | b'>')
                    {
                        j += 1;
                    }
                    value = decode_entities(&html[vs..j]);
                }
            }
            attrs.push((aname, value));
        }
        for (a, v) in &attrs {
            if a.starts_with("on") && a.len() > 2 && !v.trim().is_empty() {
                return Some(format!("<{name} {a}>"));
            }
            if URL_ATTRS.contains(&a.as_str()) && is_js_url(v) {
                return Some(format!("<{name} {a}=javascript:>"));
            }
        }
        if RAW_TEXT.contains(&name.as_str()) {
            let close = format!("</{name}");
            let lower = html[j.min(b.len())..].to_ascii_lowercase();
            // an unclosed raw-text element swallows the rest of the page
            let end = lower.find(&close)?;
            let content = &html[j..j + end];
            if name == "script"
                && (attrs.iter().any(|(a, v)| a == "src" && !v.is_empty())
                    || !content.trim().is_empty())
            {
                return Some("<script>".into());
            }
            i = j + end;
            continue;
        }
        i = j;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reflect(q: &str) -> String {
        format!(
            "<!doctype html><html><head><title>Search</title></head><body><form action=\"/search\"><input name=\"q\" value=\"{q}\"></form><p>Results for: {q}</p></body></html>"
        )
    }

    #[test]
    fn the_page_itself_runs_nothing() {
        assert_eq!(script_runs(&reflect("coffee grinder")), None);
        assert_eq!(script_runs(&reflect("O'Brien <3 & co")), None);
        assert_eq!(script_runs(&reflect("1 < 2 > 0")), None);
    }

    #[test]
    fn reflected_vectors_run() {
        for p in [
            "<script>alert(1)</script>",
            "<ScRiPt>alert(1)</sCrIpT>",
            "<script >alert(1)</script >",
            "<img src=x onerror=alert(1)>",
            "<img src=x onerror=alert(1)//",
            "<svg/onload=alert(1)>",
            "<svg onload=alert`1`>",
            "<body onload=alert(1)>",
            "<details open ontoggle=alert(1)>",
            "<img src=x oNeRrOr=&#97;lert(1)>",
            "<a href=\"java&#x09;script:alert(1)\">x</a>",
            "<a href=\"&#106;avascript:alert(1)\">x</a>",
            "<iframe src=javascript:alert(1)>",
            "\"><img src=x onerror=alert(1)>",
            "\" autofocus onfocus=alert(1) x=\"",
            "<script src=//evil.example/x.js></script>",
        ] {
            assert!(script_runs(&reflect(p)).is_some(), "{p}");
        }
    }

    #[test]
    fn inert_text_does_not() {
        for p in [
            "&lt;script&gt;alert(1)&lt;/script&gt;",
            "<b>bold</b>",
            "<img src=x>",
            "<img src=x onerror=>",
            "<a href=\"https://example.com/javascript:x\">x</a>",
            "<scrip>alert(1)</scrip>",
            "< script>alert(1)</script>",
            "<!-- <script>alert(1)</script> -->",
            "javascript:alert(1)",
            "onerror=alert(1)",
        ] {
            assert_eq!(script_runs(&reflect(p)), None, "{p}");
        }
        // inside <title>, markup is text
        assert_eq!(
            script_runs("<title><img src=x onerror=alert(1)></title>"),
            None
        );
    }
}
