//! Server- and browser-like decoding of inspected values.

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

pub(crate) fn percent_decode(s: &str, form: bool) -> String {
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
}
