//! Server- and browser-like decoding of inspected values.

/// URL / `%u` / HTML-entity / JS-escape decoding (repeated), keeping case and whitespace.
pub(crate) fn decode_keep_case(raw: &str, form: bool) -> String {
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
    s
}

/// If `s` looks like base64 (or a base64 fragment), its readable decodings at each of the
/// four alignments, lowercased. Lets indicators see payloads hidden in base64.
pub(crate) fn base64_variants(s: &str) -> Vec<String> {
    let s = s.trim();
    let is_b64 = |c: char| c.is_ascii_alphanumeric() || matches!(c, '+' | '/' | '-' | '_' | '=');
    if s.len() < 12 || s.len() > 16 * 1024 || !s.chars().all(is_b64) {
        return Vec::new();
    }
    let has_digit_or_upper = s
        .chars()
        .any(|c| c.is_ascii_digit() || c.is_ascii_uppercase());
    if !has_digit_or_upper {
        return Vec::new();
    }
    let val = |c: u8| -> Option<u32> {
        Some(match c {
            b'A'..=b'Z' => (c - b'A') as u32,
            b'a'..=b'z' => (c - b'a' + 26) as u32,
            b'0'..=b'9' => (c - b'0' + 52) as u32,
            b'+' | b'-' => 62,
            b'/' | b'_' => 63,
            _ => return None,
        })
    };
    let bytes: Vec<u8> = s.bytes().filter(|b| *b != b'=').collect();
    let mut out = Vec::new();
    for skip in 0..4 {
        if bytes.len() < skip + 8 {
            break;
        }
        let mut decoded = Vec::with_capacity(bytes.len() * 3 / 4);
        for chunk in bytes[skip..].chunks(4) {
            if chunk.len() < 2 {
                break;
            }
            let mut n = 0u32;
            for (k, c) in chunk.iter().enumerate() {
                n |= val(*c).unwrap_or(0) << (18 - 6 * k);
            }
            decoded.push((n >> 16) as u8);
            if chunk.len() > 2 {
                decoded.push((n >> 8) as u8);
            }
            if chunk.len() > 3 {
                decoded.push(n as u8);
            }
        }
        let printable = decoded
            .iter()
            .filter(|b| b.is_ascii_graphic() || **b == b' ' || **b == b'\n' || **b == b'\t')
            .count();
        if decoded.len() >= 6 && printable * 10 >= decoded.len() * 8 {
            let text = String::from_utf8_lossy(&decoded).to_lowercase();
            if !out.contains(&text) {
                out.push(text);
            }
        }
    }
    out
}

/// Characters that browsers, IIS "best fit" mapping or 7-bit stripping turn into HTML
/// syntax: full-width and angle-quote brackets, `¼`/`¾` (0xBC/0xBE with the high bit
/// removed are `<`/`>`), `¢` (`"`). Returns `None` when the value has none of them.
pub(crate) fn fold_html_lookalikes(s: &str) -> Option<String> {
    let map = |c: char| -> Option<char> {
        Some(match c {
            '\u{ff1c}' | '\u{2039}' | '\u{ab}' | '\u{bc}' | '\u{fe64}' | '\u{2329}'
            | '\u{3008}' => '<',
            '\u{ff1e}' | '\u{203a}' | '\u{bb}' | '\u{be}' | '\u{fe65}' | '\u{232a}'
            | '\u{3009}' => '>',
            '\u{a2}' | '\u{ff02}' => '"',
            '\u{ff07}' => '\'',
            '\u{ff0f}' => '/',
            '\u{ff08}' => '(',
            '\u{ff09}' => ')',
            '\u{ff1d}' => '=',
            _ => return None,
        })
    };
    if s.is_ascii() || !s.chars().any(|c| map(c).is_some()) {
        return None;
    }
    Some(s.chars().map(|c| map(c).unwrap_or(c)).collect())
}

/// Look-alike dots and slashes folded to ASCII: full-width `．` `／` `＼`, division slash
/// `∕` (`%u2215`), one-dot leader `․`, small full stop `﹒`, and the hex notation `0x2e`
/// `0x2f` `0x5c`. Windows best-fit mapping and some path canonicalisers turn these into
/// `../`. Returns `None` when the value has none of them.
pub(crate) fn fold_path_lookalikes(s: &str) -> Option<String> {
    let map = |c: char| -> Option<char> {
        Some(match c {
            '\u{ff0e}' | '\u{2024}' | '\u{fe52}' => '.',
            '\u{2215}' | '\u{2044}' | '\u{ff0f}' | '\u{29f8}' => '/',
            '\u{ff3c}' | '\u{2216}' | '\u{fe68}' | '\u{29f9}' => '\\',
            _ => return None,
        })
    };
    let has_hex = s.contains("0x2e") || s.contains("0x2f") || s.contains("0x5c");
    if !has_hex && (s.is_ascii() || !s.chars().any(|c| map(c).is_some())) {
        return None;
    }
    let folded: String = s.chars().map(|c| map(c).unwrap_or(c)).collect();
    let folded = folded
        .replace("0x2e", ".")
        .replace("0x2f", "/")
        .replace("0x5c", "\\");
    (folded != s).then_some(folded)
}

/// UTF-7 (`+ADw-script+AD4-` is `<script>`), which some browsers and parsers honour
/// when a charset says so. Returns `None` unless decoding produced HTML or quote syntax.
pub(crate) fn utf7_decode(s: &str) -> Option<String> {
    if !s.contains('+') {
        return None;
    }
    let val = |c: u8| -> Option<u32> {
        Some(match c {
            b'A'..=b'Z' => (c - b'A') as u32,
            b'a'..=b'z' => (c - b'a' + 26) as u32,
            b'0'..=b'9' => (c - b'0' + 52) as u32,
            b'+' => 62,
            b'/' => 63,
            _ => return None,
        })
    };
    let b = s.as_bytes();
    let mut out = String::with_capacity(s.len());
    let mut changed = false;
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'+' && i + 1 < b.len() && val(b[i + 1]).is_some() {
            let mut j = i + 1;
            let (mut bits, mut nbits) = (0u32, 0u32);
            let mut units: Vec<u16> = Vec::new();
            while j < b.len() {
                let Some(v) = val(b[j]) else { break };
                bits = (bits << 6) | v;
                nbits += 6;
                if nbits >= 16 {
                    nbits -= 16;
                    units.push((bits >> nbits) as u16);
                    bits &= (1 << nbits) - 1;
                }
                j += 1;
            }
            if !units.is_empty() {
                out.extend(char::decode_utf16(units).map(|r| r.unwrap_or('\u{fffd}')));
                changed = true;
                i = if b.get(j) == Some(&b'-') { j + 1 } else { j };
                continue;
            }
        }
        let ch = s[i..].chars().next().unwrap_or('\u{fffd}');
        out.push(ch);
        i += ch.len_utf8();
    }
    (changed && out.contains(['<', '>', '"', '\''])).then_some(out)
}

/// Decodes like a permissive server/browser would, then lowercases and collapses whitespace.
pub fn decode(raw: &str, form: bool) -> String {
    let s = decode_keep_case(raw, form);
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
    String::from_utf8_lossy(&fold_overlong(out)).into_owned()
}

/// Overlong UTF-8 for ASCII (`%c0%ae` and `%e0%80%ae` are `.`, `%c0%af` is `/`) is
/// invalid, but permissive servers and path canonicalisers decode it. Folding it to the
/// ASCII character lets the traversal indicators see `../`. Valid UTF-8 is untouched.
fn fold_overlong(b: Vec<u8>) -> Vec<u8> {
    if !b.iter().any(|&x| matches!(x, 0xC0 | 0xC1 | 0xE0 | 0xF0)) {
        return b;
    }
    let cont = |i: usize| b.get(i).is_some_and(|&x| x & 0xC0 == 0x80);
    let low = |i: usize| b[i] & 0x3F;
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            0xC0 | 0xC1 if cont(i + 1) => {
                out.push(((b[i] & 0x1F) << 6) | low(i + 1));
                i += 2;
            }
            0xE0 if cont(i + 1) && cont(i + 2) && b[i + 1] < 0x82 => {
                out.push((low(i + 1) << 6) | low(i + 2));
                i += 3;
            }
            0xF0 if cont(i + 1)
                && cont(i + 2)
                && cont(i + 3)
                && b[i + 1] == 0x80
                && b[i + 2] < 0x82 =>
            {
                out.push((low(i + 2) << 6) | low(i + 3));
                i += 4;
            }
            x => {
                out.push(x);
                i += 1;
            }
        }
    }
    out
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
    // HTML5 names browsers decode inside attributes; these need the `;`
    const NAMED_STRICT: [(&str, char); 21] = [
        ("&tab;", '\t'),
        ("&newline;", '\n'),
        ("&nbsp;", ' '),
        ("&grave;", '`'),
        ("&excl;", '!'),
        ("&num;", '#'),
        ("&period;", '.'),
        ("&comma;", ','),
        ("&semi;", ';'),
        ("&equals;", '='),
        ("&quest;", '?'),
        ("&bsol;", '\\'),
        ("&lsqb;", '['),
        ("&rsqb;", ']'),
        ("&lcub;", '{'),
        ("&rcub;", '}'),
        ("&plus;", '+'),
        ("&ast;", '*'),
        ("&dollar;", '$'),
        ("&vert;", '|'),
        ("&percnt;", '%'),
    ];
    let lower: String = t.chars().take(12).collect::<String>().to_ascii_lowercase();
    for (name, c) in NAMED_STRICT {
        if lower.starts_with(name) {
            return (Some(c), name.len());
        }
    }
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
    fn utf7_payloads_are_revealed() {
        assert_eq!(
            utf7_decode("+ADw-script+AD4-alert(1)+ADw-/script+AD4-").as_deref(),
            Some("<script>alert(1)</script>")
        );
        assert_eq!(utf7_decode("c++ and 1+1=2"), None);
        assert_eq!(
            utf7_decode("price +ADA-"),
            None,
            "decodes to a digit, no HTML"
        );
    }

    #[test]
    fn base64_payloads_are_revealed() {
        // "processbuilder" and an unaligned fragment of a longer encoding
        assert!(
            base64_variants("cHJvY2Vzc2J1aWxkZXI")
                .iter()
                .any(|v| v.contains("processbuilder"))
        );
        // an unaligned fragment loses its first character: "…nstantiatefactory"
        assert!(
            base64_variants("BpbnN0YW50aWF0ZWZhY3Rvcnk")
                .iter()
                .any(|v| v.contains("nstantiatefactory"))
        );
        assert!(
            base64_variants("PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==")
                .iter()
                .any(|v| v.contains("<script>"))
        );
        assert!(
            base64_variants("internationalization").is_empty(),
            "plain words are skipped"
        );
        assert!(base64_variants("short").is_empty());
    }

    #[test]
    fn path_lookalikes_fold_to_ascii() {
        assert_eq!(
            fold_path_lookalikes("\u{ff0e}\u{ff0e}\u{2215}x").as_deref(),
            Some("../x")
        );
        assert_eq!(
            fold_path_lookalikes("0x2e0x2e0x2fetc").as_deref(),
            Some("../etc")
        );
        assert_eq!(
            fold_path_lookalikes("\u{ff0e}\u{ff0e}\u{ff3c}").as_deref(),
            Some("..\\")
        );
        assert_eq!(fold_path_lookalikes("plain ../path"), None);
        assert_eq!(fold_path_lookalikes("café"), None);
    }

    #[test]
    fn overlong_utf8_folds_to_ascii() {
        assert_eq!(percent_decode("%c0%ae%c0%ae%c0%af", false), "../");
        assert_eq!(percent_decode("%e0%80%ae%e0%80%ae%e0%80%af", false), "../");
        assert_eq!(percent_decode("%f0%80%80%ae%c1%9c", false), ".\\");
        // valid UTF-8 is unchanged
        assert_eq!(
            percent_decode("caf%c3%a9 %e2%82%ac %f0%9f%98%80", false),
            "café € 😀"
        );
    }

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
