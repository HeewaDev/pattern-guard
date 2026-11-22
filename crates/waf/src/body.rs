//! A request body as text, the way the application will read it: byte-order marks,
//! the declared `charset`, UTF-16 and UTF-32 (RFC 4627 / RFC 8259 null-byte detection,
//! as JSON parsers such as Jackson do). Reading a UTF-16 body as UTF-8 turns every
//! payload into replacement characters, so it must be transcoded before inspection.

use std::borrow::Cow;

/// Charsets whose bytes 0x00–0x7F are ASCII. A payload written in ASCII keeps its
/// bytes, so reading the body as UTF-8 still shows it.
const ASCII_COMPATIBLE: &[&str] = &[
    "utf-8",
    "utf8",
    "us-ascii",
    "ascii",
    "latin1",
    "iso-8859-1",
    "iso-8859-2",
    "iso-8859-3",
    "iso-8859-4",
    "iso-8859-5",
    "iso-8859-6",
    "iso-8859-7",
    "iso-8859-8",
    "iso-8859-9",
    "iso-8859-10",
    "iso-8859-13",
    "iso-8859-14",
    "iso-8859-15",
    "iso-8859-16",
    "windows-1250",
    "windows-1251",
    "windows-1252",
    "windows-1253",
    "windows-1254",
    "windows-1255",
    "windows-1256",
    "windows-1257",
    "windows-1258",
    "cp1252",
    "koi8-r",
    "koi8-u",
    "shift_jis",
    "sjis",
    "euc-jp",
    "euc-kr",
    "gb2312",
    "gbk",
    "gb18030",
    "big5",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Encoding {
    Utf16Le,
    Utf16Be,
    Utf32Le,
    Utf32Be,
}

/// The body as text, and an indicator when its declared charset hides content
/// (EBCDIC, UTF-7, an unknown label): those bodies are read as UTF-8 anyway.
pub(crate) struct BodyText<'a> {
    pub text: Cow<'a, str>,
    /// `true` when the body was transcoded from UTF-16 / UTF-32 (it is text).
    pub transcoded: bool,
    pub anomaly: Option<(&'static str, f64)>,
}

/// The lowercased `charset` parameter of a Content-Type, if any.
pub(crate) fn charset(content_type: &str) -> Option<String> {
    crate::multipart::param(&crate::multipart::params(content_type).0, "charset")
        .map(|c| c.trim().trim_matches(['\'', '"']).to_ascii_lowercase())
        .filter(|c| !c.is_empty())
}

pub(crate) fn decode<'a>(body: &'a [u8], content_type: &str) -> BodyText<'a> {
    let declared = charset(content_type);
    let (encoding, skip) = match bom(body) {
        Some(found) => (Some(found.0), found.1),
        None => {
            let from_label = declared.as_deref().and_then(|c| label(c, body));
            (from_label.or_else(|| sniff(body)), 0)
        }
    };
    if let Some(e) = encoding {
        return BodyText {
            text: Cow::Owned(transcode(&body[skip..], e)),
            transcoded: true,
            anomaly: None,
        };
    }
    let utf8_bom = body.starts_with(b"\xEF\xBB\xBF");
    let raw = if utf8_bom { &body[3..] } else { body };
    let anomaly = declared
        .filter(|c| !ASCII_COMPATIBLE.contains(&c.as_str()) && !is_unicode_wide(c))
        .map(|_| ("body_charset", 7.0));
    BodyText {
        text: String::from_utf8_lossy(raw),
        transcoded: false,
        anomaly,
    }
}

fn is_unicode_wide(label: &str) -> bool {
    label.starts_with("utf-16")
        || label.starts_with("utf-32")
        || label.starts_with("utf16")
        || label.starts_with("utf32")
        || label == "ucs-2"
}

/// UTF-32 byte-order marks first: `FF FE 00 00` also starts with the UTF-16LE mark.
fn bom(b: &[u8]) -> Option<(Encoding, usize)> {
    if b.starts_with(&[0xFF, 0xFE, 0, 0]) {
        Some((Encoding::Utf32Le, 4))
    } else if b.starts_with(&[0, 0, 0xFE, 0xFF]) {
        Some((Encoding::Utf32Be, 4))
    } else if b.starts_with(&[0xFF, 0xFE]) {
        Some((Encoding::Utf16Le, 2))
    } else if b.starts_with(&[0xFE, 0xFF]) {
        Some((Encoding::Utf16Be, 2))
    } else {
        None
    }
}

/// A declared UTF-16 / UTF-32 charset. Without `le` / `be`, the byte order comes from
/// where the null bytes are (ASCII text in UTF-16LE has them at odd offsets).
fn label(c: &str, b: &[u8]) -> Option<Encoding> {
    let c = c.replace(['-', '_'], "");
    let zeros_at = |offset: usize, step: usize| {
        b.iter()
            .take(512)
            .skip(offset)
            .step_by(step)
            .filter(|&&x| x == 0)
            .count()
    };
    match c.as_str() {
        "utf16le" => Some(Encoding::Utf16Le),
        "utf16be" => Some(Encoding::Utf16Be),
        "utf16" | "ucs2" => Some(if zeros_at(0, 2) > zeros_at(1, 2) {
            Encoding::Utf16Be
        } else {
            Encoding::Utf16Le
        }),
        "utf32le" => Some(Encoding::Utf32Le),
        "utf32be" => Some(Encoding::Utf32Be),
        "utf32" => Some(if zeros_at(0, 4) > zeros_at(3, 4) {
            Encoding::Utf32Be
        } else {
            Encoding::Utf32Le
        }),
        _ => None,
    }
}

/// RFC 4627 §3: undeclared JSON in UTF-16 / UTF-32 shows by the null bytes in its first
/// four octets. Only when the first character can start JSON, so binary files whose
/// header happens to contain nulls (MP4: `00 00 00 18 ftyp`) are not mistaken for text.
fn sniff(b: &[u8]) -> Option<Encoding> {
    let json_start = |c: u8| matches!(c, b'{' | b'[' | b'"' | b' ' | b'\t' | b'\n' | b'\r');
    match b {
        [0, 0, 0, x, ..] if json_start(*x) => Some(Encoding::Utf32Be),
        [x, 0, 0, 0, ..] if json_start(*x) => Some(Encoding::Utf32Le),
        [0, x, 0, _, ..] if json_start(*x) => Some(Encoding::Utf16Be),
        [x, 0, _, 0, ..] if json_start(*x) => Some(Encoding::Utf16Le),
        _ => None,
    }
}

fn transcode(b: &[u8], e: Encoding) -> String {
    match e {
        Encoding::Utf16Le | Encoding::Utf16Be => {
            let units = b.chunks_exact(2).map(|c| match e {
                Encoding::Utf16Le => u16::from_le_bytes([c[0], c[1]]),
                _ => u16::from_be_bytes([c[0], c[1]]),
            });
            char::decode_utf16(units)
                .map(|r| r.unwrap_or(char::REPLACEMENT_CHARACTER))
                .collect()
        }
        Encoding::Utf32Le | Encoding::Utf32Be => b
            .chunks_exact(4)
            .map(|c| {
                let v = match e {
                    Encoding::Utf32Le => u32::from_le_bytes([c[0], c[1], c[2], c[3]]),
                    _ => u32::from_be_bytes([c[0], c[1], c[2], c[3]]),
                };
                char::from_u32(v).unwrap_or(char::REPLACEMENT_CHARACTER)
            })
            .collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn utf16(s: &str, le: bool) -> Vec<u8> {
        s.encode_utf16()
            .flat_map(|u| if le { u.to_le_bytes() } else { u.to_be_bytes() })
            .collect()
    }

    fn utf32(s: &str, le: bool) -> Vec<u8> {
        s.chars()
            .flat_map(|c| {
                if le {
                    (c as u32).to_le_bytes()
                } else {
                    (c as u32).to_be_bytes()
                }
            })
            .collect()
    }

    #[test]
    fn utf16_and_utf32_by_label_bom_and_sniffing() {
        let s = r#"{"a":"<b>é</b>"}"#;
        for (body, ct) in [
            (utf16(s, true), "application/json; charset=utf-16"),
            (utf16(s, false), "application/json; charset=UTF-16"),
            (utf16(s, true), "application/json; charset=utf-16le"),
            (utf16(s, false), "text/plain; charset=\"utf-16be\""),
            (utf32(s, true), "application/json; charset=utf-32"),
            (utf32(s, false), "application/json; charset=utf-32be"),
            (
                [&[0xFF, 0xFE][..], &utf16(s, true)].concat(),
                "application/json",
            ),
            ([&[0xFE, 0xFF][..], &utf16(s, false)].concat(), ""),
            ([&[0xFF, 0xFE, 0, 0][..], &utf32(s, true)].concat(), ""),
            (utf16(s, true), "application/json"), // RFC 4627 sniffing
            (utf32(s, false), "application/json"), // RFC 4627 sniffing
        ] {
            let t = decode(&body, ct);
            assert_eq!(t.text, s, "{ct}");
            assert!(t.transcoded && t.anomaly.is_none(), "{ct}");
        }
    }

    #[test]
    fn utf8_and_ascii_compatible_bodies_pass_through() {
        for ct in [
            "application/json",
            "application/json; charset=utf-8",
            "application/x-www-form-urlencoded; charset=ISO-8859-1",
            "text/plain; charset=Shift_JIS",
            "",
        ] {
            let t = decode(b"name=O'Brien", ct);
            assert_eq!(t.text, "name=O'Brien", "{ct}");
            assert!(!t.transcoded && t.anomaly.is_none(), "{ct}");
        }
        assert_eq!(decode(b"\xEF\xBB\xBF{}", "application/json").text, "{}");
    }

    #[test]
    fn binary_headers_with_nulls_are_not_sniffed() {
        for b in [
            &b"\0\0\0\x18ftypmp42"[..],
            b"\0\0\x01\0\x01\0",
            b"\x89PNG\r\n\x1a\n",
        ] {
            assert!(!decode(b, "application/octet-stream").transcoded);
        }
    }

    #[test]
    fn quoted_charsets_are_read_without_quotes() {
        for ct in [
            "text/plain; charset='utf-8'",
            "text/plain; charset=\"UTF-8\"",
        ] {
            assert!(decode(b"a=1", ct).anomaly.is_none(), "{ct}");
        }
        assert_eq!(
            decode(b"a", "text/plain; charset='ibm037'").anomaly,
            Some(("body_charset", 7.0))
        );
    }

    #[test]
    fn charsets_that_hide_content_are_flagged() {
        for cs in ["ibm037", "IBM500", "cp875", "utf-7", "x-made-up"] {
            let t = decode(
                b"abc",
                &format!("application/x-www-form-urlencoded; charset={cs}"),
            );
            assert_eq!(t.anomaly, Some(("body_charset", 7.0)), "{cs}");
        }
    }
}
