//! Payload inspection (web application firewall).
//!
//! Every inspected value (path, query/body parameters, JSON strings and keys, cookies,
//! selected headers) is **decoded** the way a server or browser would decode it
//! (repeated URL-decoding, `%uXXXX`, HTML entities, `\uXXXX`/`\xHH`, SQL comments,
//! case, whitespace) and then **scored**: each attack class sums the weights of the
//! indicators that matched, capped at 10. A single weak signal (an apostrophe in
//! "O'Brien", the word "select" in a sentence) stays low; combinations that only
//! appear in attacks (`' OR '1'='1`, `<img src=x onerror=…>`) score high.
//!
//! Suggested thresholds: log ≥ 4, block ≥ 7.

mod body;
mod decode;
mod indicators;
mod inspect;
mod lexicon;
mod multipart;
mod shell;
mod sql;
mod ssrf;

pub use decode::decode;
pub use indicators::AttackClass;
pub use inspect::{Finding, HttpRequest, Inspection, Inspector};

/// A request body as text, the way the application will read it: byte-order mark,
/// declared `charset`, UTF-16 / UTF-32 transcoded (also undeclared UTF-16 / UTF-32 JSON).
/// `content_type` is the raw Content-Type header value (or `""`).
pub fn body_text(body: &[u8], content_type: &str) -> String {
    body::decode(body, &content_type.to_ascii_lowercase())
        .text
        .into_owned()
}

/// The text form fields of a body, the way frameworks read them: URL-encoded (after
/// charset decoding) or `multipart/*` (parts without a file name). Keys and values are
/// decoded exactly once (`+` is a space, `%XX` a byte). Empty for other bodies.
pub fn form_fields(body: &[u8], content_type: &str) -> Vec<(String, String)> {
    let ct = content_type.to_ascii_lowercase();
    if ct.starts_with("multipart/") {
        let parsed = multipart::boundary(content_type).and_then(|b| multipart::parse(body, &b));
        return parsed
            .map(|m| {
                m.parts
                    .iter()
                    .filter(|p| p.filename.is_none())
                    .map(|p| (p.name.clone(), String::from_utf8_lossy(p.body).into_owned()))
                    .collect()
            })
            .unwrap_or_default();
    }
    let text = body::decode(body, &ct).text;
    text.split('&')
        .filter(|p| !p.is_empty())
        .map(|p| {
            let (k, v) = p.split_once('=').unwrap_or((p, ""));
            (form_decode_once(k), form_decode_once(v))
        })
        .collect()
}

fn form_decode_once(s: &str) -> String {
    let b = s.as_bytes();
    let hex = |c: u8| (c as char).to_digit(16).map(|d| d as u8);
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'+' => out.push(b' '),
            b'%' if i + 2 < b.len() => match (hex(b[i + 1]), hex(b[i + 2])) {
                (Some(h), Some(l)) => {
                    out.push(h << 4 | l);
                    i += 2;
                }
                _ => out.push(b'%'),
            },
            c => out.push(c),
        }
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn form_fields_from_urlencoded_utf16_and_multipart() {
        let f = form_fields(
            b"email=a%40b.io&pw=x+y",
            "application/x-www-form-urlencoded",
        );
        assert_eq!(
            f,
            [
                ("email".into(), "a@b.io".into()),
                ("pw".into(), "x y".into())
            ]
        );
        let utf16: Vec<u8> = "email=a%40b.io"
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect();
        let f = form_fields(
            &utf16,
            "application/x-www-form-urlencoded; charset=utf-16le",
        );
        assert_eq!(f, [("email".to_string(), "a@b.io".to_string())]);
        let mp = b"--b\r\nContent-Disposition: form-data; name=\"email\"\r\n\r\na@b.io\r\n--b\r\nContent-Disposition: form-data; name=\"f\"; filename=\"x.txt\"\r\n\r\nfile\r\n--b--\r\n";
        let f = form_fields(mp, "multipart/form-data; boundary=b");
        assert_eq!(f, [("email".to_string(), "a@b.io".to_string())]);
        assert_eq!(body_text(b"{\"a\":1}", "application/json"), "{\"a\":1}");
    }
}
