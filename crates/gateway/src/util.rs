//! Small helpers shared by the gateway's modules.

use std::time::{SystemTime, UNIX_EPOCH};

use hyper::header::HeaderMap;

/// Seconds since the Unix epoch (0 if the system clock is set before it).
pub fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// A header's value as text, if the header is present and its value is visible ASCII.
pub fn header_str<'a>(h: &'a HeaderMap, name: &str) -> Option<&'a str> {
    h.get(name).and_then(|v| v.to_str().ok())
}

/// `application/x-www-form-urlencoded` decoding, one pass: `+` is a space, `%XX` is a
/// byte, an invalid escape is kept as is. Works on bytes, so any input is safe (a
/// request target may carry non-ASCII bytes). This is exact decoding for reading a
/// field; the WAF's decoder is different on purpose (repeated, evasion-aware).
pub fn form_decode(s: &str) -> String {
    let b = s.as_bytes();
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

fn hex(c: u8) -> Option<u8> {
    (c as char).to_digit(16).map(|d| d as u8)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn form_decoding() {
        assert_eq!(form_decode("%2Fcart%3Fx%3D1"), "/cart?x=1");
        assert_eq!(form_decode("a+b%20c"), "a b c");
        assert_eq!(form_decode("%zz"), "%zz");
        assert_eq!(form_decode("100%"), "100%");
        assert_eq!(form_decode("%4"), "%4");
        assert_eq!(form_decode("caf%C3%A9"), "café");
    }

    #[test]
    fn non_ascii_after_percent_does_not_panic() {
        // used to slice the &str at a byte offset inside 'é' and panic
        assert_eq!(form_decode("%a\u{e9}"), "%a\u{e9}");
        assert_eq!(form_decode("%\u{e9}"), "%\u{e9}");
    }
}
