//! `multipart/form-data` parsing (RFC 7578): splits a body into parts with their field
//! names, file names and content types, and reports structural evasions (OWASP CRS 922).

/// One part of a multipart body.
pub(crate) struct Part<'a> {
    pub name: String,
    pub filename: Option<String>,
    pub content_type: Option<String>,
    pub body: &'a [u8],
}

/// Parsed body: the parts and the evasion indicators found in their headers.
pub(crate) struct Multipart<'a> {
    pub parts: Vec<Part<'a>>,
    pub anomalies: Vec<(&'static str, f64)>,
}

const MAX_PARTS: usize = 256;
const MAX_HEADER_BYTES: usize = 8 * 1024;

/// Charsets a part may declare. Anything else (UTF-7, UTF-16, Shift-JIS, ...) is how
/// payloads are hidden from WAFs that read the bytes as UTF-8.
const ALLOWED_CHARSETS: &[&str] = &[
    "utf-8",
    "utf8",
    "us-ascii",
    "ascii",
    "iso-8859-1",
    "iso-8859-15",
    "latin1",
    "windows-1252",
];

/// The `boundary` parameter of a `multipart/*` Content-Type.
pub(crate) fn boundary(content_type: &str) -> Option<String> {
    content_type.split(';').skip(1).find_map(|p| {
        let (k, v) = p.split_once('=')?;
        if !k.trim().eq_ignore_ascii_case("boundary") {
            return None;
        }
        let v = v.trim().trim_matches('"');
        (!v.is_empty() && v.len() <= 200).then(|| v.to_string())
    })
}

pub(crate) fn parse<'a>(body: &'a [u8], boundary: &str) -> Option<Multipart<'a>> {
    let delim = format!("--{boundary}");
    let delim = delim.as_bytes();
    let mut out = Multipart {
        parts: Vec::new(),
        anomalies: Vec::new(),
    };
    let push = |a: &mut Vec<(&'static str, f64)>, name: &'static str, w: f64| {
        if !a.iter().any(|(n, _)| *n == name) {
            a.push((name, w));
        }
    };
    let mut pos = find(body, delim, 0)?;
    loop {
        let mut start = pos + delim.len();
        if body[start..].starts_with(b"--") {
            break; // closing delimiter
        }
        // rest of the delimiter line
        match find(body, b"\n", start) {
            Some(nl) => start = nl + 1,
            None => break,
        }
        let end = find(body, delim, start).unwrap_or(body.len());
        let raw = &body[start..end];
        // strip the line break that belongs to the next delimiter
        let raw = raw
            .strip_suffix(b"\r\n")
            .or_else(|| raw.strip_suffix(b"\n"))
            .unwrap_or(raw);
        let (head, content) = split_head(raw);
        if head.len() > MAX_HEADER_BYTES {
            push(&mut out.anomalies, "multipart_header_too_large", 5.0);
        }
        let mut part = Part {
            name: String::new(),
            filename: None,
            content_type: None,
            body: content,
        };
        let mut dispositions = 0;
        for line in head.split(|&b| b == b'\n') {
            let line = line.strip_suffix(b"\r").unwrap_or(line);
            if line.is_empty() {
                continue;
            }
            let Some(colon) = line.iter().position(|&b| b == b':') else {
                // a header line without a colon: malformed, but also what a part
                // without headers looks like
                push(&mut out.anomalies, "multipart_header_malformed", 4.0);
                continue;
            };
            let (hname, hval) = (&line[..colon], &line[colon + 1..]);
            // header names are RFC 7230 tokens: no controls, spaces or separators
            if hname.is_empty() || !hname.iter().all(|&b| is_token_byte(b)) {
                push(&mut out.anomalies, "multipart_header_invalid", 7.0);
            }
            let hname = String::from_utf8_lossy(hname).trim().to_ascii_lowercase();
            let hval = String::from_utf8_lossy(hval).trim().to_string();
            match hname.as_str() {
                "content-disposition" => {
                    dispositions += 1;
                    let (ps, confusing) = params(&hval);
                    if confusing {
                        push(&mut out.anomalies, "multipart_parameter_evasion", 7.0);
                    }
                    if let Some(n) = param(&ps, "name") {
                        part.name = n;
                    }
                    if let Some(f) = param(&ps, "filename*").or_else(|| param(&ps, "filename")) {
                        part.filename = Some(f);
                    }
                }
                "content-type" => {
                    if let Some(cs) = param(&params(&hval).0, "charset") {
                        let cs = cs.to_ascii_lowercase();
                        if !ALLOWED_CHARSETS.contains(&cs.as_str()) {
                            push(&mut out.anomalies, "multipart_part_charset", 7.0);
                        }
                    }
                    part.content_type = Some(hval.to_ascii_lowercase());
                }
                // deprecated by RFC 7578; some old HTTP client libraries still send it
                "content-transfer-encoding" => {
                    push(&mut out.anomalies, "multipart_transfer_encoding", 4.0)
                }
                _ => {}
            }
        }
        if dispositions > 1 {
            push(&mut out.anomalies, "multipart_duplicate_disposition", 5.0);
        }
        // `_charset_` sets the charset of every other field
        if part.name.eq_ignore_ascii_case("_charset_") {
            let cs = String::from_utf8_lossy(content).trim().to_ascii_lowercase();
            if !ALLOWED_CHARSETS.contains(&cs.as_str()) {
                push(&mut out.anomalies, "multipart_charset_field", 7.0);
            }
        }
        out.parts.push(part);
        if out.parts.len() >= MAX_PARTS || end >= body.len() {
            break;
        }
        pos = end;
    }
    Some(out)
}

fn split_head(raw: &[u8]) -> (&[u8], &[u8]) {
    if let Some(i) = find(raw, b"\r\n\r\n", 0) {
        return (&raw[..i], &raw[i + 4..]);
    }
    if let Some(i) = find(raw, b"\n\n", 0) {
        return (&raw[..i], &raw[i + 2..]);
    }
    (raw, &[])
}

fn find(hay: &[u8], needle: &[u8], from: usize) -> Option<usize> {
    if from > hay.len() || needle.is_empty() {
        return None;
    }
    hay[from..]
        .windows(needle.len())
        .position(|w| w == needle)
        .map(|i| i + from)
}

fn is_token_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b)
}

/// Parameters of a header value (`form-data; name="a"; filename="b"`), honouring
/// quotes and backslash escapes. The flag says whether a value contains characters
/// parsers disagree on (`;` `=` `"` `\` inside quotes): a classic way to make the WAF
/// and the application see different field or file names.
fn params(v: &str) -> (Vec<(String, String)>, bool) {
    let mut out = Vec::new();
    let mut confusing = false;
    let b: Vec<char> = v.chars().collect();
    // skip the disposition type
    let mut i = b.iter().position(|&c| c == ';').map_or(b.len(), |p| p + 1);
    while i < b.len() {
        while i < b.len() && (b[i] == ' ' || b[i] == '\t' || b[i] == ';') {
            i += 1;
        }
        let ks = i;
        while i < b.len() && b[i] != '=' && b[i] != ';' {
            i += 1;
        }
        let key: String = b[ks..i]
            .iter()
            .collect::<String>()
            .trim()
            .to_ascii_lowercase();
        if i >= b.len() || b[i] == ';' {
            continue;
        }
        i += 1; // '='
        while i < b.len() && b[i] == ' ' {
            i += 1;
        }
        let mut val = String::new();
        if b.get(i) == Some(&'"') {
            i += 1;
            while i < b.len() && b[i] != '"' {
                if b[i] == '\\' && i + 1 < b.len() {
                    confusing = true;
                    i += 1;
                }
                // (a `;` ending an HTML entity such as `&auml;` is not a trick)
                if matches!(b[i], '=' | '"') || (b[i] == ';' && !ends_with_entity(&val)) {
                    confusing = true;
                }
                val.push(b[i]);
                i += 1;
            }
            i += 1; // closing quote
        } else {
            while i < b.len() && b[i] != ';' {
                if matches!(b[i], '"' | '=' | '\\') {
                    confusing = true;
                }
                val.push(b[i]);
                i += 1;
            }
            val = val.trim().to_string();
        }
        if key.ends_with('*') {
            // RFC 5987: charset'lang'percent-encoded
            let enc = val.rsplit('\'').next().unwrap_or(&val).to_string();
            val = crate::decode::percent_decode(&enc, false);
        }
        out.push((key, val));
    }
    (out, confusing)
}

/// Whether `s` ends with the start of an HTML entity: `&auml`, `&#228`, `&#xe4`.
fn ends_with_entity(s: &str) -> bool {
    match s.rfind('&') {
        Some(i) => {
            let name = &s[i + 1..];
            (2..=10).contains(&name.len())
                && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '#')
        }
        None => false,
    }
}

fn param(ps: &[(String, String)], key: &str) -> Option<String> {
    ps.iter().find(|(k, _)| k == key).map(|(_, v)| v.clone())
}

/// The file name a server is likely to store: lowercase, backslash escapes and
/// spaces around dots removed (`photo. php`, `1.j\s\p`), trailing dots, spaces and
/// slashes dropped (`shell.php/`, `shell.php.`), directory part removed.
pub(crate) fn normalize_filename(name: &str) -> String {
    let lower = name.to_ascii_lowercase().replace('\\', "");
    let mut out = String::with_capacity(lower.len());
    for (k, part) in lower.split('.').enumerate() {
        if k > 0 {
            out.push('.');
        }
        out.push_str(part.trim());
    }
    let out = out.trim_end_matches(['.', ' ', '/']);
    out.rsplit('/').next().unwrap_or(out).to_string()
}

/// Upload indicators for a file name.
pub(crate) fn filename_indicators(name: &str) -> Vec<(&'static str, f64)> {
    let mut out = Vec::new();
    let lower = name.to_ascii_lowercase();
    if lower.contains('\0') || lower.contains("%00") {
        out.push(("upload_null_byte", 8.0));
    }
    if lower.contains("../") || lower.contains("..\\") {
        out.push(("upload_path_traversal", 7.0));
    }
    if lower.starts_with('/') || lower.get(1..3) == Some(":\\") {
        out.push(("upload_absolute_path", 5.0));
    }
    let base = normalize_filename(&lower);
    let base = base.as_str();
    // PHP session files (sess_<id>) written to the session directory = code execution
    if base.starts_with("sess_") && base.len() >= 15 {
        out.push(("upload_php_session_file", 7.0));
    }
    if matches!(base, ".htaccess" | ".user.ini" | "web.config" | ".htpasswd") {
        out.push(("upload_server_config", 8.0));
    }
    let exts: Vec<&str> = base.split('.').skip(1).collect();
    let server_exec = |e: &str| {
        e.starts_with("php")
            || matches!(
                e,
                "phtml"
                    | "phar"
                    | "pht"
                    | "phps"
                    | "asp"
                    | "aspx"
                    | "ascx"
                    | "ashx"
                    | "asmx"
                    | "asa"
                    | "cer"
                    | "jsp"
                    | "jspx"
                    | "jsw"
                    | "jsv"
                    | "jspf"
                    | "cgi"
                    | "shtml"
                    | "stm"
                    | "shtm"
            )
    };
    if let Some(last) = exts.last() {
        if server_exec(last) {
            out.push(("upload_server_script", 7.0));
        } else if matches!(
            *last,
            "py" | "pl" | "sh" | "rb" | "exe" | "dll" | "bat" | "ps1"
        ) {
            out.push(("upload_executable", 4.0));
        }
    }
    // shell.php.jpg: some servers execute by the first known extension
    if exts.len() >= 2 && exts[..exts.len() - 1].iter().any(|e| server_exec(e)) {
        out.push(("upload_double_extension", 6.0));
    }
    out
}

/// Whether file content is binary (images, archives): those are not text-inspected.
pub(crate) fn is_binary(content: &[u8]) -> bool {
    let sample = &content[..content.len().min(4096)];
    if sample.contains(&0) {
        return true;
    }
    let text = std::str::from_utf8(sample).map(|s| s.chars().count()).ok();
    match text {
        Some(_) => false,
        None => {
            let printable = sample
                .iter()
                .filter(|b| b.is_ascii_graphic() || b.is_ascii_whitespace())
                .count();
            printable * 10 < sample.len() * 7
        }
    }
}

/// Server-side code hidden in an uploaded file, e.g. PHP in an image (polyglot).
pub(crate) fn embedded_code(content: &[u8]) -> Option<&'static str> {
    let markers: [(&[u8], &str); 4] = [
        (b"<?php", "upload_embedded_php"),
        (b"<?=", "upload_embedded_php"),
        (b"<%@", "upload_embedded_server_code"),
        (b"<%=", "upload_embedded_server_code"),
    ];
    let lower: Vec<u8> = content.iter().map(|b| b.to_ascii_lowercase()).collect();
    markers
        .iter()
        .find(|(m, _)| find(&lower, m, 0).is_some())
        .map(|(_, n)| *n)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_fields_files_and_anomalies() {
        let body = b"--b\r\nContent-Disposition: form-data; name=\"user\"\r\n\r\nalice\r\n--b\r\nContent-Disposition: form-data; name=\"avatar\"; filename=\"me.png\"\r\nContent-Type: image/png\r\n\r\n\x89PNG\x00\x01\r\n--b\r\nContent-Disposition: form-data; name=\"bio\"\r\nContent-Type: text/plain; charset=utf-7\r\n\r\n+ADw-script+AD4-\r\n--b--\r\n";
        let m = parse(body, "b").unwrap();
        assert_eq!(m.parts.len(), 3);
        assert_eq!(m.parts[0].name, "user");
        assert_eq!(m.parts[0].body, b"alice");
        assert_eq!(m.parts[1].filename.as_deref(), Some("me.png"));
        assert!(is_binary(m.parts[1].body));
        assert!(
            m.anomalies
                .iter()
                .any(|(n, _)| *n == "multipart_part_charset")
        );
        assert_eq!(
            boundary("multipart/form-data; boundary=\"b\"").as_deref(),
            Some("b")
        );
    }

    #[test]
    fn invalid_header_names_and_charset_field() {
        let body = b"--b\r\n\x0eContent-Disposition: form-data; name=\"f\"\r\n\r\nx\r\n--b\nContent-disposition: form-data; name=\"_charset_\"\n\nutf-7\n--b--\n";
        let m = parse(body, "b").unwrap();
        let names: Vec<_> = m.anomalies.iter().map(|(n, _)| *n).collect();
        assert!(names.contains(&"multipart_header_invalid"), "{names:?}");
        assert!(names.contains(&"multipart_charset_field"), "{names:?}");
        // quotes and separators inside parameter values confuse parsers
        let tricky = b"--b\nContent-Disposition: form-data; name=\"f\"; filename=\"te;st.txt\"\n\nx\n--b--\n";
        let m = parse(tricky, "b").unwrap();
        assert_eq!(m.parts[0].filename.as_deref(), Some("te;st.txt"));
        assert!(
            m.anomalies
                .iter()
                .any(|(n, _)| *n == "multipart_parameter_evasion")
        );
        // `!` and `~` are valid token characters
        let ok = b"--b\nContent~Disposition: form-data; name=\"f\"\n\nx\n--b--\n";
        assert!(parse(ok, "b").unwrap().anomalies.is_empty());
    }

    #[test]
    fn upload_names() {
        let n =
            |f: &str| -> Vec<&str> { filename_indicators(f).into_iter().map(|(n, _)| n).collect() };
        assert!(n("shell.php").contains(&"upload_server_script"));
        assert!(n("shell.PhTmL").contains(&"upload_server_script"));
        assert!(n("shell.php.jpg").contains(&"upload_double_extension"));
        assert!(n("shell.php%00.jpg").contains(&"upload_null_byte"));
        assert!(n(".htaccess").contains(&"upload_server_config"));
        assert!(n("../../etc/cron.d/x").contains(&"upload_path_traversal"));
        assert!(n("holiday photo.jpg").is_empty());
        assert!(n("report.final.pdf").is_empty());
        assert!(n("photo. php").contains(&"upload_server_script"));
        assert!(n("1.j\\s\\p").contains(&"upload_server_script"));
        assert!(n("something/dangerous.php/").contains(&"upload_server_script"));
        assert!(n("/tmp/sess_d8ew88tqmabdcokhumchy8htqm").contains(&"upload_php_session_file"));
        assert!(n("John's CV.pdf").is_empty());
        assert_eq!(
            embedded_code(b"\xff\xd8\xff GIF89a <?php system($_GET[c]); ?>"),
            Some("upload_embedded_php")
        );
        assert_eq!(embedded_code(b"\xff\xd8\xff\xe0 plain jpeg"), None);
    }
}
