//! Regression tests for WAF bypasses found in the 2026-11 security review. Each class
//! has attacks that must now block (score ≥ 7) and benign look-alikes that must not.

use pattern_guard_waf::{HttpRequest, Inspector};

const BLOCK: f64 = 7.0;

fn request_score(w: &Inspector, headers: &[(&str, &str)], ct: Option<&str>, body: &[u8]) -> f64 {
    let headers: Vec<(String, String)> = headers
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
    w.inspect(&HttpRequest {
        path_and_query: "/api",
        headers: &headers,
        content_type: ct,
        body,
    })
    .max_score()
}

fn value_score(w: &Inspector, v: &str) -> f64 {
    w.inspect_value("query:id", v, true)
        .map_or(0.0, |f| f.score)
}

fn utf16le(s: &str) -> Vec<u8> {
    s.encode_utf16().flat_map(u16::to_le_bytes).collect()
}

/// A numeric context broken out into a comparison on a column.
#[test]
fn sql_numeric_context_with_a_column_comparison() {
    let w = Inspector::new();
    for attack in [
        "1 OR username='admin'",
        "1 OR id=5",
        "-1 OR is_admin=true",
        "5 OR email LIKE '%@%'",
        "1 OR username IS NOT NULL",
        "1) OR (role='admin'",
        "0 OR id IN (SELECT id FROM users)",
        "1 || role<>'user'",
    ] {
        assert!(value_score(&w, attack) >= BLOCK, "{attack}");
    }
    for benign in [
        "50 or 60 people attended",
        "1 or 2 tickets",
        "10 or more items",
        "2 or kids on top",
        "3 and people in town",
        "1 and up",
        "100 or so",
        "4 or 5 like this",
    ] {
        assert!(value_score(&w, benign) < BLOCK, "{benign}");
    }
}

/// UTF-16 / UTF-32 bodies are transcoded before inspection; charsets that hide content
/// (EBCDIC, UTF-7) are flagged.
#[test]
fn wide_and_hiding_charsets() {
    let w = Inspector::new();
    let attack = r#"{"comment":"<script>alert(1)</script>"}"#;
    let utf16 = utf16le(attack);
    let with_bom = [&[0xFF, 0xFE][..], &utf16].concat();
    for (ct, body) in [
        (Some("application/json; charset=utf-16"), &utf16),
        (Some("text/plain; charset=utf-16le"), &utf16),
        (Some("application/json"), &with_bom),
        (Some("application/json"), &utf16), // undeclared: RFC 4627 null-byte detection
        (None, &utf16),
    ] {
        assert!(request_score(&w, &[], ct, body) >= BLOCK, "{ct:?}");
    }
    let ebcdic = b"\x89\x84\x7e\xf1"; // "id=1" in IBM037
    assert!(
        request_score(
            &w,
            &[],
            Some("application/x-www-form-urlencoded; charset=ibm037"),
            ebcdic
        ) >= BLOCK
    );
    let benign = utf16le(r#"{"name":"O'Brien","note":"see you at 5"}"#);
    assert!(request_score(&w, &[], Some("application/json; charset=utf-16"), &benign) < BLOCK);
    assert!(
        request_score(
            &w,
            &[],
            Some("application/x-www-form-urlencoded; charset=ISO-8859-1"),
            b"name=O%27Brien"
        ) < BLOCK
    );
}

/// A body with no or an unknown content type is still inspected.
#[test]
fn unknown_content_types_are_inspected() {
    let w = Inspector::new();
    let json = br#"{"c":"<script>alert(1)</script>"}"#;
    for ct in [
        "application/octet-stream",
        "application/x-yaml",
        "application/graphql",
        "application/x-protobuf",
    ] {
        assert!(request_score(&w, &[], Some(ct), json) >= BLOCK, "{ct}");
    }
    let form = b"id=1' UNION SELECT username,password FROM users-- ";
    assert!(request_score(&w, &[], Some("application/octet-stream"), form) >= BLOCK);
    // a raw upload of a web shell inside binary content
    let polyglot = b"GIF89a\x01\x00\x01\x00\x00\x00\x00<?php system($_GET['c']); ?>";
    assert!(request_score(&w, &[], Some("application/octet-stream"), polyglot) >= BLOCK);

    let png = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x10";
    assert!(request_score(&w, &[], Some("application/octet-stream"), png) < BLOCK);
    let yaml = b"name: O'Brien\nage: 30\nnote: select a plan from the list\n";
    assert!(request_score(&w, &[], Some("application/x-yaml"), yaml) < BLOCK);
    let graphql = b"query { user(id: 1) { name email } }";
    assert!(request_score(&w, &[], Some("application/graphql"), graphql) < BLOCK);
}

/// Overlong UTF-8 percent-encoding decodes to the ASCII it hides.
#[test]
fn overlong_utf8_traversal() {
    let w = Inspector::new();
    for attack in [
        "%e0%80%ae%e0%80%ae%e0%80%af%e0%80%ae%e0%80%ae%e0%80%afetc%e0%80%afpasswd",
        "%c0%ae%c0%ae%c0%af%c0%ae%c0%ae%c0%afetc%c0%afpasswd",
    ] {
        assert!(value_score(&w, attack) >= BLOCK, "{attack}");
    }
    assert!(value_score(&w, "caf%C3%A9 cr%C3%A8me") < BLOCK);
}

/// Client-address headers and Origin get full analysis, without URL analysis.
#[test]
fn client_address_headers_and_origin() {
    let w = Inspector::new();
    for (h, v) in [
        (
            "X-Forwarded-For",
            "1' UNION SELECT username,password FROM users-- ",
        ),
        ("X-Real-IP", "1' OR '1'='1"),
        ("Origin", "<script>alert(1)</script>"),
        ("Forwarded", "for=\"<svg onload=alert(1)>\""),
    ] {
        assert!(request_score(&w, &[(h, v)], None, b"") >= BLOCK, "{h}: {v}");
    }
    for (h, v) in [
        ("X-Forwarded-For", "203.0.113.7, 10.0.0.1, 192.168.1.5"),
        ("X-Forwarded-For", "2001:db8::1"),
        ("X-Real-IP", "127.0.0.1"),
        ("Origin", "http://localhost:3000"),
        ("Origin", "https://shop.example.com"),
        ("Origin", "null"),
        ("Forwarded", "for=192.0.2.60;proto=http;by=203.0.113.43"),
        ("Forwarded", "for=\"[2001:db8:cafe::17]:4711\""),
        ("True-Client-IP", "198.51.100.23"),
    ] {
        assert!(request_score(&w, &[(h, v)], None, b"") < 4.0, "{h}: {v}");
    }
}

/// With both `filename` and `filename*`, both names are checked.
#[test]
fn both_upload_file_names_are_checked() {
    let w = Inspector::new();
    let ct = Some("multipart/form-data; boundary=X");
    let attack = b"--X\r\nContent-Disposition: form-data; name=\"f\"; filename=\"shell.php\"; filename*=UTF-8''ok.txt\r\n\r\njust some data\r\n--X--\r\n";
    assert!(request_score(&w, &[], ct, attack) >= BLOCK);
    let attack = b"--X\r\nContent-Disposition: form-data; name=\"f\"; filename=\"ok.txt\"; filename*=UTF-8''shell%2Ephp\r\n\r\njust some data\r\n--X--\r\n";
    assert!(request_score(&w, &[], ct, attack) >= BLOCK);
    let benign = b"--X\r\nContent-Disposition: form-data; name=\"cv\"; filename=\"resume.pdf\"; filename*=UTF-8''r%C3%A9sum%C3%A9.pdf\r\n\r\nplain text cv\r\n--X--\r\n";
    assert!(request_score(&w, &[], ct, benign) < BLOCK);
}

/// JSON is walked to the end of the request's value budget, not 1 000 items per level;
/// nesting too deep to walk is flagged.
#[test]
fn large_and_deep_json() {
    let w = Inspector::new();
    let ct = Some("application/json");
    let mut arr = String::from("[");
    for _ in 0..1001 {
        arr.push_str("0,\"ok\",");
    }
    arr.push_str("\"<svg onload=alert(1)>\"]");
    assert!(request_score(&w, &[], ct, arr.as_bytes()) >= BLOCK);
    let mut obj = String::from("{");
    for i in 0..1100 {
        obj.push_str(&format!("\"a{i:04}\":0,"));
    }
    obj.push_str("\"zzzz\":\"' OR '1'='1' -- \"}");
    assert!(request_score(&w, &[], ct, obj.as_bytes()) >= BLOCK);
    let deep = format!("{}\"x\"{}", "[".repeat(70), "]".repeat(70));
    assert!(request_score(&w, &[], ct, deep.as_bytes()) >= BLOCK);
    // ordinary nesting and a bulk list of benign records stay clean
    let normal = format!("{}\"x\"{}", "[".repeat(10), "]".repeat(10));
    assert!(request_score(&w, &[], ct, normal.as_bytes()) < BLOCK);
    let bulk: String = (0..1500)
        .map(|i| format!("{{\"id\":{i},\"name\":\"item {i}\"}}"))
        .collect::<Vec<_>>()
        .join(",");
    assert!(request_score(&w, &[], ct, format!("[{bulk}]").as_bytes()) < BLOCK);
}

/// Found by the pinned benign corpus: real browser user agents with the Indonesian locale
/// (`; id;`) looked like a chained `id` command. Attacks in the User-Agent still block.
#[test]
fn user_agent_locale_tokens_are_not_commands() {
    let w = Inspector::new();
    let ua = |v: &str| request_score(&w, &[("User-Agent", v)], None, b"");
    for benign in [
        "Mozilla/5.0 (Linux; U; Android 4.4.2; id; SM-G900 Build/KOT49H) AppleWebKit/534.30 (KHTML, like Gecko) Version/4.0 UCBrowser/9.9.2.467 U3/0.8.0 Mobile Safari/534.30",
        "UCWEB/2.0 (Symbian; U; S60 V3; id; NokiaE63) U2/1.0.0 UCBrowser/9.2.0.336 U2/1.0.0 Mobile",
        "Mozilla/5.0 (BlackBerry; U; BlackBerry 9220; id) AppleWebKit/534.11+ (KHTML, like Gecko) Version/7.1.0.746 Mobile Safari/534.11+",
        "Mozilla/5.0 (Linux; U; Android 9; pt-BR; SM-A105M) AppleWebKit/537.36",
    ] {
        assert!(ua(benign) < BLOCK, "{benign}");
    }
    for attack in [
        "() { :; }; /bin/bash -c 'id'",
        "Mozilla/5.0; id; uname -a",
        "Mozilla/5.0 $(id)",
    ] {
        assert!(ua(attack) >= BLOCK, "{attack}");
    }
}

/// Traversal disguised with encoded dots, double encoding, overlong UTF-8, look-alike
/// characters or hex notation blocks; plain relative paths don't.
#[test]
fn disguised_traversal() {
    let w = Inspector::new();
    for attack in [
        "%uff0e%uff0e/%uff0e%uff0e/etc/passwd",
        "..%u2215..%u2215..%u2215etc%u2215passwd",
        "0x2e0x2e0x2f0x2e0x2e0x2fetc0x2fpasswd",
        "%2e%2e%2fconfig.php",
        "..%252f..%252fconfig.php",
        "%%32%65%%32%65/config.php",
        "/%c0%ae%c0%ae/config.php",
        "..&#x2f;..&#x2f;config.php",
    ] {
        assert!(value_score(&w, attack) >= BLOCK, "{attack}");
    }
    for benign in [
        "../img/logo.png",
        "../../assets/css/app.css",
        "..%2Fimg%2Flogo.png", // a browser encodes the slashes of a form field, not the dots
        "see ../README.md and ../../docs/",
        "version 1.2.3..1.2.4",
    ] {
        assert!(value_score(&w, benign) < BLOCK, "{benign}");
    }
}

/// PHP filter chains, RFI parameter names in any case, and command substitution in headers.
#[test]
fn php_filter_chain_rfi_names_and_header_substitution() {
    let w = Inspector::new();
    assert!(value_score(&w, "convert.iconv.UTF8.CSISO2022KR|convert.base64-decode") >= BLOCK);
    assert!(value_score(&w, "convert.iconv.CP1390.CSIBM932") >= BLOCK);
    let rfi = |target: &str| {
        w.inspect(&HttpRequest {
            path_and_query: target,
            headers: &[],
            content_type: None,
            body: b"",
        })
        .max_score()
    };
    assert!(rfi("/x.php?_CONF[path]=https://evil.example/") >= BLOCK);
    assert!(rfi("/x.php?mosConfig_absolute_path=https://evil.example/") >= BLOCK);
    assert!(rfi("/x.php?path=https://example.com/docs") < BLOCK);
    let ua = |v: &str| request_score(&w, &[("User-Agent", v)], None, b"");
    assert!(ua("Mozilla/5.0`id`") >= BLOCK);
    assert!(ua("Mozilla/5.0 (X11; Linux x86_64) Firefox/131.0") < BLOCK);
}

/// A value that is only the path of an OS file is a file-read attempt; the same path in
/// a sentence is not.
#[test]
fn os_file_path_as_the_whole_value() {
    let w = Inspector::new();
    for attack in [
        "/etc/passwd",
        "/proc/self/environ",
        ".ssh/id_rsa",
        "c:\\boot.ini",
        "/etc/shadow%00",
        "file:///etc/hosts",
    ] {
        assert!(value_score(&w, attack) >= BLOCK, "{attack}");
    }
    for benign in [
        "my key is in .ssh/id_rsa on the laptop", // the rule needs the whole value to be the path
        "copy it to /home/anna/notes.txt",
        "/products/42",
        "/static/css/app.css",
        "./build.sh",
        "c:\\users\\anna\\documents\\cv.docx",
    ] {
        assert!(value_score(&w, benign) < BLOCK, "{benign}");
    }
}
