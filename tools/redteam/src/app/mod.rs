//! The deliberately vulnerable demo shop: an in-process hyper server on localhost. Every
//! vulnerability is simulated (a small SQL engine, a small shell, a fake file system): no
//! real database, shell or file is ever touched.
//!
//! | Path | Vulnerability | Confirmed when the response shows |
//! |---|---|---|
//! | `GET /products?id=1` | SQL injection (numeric context, MySQL) | the hidden product or the admin's password hash |
//! | `GET /search?q=…` | reflected XSS (element body and a quoted attribute) | markup a browser would run |
//! | `GET /download?file=report.pdf` | path traversal (`readfile("/srv/app/files/" . $file)`) | the fake `/etc/passwd` or `/proc/self/environ` |
//! | `POST /tools/ping` `host=…` | OS command injection (`shell_exec("ping -c 1 $host 2>&1")`) | output of `id`, `whoami`, `uname -a` or `/etc/passwd` |
//! | `GET /api/orders/{id}` (Bearer token) | BOLA / IDOR: no ownership check | an order of another customer |
//! | `POST /login` `username`, `password` | brute force: no lockout, a guessable admin password | a session for `admin` |
//!
//! Parameters are read like PHP's `$_REQUEST` with cookies: from the body first (form,
//! multipart or JSON; JSON is recognised by its first character, whatever the
//! Content-Type), then the query string, then cookies; the last occurrence wins. Values
//! are percent-decoded once.

pub mod data;
pub mod fs;
pub mod shell;
pub mod sql;

use std::convert::Infallible;
use std::net::SocketAddr;

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use tokio::net::TcpListener;

/// `application/x-www-form-urlencoded` decoding: `+` is a space, `%XX` a byte; invalid
/// escapes stay as they are.
pub fn form_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'+' => out.push(b' '),
            b'%' if i + 2 < b.len() => {
                let hex = std::str::from_utf8(&b[i + 1..i + 3]).ok();
                match hex.and_then(|h| u8::from_str_radix(h, 16).ok()) {
                    Some(v) => {
                        out.push(v);
                        i += 3;
                        continue;
                    }
                    None => out.push(b'%'),
                }
            }
            x => out.push(x),
        }
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn pairs(s: &str) -> Vec<(String, String)> {
    s.split('&')
        .filter(|p| !p.is_empty())
        .map(|p| match p.split_once('=') {
            Some((k, v)) => (form_decode(k), form_decode(v)),
            None => (form_decode(p), String::new()),
        })
        .collect()
}

fn multipart(body: &str, boundary: &str) -> Vec<(String, String)> {
    let delim = format!("--{boundary}");
    let mut out = Vec::new();
    for part in body.split(delim.as_str()).skip(1) {
        if part.starts_with("--") {
            break;
        }
        let part = part.strip_prefix("\r\n").unwrap_or(part);
        let Some((head, value)) = part.split_once("\r\n\r\n") else {
            continue;
        };
        let name = head
            .lines()
            .find(|l| l.to_ascii_lowercase().starts_with("content-disposition"))
            .and_then(|l| l.split(';').find_map(|kv| kv.trim().strip_prefix("name=")))
            .map(|n| n.trim_matches('"').to_string());
        if let Some(n) = name {
            out.push((n, value.strip_suffix("\r\n").unwrap_or(value).to_string()));
        }
    }
    out
}

fn json_fields(body: &str) -> Option<Vec<(String, String)>> {
    let v: serde_json::Value = serde_json::from_str(body).ok()?;
    let obj = v.as_object()?;
    Some(
        obj.iter()
            .map(|(k, v)| {
                let s = match v {
                    serde_json::Value::String(s) => s.clone(),
                    serde_json::Value::Null => String::new(),
                    serde_json::Value::Bool(b) => {
                        if *b {
                            "1".into()
                        } else {
                            String::new()
                        }
                    }
                    other => other.to_string(),
                };
                (k.clone(), s)
            })
            .collect(),
    )
}

/// Request parameters, in lookup order: body, query, cookies.
pub struct Params {
    sources: [Vec<(String, String)>; 3],
}

impl Params {
    pub fn parse(query: &str, content_type: &str, body: &[u8], cookie: &str) -> Params {
        let text = String::from_utf8_lossy(body);
        let body_fields = if text.trim_start().starts_with('{') {
            json_fields(&text).unwrap_or_default()
        } else if let Some(b) = content_type
            .to_ascii_lowercase()
            .contains("multipart/form-data")
            .then(|| content_type.split("boundary=").nth(1))
            .flatten()
        {
            multipart(&text, b.trim_matches('"'))
        } else {
            pairs(&text)
        };
        let cookies = cookie
            .split(';')
            .filter_map(|c| c.trim().split_once('='))
            .map(|(k, v)| (k.to_string(), form_decode(v)))
            .collect();
        Params {
            sources: [body_fields, pairs(query), cookies],
        }
    }

    pub fn get(&self, name: &str) -> Option<&str> {
        self.sources.iter().find_map(|s| {
            s.iter()
                .rev()
                .find(|(k, _)| k == name)
                .map(|(_, v)| v.as_str())
        })
    }
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

fn page(title: &str, body: &str) -> String {
    format!(
        "<!doctype html><html><head><meta charset=utf-8><title>{title}</title></head><body><nav><a href=\"/\">Demo shop</a> · <a href=\"/search\">Search</a></nav><main>{body}</main></body></html>"
    )
}

type Resp = Response<Full<Bytes>>;

fn respond(status: StatusCode, ctype: &str, body: impl Into<Bytes>) -> Resp {
    let mut r = Response::new(Full::new(body.into()));
    *r.status_mut() = status;
    r.headers_mut()
        .insert("content-type", ctype.parse().expect("content type"));
    r
}

fn html(status: StatusCode, title: &str, body: &str) -> Resp {
    respond(status, "text/html; charset=utf-8", page(title, body))
}

fn json(status: StatusCode, body: String) -> Resp {
    respond(status, "application/json", body)
}

fn products(p: &Params) -> Resp {
    let id = p.get("id").unwrap_or("1");
    let q = format!("SELECT name, price FROM products WHERE hidden = 0 AND id = {id}");
    match sql::query(&q) {
        Ok(rows) => {
            let items: String = rows
                .rows
                .iter()
                .map(|r| {
                    let col = |i: usize| r.get(i).map(sql::Value::render).unwrap_or_default();
                    format!(
                        "<li>{} — {}</li>",
                        html_escape(&col(0)),
                        html_escape(&col(1))
                    )
                })
                .collect::<Vec<_>>()
                .concat();
            let list = if items.is_empty() {
                "<p>No such product.</p>".to_string()
            } else {
                format!("<ul>{items}</ul>")
            };
            html(StatusCode::OK, "Product", &list)
        }
        // display_errors = On: the database error is shown
        Err(e) => html(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Error",
            &format!("<h1>Database error</h1><p>{}</p>", html_escape(&e.0)),
        ),
    }
}

/// The search page reflects `q` unescaped, in an attribute and in the page body.
pub fn search_page(q: &str) -> String {
    page(
        "Search",
        &format!(
            "<form action=\"/search\"><input name=\"q\" value=\"{q}\"><button>Search</button></form><p>Results for: {q}</p><p>No products found.</p>"
        ),
    )
}

fn download(p: &Params) -> Resp {
    let file = p.get("file").unwrap_or("report.pdf");
    if file.contains('\0') {
        return html(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Error",
            "<p>readfile(): Argument #1 ($filename) must not contain any null bytes</p>",
        );
    }
    match fs::read("/", &format!("/srv/app/files/{file}")) {
        Ok(content) => respond(StatusCode::OK, "application/octet-stream", content),
        Err(e) => html(
            StatusCode::NOT_FOUND,
            "Not found",
            &format!("<p>Cannot open {}: {}</p>", html_escape(file), e.message()),
        ),
    }
}

fn ping(p: &Params) -> Resp {
    let Some(host) = p.get("host") else {
        return html(
            StatusCode::OK,
            "Network check",
            "<form method=post><input name=host value=127.0.0.1><button>Ping</button></form>",
        );
    };
    let out = shell::run(&format!("ping -c 1 {host} 2>&1"));
    html(
        StatusCode::OK,
        "Network check",
        &format!("<pre>{}</pre>", html_escape(&out.stdout)),
    )
}

fn order(path: &str, auth: &str) -> Resp {
    if auth != format!("Bearer {}", data::ATTACKER_TOKEN) {
        return json(
            StatusCode::UNAUTHORIZED,
            "{\"error\":\"unauthorized\"}".into(),
        );
    }
    let id = form_decode(path.trim_start_matches("/api/orders/"));
    match id.trim().parse::<i64>().ok().and_then(data::order_json) {
        // no check that the order belongs to the caller
        Some(o) => json(StatusCode::OK, o),
        None => json(
            StatusCode::NOT_FOUND,
            "{\"error\":\"no such order\"}".into(),
        ),
    }
}

fn login(method: &hyper::Method, p: &Params) -> Resp {
    if method != hyper::Method::POST {
        return html(
            StatusCode::OK,
            "Sign in",
            "<form method=post><input name=username><input name=password type=password><button>Sign in</button></form>",
        );
    }
    let (u, pw) = (
        p.get("username").unwrap_or(""),
        p.get("password").unwrap_or(""),
    );
    if u == "admin" && pw == data::ADMIN_PASSWORD {
        let mut r = json(
            StatusCode::OK,
            "{\"ok\":true,\"user\":\"admin\",\"role\":\"administrator\"}".into(),
        );
        r.headers_mut().insert(
            "set-cookie",
            "session=adm-2f9c41d07b; Path=/; HttpOnly"
                .parse()
                .expect("cookie"),
        );
        return r;
    }
    json(
        StatusCode::UNAUTHORIZED,
        "{\"error\":\"invalid credentials\"}".into(),
    )
}

async fn handle(req: Request<hyper::body::Incoming>) -> Result<Resp, Infallible> {
    let (parts, body) = req.into_parts();
    let body = body
        .collect()
        .await
        .map(|b| b.to_bytes())
        .unwrap_or_default();
    let header = |n: &str| {
        parts
            .headers
            .get(n)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string()
    };
    let path = parts.uri.path().to_string();
    let params = Params::parse(
        parts.uri.query().unwrap_or(""),
        &header("content-type"),
        &body,
        &header("cookie"),
    );
    Ok(match path.as_str() {
        "/" => html(
            StatusCode::OK,
            "Demo shop",
            "<h1>Demo shop</h1><ul><li><a href=\"/products?id=1\">Espresso cup</a></li><li><a href=\"/products?id=2\">Burr grinder</a></li><li><a href=\"/download?file=report.pdf\">Quarterly report</a></li><li><a href=\"/tools/ping\">Network check</a></li><li><a href=\"/login\">Sign in</a></li></ul>",
        ),
        "/robots.txt" => respond(
            StatusCode::OK,
            "text/plain",
            "User-agent: *\nDisallow: /admin/\nDisallow: /tools/\n",
        ),
        "/products" => products(&params),
        "/search" => {
            let q = params.get("q").unwrap_or("");
            respond(StatusCode::OK, "text/html; charset=utf-8", search_page(q))
        }
        "/download" => download(&params),
        "/tools/ping" => ping(&params),
        "/login" => login(&parts.method, &params),
        p if p.starts_with("/api/orders/") => order(p, &header("authorization")),
        _ => html(StatusCode::NOT_FOUND, "Not found", "<h1>Not found</h1>"),
    })
}

/// Starts the app on `127.0.0.1:0`; it runs until the runtime stops.
pub async fn start() -> std::io::Result<SocketAddr> {
    let l = TcpListener::bind("127.0.0.1:0").await?;
    let addr = l.local_addr()?;
    tokio::spawn(async move {
        loop {
            let Ok((s, _)) = l.accept().await else {
                continue;
            };
            tokio::spawn(async move {
                let _ = http1::Builder::new()
                    .serve_connection(TokioIo::new(s), service_fn(handle))
                    .await;
            });
        }
    });
    Ok(addr)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn form_decoding() {
        assert_eq!(form_decode("a+b%27c%2"), "a b'c%2");
        assert_eq!(form_decode("%2e%2e%2f"), "../");
        assert_eq!(form_decode("%252e"), "%2e", "decoded once");
        assert_eq!(form_decode("%zz"), "%zz");
    }

    #[test]
    fn parameters_come_from_body_query_and_cookies() {
        let p = Params::parse("id=1&id=2&q=x", "", b"", "id=9; c=a%20b");
        assert_eq!(p.get("id"), Some("2"), "last query value wins");
        assert_eq!(p.get("c"), Some("a b"));
        let p = Params::parse("id=1", "application/x-www-form-urlencoded", b"id=3", "");
        assert_eq!(p.get("id"), Some("3"), "body before query");
        let p = Params::parse("", "text/plain", br#"{"id": "1 OR 1=1", "n": 5}"#, "");
        assert_eq!(p.get("id"), Some("1 OR 1=1"), "JSON sniffed");
        assert_eq!(p.get("n"), Some("5"));
        let mp =
            "--b\r\nContent-Disposition: form-data; name=\"host\"\r\n\r\n127.0.0.1;id\r\n--b--\r\n";
        let p = Params::parse("", "multipart/form-data; boundary=b", mp.as_bytes(), "");
        assert_eq!(p.get("host"), Some("127.0.0.1;id"));
        assert_eq!(p.get("missing"), None);
    }
}
