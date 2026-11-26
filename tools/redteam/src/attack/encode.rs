//! Where a payload goes in the request and how it is encoded on the wire. The demo app
//! decodes once and reads the parameter from the body, the query or a cookie, so these
//! choices change what the gateway sees but not what the app runs (double encoding is the
//! exception: the app decodes only once, so it breaks the payload, as on a real app).

use super::{Probe, Target, USER_AGENT};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Delivery {
    Query,
    /// `?p=<benign>&p=<payload>`: the app takes the last value.
    PollutedQuery,
    Form,
    Json,
    /// JSON with `Content-Type: text/plain` (the app sniffs JSON).
    JsonAsText,
    Multipart,
    Cookie,
}

impl Delivery {
    pub fn as_str(self) -> &'static str {
        match self {
            Delivery::Query => "query",
            Delivery::PollutedQuery => "polluted-query",
            Delivery::Form => "form",
            Delivery::Json => "json",
            Delivery::JsonAsText => "json-as-text",
            Delivery::Multipart => "multipart",
            Delivery::Cookie => "cookie",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Encoding {
    /// Only what the URI or form syntax requires.
    Minimal,
    /// Every byte that is not a letter or digit.
    Specials,
    /// Every byte.
    All,
    /// Percent-encoded twice.
    Double,
}

/// A payload with its delivery, ready to render.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Attempt {
    pub value: String,
    pub delivery: Delivery,
    pub encoding: Encoding,
    /// JSON strings with every non-alphanumeric character as `\u00XX`.
    pub json_unicode: bool,
}

impl Attempt {
    pub fn plain(value: &str, target: &Target) -> Attempt {
        Attempt {
            value: value.to_string(),
            delivery: if target.method == "POST" {
                Delivery::Form
            } else {
                Delivery::Query
            },
            encoding: Encoding::Minimal,
            json_unicode: false,
        }
    }
}

fn hex(b: u8) -> String {
    format!("%{b:02X}")
}

/// Percent-encodes a value for a query string, form body or cookie.
pub fn encode(value: &str, enc: Encoding) -> String {
    let mut out = String::new();
    for &b in value.as_bytes() {
        let keep = match enc {
            // RFC 3986 unreserved and sub-delimiters, minus the form's own `&`, `+`, `=`
            // stays as is too (the app splits on the first `=`)
            Encoding::Minimal => b.is_ascii_alphanumeric() || b"-._~!$'()*,/:;=?@".contains(&b),
            Encoding::Specials | Encoding::Double => b.is_ascii_alphanumeric(),
            Encoding::All => false,
        };
        if keep {
            out.push(b as char);
        } else {
            out.push_str(&hex(b));
        }
    }
    if enc == Encoding::Double {
        out = out.replace('%', "%25");
    }
    out
}

fn json_string(value: &str, unicode: bool) -> String {
    if !unicode {
        return serde_json::Value::String(value.to_string()).to_string();
    }
    let mut s = String::from("\"");
    for c in value.chars() {
        if c.is_ascii_alphanumeric() {
            s.push(c);
        } else {
            let mut buf = [0u16; 2];
            for u in c.encode_utf16(&mut buf) {
                s.push_str(&format!("\\u{u:04x}"));
            }
        }
    }
    s.push('"');
    s
}

const BOUNDARY: &str = "----pgrt7f3a9c";

/// The request for `attempt` against `target`.
pub fn render(attempt: &Attempt, target: &Target) -> Probe {
    let name = target.param;
    let v = encode(&attempt.value, attempt.encoding);
    let mut headers = vec![
        ("user-agent".to_string(), USER_AGENT.to_string()),
        ("accept".to_string(), "*/*".to_string()),
    ];
    let mut body = Vec::new();
    let (method, query) = match attempt.delivery {
        Delivery::Query => ("GET", Some(format!("{name}={v}"))),
        Delivery::PollutedQuery => (
            "GET",
            Some(format!(
                "{name}={}&{name}={v}",
                encode(target.benign, Encoding::Minimal)
            )),
        ),
        Delivery::Cookie => {
            // `;` and `,` separate cookies
            let v = v.replace(';', "%3B").replace(',', "%2C");
            headers.push(("cookie".into(), format!("{name}={v}")));
            ("GET", None)
        }
        Delivery::Form => {
            headers.push((
                "content-type".into(),
                "application/x-www-form-urlencoded".into(),
            ));
            body = format!("{name}={v}").into_bytes();
            ("POST", None)
        }
        Delivery::Json | Delivery::JsonAsText => {
            let ct = if attempt.delivery == Delivery::Json {
                "application/json"
            } else {
                "text/plain"
            };
            headers.push(("content-type".into(), ct.into()));
            body = format!(
                "{{\"{name}\":{}}}",
                json_string(&attempt.value, attempt.json_unicode)
            )
            .into_bytes();
            ("POST", None)
        }
        Delivery::Multipart => {
            headers.push((
                "content-type".into(),
                format!("multipart/form-data; boundary={BOUNDARY}"),
            ));
            body = format!(
                "--{BOUNDARY}\r\nContent-Disposition: form-data; name=\"{name}\"\r\n\r\n{}\r\n--{BOUNDARY}--\r\n",
                attempt.value
            )
            .into_bytes();
            ("POST", None)
        }
    };
    let target_uri = match query {
        Some(q) => format!("{}?{q}", target.path),
        None => target.path.to_string(),
    };
    Probe {
        method: method.into(),
        target: target_uri,
        headers,
        body,
        goal: Some(target.vuln),
        ..Default::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Vuln;
    use crate::app::{Params, form_decode};
    use crate::attack::target;

    /// What the demo app reads back from a rendered attempt.
    fn read_back(a: &Attempt, t: &Target) -> String {
        let p = render(a, t);
        let (path, query) = p.target.split_once('?').unwrap_or((&p.target, ""));
        assert_eq!(path, t.path);
        let h = |n: &str| {
            p.headers
                .iter()
                .find(|(k, _)| k == n)
                .map(|(_, v)| v.clone())
                .unwrap_or_default()
        };
        Params::parse(query, &h("content-type"), &p.body, &h("cookie"))
            .get(t.param)
            .unwrap_or("")
            .to_string()
    }

    #[test]
    fn every_delivery_reaches_the_app_unchanged() {
        let t = target(Vuln::Sqli);
        let value = "0 UNION SELECT a,b FROM users WHERE x='1&2' -- é;\"+%";
        for d in [
            Delivery::Query,
            Delivery::PollutedQuery,
            Delivery::Form,
            Delivery::Json,
            Delivery::JsonAsText,
            Delivery::Multipart,
            Delivery::Cookie,
        ] {
            for e in [Encoding::Minimal, Encoding::Specials, Encoding::All] {
                for u in [false, true] {
                    let a = Attempt {
                        value: value.into(),
                        delivery: d,
                        encoding: e,
                        json_unicode: u,
                    };
                    assert_eq!(read_back(&a, t), value, "{d:?} {e:?} unicode={u}");
                }
            }
        }
    }

    #[test]
    fn double_encoding_reaches_the_app_still_encoded() {
        assert_eq!(encode("../", Encoding::Double), "%252E%252E%252F");
        assert_eq!(form_decode(&encode("../", Encoding::Double)), "%2E%2E%2F");
        assert_eq!(encode("a b", Encoding::Minimal), "a%20b");
    }
}
