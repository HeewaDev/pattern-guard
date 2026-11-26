//! Decides from a response whether a vulnerability was confirmed. The vulnerability is
//! the one of the endpoint the request went to, and the evidence must be in what the
//! client received (a response the gateway replaced confirms nothing).

use crate::Vuln;
use crate::app::{data, fs, shell};
use crate::browser;

/// A confirmed vulnerability and what proves it.
#[derive(Debug, Clone, PartialEq)]
pub struct Confirmation {
    pub vuln: Vuln,
    pub evidence: String,
    /// The BOLA order id read (another customer's), for counting leaked records.
    pub record: Option<i64>,
}

fn found(vuln: Vuln, evidence: &str) -> Option<Confirmation> {
    Some(Confirmation {
        vuln,
        evidence: evidence.to_string(),
        record: None,
    })
}

/// The vulnerable endpoint a request path belongs to.
pub fn endpoint(path: &str) -> Option<Vuln> {
    let path = path.split('?').next().unwrap_or(path);
    Some(match path {
        "/products" => Vuln::Sqli,
        "/search" => Vuln::Xss,
        "/download" => Vuln::Traversal,
        "/tools/ping" => Vuln::Cmdi,
        "/login" => Vuln::BruteForce,
        p if p.starts_with("/api/orders/") => Vuln::Bola,
        _ => return None,
    })
}

/// The request, as far as the oracle needs it.
pub struct Request<'a> {
    pub target: &'a str,
    pub content_type: &'a str,
    pub body: &'a [u8],
}

/// [`confirm`], plus: a reflected XSS counts only when a victim can be made to send it
/// (a link or a cross-site form post), not from a cookie or an `application/json` body.
pub fn confirm_request(req: &Request, status: u16, body: &str) -> Option<Confirmation> {
    let c = confirm(req.target, status, body)?;
    if c.vuln == Vuln::Xss {
        if req
            .content_type
            .to_ascii_lowercase()
            .contains("application/json")
        {
            return None;
        }
        let query = req.target.split_once('?').map_or("", |(_, q)| q);
        let params = crate::app::Params::parse(query, req.content_type, req.body, "");
        params.get("q")?;
    }
    Some(c)
}

/// `path` is the request target, `status` and `body` the response as received.
pub fn confirm(path: &str, status: u16, body: &str) -> Option<Confirmation> {
    if status != 200 {
        return None;
    }
    let vuln = endpoint(path)?;
    match vuln {
        Vuln::Sqli => {
            if body.contains(data::ADMIN_HASH) {
                found(vuln, "admin password hash read via UNION")
            } else if body.contains(data::HIDDEN_PRODUCT) {
                found(vuln, "hidden product listed")
            } else {
                None
            }
        }
        Vuln::Xss => {
            // only the app's search page counts (not, say, a gateway page with script)
            if !body.contains("Results for: ") {
                return None;
            }
            browser::script_runs(body).map(|what| Confirmation {
                vuln,
                evidence: format!("script runs: {what}"),
                record: None,
            })
        }
        Vuln::Traversal => {
            if body.contains(fs::PASSWD_MARKER) {
                found(vuln, "/etc/passwd read")
            } else if body.contains(fs::ENVIRON_MARKER) {
                found(vuln, "/proc/self/environ read")
            } else {
                None
            }
        }
        Vuln::Cmdi => {
            let pre = body
                .split("<pre>")
                .nth(1)
                .and_then(|r| r.split("</pre>").next())
                .unwrap_or("");
            if pre.contains("33(www-data)") {
                found(vuln, "id ran")
            } else if pre.contains(fs::PASSWD_MARKER)
                || pre.contains(":/bin/bash")
                || pre.contains("/usr/sbin/nologin")
            {
                // (all of it, or the one line a substitution leaves in ping's error)
                found(vuln, "/etc/passwd printed")
            } else if pre.contains(shell::UNAME_A) {
                found(vuln, "uname -a ran")
            } else if pre.lines().any(|l| l == "www-data") || pre.contains("ping: www-data:") {
                found(vuln, "whoami ran")
            } else {
                None
            }
        }
        Vuln::Bola => {
            let v: serde_json::Value = serde_json::from_str(body).ok()?;
            let owner = v["owner"].as_str()?;
            if owner == data::ATTACKER_USER {
                return None;
            }
            Some(Confirmation {
                vuln,
                evidence: format!("order of {owner} read"),
                record: v["id"].as_i64(),
            })
        }
        Vuln::BruteForce => {
            if body.contains("\"user\":\"admin\"") {
                found(vuln, "logged in as admin")
            } else {
                None
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn evidence_must_come_back_with_200() {
        let page = crate::app::search_page("<svg onload=alert(1)>");
        assert_eq!(confirm("/search?q=x", 200, &page).unwrap().vuln, Vuln::Xss);
        assert!(confirm("/search?q=x", 403, &page).is_none());
        assert!(confirm("/search", 200, "<script>gateway challenge</script>").is_none());
        assert!(confirm("/products?id=1", 200, data::HIDDEN_PRODUCT).is_some());
        assert!(confirm("/download?file=x", 200, fs::PASSWD_MARKER).is_some());
        assert!(confirm("/elsewhere", 200, fs::PASSWD_MARKER).is_none());
        let theirs = data::order_json(1001).unwrap();
        let mine = data::order_json(1002).unwrap();
        assert_eq!(
            confirm("/api/orders/1001", 200, &theirs).unwrap().record,
            Some(1001)
        );
        assert!(confirm("/api/orders/1002", 200, &mine).is_none());
        assert!(confirm("/tools/ping", 200, "<pre>uid=33(www-data) gid=33</pre>").is_some());
        assert!(confirm("/tools/ping", 200, "<pre>PING 127.0.0.1</pre>").is_none());
    }

    #[test]
    fn xss_must_be_deliverable_to_a_victim() {
        let page = crate::app::search_page("<svg onload=alert(1)>");
        let req = |target, content_type, body: &'static [u8]| Request {
            target,
            content_type,
            body,
        };
        assert!(confirm_request(&req("/search?q=%3Csvg%3E", "", b""), 200, &page).is_some());
        assert!(
            confirm_request(
                &req("/search", "application/x-www-form-urlencoded", b"q=x"),
                200,
                &page
            )
            .is_some()
        );
        assert!(
            confirm_request(&req("/search", "text/plain", b"{\"q\":\"x\"}"), 200, &page).is_some()
        );
        assert!(
            confirm_request(&req("/search", "", b""), 200, &page).is_none(),
            "cookie only"
        );
        assert!(
            confirm_request(
                &req("/search", "application/json", b"{\"q\":\"x\"}"),
                200,
                &page
            )
            .is_none()
        );
    }
}
