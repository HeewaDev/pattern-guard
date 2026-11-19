//! Custom firewall rules: conditions on path, method, host, client IP, user agent, query
//! and headers, with an action. Evaluated in file order; the first terminal action
//! (allow / block / challenge / delay) wins, `log` and `skip_waf` accumulate.

use std::net::IpAddr;

use hyper::http::request::Parts;
use regex::Regex;

use crate::config::{RuleAction, RuleConfig};
use crate::ipnet::{Cidr, any_contains};

struct HeaderCond {
    name: String,
    regex: Option<Regex>,
    absent: bool,
}

struct Rule {
    name: String,
    path_prefix: Option<String>,
    path_re: Option<Regex>,
    methods: Vec<String>,
    hosts: Vec<String>,
    ips: Vec<Cidr>,
    not_ips: Vec<Cidr>,
    ua_re: Option<Regex>,
    query_re: Option<Regex>,
    headers: Vec<HeaderCond>,
    countries: Vec<String>,
    action: RuleAction,
}

/// Result of evaluating all rules for one request.
#[derive(Debug, Default, Clone, PartialEq)]
pub struct RuleOutcome {
    /// First terminal action and the rule's name.
    pub terminal: Option<(RuleAction, String)>,
    pub skip_waf: bool,
    /// Names of matching `log` rules.
    pub logged: Vec<String>,
}

#[derive(Default)]
pub struct RuleSet {
    rules: Vec<Rule>,
}

fn regex(field: &str, rule: &str, pattern: &Option<String>) -> Result<Option<Regex>, String> {
    pattern
        .as_deref()
        .map(|p| Regex::new(p).map_err(|e| format!("rule {rule:?}: bad {field}: {e}")))
        .transpose()
}

fn cidrs(field: &str, rule: &str, list: &[String]) -> Result<Vec<Cidr>, String> {
    list.iter()
        .map(|c| Cidr::parse(c).ok_or_else(|| format!("rule {rule:?}: bad {field} entry {c:?}")))
        .collect()
}

impl RuleSet {
    pub fn compile(cfgs: &[RuleConfig]) -> Result<Self, String> {
        let mut rules = Vec::with_capacity(cfgs.len());
        for c in cfgs {
            let n = &c.name;
            let headers = c
                .headers
                .iter()
                .map(|h| {
                    Ok(HeaderCond {
                        name: h.name.to_ascii_lowercase(),
                        regex: regex("header regex", n, &h.regex)?,
                        absent: h.absent,
                    })
                })
                .collect::<Result<Vec<_>, String>>()?;
            rules.push(Rule {
                name: c.name.clone(),
                path_prefix: c.path.clone(),
                path_re: regex("path_regex", n, &c.path_regex)?,
                methods: c.methods.iter().map(|m| m.to_ascii_uppercase()).collect(),
                hosts: c.hosts.iter().map(|h| h.to_ascii_lowercase()).collect(),
                ips: cidrs("ips", n, &c.ips)?,
                not_ips: cidrs("not_ips", n, &c.not_ips)?,
                ua_re: regex("user_agent_regex", n, &c.user_agent_regex)?,
                query_re: regex("query_regex", n, &c.query_regex)?,
                headers,
                countries: c.countries.iter().map(|c| c.to_ascii_uppercase()).collect(),
                action: c.action,
            });
        }
        Ok(Self { rules })
    }

    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    /// True if any rule has a `countries` condition (needs a geo database).
    pub fn uses_countries(&self) -> bool {
        self.rules.iter().any(|r| !r.countries.is_empty())
    }

    pub fn evaluate(&self, ip: IpAddr, parts: &Parts, country: Option<&str>) -> RuleOutcome {
        let mut out = RuleOutcome::default();
        for r in &self.rules {
            if !r.matches(ip, parts, country) {
                continue;
            }
            match r.action {
                RuleAction::Log => out.logged.push(r.name.clone()),
                RuleAction::SkipWaf => out.skip_waf = true,
                terminal => {
                    out.terminal = Some((terminal, r.name.clone()));
                    break;
                }
            }
        }
        out
    }
}

fn host_matches(pattern: &str, host: &str) -> bool {
    match pattern.strip_prefix("*.") {
        Some(suffix) => host.len() > suffix.len() + 1 && host.ends_with(&format!(".{suffix}")),
        None => pattern == host,
    }
}

impl Rule {
    fn matches(&self, ip: IpAddr, parts: &Parts, country: Option<&str>) -> bool {
        if !self.countries.is_empty()
            && !country.is_some_and(|c| self.countries.iter().any(|x| x == c))
        {
            return false;
        }
        let path = parts.uri.path();
        let header = |name: &str| parts.headers.get(name).and_then(|v| v.to_str().ok());
        if let Some(p) = &self.path_prefix {
            if !path.starts_with(p.as_str()) {
                return false;
            }
        }
        if let Some(re) = &self.path_re {
            if !re.is_match(path) {
                return false;
            }
        }
        if !self.methods.is_empty() && !self.methods.iter().any(|m| m == parts.method.as_str()) {
            return false;
        }
        if !self.hosts.is_empty() {
            let host = header("host")
                .or(parts.uri.host())
                .unwrap_or("")
                .split(':')
                .next()
                .unwrap_or("")
                .to_ascii_lowercase();
            if !self.hosts.iter().any(|h| host_matches(h, &host)) {
                return false;
            }
        }
        if !self.ips.is_empty() && !any_contains(&self.ips, ip) {
            return false;
        }
        if any_contains(&self.not_ips, ip) {
            return false;
        }
        if let Some(re) = &self.ua_re {
            if !re.is_match(header("user-agent").unwrap_or("")) {
                return false;
            }
        }
        if let Some(re) = &self.query_re {
            if !re.is_match(parts.uri.query().unwrap_or("")) {
                return false;
            }
        }
        for h in &self.headers {
            let v = header(&h.name);
            let ok = match (v, h.absent) {
                (None, true) => true,
                (Some(_), true) => false,
                (None, false) => false,
                (Some(v), false) => h.regex.as_ref().is_none_or(|re| re.is_match(v)),
            };
            if !ok {
                return false;
            }
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyper::Request;

    fn parts(method: &str, uri: &str, headers: &[(&str, &str)]) -> Parts {
        let mut b = Request::builder().method(method).uri(uri);
        for (k, v) in headers {
            b = b.header(*k, *v);
        }
        b.body(()).unwrap().into_parts().0
    }

    fn rules(toml_rules: &str) -> RuleSet {
        let cfg = crate::config::GatewayConfig::from_toml_str(&format!(
            "upstream = \"http://127.0.0.1:1\"\n{toml_rules}"
        ))
        .unwrap();
        RuleSet::compile(&cfg.rules).unwrap()
    }

    #[test]
    fn first_terminal_wins_and_log_accumulates() {
        let rs = rules(
            r#"
[[rules]]
name = "audit admin"
path = "/admin"
action = "log"
[[rules]]
name = "office may use admin"
path = "/admin"
ips = ["10.0.0.0/8"]
action = "allow"
[[rules]]
name = "nobody else"
path = "/admin"
action = "block"
"#,
        );
        let office: IpAddr = "10.1.2.3".parse().unwrap();
        let other: IpAddr = "203.0.113.9".parse().unwrap();
        let p = parts("GET", "/admin/users", &[]);
        let o = rs.evaluate(office, &p, None);
        assert_eq!(
            o.terminal,
            Some((RuleAction::Allow, "office may use admin".into()))
        );
        assert_eq!(o.logged, vec!["audit admin".to_string()]);
        assert_eq!(
            rs.evaluate(other, &p, None).terminal.unwrap().0,
            RuleAction::Block
        );
        assert_eq!(
            rs.evaluate(other, &parts("GET", "/shop", &[]), None),
            RuleOutcome::default()
        );
    }

    #[test]
    fn conditions() {
        let rs = rules(
            r#"
[[rules]]
name = "api needs key"
path_regex = "^/api/"
methods = ["post", "put"]
hosts = ["*.example.com"]
headers = [{ name = "X-Api-Key", absent = true }]
action = "block"
[[rules]]
name = "bad ua"
user_agent_regex = "(?i)sqlmap|nikto"
action = "challenge"
[[rules]]
name = "no waf on webhooks"
query_regex = "^sig="
not_ips = ["192.0.2.0/24"]
action = "skip_waf"
"#,
        );
        let ip: IpAddr = "198.51.100.1".parse().unwrap();
        let hit = parts("POST", "/api/items", &[("host", "shop.example.com:8443")]);
        assert_eq!(
            rs.evaluate(ip, &hit, None).terminal.unwrap().1,
            "api needs key"
        );
        let keyed = parts(
            "POST",
            "/api/items",
            &[("host", "shop.example.com"), ("x-api-key", "k")],
        );
        assert!(rs.evaluate(ip, &keyed, None).terminal.is_none());
        let apex = parts("POST", "/api/items", &[("host", "example.com")]);
        assert!(
            rs.evaluate(ip, &apex, None).terminal.is_none(),
            "*.example.com excludes the apex"
        );
        let get = parts("GET", "/api/items", &[("host", "a.example.com")]);
        assert!(rs.evaluate(ip, &get, None).terminal.is_none());
        let ua = parts("GET", "/", &[("user-agent", "sqlmap/1.7")]);
        assert_eq!(
            rs.evaluate(ip, &ua, None).terminal.unwrap().0,
            RuleAction::Challenge
        );
        let hook = parts("POST", "/hook?sig=abc", &[]);
        assert!(rs.evaluate(ip, &hook, None).skip_waf);
        assert!(
            !rs.evaluate("192.0.2.5".parse().unwrap(), &hook, None)
                .skip_waf
        );
    }

    #[test]
    fn bad_patterns_are_reported() {
        let cfg = crate::config::GatewayConfig::from_toml_str(
            "upstream = \"http://127.0.0.1:1\"\n[[rules]]\nname = \"x\"\npath_regex = \"(\"\naction = \"block\"\n",
        )
        .unwrap();
        let err = RuleSet::compile(&cfg.rules).err().expect("compile error");
        assert!(err.contains("path_regex"), "{err}");
    }
}
