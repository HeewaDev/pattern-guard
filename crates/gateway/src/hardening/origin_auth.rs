//! Origin authentication: a secret header on every upstream request, so the application
//! (or the web server in front of it) can refuse requests that bypassed the gateway.
//! A firewall that only lets the gateway reach the application is the stronger control;
//! this header is for upstreams that are reachable some other way (a cloud load balancer,
//! a shared network, a public IP that cannot be closed).

use hyper::HeaderMap;
use hyper::header::{HeaderName, HeaderValue};

use crate::config::OriginAuthConfig;

/// Shortest secret accepted (characters).
const MIN_SECRET: usize = 32;

pub struct OriginAuth {
    name: HeaderName,
    value: HeaderValue,
}

impl OriginAuth {
    /// `None` when disabled. Reads `secret_env` now, so a missing variable stops start-up.
    pub fn new(cfg: &OriginAuthConfig) -> Result<Option<Self>, String> {
        if !cfg.enabled {
            return Ok(None);
        }
        let secret = match (&cfg.secret_env, &cfg.secret) {
            (Some(var), _) => std::env::var(var)
                .map_err(|_| format!("origin_auth: environment variable {var} is not set"))?,
            (None, Some(s)) => s.clone(),
            (None, None) => return Err("origin_auth: set secret_env (or secret)".into()),
        };
        let secret = secret.trim();
        if secret.len() < MIN_SECRET {
            return Err(format!(
                "origin_auth: the secret must be at least {MIN_SECRET} characters"
            ));
        }
        let name = HeaderName::from_bytes(cfg.header.to_ascii_lowercase().as_bytes())
            .map_err(|_| format!("origin_auth.header: {:?} is not a header name", cfg.header))?;
        let mut value = HeaderValue::from_str(secret)
            .map_err(|_| "origin_auth: the secret must be printable ASCII".to_string())?;
        // kept out of debug output and HTTP/2 header compression tables
        value.set_sensitive(true);
        Ok(Some(Self { name, value }))
    }

    /// On a request to the upstream: replaces any copy the client sent.
    pub fn apply(&self, h: &mut HeaderMap) {
        h.insert(self.name.clone(), self.value.clone());
    }

    /// On a response to the client: an application that echoes request headers (debug
    /// pages, error pages) must not reveal the secret.
    pub fn strip(&self, h: &mut HeaderMap) {
        h.remove(&self.name);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(toml: &str) -> OriginAuthConfig {
        toml::from_str(toml).unwrap()
    }

    #[test]
    fn replaces_client_copies_and_strips_echoes() {
        let a = OriginAuth::new(&cfg(&format!(
            "enabled = true\nheader = \"X-Origin-Auth\"\nsecret = \"{}\"",
            "s".repeat(40)
        )))
        .unwrap()
        .unwrap();
        let mut h = HeaderMap::new();
        h.append("x-origin-auth", HeaderValue::from_static("forged"));
        h.append("x-origin-auth", HeaderValue::from_static("forged-too"));
        a.apply(&mut h);
        let all: Vec<_> = h.get_all("x-origin-auth").iter().collect();
        assert_eq!(all.len(), 1);
        assert_eq!(all[0], "s".repeat(40).as_str());
        assert!(all[0].is_sensitive());
        a.strip(&mut h);
        assert!(h.get("x-origin-auth").is_none());
    }

    #[test]
    fn disabled_short_or_missing_secrets() {
        assert!(OriginAuth::new(&cfg("")).unwrap().is_none());
        let short = cfg("enabled = true\nsecret = \"tooshort\"");
        assert!(OriginAuth::new(&short).is_err());
        let missing = cfg("enabled = true\nsecret_env = \"PG_TEST_ORIGIN_SECRET_UNSET_7F3A\"");
        let e = OriginAuth::new(&missing).err().unwrap();
        assert!(e.contains("PG_TEST_ORIGIN_SECRET_UNSET_7F3A"), "{e}");
    }
}
