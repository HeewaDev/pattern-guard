//! What `[[operations]]` and `[[logins]]` read from a request: the route they apply to,
//! and identifiers from a header, cookie, query parameter, form field or JSON field.
//!
//! Body identifiers (`form:` / `json:`) are read the way applications read them, not
//! by the declared content type alone (see `Body`), so switching the Content-Type
//! does not hide an account from the counters.
//!
//! Identifiers are hashed ([`hash`]: SHA-256, 64 bits kept); tokens and user names are
//! never stored or logged.

use std::cell::OnceCell;
use std::fmt;

use hyper::http::request::Parts;
use pattern_guard::waf::{body_text, form_fields};
use regex::Regex;
use serde::de::{DeserializeSeed, Deserializer, IgnoredAny, MapAccess, SeqAccess, Visitor};
use sha2::{Digest, Sha256};

use crate::policy::path::PathView;
use crate::util::form_decode;

/// Where an identifier comes from.
#[derive(Debug, Clone)]
pub(super) enum Field {
    Header(String),
    Cookie(String),
    Query(String),
    Form(String),
    Json(Vec<String>),
}

impl Field {
    pub(super) fn parse(spec: &str) -> Result<Self, String> {
        let (kind, name) = spec
            .split_once(':')
            .filter(|(_, n)| !n.is_empty())
            .ok_or_else(|| {
                format!("{spec:?}: expected header:, cookie:, query:, form: or json:")
            })?;
        Ok(match kind {
            "header" => Field::Header(name.to_ascii_lowercase()),
            "cookie" => Field::Cookie(name.to_string()),
            "query" => Field::Query(name.to_string()),
            "form" => Field::Form(name.to_string()),
            "json" => Field::Json(name.split('.').map(str::to_string).collect()),
            _ => return Err(format!("{spec:?}: unknown source {kind:?}")),
        })
    }

    /// The path of a body field: `[name]` for `form:`, the segments for `json:`.
    pub(super) fn body_path(&self) -> Option<&[String]> {
        match self {
            Field::Form(f) => Some(std::slice::from_ref(f)),
            Field::Json(path) => Some(path),
            _ => None,
        }
    }

    pub(super) fn extract(&self, parts: &Parts, body: &Body<'_>) -> Option<String> {
        let v = match self {
            Field::Header(h) => parts.headers.get(h)?.to_str().ok()?.to_string(),
            Field::Cookie(c) => parts
                .headers
                .get_all("cookie")
                .iter()
                .filter_map(|v| v.to_str().ok())
                .flat_map(|v| v.split(';'))
                .find_map(|kv| {
                    let (k, v) = kv.split_once('=')?;
                    (k.trim() == c).then(|| v.trim().to_string())
                })?,
            Field::Query(q) => form_value(parts.uri.query()?, q)?,
            Field::Form(_) | Field::Json(_) => body.get(self.body_path()?)?.to_string(),
        };
        let v = v.trim().to_string();
        (!v.is_empty()).then_some(v)
    }
}

fn form_value(s: &str, name: &str) -> Option<String> {
    s.split('&').find_map(|kv| {
        let (k, v) = kv.split_once('=').unwrap_or((kv, ""));
        (form_decode(k) == name).then(|| form_decode(v))
    })
}

/// A request body as the matching operations and logins read it.
///
/// Applications parse bodies whatever the declared type: many parse JSON from any
/// body, PHP, Django and Rails read multipart forms into the same parameters as
/// URL-encoded ones, and Laravel, Rails and Express merge JSON and form fields. So:
///
/// * the text comes from [`body_text`] (byte-order mark, charset, UTF-16 / UTF-32);
/// * `multipart/*` is read as form fields ([`form_fields`]);
/// * `application/x-www-form-urlencoded` is read as form fields first, then as JSON
///   if it looks like JSON;
/// * anything else is read as JSON first when the content type says JSON or the text
///   starts with `{` / `[`, then as form fields;
/// * `form:name` also matches a top-level JSON field `name`, and a one-segment
///   `json:name` a form field `name`.
///
/// The body is parsed at most once per request (lazily, only if a matching entry has
/// a body field), in one pass for the fields of all matching entries, and never into
/// a tree: JSON values off the wanted paths are skipped, and form pairs are compared
/// as they are read. Memory stays at one decoded copy of the text whatever the body's
/// shape, so the whole body is read and padding cannot push an identifier out of
/// view. Form fields keep their first value and JSON fields their last, like most
/// frameworks.
pub(super) struct Body<'a> {
    raw: &'a [u8],
    content_type: &'a str,
    multipart: bool,
    urlencoded: bool,
    declared_json: bool,
    /// The distinct body paths of the matching entries.
    wanted: Vec<&'a [String]>,
    text: OnceCell<String>,
    /// Per wanted path; `None` when the body isn't read as JSON.
    json: OnceCell<Option<Vec<Option<String>>>>,
    /// Per wanted path.
    form: OnceCell<Vec<Option<String>>>,
}

impl<'a> Body<'a> {
    pub(super) fn new(raw: &'a [u8], parts: &'a Parts, wanted: Vec<&'a [String]>) -> Self {
        let content_type = parts
            .headers
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        let ct = content_type.trim_start().to_ascii_lowercase();
        Self {
            raw,
            content_type,
            multipart: ct.starts_with("multipart/"),
            urlencoded: ct.starts_with("application/x-www-form-urlencoded"),
            declared_json: ct.contains("json"),
            wanted,
            text: OnceCell::new(),
            json: OnceCell::new(),
            form: OnceCell::new(),
        }
    }

    /// The value at a wanted `path`: from the body's main reading, else the other one.
    fn get(&self, path: &[String]) -> Option<&str> {
        let i = self.wanted.iter().position(|w| *w == path)?;
        let json = || self.json().and_then(|v| v[i].as_deref());
        let form = || self.form()[i].as_deref();
        if self.multipart {
            form()
        } else if !self.urlencoded && self.json().is_some() {
            json().or_else(form)
        } else {
            form().or_else(json)
        }
    }

    fn text(&self) -> &str {
        self.text
            .get_or_init(|| body_text(self.raw, self.content_type))
    }

    fn json(&self) -> Option<&Vec<Option<String>>> {
        self.json
            .get_or_init(|| {
                if self.multipart {
                    return None;
                }
                let text = self.text();
                let t = text.trim_start();
                (self.declared_json || t.starts_with('{') || t.starts_with('['))
                    .then(|| json_fields(text, &self.wanted))
            })
            .as_ref()
    }

    fn form(&self) -> &Vec<Option<String>> {
        self.form.get_or_init(|| {
            let mut out = vec![None; self.wanted.len()];
            let names: Vec<(usize, &str)> = self
                .wanted
                .iter()
                .enumerate()
                .filter_map(|(i, p)| match p {
                    [name] => Some((i, name.as_str())),
                    _ => None,
                })
                .collect();
            if names.is_empty() {
                return out;
            }
            if self.multipart {
                for (k, v) in form_fields(self.raw, self.content_type) {
                    for &(i, name) in &names {
                        if out[i].is_none() && k == name {
                            out[i] = Some(v.clone());
                        }
                    }
                }
                return out;
            }
            let mut left = names.len();
            for pair in self.text().split('&').filter(|p| !p.is_empty()) {
                let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
                for &(i, name) in &names {
                    if out[i].is_none() && form_key_is(k, name) {
                        out[i] = Some(form_decode(v));
                        left -= 1;
                    }
                }
                if left == 0 {
                    break;
                }
            }
            out
        })
    }
}

/// Whether a raw form key decodes to `name`. Decodes only keys that could: `%XX`
/// shrinks three bytes to one, so the decoded length lies between a third of the raw
/// length and the raw length.
fn form_key_is(raw: &str, name: &str) -> bool {
    if !raw.contains(['%', '+']) {
        return raw == name;
    }
    raw.len() >= name.len() && raw.len() <= name.len() * 3 && form_decode(raw) == name
}

/// The scalar (string, number or boolean) at each of `paths` in the JSON `text`. One
/// pass: values off the wanted paths are skipped without being built. A syntax error
/// keeps what was found before it.
fn json_fields(text: &str, paths: &[&[String]]) -> Vec<Option<String>> {
    let root = PathNode::build(paths);
    let mut out = vec![None; paths.len()];
    let mut de = serde_json::Deserializer::from_str(text);
    let _ = Seek {
        node: &root,
        out: &mut out,
    }
    .deserialize(&mut de);
    out
}

/// The wanted JSON paths as a tree.
#[derive(Default)]
struct PathNode<'a> {
    /// The path ending here.
    slot: Option<usize>,
    /// Every path ending in this subtree, cleared when a later duplicate key replaces it.
    below: Vec<usize>,
    children: Vec<(&'a str, PathNode<'a>)>,
}

impl<'a> PathNode<'a> {
    fn build(paths: &[&'a [String]]) -> Self {
        let mut root = PathNode::default();
        for (i, path) in paths.iter().enumerate() {
            let mut node = &mut root;
            for seg in path.iter() {
                node.below.push(i);
                let at = match node.children.iter().position(|(k, _)| k == seg) {
                    Some(at) => at,
                    None => {
                        node.children.push((seg.as_str(), PathNode::default()));
                        node.children.len() - 1
                    }
                };
                node = &mut node.children[at].1;
            }
            node.below.push(i);
            node.slot = Some(i);
        }
        root
    }

    fn child(&self, key: &str) -> Option<&PathNode<'a>> {
        self.children
            .iter()
            .find(|(k, _)| *k == key)
            .map(|(_, n)| n)
    }

    fn element(&self, index: usize) -> Option<&PathNode<'a>> {
        self.children
            .iter()
            .find(|(k, _)| k.parse::<usize>() == Ok(index))
            .map(|(_, n)| n)
    }

    fn last_element(&self) -> Option<usize> {
        self.children
            .iter()
            .filter_map(|(k, _)| k.parse::<usize>().ok())
            .max()
    }

    fn clear(&self, out: &mut [Option<String>]) {
        for &i in &self.below {
            out[i] = None;
        }
    }
}

/// Visits one JSON value at `node`, recording the scalars that end a wanted path.
struct Seek<'n, 'a, 'o> {
    node: &'n PathNode<'a>,
    out: &'o mut [Option<String>],
}

impl Seek<'_, '_, '_> {
    fn scalar(self, value: impl FnOnce() -> String) {
        if let Some(i) = self.node.slot {
            self.out[i] = Some(value());
        }
    }
}

impl<'de> DeserializeSeed<'de> for Seek<'_, '_, '_> {
    type Value = ();

    fn deserialize<D: Deserializer<'de>>(self, d: D) -> Result<(), D::Error> {
        d.deserialize_any(self)
    }
}

impl<'de> Visitor<'de> for Seek<'_, '_, '_> {
    type Value = ();

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a JSON value")
    }

    fn visit_bool<E>(self, v: bool) -> Result<(), E> {
        self.scalar(|| v.to_string());
        Ok(())
    }

    fn visit_i64<E>(self, v: i64) -> Result<(), E> {
        self.scalar(|| v.to_string());
        Ok(())
    }

    fn visit_u64<E>(self, v: u64) -> Result<(), E> {
        self.scalar(|| v.to_string());
        Ok(())
    }

    fn visit_f64<E>(self, v: f64) -> Result<(), E> {
        self.scalar(|| {
            serde_json::Number::from_f64(v)
                .map(|n| n.to_string())
                .unwrap_or_default()
        });
        Ok(())
    }

    fn visit_str<E>(self, v: &str) -> Result<(), E> {
        self.scalar(|| v.to_string());
        Ok(())
    }

    fn visit_unit<E>(self) -> Result<(), E> {
        Ok(())
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<(), A::Error> {
        let Seek { node, out } = self;
        while let Some(child) = map.next_key_seed(Key(node))? {
            match child {
                Some(n) => {
                    n.clear(out);
                    map.next_value_seed(Seek {
                        node: n,
                        out: &mut *out,
                    })?;
                }
                None => {
                    map.next_value::<IgnoredAny>()?;
                }
            }
        }
        Ok(())
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<(), A::Error> {
        let Seek { node, out } = self;
        let last = node.last_element();
        let mut index = 0usize;
        loop {
            let child = last
                .filter(|&l| index <= l)
                .and_then(|_| node.element(index));
            let more = match child {
                Some(n) => {
                    n.clear(out);
                    seq.next_element_seed(Seek {
                        node: n,
                        out: &mut *out,
                    })?
                    .is_some()
                }
                None => seq.next_element::<IgnoredAny>()?.is_some(),
            };
            if !more {
                return Ok(());
            }
            index += 1;
        }
    }
}

/// An object key: the matching child of the node, without copying the key.
struct Key<'n, 'a>(&'n PathNode<'a>);

impl<'de, 'n, 'a> DeserializeSeed<'de> for Key<'n, 'a> {
    type Value = Option<&'n PathNode<'a>>;

    fn deserialize<D: Deserializer<'de>>(self, d: D) -> Result<Self::Value, D::Error> {
        d.deserialize_str(self)
    }
}

impl<'n, 'a> Visitor<'_> for Key<'n, 'a> {
    type Value = Option<&'n PathNode<'a>>;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("an object key")
    }

    fn visit_str<E>(self, k: &str) -> Result<Self::Value, E> {
        Ok(self.0.child(k))
    }
}

/// Where an operation or login applies: a path prefix and / or regex, and methods.
pub(super) struct Route {
    prefix: Option<String>,
    re: Option<Regex>,
    methods: Vec<String>,
}

impl Route {
    pub(super) fn new(
        what: &str,
        prefix: &Option<String>,
        re: &Option<String>,
        methods: &[String],
    ) -> Result<Self, String> {
        if prefix.is_none() && re.is_none() {
            return Err(format!("{what}: set path or path_regex"));
        }
        Ok(Self {
            prefix: prefix.clone(),
            re: re
                .as_deref()
                .map(Regex::new)
                .transpose()
                .map_err(|e| format!("{what}: bad path_regex: {e}"))?,
            methods: methods.iter().map(|m| m.to_ascii_uppercase()).collect(),
        })
    }

    pub(super) fn matches(&self, parts: &Parts) -> bool {
        let path = PathView::new(parts.uri.path());
        self.prefix
            .as_deref()
            .is_none_or(|p| path.protects_prefix(p))
            && self.re.as_ref().is_none_or(|re| path.protects_regex(re))
            && (self.methods.is_empty() || self.methods.iter().any(|m| m == parts.method.as_str()))
    }
}

/// SHA-256 of `scope` and `value`, 64 bits kept: how identifiers are stored.
pub(super) fn hash(scope: &str, value: &str) -> u64 {
    let d = Sha256::new()
        .chain_update(scope.as_bytes())
        .chain_update([0u8])
        .chain_update(value.as_bytes())
        .finalize();
    u64::from_be_bytes(d[..8].try_into().expect("8 bytes"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyper::Request;

    fn req(method: &str, uri: &str, headers: &[(&str, &str)]) -> Parts {
        let mut b = Request::builder().method(method).uri(uri);
        for (k, v) in headers {
            b = b.header(*k, *v);
        }
        b.body(()).unwrap().into_parts().0
    }

    /// The identifier `spec` read from a body.
    fn read(spec: &str, content_type: Option<&str>, body: &[u8]) -> Option<String> {
        let headers: Vec<(&str, &str)> = content_type
            .map(|c| ("content-type", c))
            .into_iter()
            .collect();
        let p = req("POST", "/", &headers);
        let field = Field::parse(spec).unwrap();
        let b = Body::new(body, &p, vec![field.body_path().unwrap()]);
        field.extract(&p, &b)
    }

    #[test]
    fn json_fields_are_read_in_one_pass_like_a_json_parser() {
        let json = Some("application/json");
        let r = |spec, body: &str| read(spec, json, body.as_bytes());
        assert_eq!(
            r("json:user.email", r#"{"user":{"email":"a@x.io"}}"#).as_deref(),
            Some("a@x.io")
        );
        let items = r#"{"items":[{"id":1},{"id":"two"}]}"#;
        assert_eq!(r("json:items.1.id", items).as_deref(), Some("two"));
        assert_eq!(r("json:items.2.id", items), None);
        let scalars = r#"{"n": 12.5, "b": true, "i": -3, "z": null}"#;
        assert_eq!(r("json:n", scalars).as_deref(), Some("12.5"));
        assert_eq!(r("json:b", scalars).as_deref(), Some("true"));
        assert_eq!(r("json:i", scalars).as_deref(), Some("-3"));
        assert_eq!(r("json:z", scalars), None);
        assert_eq!(
            r("json:email", r#"{"email":{"x":"y"}}"#),
            None,
            "not a scalar"
        );
        // the last duplicate wins, as in JSON parsers
        assert_eq!(
            r("json:email", r#"{"email":"a","email":"b"}"#).as_deref(),
            Some("b")
        );
        assert_eq!(r("json:email", r#"{"email":"a","email":[1]}"#), None);
        let dup = r#"{"user":{"email":"a"},"user":{"name":"n"}}"#;
        assert_eq!(r("json:user.email", dup), None);
        // what precedes a syntax error (NaN, comments: lenient parsers accept them) counts
        assert_eq!(
            r("json:email", r#"{"email":"a", "x": NaN}"#).as_deref(),
            Some("a")
        );
        // deep nesting in another field is skipped, not refused
        let deep = format!(
            r#"{{"x":{}{},"email":"a"}}"#,
            "[".repeat(500),
            "]".repeat(500)
        );
        assert_eq!(r("json:email", &deep).as_deref(), Some("a"));
        // padding cannot push the identifier out of view
        let padded = format!(r#"{{"pad":"{}","email":"victim"}}"#, "x".repeat(200_000));
        assert_eq!(r("json:email", &padded).as_deref(), Some("victim"));
        let form = Some("application/x-www-form-urlencoded");
        let padded = format!("pad={}&username=victim", "x".repeat(200_000));
        assert_eq!(
            read("form:username", form, padded.as_bytes()).as_deref(),
            Some("victim")
        );
    }

    #[test]
    fn the_body_is_read_the_way_the_application_reads_it() {
        let form = Some("application/x-www-form-urlencoded");
        // a body that is valid JSON and also a form with a clean `email` field: a
        // URL-encoded body is a form to PHP and every framework, so the form decides
        let both = br#"{"a":"&email=target&","email":"decoy"}"#;
        assert_eq!(read("form:email", form, both).as_deref(), Some("target"));
        assert_eq!(read("json:email", form, both).as_deref(), Some("target"));
        // any other type is read as JSON first
        assert_eq!(
            read("form:email", Some("text/plain"), both).as_deref(),
            Some("decoy")
        );
        assert_eq!(read("json:email", None, both).as_deref(), Some("decoy"));
        // forms keep the first value; keys are decoded once
        assert_eq!(
            read("form:email", form, b"email=a&email=b").as_deref(),
            Some("a")
        );
        assert_eq!(
            read("form:email", form, b"%65mail=a%40x").as_deref(),
            Some("a@x")
        );
        assert_eq!(read("form:e mail", form, b"e+mail=a").as_deref(), Some("a"));
        assert_eq!(
            read("form:email", form, b"%2565mail=a"),
            None,
            "decoded once"
        );
        // multipart: text fields only, never file parts
        let mp = b"--b\r\nContent-Disposition: form-data; name=\"email\"; filename=\"e.txt\"\r\n\r\nfile\r\n--b--\r\n";
        assert_eq!(
            read("form:email", Some("multipart/form-data; boundary=b"), mp),
            None
        );
    }
}
