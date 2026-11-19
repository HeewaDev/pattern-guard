//! Payload inspection (web application firewall).
//!
//! Every inspected value (path, query/body parameters, JSON strings and keys, cookies,
//! selected headers) is **decoded** the way a server or browser would decode it
//! (repeated URL-decoding, `%uXXXX`, HTML entities, `\uXXXX`/`\xHH`, SQL comments,
//! case, whitespace) and then **scored**: each attack class sums the weights of the
//! indicators that matched, capped at 10. A single weak signal (an apostrophe in
//! "O'Brien", the word "select" in a sentence) stays low; combinations that only
//! appear in attacks (`' OR '1'='1`, `<img src=x onerror=…>`) score high.
//!
//! Suggested thresholds: log ≥ 4, block ≥ 7.

mod decode;
mod indicators;
mod inspect;
mod lexicon;
mod shell;
mod ssrf;

pub use decode::decode;
pub use indicators::AttackClass;
pub use inspect::{Finding, HttpRequest, Inspection, Inspector};
