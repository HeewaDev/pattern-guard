//! Gatekeeper policy evaluated before inspection: custom rules, rate limits, business
//! operations and logins, bans, honeypot traps and protocol enforcement.
//!
//! Policies that learn from traffic come in two halves: the **definitions**, compiled
//! from the config and rebuilt on a reload (`Limits`, `Operations`, `Bans`), and the
//! **learned state**, which is kept (`Buckets`, `OperationCaches`, `Offenders`). The
//! learned half is keyed by `definition_ids`, so it follows a definition by name.

use std::collections::HashMap;
use std::hash::{DefaultHasher, Hash, Hasher};

pub mod bans;
mod fields;
mod logins;
pub mod operations;
pub mod path;
pub mod protocol;
pub mod rate_limit;
pub mod rules;

/// Stable identities for definitions in config order: the `n`-th definition called
/// `name` gets a hash of `(name, n)`. Learned state is keyed by it rather than by the
/// position in the list, so a definition keeps its state when others are added or
/// removed around it, and two definitions sharing a name still keep separate state.
pub(crate) fn definition_ids<'a>(names: impl IntoIterator<Item = &'a str>) -> Vec<u64> {
    let mut seen: HashMap<&str, usize> = HashMap::new();
    names
        .into_iter()
        .map(|name| {
            let nth = seen.entry(name).or_default();
            // `DefaultHasher::new()` hashes alike within a process; names come from
            // the operator's config, not from clients.
            let mut h = DefaultHasher::new();
            (name, *nth).hash(&mut h);
            *nth += 1;
            h.finish()
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn definition_ids_follow_names_and_keep_duplicates_apart() {
        let a = definition_ids(["login", "api", "login"]);
        let b = definition_ids(["api", "login", "new", "login"]);
        assert_eq!(a.len(), 3);
        assert_ne!(a[0], a[2], "duplicates keep separate state");
        assert_eq!(
            (a[0], a[1], a[2]),
            (b[1], b[0], b[3]),
            "found again by name"
        );
        assert!(!a.contains(&b[2]));
    }
}
