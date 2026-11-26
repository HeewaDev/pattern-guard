//! Snapshots of what a [`Guard`](crate::Guard) has learned, so it can survive a restart.
//!
//! [`Guard::snapshot`](crate::Guard::snapshot) copies the learned state (the clock, the
//! feature engine's actor / client / subnet / route tables, the rules' sliding windows
//! and the cooldowns), a chunk of entries per hold of the state lock;
//! [`Guard::restore`](crate::Guard::restore) puts one back. The engine does no I/O:
//! serialise the [`Snapshot`] with any serde format ([`Snapshot::to_json`] /
//! [`Snapshot::from_json`] for JSON) and store it yourself.
//!
//! Size at the default caps (100 000 actors, 50 000 clients and subnets, 10 000 routes):
//! ~160 MB of JSON when actors send a few requests each, ~540 MB when every actor has
//! filled its route and object-id lists, ~900 MB with rule windows of 40 entries on
//! top. Serialising that takes 0.15–0.8 s, parsing about twice as long.
//!
//! - **Versioned.** A snapshot carries [`FORMAT_VERSION`] and a [`layout_fingerprint`]
//!   (the feature layout and the key hashing). A snapshot from another format or layout
//!   is refused with [`Error::SnapshotVersion`] / [`Error::SnapshotLayout`] (after
//!   skipping its body, so an old format doesn't have to parse).
//! - **Bounded.** `restore` re-applies the configured caps (`max_actors`,
//!   `adaptive.max_*`, per-entry list sizes): a snapshot can't make the guard hold more
//!   than its config allows. Tables keep their least-recently-used order.
//! - **Keys only.** Actors, clients, routes and rule targets are stored as the 64-bit
//!   hashes the engine keys them by, never as the ids, user agents or paths themselves.
//!   They are not anonymous: `ip:<address>` is quick to brute-force. Protect the file.
//! - **Exact.** Floats are stored as their IEEE-754 bits, so a restored guard makes the
//!   same decisions as the original would have; NaN and infinities are refused on load.
//! - **Time.** Counters hold absolute times, so with `time_source = "event"` the first
//!   event after a restart decays everything by the real gap, however long it was. A
//!   snapshot whose clock is more than [`MAX_CLOCK_AHEAD_SECS`] ahead of the system clock
//!   is refused (the clock never goes backwards, so decay would stop until real time
//!   caught up). With `time_source = "system"` the restored clock resumes at the saved
//!   reading plus the wall-clock time that passed.

use std::hash::Hash;

use lru::LruCache;
use serde::de::{self, Deserializer, IgnoredAny, MapAccess, SeqAccess, Visitor};
use serde::ser::{SerializeStruct, Serializer};
use serde::{Deserialize, Serialize};

use crate::error::Error;
use crate::features::{FEATURE_NAMES, N_FEATURES};
use crate::util::normalize::hash_str;

/// Snapshot format written by this build.
pub const FORMAT_VERSION: u32 = 1;

/// With `time_source = "event"`, a snapshot whose clock is this far ahead of the system
/// clock is refused.
pub const MAX_CLOCK_AHEAD_SECS: f64 = 60.0;

/// With `time_source = "system"`, the largest clock reading a restore accepts (about 300
/// years of uptime; beyond it the clock would lose its sub-second resolution).
pub const MAX_SYSTEM_CLOCK_SECS: f64 = 1e10;

/// With `time_source = "system"`, the longest gap between `taken_at` and the restore
/// that is added to the clock (ten years: every counter has decayed long before).
pub const MAX_RESTART_GAP_SECS: f64 = 10.0 * 365.0 * 86_400.0;

/// Identifies what a snapshot's tables depend on besides their format: the feature
/// layout ([`N_FEATURES`], [`FEATURE_NAMES`]) and the hash that turns actor ids, user
/// agents and routes into keys (`hash_str`, computed here with it, so a build whose hash
/// differs gets a different fingerprint instead of tables nothing would ever match).
pub fn layout_fingerprint() -> u64 {
    let n = N_FEATURES.to_string();
    let mut parts: Vec<&str> = vec!["pattern-guard snapshot layout", &n];
    parts.extend(FEATURE_NAMES);
    hash_str(&parts)
}

/// What a [`Guard`](crate::Guard) has learned. See the [module docs](self).
#[derive(Debug, Clone)]
pub struct Snapshot {
    pub(crate) version: u32,
    pub(crate) layout: u64,
    /// `None` when the version or layout didn't match (the body was skipped).
    pub(crate) state: Option<crate::guard::Learned>,
}

impl Snapshot {
    pub(crate) fn new(state: crate::guard::Learned) -> Self {
        Self {
            version: FORMAT_VERSION,
            layout: layout_fingerprint(),
            state: Some(state),
        }
    }

    /// Format version it was written with.
    pub fn version(&self) -> u32 {
        self.version
    }

    /// Actors it holds (feature tables), 0 for an incompatible snapshot.
    pub fn actors(&self) -> usize {
        self.state.as_ref().map_or(0, |s| s.actors())
    }

    /// The learned state, or why this build can't use it.
    pub(crate) fn into_state(self) -> Result<crate::guard::Learned, Error> {
        if self.version != FORMAT_VERSION {
            return Err(Error::SnapshotVersion {
                found: self.version,
                expected: FORMAT_VERSION,
            });
        }
        if self.layout != layout_fingerprint() {
            return Err(Error::SnapshotLayout);
        }
        self.state
            .ok_or_else(|| Error::SnapshotInvalid("no state in the snapshot".into()))
    }

    pub fn to_json(&self) -> Vec<u8> {
        serde_json::to_vec(self).expect("a snapshot always serialises")
    }

    /// Parses [`to_json`](Self::to_json) output. Truncated or malformed input is an
    /// [`Error::SnapshotInvalid`]; a version or layout mismatch is reported by
    /// [`Guard::restore`](crate::Guard::restore).
    pub fn from_json(bytes: &[u8]) -> Result<Self, Error> {
        serde_json::from_slice(bytes).map_err(|e| Error::SnapshotInvalid(e.to_string()))
    }
}

/// Field names: in alphabetical order too, so a tool that re-serialises the JSON with
/// sorted keys keeps `state` last.
const FIELDS: &[&str] = &["format", "layout", "state"];

impl Serialize for Snapshot {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let mut st = s.serialize_struct("Snapshot", 3)?;
        st.serialize_field("format", &self.version)?;
        st.serialize_field("layout", &self.layout)?;
        st.serialize_field("state", &self.state)?;
        st.end()
    }
}

/// Reads `format` and `layout` first and skips `state` when they don't match, so a
/// snapshot of another format is reported as such instead of as a parse error.
impl<'de> Deserialize<'de> for Snapshot {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V;
        /// `false` only once both are known and one differs (unknown: try to parse).
        fn compatible(version: Option<u32>, layout: Option<u64>) -> bool {
            version.is_none_or(|v| v == FORMAT_VERSION)
                && layout.is_none_or(|l| l == layout_fingerprint())
        }
        impl<'de> Visitor<'de> for V {
            type Value = Snapshot;

            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("a Pattern-Guard engine snapshot")
            }

            fn visit_map<A: MapAccess<'de>>(self, mut m: A) -> Result<Snapshot, A::Error> {
                let (mut version, mut layout, mut state) = (None, None, None);
                while let Some(key) = m.next_key::<String>()? {
                    match key.as_str() {
                        "format" => version = Some(m.next_value()?),
                        "layout" => layout = Some(m.next_value()?),
                        "state" if compatible(version, layout) => state = m.next_value()?,
                        _ => {
                            m.next_value::<IgnoredAny>()?;
                        }
                    }
                }
                Ok(Snapshot {
                    version: version.ok_or_else(|| de::Error::missing_field("format"))?,
                    layout: layout.ok_or_else(|| de::Error::missing_field("layout"))?,
                    state,
                })
            }

            fn visit_seq<A: SeqAccess<'de>>(self, mut s: A) -> Result<Snapshot, A::Error> {
                let missing = || de::Error::invalid_length(0, &"format, layout, state");
                let version = s.next_element()?.ok_or_else(missing)?;
                let layout = s.next_element()?.ok_or_else(missing)?;
                let state = if compatible(Some(version), Some(layout)) {
                    s.next_element()?.ok_or_else(missing)?
                } else {
                    while s.next_element::<IgnoredAny>()?.is_some() {}
                    None
                };
                Ok(Snapshot {
                    version,
                    layout,
                    state,
                })
            }
        }
        d.deserialize_struct("Snapshot", FIELDS, V)
    }
}

/// Entries a snapshot copies per hold of the guard's state lock.
pub(crate) const CHUNK: usize = 1024;

/// Pause between two chunks, so the requests waiting for the lock get it.
const CHUNK_PAUSE: std::time::Duration = std::time::Duration::from_micros(50);

/// Lends out the value a table lives in, holding the guard's state lock for one call.
pub(crate) type With<'a, T> = &'a dyn Fn(&mut dyn FnMut(&T));

/// Copies a table, least recently used first, `CHUNK` entries per call of `with`, so
/// the state lock is never held for a whole table (all tables at their default caps
/// took 75–320 ms to copy in one go). One hold lists the keys in LRU order (2–10 ms for
/// 100 000 entries: the list can't be walked in pieces), then each chunk takes ≤ 1.5 ms.
/// The order is the one when the copy started; entries evicted meanwhile are left out,
/// entries changed meanwhile are copied as they are by then.
pub(crate) fn copy_in_chunks<T: ?Sized, K: Hash + Eq + Clone, V, W>(
    with: With<'_, T>,
    table: impl Fn(&T) -> &LruCache<K, V>,
    copy: impl Fn(&V) -> W,
) -> Vec<(K, W)> {
    let mut keys: Vec<K> = Vec::new();
    with(&mut |t| keys = table(t).iter().rev().map(|(k, _)| k.clone()).collect());
    let mut out = Vec::with_capacity(keys.len());
    for chunk in keys.chunks(CHUNK) {
        // std's `Mutex` isn't fair: without a pause this thread takes the lock straight
        // back before a waiting request has even woken up (a yield is too short), and
        // requests wait as if it were held throughout (measured: 50–180 ms)
        std::thread::sleep(CHUNK_PAUSE);
        with(&mut |t| {
            let table = table(t);
            out.extend(
                chunk
                    .iter()
                    .filter_map(|k| table.peek(k).map(|v| (k.clone(), copy(v)))),
            );
        });
    }
    out
}

/// Refills `cache` with `entries` (least recently used first): the most recent ones
/// that fit its capacity, each passed through `bound` (per-entry caps).
pub(crate) fn lru_refill<K: Hash + Eq, V>(
    cache: &mut LruCache<K, V>,
    entries: Vec<(K, V)>,
    bound: impl Fn(&mut V),
) {
    cache.clear();
    let skip = entries.len().saturating_sub(cache.cap().get());
    for (k, mut v) in entries.into_iter().skip(skip) {
        bound(&mut v);
        cache.put(k, v);
    }
}

/// `f64` stored as its IEEE-754 bits (`#[serde(with = "bits")]`): exact, where
/// serde_json's default float parsing may be off by one unit in the last place, and NaN
/// or an infinity (which JSON can't hold either) is refused on load.
pub(crate) mod bits {
    use serde::de::Error as _;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    /// One `f64` as bits, for use in tuples and containers.
    #[derive(Debug, Clone, Copy)]
    pub struct F(pub f64);

    impl Serialize for F {
        fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
            s.serialize_u64(self.0.to_bits())
        }
    }

    impl<'de> Deserialize<'de> for F {
        fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
            let x = f64::from_bits(u64::deserialize(d)?);
            if x.is_finite() {
                Ok(F(x))
            } else {
                Err(D::Error::custom("a number in a snapshot is not finite"))
            }
        }
    }

    pub fn serialize<S: Serializer>(x: &f64, s: S) -> Result<S::Ok, S::Error> {
        F(*x).serialize(s)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<f64, D::Error> {
        Ok(F::deserialize(d)?.0)
    }

    pub mod opt {
        use super::F;
        use serde::{Deserialize, Deserializer, Serialize, Serializer};

        pub fn serialize<S: Serializer>(x: &Option<f64>, s: S) -> Result<S::Ok, S::Error> {
            x.map(F).serialize(s)
        }

        pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Option<f64>, D::Error> {
            Ok(Option::<F>::deserialize(d)?.map(|F(x)| x))
        }
    }
}
