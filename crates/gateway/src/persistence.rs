//! Learned state across restarts (`[persistence]`).
//!
//! Two files, so that one can't cost the other:
//!
//! - `path`: every live reputation entry of the sources the config produces (gateway
//!   bans, CrowdSec, the configured feeds) with its expiry as Unix time, and the
//!   challenge HMAC key, only when it was generated (no usable `challenge.secret`) and
//!   challenges are enabled, so clearance cookies stay valid. A configured key is never
//!   written. Small: about 80 bytes per entry.
//! - `<path>.engine`: the behavioural engine's snapshot (`pattern_guard::Snapshot`:
//!   actor / client / subnet / route tables, route baselines, rule windows, cooldowns,
//!   the clock). Large at full caps, and versioned on its own.
//!
//! **Load** at startup, before serving and before CrowdSec's first pull (whose full list
//! then replaces the restored CrowdSec entries). Each file is parsed on its own and
//! streamed (no copy of the file in memory). No file: that part starts empty. A file that
//! can't be read or used: one warning line, the file is kept as `<file>.bad`, and only its
//! part starts empty. A restored entry never gets more time than it had left at the save,
//! and at most what its source can give (`bans.max_ban_secs`, a feed's `block_secs`,
//! CrowdSec's year). Entries of sources the config doesn't produce are dropped (they
//! would keep blocking with nothing to lift them), and so are malformed ones; every cap
//! is re-applied.
//!
//! **Save** every `interval_secs` (read again on every tick, so it follows reloads) and
//! after the graceful shutdown, in `spawn_blocking`. The engine copies its tables a chunk
//! per hold of its lock, the reputation store a batch per read lock, and each file is
//! streamed to `<file>.tmp` in the same directory (mode 0600: it may hold the HMAC key),
//! fsynced, renamed over the file, and the directory is fsynced. A crash mid-save leaves
//! the previous file; a failed save leaves no temporary file. The last save holds the
//! reload lock and stops the CrowdSec and feed tasks first, so neither a reload nor a
//! poll changes the state while it is written.
//!
//! Not persisted: the `[bans]` escalation history, rate-limit buckets, operation and
//! login caches, the inventory.

use std::fs::{self, File, OpenOptions};
use std::io::{self, BufReader, BufWriter};
use std::path::{Path, PathBuf};
use std::sync::atomic::Ordering::Relaxed;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use pattern_guard::Snapshot;
use serde::{Deserialize, Serialize};
use tokio::task::JoinHandle;

use crate::challenge::{hex, unhex};
use crate::config::{FeedKind, GatewayConfig};
use crate::intel::{IntelAction, IntelEntry, IntelStore};
use crate::ipnet::Cidr;
use crate::policy::bans;
use crate::state::State;
use crate::util::now_secs;

/// Format of the `path` file (the engine file carries the engine's own version).
const FORMAT: u32 = 1;

/// The longest a CrowdSec decision lasts (`intel::crowdsec` caps durations at a year).
const CROWDSEC_MAX_SECS: u64 = 365 * 86_400;

/// Longest `reason` kept from the file (the decision log cuts reasons at the same size).
const MAX_REASON_BYTES: usize = 512;

/// How often the periodic saver checks whether a save is due.
const TICK: Duration = Duration::from_secs(1);

#[derive(Serialize, Deserialize)]
struct Persisted {
    format: u32,
    /// Unix time of the save.
    saved_at: u64,
    /// Hex; only a generated key.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    challenge_secret: Option<String>,
    intel: Vec<Reputation>,
}

#[derive(Serialize, Deserialize)]
struct Reputation {
    /// An address or a CIDR.
    target: String,
    action: Action,
    source: String,
    reason: String,
    /// Unix time; `None` = never.
    expires: Option<u64>,
}

#[derive(Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Action {
    Ban,
    Challenge,
}

/// What a successful save wrote.
#[derive(Debug)]
pub(crate) struct Saved {
    pub bytes: u64,
    pub took: Duration,
}

/// The engine's file next to `path`.
pub(crate) fn engine_path(path: &Path) -> PathBuf {
    sibling(path, ".engine")
}

/// Checks `persistence.path` against the file system (once relative paths are
/// resolved, so not in `GatewayConfig::validate`): its directory must exist, and the
/// state files, where they exist, must be regular files.
pub(crate) fn check_path(cfg: &GatewayConfig) -> Result<(), String> {
    let Some(path) = &cfg.persistence.path else {
        return Ok(());
    };
    let dir = parent(path);
    if !dir.is_dir() {
        return Err(format!(
            "persistence.path: directory {} does not exist",
            dir.display()
        ));
    }
    for f in [path.clone(), engine_path(path)] {
        if fs::symlink_metadata(&f).is_ok_and(|m| !m.is_file()) {
            return Err(format!(
                "persistence.path: {} exists and is not a regular file",
                f.display()
            ));
        }
    }
    Ok(())
}

/// Runs the periodic saves and does the last one at shutdown.
pub(crate) struct Saver {
    path: PathBuf,
    /// One save at a time (a periodic one may still run when the shutdown starts).
    lock: Arc<Mutex<()>>,
    periodic: JoinHandle<()>,
}

/// At startup, before serving and before the background tasks: restores what the state
/// files hold, then starts the periodic saves. `None` when persistence is off.
pub(crate) async fn start(state: &Arc<State>) -> Result<Option<Saver>, String> {
    let Some(path) = state.compiled().cfg.persistence.path.clone() else {
        return Ok(None);
    };
    let (st, p) = (state.clone(), path.clone());
    tokio::task::spawn_blocking(move || restore(&st, &p))
        .await
        .map_err(|e| format!("persistence: loading the state failed: {e}"))?;
    let lock = Arc::new(Mutex::new(()));
    let (st, p, l) = (state.clone(), path.clone(), lock.clone());
    let periodic = tokio::spawn(async move {
        let mut last = Instant::now();
        loop {
            tokio::time::sleep(TICK).await;
            let every = st.compiled().cfg.persistence.interval_secs; // as reloaded
            if every == 0 || last.elapsed() < Duration::from_secs(every) {
                continue;
            }
            last = Instant::now();
            if let Err(e) = save_in_background(&st, &p, &l, false).await {
                eprintln!("pattern-guard-gateway: {e}");
            }
        }
    });
    Ok(Some(Saver {
        path,
        lock,
        periodic,
    }))
}

impl Saver {
    /// The last save, once the connections are closed.
    pub(crate) async fn finish(self, state: &Arc<State>) {
        self.periodic.abort(); // a save it already started finishes first (`lock`)
        match save_in_background(state, &self.path, &self.lock, true).await {
            Ok(s) => eprintln!(
                "pattern-guard-gateway: saved learned state to {} ({} KiB in {:.1?})",
                self.path.display(),
                s.bytes.div_ceil(1024),
                s.took
            ),
            Err(e) => eprintln!("pattern-guard-gateway: {e}"),
        }
    }
}

/// `last`: the save at shutdown, which first takes the reload lock and stops the CrowdSec
/// and feed tasks.
async fn save_in_background(
    state: &Arc<State>,
    path: &Path,
    lock: &Arc<Mutex<()>>,
    last: bool,
) -> Result<Saved, String> {
    let (st, p, l) = (state.clone(), path.to_path_buf(), lock.clone());
    tokio::task::spawn_blocking(move || {
        let _one = l.lock().unwrap_or_else(PoisonError::into_inner);
        let _no_reload =
            last.then(|| (st.runtime.reload_lock.lock()).unwrap_or_else(PoisonError::into_inner));
        if last {
            st.runtime.intel_tasks.stop();
        }
        save(&st, &p)
    })
    .await
    .map_err(|e| format!("persistence: the save task failed: {e}"))?
}

/// Writes both state files (see the module docs). Blocking.
pub(crate) fn save(state: &State, path: &Path) -> Result<Saved, String> {
    let started = Instant::now();
    let c = state.compiled();
    let engine = state.learned.guard.snapshot();
    let file = Persisted {
        format: FORMAT,
        saved_at: now_secs(),
        challenge_secret: if c.cfg.challenge.enabled {
            c.challenger.generated_secret().map(hex)
        } else {
            None
        },
        intel: export_intel(&state.learned.intel),
    };
    let written = write_atomic(&engine_path(path), |w| {
        serde_json::to_writer(w, &engine).map_err(io::Error::from)
    })
    .map_err(|e| (engine_path(path), e))
    .and_then(|engine_bytes| {
        write_atomic(path, |w| {
            serde_json::to_writer(w, &file).map_err(io::Error::from)
        })
        .map(|b| b + engine_bytes)
        .map_err(|e| (path.to_path_buf(), e))
    });
    let m = &state.runtime.metrics;
    match written {
        Ok(bytes) => {
            let took = started.elapsed();
            m.state_saves_ok.fetch_add(1, Relaxed);
            m.state_save_micros.store(took.as_micros() as u64, Relaxed);
            m.state_save_bytes.store(bytes, Relaxed);
            m.state_saved_at.store(file.saved_at, Relaxed);
            Ok(Saved { bytes, took })
        }
        Err((f, e)) => {
            m.state_saves_failed.fetch_add(1, Relaxed);
            Err(format!(
                "persistence: cannot save learned state to {}: {e}",
                f.display()
            ))
        }
    }
}

fn export_intel(store: &IntelStore) -> Vec<Reputation> {
    let (now, now_unix) = (Instant::now(), now_secs());
    store
        .export()
        .into_iter()
        .map(|(target, e)| Reputation {
            target,
            action: match e.action {
                IntelAction::Ban => Action::Ban,
                IntelAction::Challenge => Action::Challenge,
            },
            source: e.source,
            reason: e.reason,
            // rounded up, so a restored entry never ends early
            expires: e.expires.map(|x| {
                let left = x.saturating_duration_since(now);
                now_unix + left.as_secs() + u64::from(left.subsec_nanos() > 0)
            }),
        })
        .collect()
}

/// Streams `write` into `<path>.tmp` (mode 0600), fsyncs it, renames it over `path` and
/// fsyncs the directory. Returns the file's size. On any failure the temporary file is
/// removed (it may hold the HMAC key).
fn write_atomic(
    path: &Path,
    write: impl FnOnce(&mut BufWriter<File>) -> io::Result<()>,
) -> io::Result<u64> {
    let tmp = sibling(path, ".tmp");
    let written = (|| -> io::Result<u64> {
        let mut opts = OpenOptions::new();
        opts.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let file = opts.open(&tmp)?;
        #[cfg(unix)]
        {
            // `mode` applies only when the file is created; a leftover one keeps its own
            use std::os::unix::fs::PermissionsExt;
            file.set_permissions(fs::Permissions::from_mode(0o600))?;
        }
        let mut w = BufWriter::with_capacity(1 << 20, file);
        write(&mut w)?;
        let file = w.into_inner().map_err(|e| e.into_error())?;
        file.sync_all()?;
        let bytes = file.metadata()?.len();
        drop(file);
        fs::rename(&tmp, path)?;
        Ok(bytes)
    })();
    match written {
        Ok(bytes) => {
            #[cfg(unix)]
            File::open(parent(path))?.sync_all()?; // the rename itself
            Ok(bytes)
        }
        Err(e) => {
            // only ever our own regular file
            if fs::symlink_metadata(&tmp).is_ok_and(|m| m.is_file()) {
                let _ = fs::remove_file(&tmp);
            }
            Err(e)
        }
    }
}

fn parent(path: &Path) -> &Path {
    match path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p,
        _ => Path::new("."),
    }
}

fn sibling(path: &Path, suffix: &str) -> PathBuf {
    let mut s = path.as_os_str().to_owned();
    s.push(suffix);
    PathBuf::from(s)
}

/// How long a restored entry of `source` may last, if the config produces that source:
/// `(longest expiry in seconds, whether it may never expire)`.
fn source_limit(cfg: &GatewayConfig, source: &str) -> Option<(u64, bool)> {
    if source == bans::SOURCE {
        let b = &cfg.bans;
        return Some((
            b.max_ban_secs.max(b.ban_secs).max(cfg.traps.ban_secs),
            false,
        ));
    }
    if source.starts_with("crowdsec:") {
        return cfg.crowdsec.enabled.then_some((CROWDSEC_MAX_SECS, true));
    }
    let kind = match source {
        "suricata" => FeedKind::Suricata,
        "wazuh" => FeedKind::Wazuh,
        _ => return None,
    };
    (cfg.feeds.iter())
        .filter(|f| f.kind == kind)
        .map(|f| f.block_secs)
        .max()
        .map(|secs| (secs, false))
}

/// A gateway ban names one host: an address, or the `/64` that merges one host's IPv6
/// addresses (`IntelStore::add_aggregated`). Never a wider range such as `0.0.0.0/0`.
fn is_host(c: Cidr) -> bool {
    c.is_single()
        || matches!(c.addr(), std::net::IpAddr::V6(a) if Cidr::parse(&format!("{a}/64")) == Some(c))
}

/// `s` cut to at most `max` bytes, at a character boundary.
fn cut(mut s: String, max: usize) -> String {
    if s.len() > max {
        let mut end = max;
        while !s.is_char_boundary(end) {
            end -= 1;
        }
        s.truncate(end);
    }
    s
}

/// What restoring the reputation entries did.
#[derive(Default)]
struct Counts {
    restored: usize,
    expired: usize,
    /// From a source the config doesn't produce (switched off, or unknown).
    unconfigured: usize,
    /// Unparsable target, a gateway ban that isn't one host or never expires.
    invalid: usize,
}

/// Puts the reputation entries of `saved` into the store (see the module docs).
fn restore_intel(
    state: &State,
    cfg: &GatewayConfig,
    saved: Vec<Reputation>,
    saved_at: u64,
) -> Counts {
    let (now, now_unix) = (Instant::now(), now_secs());
    // time since the save; 0 if the clock is now behind it
    let since = now_unix.saturating_sub(saved_at);
    let mut n = Counts::default();
    for r in saved {
        let Some((max_secs, may_be_permanent)) = source_limit(cfg, &r.source) else {
            n.unconfigured += 1;
            continue;
        };
        let Some(target) = Cidr::parse(&r.target) else {
            n.invalid += 1;
            continue;
        };
        if r.source == bans::SOURCE && !is_host(target) {
            n.invalid += 1;
            continue;
        }
        let left = match r.expires {
            // what was left at the save, minus the time since: never more
            Some(t) => match t.saturating_sub(saved_at).checked_sub(since) {
                Some(left) if left > 0 => Some(left.min(max_secs)),
                _ => {
                    n.expired += 1;
                    continue;
                }
            },
            None if may_be_permanent => None,
            None => {
                n.invalid += 1;
                continue;
            }
        };
        let action = match r.action {
            Action::Ban => IntelAction::Ban,
            Action::Challenge => IntelAction::Challenge,
        };
        state.learned.intel.add(
            target,
            IntelEntry {
                action,
                source: r.source,
                reason: cut(r.reason, MAX_REASON_BYTES),
                expires: left.map(|s| now + Duration::from_secs(s)),
            },
        );
        n.restored += 1;
    }
    n
}

/// Loads the state files into `state` (see the module docs). Blocking.
pub(crate) fn restore(state: &State, path: &Path) {
    let c = state.compiled();
    match read::<Persisted>(path) {
        Read::Missing => eprintln!(
            "pattern-guard-gateway: no saved reputation at {} yet; starting without",
            path.display()
        ),
        Read::Bad(why, keep) => warn(path, &why, keep, "no reputation or clearance key restored"),
        Read::Ok(saved) if saved.format != FORMAT => {
            let why = format!(
                "state file format {}, this build reads {FORMAT}",
                saved.format
            );
            warn(path, &why, true, "no reputation or clearance key restored");
        }
        Read::Ok(saved) => {
            let mut problems = Vec::new();
            let n = restore_intel(state, &c.cfg, saved.intel, saved.saved_at);
            if n.invalid > 0 {
                problems.push(format!(
                    "{} malformed reputation entries dropped",
                    n.invalid
                ));
            }
            let key = match saved.challenge_secret.as_deref().map(unhex) {
                None => "not saved",
                Some(Some(k)) if k.len() >= 16 => {
                    if c.challenger.restore_secret(&k) {
                        "restored"
                    } else {
                        "configured (the saved one is ignored)"
                    }
                }
                Some(_) => {
                    problems.push("the saved clearance key is invalid".into());
                    "new"
                }
            };
            let what = format!(
                "{} reputation entries ({} expired, {} of sources not configured dropped), clearance key {key}",
                n.restored, n.expired, n.unconfigured
            );
            if problems.is_empty() {
                let age = now_secs().saturating_sub(saved.saved_at);
                eprintln!(
                    "pattern-guard-gateway: restored {what} from {} (saved {age} s ago)",
                    path.display()
                );
            } else {
                warn(
                    path,
                    &problems.join("; "),
                    true,
                    &format!("restored {what}"),
                );
            }
        }
    }

    let engine = engine_path(path);
    let none = "the behavioural engine starts with nothing learned";
    match read::<Snapshot>(&engine) {
        Read::Missing => {}
        Read::Bad(why, keep) => warn(&engine, &why, keep, none),
        Read::Ok(snap) => {
            let actors = snap.actors();
            match state.learned.guard.restore(snap) {
                Ok(()) => eprintln!(
                    "pattern-guard-gateway: restored the behaviour of {actors} actors from {}",
                    engine.display()
                ),
                Err(e) => warn(&engine, &e.to_string(), true, none),
            }
        }
    }
}

enum Read<T> {
    Missing,
    /// Why, and whether the file should be kept as `.bad`.
    Bad(String, bool),
    Ok(T),
}

/// Parses `path` as a stream, without a copy of the file in memory.
fn read<T: serde::de::DeserializeOwned>(path: &Path) -> Read<T> {
    match File::open(path) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => Read::Missing,
        Err(e) => Read::Bad(format!("cannot read it ({e})"), false),
        Ok(f) => match serde_json::from_reader(BufReader::with_capacity(1 << 20, f)) {
            Ok(v) => Read::Ok(v),
            Err(e) => Read::Bad(format!("not a valid state file ({e})"), true),
        },
    }
}

/// The one warning line for a state file that can't be (fully) used; with `keep`, the
/// file is renamed to `<file>.bad` so the next save doesn't overwrite it. Only a regular
/// file is ever renamed.
fn warn(path: &Path, why: &str, keep: bool, then: &str) {
    let bad = sibling(path, ".bad");
    let kept = if !keep {
        "left in place".into()
    } else if !fs::symlink_metadata(path).is_ok_and(|m| m.is_file()) {
        "not a regular file, left in place".into()
    } else {
        match fs::rename(path, &bad) {
            Ok(()) => format!("kept as {}", bad.display()),
            Err(e) => format!("could not keep it as {} ({e})", bad.display()),
        }
    };
    eprintln!(
        "pattern-guard-gateway: WARNING: saved state {}: {why}; {kept}; {then}",
        path.display()
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::GatewayConfig;
    use pattern_guard::Event;
    use serde_json::Value;
    use std::net::IpAddr;
    use std::time::SystemTime;

    fn dir(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("pg-persist-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).unwrap();
        d
    }

    fn cfg(extra: &str) -> GatewayConfig {
        GatewayConfig::from_toml_str(&format!("upstream = \"http://127.0.0.1:1\"\n{extra}\n"))
            .unwrap()
    }

    fn state(extra: &str) -> Arc<State> {
        crate::build_state(cfg(extra)).unwrap()
    }

    fn entry(source: &str, secs: Option<u64>) -> IntelEntry {
        IntelEntry {
            action: IntelAction::Ban,
            source: source.into(),
            reason: format!("test {source}"),
            expires: secs.map(|s| Instant::now() + Duration::from_secs(s)),
        }
    }

    fn ban(ip: &str, secs: Option<u64>) -> (Cidr, IntelEntry) {
        (Cidr::parse(ip).unwrap(), entry(bans::SOURCE, secs))
    }

    fn learn(s: &State) {
        for i in 0..20 {
            s.learned.guard.assess(&Event::new(
                format!("ip:198.51.100.{i}"),
                "GET",
                format!("/item/{i}"),
                SystemTime::now(),
            ));
        }
    }

    fn json(path: &Path) -> Value {
        serde_json::from_slice(&fs::read(path).unwrap()).unwrap()
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    /// Seconds left of the entry for `ip`, rounded.
    fn left(s: &State, a: &str) -> Option<u64> {
        let e = s.learned.intel.lookup(ip(a))?;
        Some(
            (e.expires?
                .saturating_duration_since(Instant::now())
                .as_secs_f64())
            .round() as u64,
        )
    }

    #[test]
    fn save_then_restore() {
        let d = dir("round-trip");
        let path = d.join("state.json");
        let a = state("");
        learn(&a);
        for (c, e) in [
            ban("203.0.113.7", Some(3600)),
            ban("2001:db8:1:2::/64", Some(60)),
        ] {
            a.learned.intel.add(c, e);
        }
        let saved = save(&a, &path).unwrap();
        let both =
            fs::metadata(&path).unwrap().len() + fs::metadata(engine_path(&path)).unwrap().len();
        assert_eq!(saved.bytes, both);
        for f in [path.clone(), engine_path(&path)] {
            assert!(!sibling(&f, ".tmp").exists());
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                assert_eq!(
                    fs::metadata(&f).unwrap().permissions().mode() & 0o777,
                    0o600
                );
            }
        }
        assert_eq!(a.runtime.metrics.state_saves_ok.load(Relaxed), 1);
        let v = json(&path);
        assert_eq!(v["format"], 1);
        assert_eq!(v["intel"].as_array().unwrap().len(), 2);
        let key = v["challenge_secret"].as_str().unwrap().to_string();
        assert_eq!(key.len(), 64);

        let b = state("");
        restore(&b, &path);
        assert!(b.learned.intel.lookup(ip("203.0.113.7")).is_some());
        assert!(b.learned.intel.lookup(ip("2001:db8:1:2::9")).is_some());
        assert_eq!(
            b.compiled().challenger.generated_secret().map(hex),
            Some(key.clone())
        );
        assert_eq!(b.learned.guard.snapshot().actors(), 20);
        assert!(
            path.exists() && engine_path(&path).exists(),
            "good files stay"
        );

        // the restored key survives a reload that keeps the (empty) secret
        crate::reload(&b, cfg("mode = \"detect\"\n")).unwrap();
        assert_eq!(
            b.compiled().challenger.generated_secret().map(hex),
            Some(key)
        );
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn a_clock_behind_never_stretches_an_expiry() {
        let d = dir("clock");
        let path = d.join("state.json");
        let a = state("[bans]\nmax_ban_secs = 7200\n");
        let (c, e) = ban("203.0.113.7", Some(3600));
        a.learned.intel.add(c, e);
        save(&a, &path).unwrap();
        // the clock was a year ahead at the save (or is a year behind now)
        let mut v = json(&path);
        let year = 365 * 86_400;
        v["saved_at"] = Value::from(v["saved_at"].as_u64().unwrap() + year);
        v["intel"][0]["expires"] = Value::from(v["intel"][0]["expires"].as_u64().unwrap() + year);
        fs::write(&path, serde_json::to_vec(&v).unwrap()).unwrap();
        let b = state("[bans]\nmax_ban_secs = 7200\n");
        restore(&b, &path);
        let l = left(&b, "203.0.113.7").unwrap();
        assert!(
            (3599..=3600).contains(&l),
            "the hour that was left, not a year: {l}"
        );

        // half an hour passed since the save
        let mut v = json(&path);
        v["saved_at"] = Value::from(now_secs() - 1800);
        v["intel"][0]["expires"] = Value::from(now_secs() + 1800);
        fs::write(&path, serde_json::to_vec(&v).unwrap()).unwrap();
        let b = state("[bans]\nmax_ban_secs = 7200\n");
        restore(&b, &path);
        let l = left(&b, "203.0.113.7").unwrap();
        assert!((1799..=1800).contains(&l), "{l}");

        // a crafted expiry is cut to what the source can give
        let mut v = json(&path);
        v["saved_at"] = Value::from(now_secs());
        v["intel"][0]["expires"] = Value::from(now_secs() + 10 * year);
        fs::write(&path, serde_json::to_vec(&v).unwrap()).unwrap();
        let b = state("[bans]\nmax_ban_secs = 7200\n");
        restore(&b, &path);
        assert!(left(&b, "203.0.113.7").unwrap() <= 7200);
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn only_sources_the_config_produces_are_restored() {
        let d = dir("sources");
        let path = d.join("state.json");
        let on = "[crowdsec]\nenabled = true\napi_key = \"k\"\n[[feeds]]\nkind = \"suricata\"\npath = \"/nonexistent/eve.json\"\nblock_secs = 600\n";
        let a = state(on);
        for (target, source, secs) in [
            ("192.0.2.1", bans::SOURCE, Some(600)),
            ("192.0.2.2", "crowdsec:CAPI", None),
            ("192.0.2.3", "suricata", Some(3600)),
            ("192.0.2.4", "wazuh", Some(600)),
            ("192.0.2.5", "something-else", Some(600)),
        ] {
            a.learned
                .intel
                .add(Cidr::parse(target).unwrap(), entry(source, secs));
        }
        save(&a, &path).unwrap();
        let b = state(on);
        restore(&b, &path);
        let has = |s: &State, a: &str| s.learned.intel.lookup(ip(a)).is_some();
        assert!(has(&b, "192.0.2.1") && has(&b, "192.0.2.2") && has(&b, "192.0.2.3"));
        assert!(
            !has(&b, "192.0.2.4") && !has(&b, "192.0.2.5"),
            "no wazuh feed, unknown source"
        );
        assert!(
            left(&b, "192.0.2.3").unwrap() <= 600,
            "the feed's block_secs"
        );
        assert!(
            !sibling(&path, ".bad").exists(),
            "dropping them is not a problem"
        );
        // CrowdSec and the feed switched off: only the gateway's own ban comes back
        let c = state("");
        restore(&c, &path);
        assert_eq!(c.learned.intel.len(), 1);
        assert!(has(&c, "192.0.2.1"));
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn malformed_entries_are_dropped() {
        let d = dir("malformed");
        let path = d.join("state.json");
        let a = state("");
        let (c, e) = ban("203.0.113.7", Some(600));
        a.learned.intel.add(c, e);
        save(&a, &path).unwrap();
        let mut v = json(&path);
        let good = v["intel"][0].clone();
        let with = |k: &str, x: Value| {
            let mut e = good.clone();
            e[k] = x;
            e
        };
        v["intel"] = Value::from(vec![
            with("target", Value::from("0.0.0.0/0")),
            with("target", Value::from("10.0.0.0/8")),
            with("target", Value::from("not an address")),
            with("expires", Value::Null), // a gateway ban that never ends
            with("reason", Value::from("é".repeat(5000))),
        ]);
        fs::write(&path, serde_json::to_vec(&v).unwrap()).unwrap();
        let b = state("");
        restore(&b, &path);
        assert_eq!(b.learned.intel.len(), 1, "only the last one");
        let e = b.learned.intel.lookup(ip("203.0.113.7")).unwrap();
        assert!(e.reason.len() <= MAX_REASON_BYTES && e.reason.starts_with('é'));
        assert!(b.learned.intel.lookup(ip("10.1.2.3")).is_none());
        assert!(sibling(&path, ".bad").exists());
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn a_configured_secret_is_never_written() {
        let d = dir("secret");
        let path = d.join("state.json");
        let secret = "0123456789abcdef".repeat(4);
        let s = state(&format!("[challenge]\nsecret = \"{secret}\"\n"));
        save(&s, &path).unwrap();
        for f in [path.clone(), engine_path(&path)] {
            assert!(!String::from_utf8_lossy(&fs::read(&f).unwrap()).contains(&secret));
        }
        assert!(json(&path).get("challenge_secret").is_none());
        // nor a generated one when challenges are off
        let off = state("[challenge]\nenabled = false\n");
        save(&off, &path).unwrap();
        assert!(json(&path).get("challenge_secret").is_none());
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn a_bad_engine_file_costs_only_the_behaviour() {
        let d = dir("engine");
        let path = d.join("state.json");
        let a = state("");
        learn(&a);
        let (c, e) = ban("203.0.113.7", Some(600));
        a.learned.intel.add(c, e);
        save(&a, &path).unwrap();
        let engine = engine_path(&path);
        // a corrupt number deep in an actor, a shape change, another layout, garbage
        let mut corrupt = json(&engine);
        corrupt["state"]["features"]["actors"][0][1][4][0][0] = Value::from("x");
        let mut shape = json(&engine);
        shape["state"]["cooldowns"] = Value::from(vec![Value::from(vec![1, 2, 3])]);
        let mut layout = json(&engine);
        layout["layout"] = Value::from(1u64);
        for bad in [
            serde_json::to_vec(&corrupt).unwrap(),
            serde_json::to_vec(&shape).unwrap(),
            serde_json::to_vec(&layout).unwrap(),
            b"{\"format\": 1, \"layout\"".to_vec(),
        ] {
            save(&a, &path).unwrap();
            fs::write(&engine, bad).unwrap();
            let b = state("");
            restore(&b, &path);
            assert_eq!(b.learned.guard.snapshot().actors(), 0);
            assert!(
                b.learned.intel.lookup(ip("203.0.113.7")).is_some(),
                "the ban still comes back"
            );
            assert!(b.compiled().challenger.generated_secret().is_some());
            assert_eq!(
                b.compiled().challenger.generated_secret(),
                a.compiled().challenger.generated_secret(),
                "and the key"
            );
            assert!(sibling(&engine, ".bad").exists() && !engine.exists());
            assert!(path.exists(), "the reputation file is fine");
        }
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn unusable_files_are_kept_aside_and_the_gateway_starts_empty() {
        let d = dir("bad");
        let path = d.join("state.json");
        let s = state("");
        restore(&s, &path); // missing: nothing happens
        assert!(s.learned.intel.is_empty() && !sibling(&path, ".bad").exists());

        for garbage in [
            &b"{\"format\": 1, \"saved_at\": 5, \"intel\": ["[..],
            b"\x00\x01",
            b"[]",
        ] {
            fs::write(&path, garbage).unwrap();
            let s = state("");
            restore(&s, &path);
            assert!(!path.exists() && sibling(&path, ".bad").exists());
            assert!(s.learned.intel.is_empty());
        }

        // another format
        let a = state("");
        let (c, e) = ban("203.0.113.7", Some(600));
        a.learned.intel.add(c, e);
        save(&a, &path).unwrap();
        let mut v = json(&path);
        v["format"] = Value::from(2);
        fs::write(&path, serde_json::to_vec(&v).unwrap()).unwrap();
        let s = state("");
        restore(&s, &path);
        assert!(s.learned.intel.is_empty());
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn the_path_must_be_a_regular_file_in_an_existing_directory() {
        let d = dir("path");
        let with = |p: &Path| {
            cfg(&format!(
                "[persistence]\npath = {:?}\n",
                p.display().to_string()
            ))
        };
        let e = crate::build_state(with(Path::new("/nonexistent-pg-dir/state.json")))
            .err()
            .unwrap();
        assert!(
            e.contains("persistence.path") && e.contains("does not exist"),
            "{e}"
        );
        // a directory where the file should be: a config error, and it is never renamed
        let taken = d.join("state.json");
        fs::create_dir_all(&taken).unwrap();
        let e = crate::build_state(with(&taken)).err().unwrap();
        assert!(e.contains("not a regular file"), "{e}");
        let s = state("");
        restore(&s, &taken);
        assert!(taken.is_dir() && !sibling(&taken, ".bad").exists());
        fs::remove_dir(&taken).unwrap();
        fs::create_dir_all(engine_path(&taken)).unwrap();
        assert!(
            crate::build_state(with(&taken)).is_err(),
            "the engine file too"
        );
        fs::remove_dir(engine_path(&taken)).unwrap();
        assert!(crate::build_state(with(&taken)).is_ok());
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn a_failed_save_leaves_no_temporary_file() {
        let d = dir("tmp");
        let path = d.join("state.json");
        let s = state("");
        // the rename fails: a directory is in the way of the engine file
        fs::create_dir_all(engine_path(&path)).unwrap();
        assert!(save(&s, &path).is_err());
        assert!(!sibling(&engine_path(&path), ".tmp").exists());
        assert_eq!(s.runtime.metrics.state_saves_failed.load(Relaxed), 1);
        fs::remove_dir(engine_path(&path)).unwrap();
        // the write fails half-way
        let r = write_atomic(&path, |_| Err(io::Error::other("disk full")));
        assert!(r.is_err() && !sibling(&path, ".tmp").exists() && !path.exists());
        let _ = fs::remove_dir_all(&d);
    }

    #[tokio::test]
    async fn start_is_off_by_default() {
        assert!(start(&state("")).await.unwrap().is_none());
    }

    /// State file sizes and save time with the engine and the reputation store at their
    /// default caps: 100 000 actors (4 requests each), 50 000 clients and subnets,
    /// 10 000 routes, 100 000 gateway bans and 500 000 CrowdSec entries.
    /// `cargo test --release -p pattern-guard-gateway --lib -- --ignored full_caps --nocapture`
    #[test]
    #[ignore]
    fn measure_save_at_full_caps() {
        let on = "[crowdsec]\nenabled = true\napi_key = \"k\"\n";
        let s = state(on);
        let word = |mut n: u64| {
            let mut w = String::new();
            for _ in 0..3 {
                w.push((b'a' + (n % 26) as u8) as char);
                n /= 26;
            }
            w
        };
        for i in 0..100_000u64 {
            let net = i % 60_000;
            let ip: IpAddr = format!("10.{}.{}.{}", net / 256, net % 256, i / 60_000 + 1)
                .parse()
                .unwrap();
            for j in 0..4 {
                let ev = Event::new(
                    format!("ip:{ip}"),
                    "GET",
                    format!("/{}/{}", word((i + j) % 12_000), i * 50 + j),
                    SystemTime::now(),
                )
                .with_ip(ip)
                .with_user_agent(format!("agent-{}", i % 60_000));
                s.learned.guard.assess(&ev);
                s.learned.guard.observe_response(&ev, 200);
            }
            let (c, e) = ban(
                &format!("172.{}.{}.{}", 16 + i / 65536, i / 256 % 256, i % 256),
                Some(3600),
            );
            s.learned.intel.add(c, e);
        }
        for i in 0..500_000u32 {
            s.learned.intel.add(
                Cidr::parse(&std::net::Ipv4Addr::from(0x5000_0000 + i).to_string()).unwrap(),
                IntelEntry {
                    reason: "crowdsecurity/http-probing".into(),
                    ..entry("crowdsec:CAPI", Some(86_400))
                },
            );
        }
        let d = dir("measure");
        let path = d.join("state.json");
        let saved = save(&s, &path).unwrap();
        let t = Instant::now();
        let fresh = state(on);
        restore(&fresh, &path);
        println!(
            "state files {:.1} MB ({:.1} MB reputation + {:.1} MB engine), save {:.2?}, load {:.2?} ({} reputation entries)",
            saved.bytes as f64 / 1e6,
            fs::metadata(&path).unwrap().len() as f64 / 1e6,
            fs::metadata(engine_path(&path)).unwrap().len() as f64 / 1e6,
            saved.took,
            t.elapsed(),
            fresh.learned.intel.len()
        );
        let _ = fs::remove_dir_all(&d);
    }
}
