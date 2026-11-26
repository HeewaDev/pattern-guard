//! Hot reload of the config: on `SIGHUP` ([`watch_sighup`]), or from code ([`reload`]).
//!
//! A reload builds everything first: the new `Compiled` snapshot (every section
//! validated and compiled), the engine config and its model. Only when all of it is
//! valid does anything change, and then the engine settings and the snapshot are
//! swapped. On an error the running config stays as it was.
//!
//! Nothing is interrupted. Connections stay open. A request is judged on the snapshot
//! current when its body has arrived and keeps it to the end, so one waiting on the
//! upstream during a reload finishes on the old config, and an upload still arriving is
//! judged on the new one. Learned state (baselines, reputation, bans, buckets,
//! caches, clearances) is kept, except the entries of rate limits, operations and logins
//! that the new config no longer defines.
//!
//! A few keys own what was built once at startup and can't change without a restart
//! ([`RESTART_ONLY`]). A reload keeps their running values and warns.

use std::path::Path;
#[cfg(unix)]
use std::path::PathBuf;
use std::sync::atomic::Ordering::Relaxed;
use std::sync::{Arc, PoisonError};

use crate::config::GatewayConfig;
use crate::intel;
use crate::state::{Compiled, State};

/// Gateway keys a reload can't change: the listeners are bound, the decision-log
/// writer owns its file and queue, the caps size the reputation store, and the state
/// files were loaded from `persistence.path` (saving elsewhere would lose them). The
/// engine adds `guard.time_source`, `guard.max_actors` and `guard.adaptive` (see
/// `pattern_guard::Guard::reload`). `persistence.interval_secs` and
/// `limits.shutdown_grace_secs` do reload: they are read when they are used.
pub const RESTART_ONLY: &[&str] = &[
    "listen",
    "admin_listen",
    "log.decisions",
    "limits.decision_log_queue_bytes",
    "limits.max_bans",
    "limits.max_intel_entries_per_source",
    "persistence.path",
];

/// What an applied reload did.
#[derive(Debug, Default)]
pub struct Reloaded {
    /// Keys whose new value needs a restart: the running value was kept.
    pub kept: Vec<&'static str>,
    /// CrowdSec and feed tasks started, restarted or stopped.
    pub tasks: Vec<String>,
    /// Things that were accepted but deserve a look (a model kept although it doesn't
    /// match this version's features).
    pub warnings: Vec<String>,
    /// Learned entries dropped because their rate limit, operation or login is gone.
    pub forgotten: usize,
}

/// Validates and compiles `cfg`, then makes it the running config. On an error nothing
/// changes. Either way one line goes to stderr and `pattern_guard_config_reloads_total`
/// counts the result.
///
/// Paths in `cfg` are used as they are; [`GatewayConfig::load`] resolves the relative
/// ones. Compiling is CPU and file work (regexes, the geo database, the model): from
/// async code, call it with `spawn_blocking`.
pub fn reload(state: &State, cfg: GatewayConfig) -> Result<Reloaded, String> {
    let result = apply(state, cfg).map_err(|e| one_line(&e));
    report(state, &result);
    result
}

/// [`reload`] with the config read again from `path`.
pub fn reload_from_path(state: &State, path: &Path) -> Result<Reloaded, String> {
    let result = GatewayConfig::load(path)
        .and_then(|cfg| apply(state, cfg))
        .map_err(|e| one_line(&e));
    report(state, &result);
    result
}

/// An error on one line: a TOML parse error comes with a source snippet (`7 | [[rules]]`,
/// `  | ^^^`), which is dropped; the location and the message are kept.
fn one_line(e: &str) -> String {
    let snippet = |l: &str| {
        let t = l.trim_start_matches(|c: char| c.is_ascii_digit() || c == ' ');
        t.starts_with('|')
    };
    (e.lines())
        .map(str::trim)
        .filter(|l| !l.is_empty() && !snippet(l))
        .collect::<Vec<_>>()
        .join(": ")
}

/// Reloads the config from `path` on every `SIGHUP` (`systemctl reload`, `kill -HUP`).
/// The handler is in place when this returns, so a `SIGHUP` no longer ends the process.
#[cfg(unix)]
pub fn watch_sighup(state: Arc<State>, path: PathBuf) -> Result<(), String> {
    use tokio::signal::unix::{SignalKind, signal};
    let mut hup = signal(SignalKind::hangup()).map_err(|e| format!("cannot watch SIGHUP: {e}"))?;
    tokio::spawn(async move {
        while hup.recv().await.is_some() {
            let (st, p) = (state.clone(), path.clone());
            // the result is reported (stderr, metric) by reload_from_path
            let _ = tokio::task::spawn_blocking(move || reload_from_path(&st, &p)).await;
        }
    });
    Ok(())
}

/// Replaces `new` with `old` when they differ, and records `key`.
fn keep<T: PartialEq + Clone>(
    kept: &mut Vec<&'static str>,
    key: &'static str,
    old: &T,
    new: &mut T,
) {
    if new != old {
        *new = old.clone();
        kept.push(key);
    }
}

/// The [`RESTART_ONLY`] keys of `new` set back to their running values.
fn keep_restart_only(old: &GatewayConfig, new: &mut GatewayConfig) -> Vec<&'static str> {
    let mut kept = Vec::new();
    let k = &mut kept;
    keep(k, RESTART_ONLY[0], &old.listen, &mut new.listen);
    keep(k, RESTART_ONLY[1], &old.admin_listen, &mut new.admin_listen);
    keep(
        k,
        RESTART_ONLY[2],
        &old.log.decisions,
        &mut new.log.decisions,
    );
    let (o, n) = (&old.limits, &mut new.limits);
    keep(
        k,
        RESTART_ONLY[3],
        &o.decision_log_queue_bytes,
        &mut n.decision_log_queue_bytes,
    );
    keep(k, RESTART_ONLY[4], &o.max_bans, &mut n.max_bans);
    keep(
        k,
        RESTART_ONLY[5],
        &o.max_intel_entries_per_source,
        &mut n.max_intel_entries_per_source,
    );
    keep(
        k,
        RESTART_ONLY[6],
        &old.persistence.path,
        &mut new.persistence.path,
    );
    kept
}

fn apply(state: &State, mut cfg: GatewayConfig) -> Result<Reloaded, String> {
    let _one_at_a_time = state
        .runtime
        .reload_lock
        .lock()
        .unwrap_or_else(PoisonError::into_inner);
    let old = state.compiled();
    // everything that can fail, without side effects
    let mut kept = keep_restart_only(&old.cfg, &mut cfg);
    let crowdsec_key = intel::tasks::crowdsec_key(&cfg)?;
    let engine = match &cfg.guard_config {
        Some(p) => pattern_guard::Config::load(p),
        None => pattern_guard::Config::from_toml_str(""),
    }
    .map_err(|e| format!("guard_config: {e}"))?;
    let mut new = Compiled::compile(cfg)?;
    if new.cfg.challenge.secret == old.cfg.challenge.secret {
        // the same key (also a random one): clearances and open challenges stay valid
        new.challenger = new.challenger.with_key_of(&old.challenger);
    }
    // the last step that can fail; it changes nothing unless it succeeds
    let engine = state
        .learned
        .guard
        .reload(engine)
        .map_err(|e| format!("guard_config: {e}"))?;
    kept.extend(engine.kept);
    let warnings: Vec<String> = (engine.model_warning.into_iter())
        .map(|w| format!("guard_config: {w}"))
        .collect();
    let new = Arc::new(new);
    state.replace_compiled(new.clone());
    let learned = &state.learned;
    let forgotten = learned
        .rate_buckets
        .forget_removed(&old.rate_limits, &new.rate_limits)
        + learned
            .operations
            .forget_removed(&old.operations, &new.operations);
    let tasks = state.runtime.intel_tasks.update(&new.cfg, crowdsec_key);
    Ok(Reloaded {
        kept,
        tasks,
        warnings,
        forgotten,
    })
}

fn report(state: &State, result: &Result<Reloaded, String>) {
    let metrics = &state.runtime.metrics;
    match result {
        Ok(r) => {
            metrics.reloads_ok.fetch_add(1, Relaxed);
            let mut notes = vec![format!(
                "model: {}",
                state.learned.guard.model().description
            )];
            notes.extend(r.tasks.iter().cloned());
            if r.forgotten > 0 {
                notes.push(format!(
                    "{} entries of removed limits, operations or logins dropped",
                    r.forgotten
                ));
            }
            eprintln!(
                "pattern-guard-gateway: config reloaded ({})",
                notes.join(", ")
            );
            for w in &r.warnings {
                eprintln!("pattern-guard-gateway: reload: {w}");
            }
            if !r.kept.is_empty() {
                eprintln!(
                    "pattern-guard-gateway: reload: {} can only change with a restart; the running values are kept",
                    r.kept.join(", ")
                );
            }
        }
        Err(e) => {
            metrics.reloads_failed.fetch_add(1, Relaxed);
            eprintln!("pattern-guard-gateway: reload refused, the running config is kept: {e}");
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::IpAddr;
    use std::sync::atomic::Ordering::Relaxed;

    use hyper::Request;

    use super::*;

    const BASE: &str = "upstream = \"http://127.0.0.1:1\"\n";

    fn cfg(toml: &str) -> GatewayConfig {
        GatewayConfig::from_toml_str(&format!("{BASE}{toml}")).unwrap()
    }

    fn state(toml: &str) -> Arc<State> {
        crate::build_state(cfg(toml)).unwrap()
    }

    fn get(path: &str) -> hyper::http::request::Parts {
        Request::get(path).body(()).unwrap().into_parts().0
    }

    fn counts(state: &State) -> (u64, u64) {
        let m = &state.runtime.metrics;
        (m.reloads_ok.load(Relaxed), m.reloads_failed.load(Relaxed))
    }

    const IP: &str = "203.0.113.9";

    #[test]
    fn a_valid_change_applies() {
        let st = state("mode = \"detect\"\n");
        let ip: IpAddr = IP.parse().unwrap();
        assert!(
            st.compiled()
                .rules
                .evaluate(ip, &get("/admin"), None)
                .terminal
                .is_none()
        );
        let r = reload(
            &st,
            cfg("mode = \"prevent\"\n[[rules]]\nname = \"admin\"\npath = \"/admin\"\naction = \"block\"\n"),
        )
        .unwrap();
        assert!(r.kept.is_empty() && r.tasks.is_empty());
        let c = st.compiled();
        assert_eq!(c.cfg.mode, crate::config::Mode::Prevent);
        assert!(
            c.rules
                .evaluate(ip, &get("/admin"), None)
                .terminal
                .is_some()
        );
        assert_eq!(counts(&st), (1, 0));
    }

    #[test]
    fn an_invalid_change_keeps_the_running_config() {
        let st = state("[[rules]]\nname = \"admin\"\npath = \"/admin\"\naction = \"block\"\n");
        let before = st.compiled();
        let bad = [
            // compile errors, each a different section
            "[[rules]]\nname = \"x\"\npath_regex = \"(\"\naction = \"block\"\n",
            "[[rate_limits]]\nname = \"x\"\nkey = \"cookie\"\nrequests = 1\nper_secs = 1\n",
            "[[operations]]\nname = \"x\"\naccount = \"form:user\"\n",
            "[geo]\ndeny_countries = [\"ZZ\"]\n",
            "[crowdsec]\nenabled = true\napi_key_env = \"PG_RELOAD_TEST_UNSET\"\n",
            "guard_config = \"/nonexistent/guard.toml\"\n",
        ];
        for (i, b) in bad.iter().enumerate() {
            let e = reload(&st, cfg(b)).unwrap_err();
            assert!(!e.is_empty());
            assert!(Arc::ptr_eq(&before, &st.compiled()), "{b}");
            assert_eq!(counts(&st), (0, i as u64 + 1));
        }
        assert!(
            reload(
                &st,
                cfg("[[rules]]\nname = \"x\"\npath_regex = \"(\"\naction = \"block\"\n")
            )
            .unwrap_err()
            .contains("rule \"x\""),
            "the error names the section"
        );
        // a config that doesn't parse is refused before anything is compiled
        let dir = std::env::temp_dir().join(format!("pg_reload_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("gateway.toml");
        std::fs::write(&path, format!("{BASE}typo = 1\n")).unwrap();
        assert!(reload_from_path(&st, &path).unwrap_err().contains("typo"));
        std::fs::write(&path, format!("{BASE}[[rules]]\nname = \"x\"\n")).unwrap();
        let e = reload_from_path(&st, &path).unwrap_err();
        assert!(
            !e.contains('\n') && e.contains("line 2") && e.ends_with("missing field `action`"),
            "{e}"
        );
        assert!(Arc::ptr_eq(&before, &st.compiled()));
        std::fs::write(&path, format!("{BASE}mode = \"detect\"\n")).unwrap();
        assert!(reload_from_path(&st, &path).is_ok());
        assert_eq!(st.compiled().cfg.mode, crate::config::Mode::Detect);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn restart_only_keys_keep_their_running_values() {
        let st = state("listen = \"127.0.0.1:8080\"\n");
        let r = reload(
            &st,
            cfg(
                "listen = \"127.0.0.1:9999\"\nadmin_listen = \"127.0.0.1:9998\"\n\
                 [log]\ndecisions = \"/nonexistent/decisions.jsonl\"\ninclude_allowed = true\n\
                 [limits]\nmax_bans = 5\nmax_intel_entries_per_source = 6\n\
                 decision_log_queue_bytes = 65536\nmax_connections_per_ip = 3\n\
                 shutdown_grace_secs = 2\n\
                 [persistence]\npath = \"/nonexistent/state.json\"\ninterval_secs = 60\n",
            ),
        )
        .unwrap();
        assert_eq!(r.kept, RESTART_ONLY);
        let c = st.compiled();
        assert_eq!(c.cfg.listen.port(), 8080);
        assert_eq!(c.cfg.admin_listen.unwrap().port(), 9901);
        assert_eq!(c.cfg.log.decisions, None);
        assert_eq!(c.cfg.limits.max_bans, 100_000);
        assert_eq!(c.cfg.persistence.path, None);
        // the other keys of the same sections apply
        assert!(c.cfg.log.include_allowed);
        assert_eq!(c.cfg.limits.max_connections_per_ip, 3);
        assert_eq!(c.cfg.limits.shutdown_grace_secs, 2);
        assert_eq!(c.cfg.persistence.interval_secs, 60);
    }

    #[test]
    fn learned_state_of_a_surviving_rate_limit_is_kept() {
        let limit = |name: &str| {
            format!(
                "[[rate_limits]]\nname = \"{name}\"\npath = \"/{name}\"\nrequests = 1\nper_secs = 3600\n"
            )
        };
        let st = state(&format!("{}{}", limit("login"), limit("search")));
        let ip: IpAddr = IP.parse().unwrap();
        let check = |path: &str| {
            st.compiled()
                .rate_limits
                .check(&st.learned.rate_buckets, ip, &get(path))
        };
        assert!(check("/login").is_none() && check("/search").is_none());
        assert!(check("/login").is_some(), "budget spent");
        // "search" removed, a new limit in front of "login"
        let r = reload(&st, cfg(&format!("{}{}", limit("api"), limit("login")))).unwrap();
        assert_eq!(r.forgotten, 1, "the bucket of \"search\"");
        assert!(check("/login").is_some(), "still spent after the reload");
        assert!(check("/api").is_none());
        // brought back: a fresh bucket
        reload(&st, cfg(&format!("{}{}", limit("login"), limit("search")))).unwrap();
        assert!(check("/search").is_none());
        assert!(check("/login").is_some());
    }

    #[test]
    fn learned_state_survives_and_the_challenge_key_is_kept() {
        let st = state("[challenge]\ndifficulty = 8\n");
        let ip: IpAddr = IP.parse().unwrap();
        let cookie = st.compiled().challenger.clearance_cookie(ip);
        let cookie = cookie.split(';').next().unwrap().to_string();
        st.learned.intel.add(
            crate::ipnet::Cidr::parse("192.0.2.1").unwrap(),
            crate::intel::IntelEntry {
                action: crate::intel::IntelAction::Ban,
                source: crate::policy::bans::SOURCE.into(),
                reason: "test".into(),
                expires: None,
            },
        );
        reload(&st, cfg("[challenge]\ndifficulty = 10\n")).unwrap();
        let c = st.compiled();
        assert_eq!(c.challenger.difficulty, 10);
        assert!(
            c.challenger.has_clearance(ip, Some(&cookie)),
            "same (random) key"
        );
        assert!(
            st.learned
                .intel
                .lookup("192.0.2.1".parse().unwrap())
                .is_some()
        );
        // a new secret is a new key
        let secret = "ab".repeat(16);
        reload(&st, cfg(&format!("[challenge]\nsecret = \"{secret}\"\n"))).unwrap();
        assert!(!st.compiled().challenger.has_clearance(ip, Some(&cookie)));
    }

    #[test]
    fn the_engine_model_and_thresholds_reload() {
        let dir = std::env::temp_dir().join(format!("pg_reload_guard_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let model = pattern_guard::Model::builtin().to_toml_string();
        std::fs::write(dir.join("m.toml"), model.replace("built-in", "retrained")).unwrap();
        let partial = model.replacen("name = \"actor_burst\"", "name = \"other\"", 1);
        std::fs::write(dir.join("partial.toml"), partial).unwrap();
        let guard = |body: &str| {
            std::fs::write(dir.join("guard.toml"), body).unwrap();
            format!("guard_config = {:?}\n", dir.join("guard.toml"))
        };
        let st = state("");
        reload(
            &st,
            cfg(&guard("[guard]\nwarn_below = 0.7\nmodel = \"m.toml\"\n")),
        )
        .unwrap();
        let g = &st.learned.guard;
        assert!(g.model().description.starts_with("retrained"));
        assert_eq!(g.config().guard.warn_below, 0.7);
        // a model for another feature layout is refused, with everything else
        let e = reload(
            &st,
            cfg(&format!(
                "{}[[rules]]\nname = \"r\"\npath = \"/r\"\naction = \"block\"\n",
                guard("[guard]\nmodel = \"partial.toml\"\n")
            )),
        )
        .unwrap_err();
        assert!(
            e.starts_with("guard_config:") && e.contains("feature layout"),
            "{e}"
        );
        assert!(g.model().description.starts_with("retrained"));
        assert!(st.compiled().cfg.rules.is_empty());
        // restart-only engine keys are reported with the gateway's
        let r = reload(&st, cfg(&guard("[guard]\nmax_actors = 10\n"))).unwrap();
        assert_eq!(r.kept, ["guard.max_actors"]);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A gateway that started with an older model (one feature missing, which startup
    /// accepts) can still reload the rest of its config.
    #[test]
    fn an_older_model_does_not_block_later_reloads() {
        let dir = std::env::temp_dir().join(format!("pg_reload_old_model_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let model = pattern_guard::Model::builtin().to_toml_string();
        let older = model.replacen("name = \"actor_burst\"", "name = \"retired\"", 1);
        std::fs::write(dir.join("older.toml"), older.replace("built-in", "older")).unwrap();
        std::fs::write(dir.join("full.toml"), model).unwrap();
        let guard = |m: &str| {
            let path = dir.join(format!("guard-{m}"));
            std::fs::write(&path, format!("[guard]\nmodel = \"{m}\"\n")).unwrap();
            format!("guard_config = {path:?}\n")
        };
        let rule = "[[rules]]\nname = \"admin\"\npath = \"/admin\"\naction = \"block\"\n";
        let st = state(&guard("older.toml"));
        let r = reload(&st, cfg(&format!("{}{rule}", guard("older.toml")))).unwrap();
        assert!(r.warnings[0].contains("feature layout"), "{:?}", r.warnings);
        let ip: IpAddr = IP.parse().unwrap();
        let admin = st.compiled().rules.evaluate(ip, &get("/admin"), None);
        assert!(admin.terminal.is_some(), "the rule applies");
        assert!(st.learned.guard.model().description.starts_with("older"));
        // warned once
        let r = reload(&st, cfg(&format!("{}{rule}", guard("older.toml")))).unwrap();
        assert!(r.warnings.is_empty());
        // moving to a model that fits works; moving back is refused
        reload(&st, cfg(&guard("full.toml"))).unwrap();
        assert!(reload(&st, cfg(&guard("older.toml"))).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// `reload` takes a `GatewayConfig` built or changed in code, which never went
    /// through `GatewayConfig::load`: its values are validated all the same.
    #[test]
    fn values_set_in_code_are_validated() {
        let st = state("");
        let before = st.compiled();
        let mut threshold = cfg("");
        threshold.bans.threshold = 0;
        let mut difficulty = cfg("");
        difficulty.challenge.difficulty = 40;
        let mut https = cfg("");
        https.upstream = "https://127.0.0.1:1".into();
        for (bad, says) in [
            (threshold, "bans"),
            (difficulty, "challenge.difficulty"),
            (https, "upstream"),
        ] {
            let e = reload(&st, bad).unwrap_err();
            assert!(e.contains(says), "{e}");
            assert!(Arc::ptr_eq(&before, &st.compiled()));
        }
    }
}
