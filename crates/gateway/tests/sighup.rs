//! `SIGHUP` reloads the config file. In its own test binary: the signal goes to the
//! whole process.
#![cfg(unix)]

use std::sync::atomic::Ordering::Relaxed;
use std::time::Duration;

use pattern_guard_gateway::config::{GatewayConfig, Mode};
use pattern_guard_gateway::state::State;

fn hup() {
    let pid = std::process::id().to_string();
    let ok = std::process::Command::new("sh")
        .args(["-c", &format!("kill -HUP {pid}")])
        .status()
        .unwrap()
        .success();
    assert!(ok);
}

async fn reloads(state: &State, ok: u64, failed: u64) {
    let m = &state.runtime.metrics;
    for _ in 0..500 {
        if (m.reloads_ok.load(Relaxed), m.reloads_failed.load(Relaxed)) == (ok, failed) {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("expected {ok} applied and {failed} refused reloads");
}

#[tokio::test]
async fn sighup_reloads_the_config_file() {
    let dir = std::env::temp_dir().join(format!("pg-sighup-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("gateway.toml");
    let write = |toml: &str| {
        std::fs::write(&path, format!("upstream = \"http://127.0.0.1:1\"\n{toml}")).unwrap()
    };
    write("mode = \"prevent\"\n");
    let state = pattern_guard_gateway::build_state(GatewayConfig::load(&path).unwrap()).unwrap();
    pattern_guard_gateway::watch_sighup(state.clone(), path.clone()).unwrap();

    write("mode = \"detect\"\n");
    hup();
    reloads(&state, 1, 0).await;
    assert_eq!(state.compiled().cfg.mode, Mode::Detect);

    // a broken file is refused; the process and its config live on
    write("mode = \"detect\"\n[[rules]]\nname = \"x\"\n");
    hup();
    reloads(&state, 1, 1).await;
    assert_eq!(state.compiled().cfg.mode, Mode::Detect);
    assert!(state.compiled().cfg.rules.is_empty());
    let _ = std::fs::remove_dir_all(&dir);
}
