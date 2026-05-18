//! Spawns the `pattern-guard` binary (requires `cargo test` to build it).

use std::path::PathBuf;
use std::process::Command;

fn repo_file(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(name)
}

fn pattern_guard_exe() -> PathBuf {
    option_env!("CARGO_BIN_EXE_pattern-guard")
        .or(option_env!("CARGO_BIN_EXE_pattern_guard"))
        .map(PathBuf::from)
        .expect("CARGO_BIN_EXE_pattern-guard should be set when running integration tests")
}

#[test]
fn cli_accepts_command_after_flags_without_double_dash() {
    let status = Command::new(pattern_guard_exe())
        .args([
            "--config",
            repo_file("guard.toml.demo").to_str().unwrap(),
            "true",
        ])
        .status()
        .expect("spawn pattern-guard");
    assert!(status.success());
}

#[test]
fn cli_rejects_unknown_flag() {
    let output = Command::new(pattern_guard_exe())
        .args([
            "--config",
            repo_file("guard.toml.demo").to_str().unwrap(),
            "--not-a-real-flag",
            "true",
        ])
        .output()
        .expect("spawn pattern-guard");
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("unknown flag") || stderr.contains("pattern-guard:"),
        "stderr: {}",
        stderr
    );
}
