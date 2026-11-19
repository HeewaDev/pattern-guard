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

fn temp_dir(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("pattern_guard_it_{}_{}", name, std::process::id()));
    std::fs::create_dir_all(&d).unwrap();
    d
}

/// 20 minutes of labelled traffic: browsing users + a credential-stuffing botnet.
fn write_labelled_jsonl(path: &std::path::Path) {
    use std::fmt::Write as _;
    let mut s = String::new();
    let t0 = 1_700_000_000.0;
    let mut lines: Vec<(f64, String)> = Vec::new();
    for u in 0..40u32 {
        let ip = format!("198.51.100.{}", u + 1);
        let mut t = u as f64 * 13.0;
        while t < 1200.0 {
            for (k, path) in [
                format!("/product/{}", (u * 37 + t as u32) % 900),
                "/api/cart".into(),
                format!("/img/{}.jpg", u),
            ]
            .iter()
            .enumerate()
            {
                lines.push((t + k as f64 * 0.1, format!(
                    r#"{{"ts":{},"ip":"{ip}","method":"GET","path":"{path}","status":200,"ua":"Mozilla/5.0 Chrome/130","label":0,"scenario":"browsing"}}"#,
                    t0 + t + k as f64 * 0.1
                )));
            }
            t += 20.0 + (u % 7) as f64 * 3.0;
        }
    }
    for b in 0..60u32 {
        let ip = format!("203.0.113.{}", b + 1);
        let mut t = 400.0 + b as f64;
        while t < 1200.0 {
            lines.push((t, format!(
                r#"{{"ts":{},"ip":"{ip}","method":"POST","path":"/login","status":401,"ua":"python-requests/2.32","label":1,"scenario":"stuffing"}}"#,
                t0 + t
            )));
            t += 30.0;
        }
    }
    lines.sort_by(|a, b| a.0.total_cmp(&b.0));
    for (_, l) in lines {
        writeln!(s, "{l}").unwrap();
    }
    std::fs::write(path, s).unwrap();
}

#[test]
fn cli_train_and_replay_labelled_jsonl() {
    let dir = temp_dir("train");
    let log = dir.join("traffic.jsonl");
    let model = dir.join("model.toml");
    write_labelled_jsonl(&log);

    let out = Command::new(pattern_guard_exe())
        .args([
            "train",
            "--epochs",
            "200",
            "-o",
            model.to_str().unwrap(),
            log.to_str().unwrap(),
        ])
        .output()
        .expect("spawn train");
    assert!(
        out.status.success(),
        "train failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let model_text = std::fs::read_to_string(&model).unwrap();
    assert!(model_text.contains("actor_fail_ratio"));

    let out = Command::new(pattern_guard_exe())
        .args([
            "replay",
            "--model",
            model.to_str().unwrap(),
            log.to_str().unwrap(),
        ])
        .output()
        .expect("spawn replay");
    assert!(
        out.status.success(),
        "replay failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("Detection:"), "{stdout}");
    assert!(stdout.contains("stuffing"), "{stdout}");
}

#[test]
fn cli_replay_combined_log() {
    let dir = temp_dir("combined");
    let log = dir.join("access.log");
    let mut s = String::new();
    for i in 0..50 {
        s.push_str(&format!(
            "203.0.113.9 - - [10/Oct/2024:13:{:02}:{:02} +0000] \"GET /product/{} HTTP/1.1\" 200 512 \"-\" \"Mozilla/5.0\"\n",
            i / 60,
            i % 60,
            i
        ));
    }
    std::fs::write(&log, s).unwrap();
    let out = Command::new(pattern_guard_exe())
        .args(["replay", log.to_str().unwrap()])
        .output()
        .expect("spawn replay");
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(String::from_utf8_lossy(&out.stdout).contains("Replayed 50 requests from 1 actors"));
}

#[test]
fn cli_train_requires_labels() {
    let dir = temp_dir("nolabels");
    let log = dir.join("t.jsonl");
    std::fs::write(
        &log,
        "{\"ts\":1700000000,\"ip\":\"1.2.3.4\",\"path\":\"/\"}\n",
    )
    .unwrap();
    let out = Command::new(pattern_guard_exe())
        .args([
            "train",
            "-o",
            dir.join("m.toml").to_str().unwrap(),
            log.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(!out.status.success());
}
