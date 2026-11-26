//! An attacker in another process (an LLM agent, a Playwright script, …), driven over JSON
//! lines on its stdin / stdout. One object per line.
//!
//! Harness → attacker:
//!
//! ```text
//! {"type":"start","scenario":"targeted","seed":7,"client_ips":["203.0.113.7"],
//!  "rotate":false,"solve_pow":false,"bearer_token":"…",
//!  "targets":[{"vuln":"sqli","method":"GET","path":"/products","param":"id","benign":"1"},…]}
//! {"type":"response","status":403,"headers":{"content-type":"…"},"body":"…",
//!  "elapsed_ms":3,"confirmed":"sqli"|null,"evidence":"…"|null}
//! ```
//!
//! Attacker → harness, after `start` and after every `response`:
//!
//! ```text
//! {"type":"request","method":"GET","path":"/products?id=1","headers":[["accept","*/*"]],
//!  "body":"","client_ip":"203.0.113.7","wait_ms":50,"goal":"sqli","label":"…"}
//! {"type":"done","reason":"…"}
//! ```
//!
//! `confirmed` is the harness's own verdict (the same oracle as for the built-in attacker);
//! an attacker may ignore it and judge the response itself. Lines that are not JSON are
//! skipped, so an attacker can log to stdout. The process's stderr is passed through.

use std::io::{BufRead, BufReader, Write};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::time::Duration;

use super::{Observation, Probe, Strategy, TARGETS};
use crate::Vuln;
use crate::app::data;

pub struct External {
    cmd: String,
    child: Child,
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
    stop: Option<String>,
}

impl External {
    /// Starts `cmd` with `sh -c` and sends the `start` message.
    pub fn spawn(cmd: &str, start: serde_json::Value) -> Result<Self, String> {
        let mut child = Command::new("sh")
            .arg("-c")
            .arg(cmd)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .map_err(|e| format!("cannot start {cmd:?}: {e}"))?;
        let stdin = child.stdin.take().ok_or("no stdin")?;
        let stdout = BufReader::new(child.stdout.take().ok_or("no stdout")?);
        let mut me = External {
            cmd: cmd.to_string(),
            child,
            stdin,
            stdout,
            stop: None,
        };
        me.send(&start);
        Ok(me)
    }

    /// The `start` message for a scenario.
    pub fn start_message(
        scenario: &str,
        seed: u64,
        ips: &[std::net::IpAddr],
        rotate: bool,
        solve_pow: bool,
    ) -> serde_json::Value {
        let targets: Vec<_> = TARGETS
            .iter()
            .map(|t| {
                serde_json::json!({
                    "vuln": t.vuln.as_str(), "method": t.method, "path": t.path,
                    "param": t.param, "benign": t.benign,
                })
            })
            .collect();
        serde_json::json!({
            "type": "start", "scenario": scenario, "seed": seed,
            "client_ips": ips.iter().map(|i| i.to_string()).collect::<Vec<_>>(),
            "rotate": rotate, "solve_pow": solve_pow,
            "bearer_token": data::ATTACKER_TOKEN, "targets": targets,
        })
    }

    fn send(&mut self, v: &serde_json::Value) {
        if writeln!(self.stdin, "{v}")
            .and_then(|_| self.stdin.flush())
            .is_err()
        {
            self.stop
                .get_or_insert_with(|| "attacker closed its input".into());
        }
    }

    fn read(&mut self) -> Option<serde_json::Value> {
        let mut line = String::new();
        loop {
            line.clear();
            match self.stdout.read_line(&mut line) {
                Ok(0) | Err(_) => return None,
                Ok(_) => {
                    if let Ok(v) = serde_json::from_str::<serde_json::Value>(line.trim()) {
                        if v.is_object() {
                            return Some(v);
                        }
                    }
                }
            }
        }
    }
}

fn parse_request(v: &serde_json::Value) -> Probe {
    let s = |k: &str| v[k].as_str().unwrap_or("").to_string();
    let headers = v["headers"]
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|h| {
                    let pair = h.as_array()?;
                    Some((
                        pair.first()?.as_str()?.to_ascii_lowercase(),
                        pair.get(1)?.as_str()?.to_string(),
                    ))
                })
                .collect()
        })
        .unwrap_or_default();
    Probe {
        method: if s("method").is_empty() {
            "GET".into()
        } else {
            s("method")
        },
        target: if s("path").is_empty() {
            "/".into()
        } else {
            s("path")
        },
        headers,
        body: s("body").into_bytes(),
        client_ip: v["client_ip"].as_str().and_then(|ip| ip.parse().ok()),
        wait: Duration::from_millis(v["wait_ms"].as_u64().unwrap_or(0)),
        goal: v["goal"].as_str().and_then(Vuln::parse),
        label: s("label"),
    }
}

impl Strategy for External {
    fn name(&self) -> String {
        format!("external: {}", self.cmd)
    }

    fn next(&mut self) -> Option<Probe> {
        if self.stop.is_some() {
            return None;
        }
        let Some(v) = self.read() else {
            self.stop = Some("attacker exited".into());
            return None;
        };
        match v["type"].as_str() {
            Some("request") => Some(parse_request(&v)),
            _ => {
                self.stop = Some(
                    v["reason"]
                        .as_str()
                        .map(|r| format!("done: {r}"))
                        .unwrap_or_else(|| "done".into()),
                );
                None
            }
        }
    }

    fn observe(&mut self, _probe: &Probe, obs: &Observation) {
        let headers: serde_json::Map<String, serde_json::Value> = obs
            .headers
            .iter()
            .map(|(k, v)| (k.clone(), serde_json::Value::String(v.clone())))
            .collect();
        let msg = serde_json::json!({
            "type": "response", "status": obs.status, "headers": headers, "body": obs.body,
            "elapsed_ms": obs.elapsed.as_millis() as u64,
            "confirmed": obs.confirmed.as_ref().map(|c| c.vuln.as_str()),
            "evidence": obs.confirmed.as_ref().map(|c| c.evidence.clone()),
        });
        self.send(&msg);
    }

    fn stop_reason(&self) -> String {
        self.stop.clone().unwrap_or_else(|| "running".into())
    }
}

impl Drop for External {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn speaks_json_lines_with_a_child_process() {
        // reads `start`, asks for one request, reads the response, stops
        let script = r#"read start; echo 'log line, not JSON'; echo '{"type":"request","method":"POST","path":"/login","headers":[["Content-Type","application/x-www-form-urlencoded"]],"body":"username=admin","client_ip":"198.51.100.9","wait_ms":5,"goal":"bruteforce"}'; read resp; case "$resp" in *'"status":401'*) echo '{"type":"done","reason":"saw 401"}';; *) echo '{"type":"done","reason":"unexpected"}';; esac"#;
        let start =
            External::start_message("t", 1, &["203.0.113.7".parse().unwrap()], false, false);
        let mut e = External::spawn(script, start).unwrap();
        let p = e.next().unwrap();
        assert_eq!(p.method, "POST");
        assert_eq!(p.target, "/login");
        assert_eq!(p.headers[0].0, "content-type");
        assert_eq!(p.client_ip, Some("198.51.100.9".parse().unwrap()));
        assert_eq!(p.wait, Duration::from_millis(5));
        assert_eq!(p.goal, Some(Vuln::BruteForce));
        e.observe(
            &p,
            &Observation {
                status: 401,
                ..Default::default()
            },
        );
        assert!(e.next().is_none());
        assert_eq!(e.stop_reason(), "done: saw 401");
    }
}
