//! `pattern-guard --config F -- CMD`: run a command under the guard (one event per run).

use std::path::PathBuf;
use std::process::Command;
use std::time::SystemTime;

use pattern_guard::{Decision, Guard};

use crate::{BoxErr, USAGE};

type ParsedArgs = (Option<PathBuf>, Option<u32>, Vec<String>);

pub(crate) fn wrap(args: &[String]) -> Result<(), BoxErr> {
    let (config_path, repeat_n, rest) = parse_args(args)?;

    let guard = if let Some(p) = config_path {
        Guard::from_config_path(p)?
    } else {
        eprintln!("pattern-guard: no --config given; running without guard");
        if rest.is_empty() {
            return Err(format!("no command given\n\n{USAGE}").into());
        }
        let code = run_child(&rest)?;
        std::process::exit(code);
    };

    if rest.is_empty() {
        return Err("no command given (use `-- cmd` or put the command after flags)".into());
    }

    let target = rest.join(" ");
    let runs = repeat_n.unwrap_or(1);
    let mut last_code = 0i32;

    for _ in 1..=runs {
        let event = pattern_guard::Event::new("cli", "run", target.clone(), SystemTime::now());
        let (decision, risk) = guard.check_with_risk(&event);

        match decision {
            Decision::Block => {
                let msg = format!("pattern-guard: block (risk {:.2})", risk);
                eprintln!("{}", msg);
                log::warn!("{}", msg);
                std::process::exit(2);
            }
            Decision::Challenge => {
                let msg = format!(
                    "pattern-guard: challenge (risk {:.2}) — refusing to run unattended",
                    risk
                );
                eprintln!("{}", msg);
                log::warn!("{}", msg);
                std::process::exit(2);
            }
            Decision::Delay(d) => {
                let msg = format!("pattern-guard: delay {:?} (risk {:.2})", d, risk);
                eprintln!("{}", msg);
                log::info!("{}", msg);
                std::thread::sleep(d);
            }
            Decision::Warn => {
                let msg = format!("pattern-guard: warn (risk {:.2}) — proceeding", risk);
                eprintln!("{}", msg);
                log::info!("{}", msg);
            }
            Decision::Allow => {}
        }

        last_code = run_child(&rest)?;
    }

    std::process::exit(last_code);
}

/// Parses argv[0] = program name. Supports `--config`, `--repeat`, optional `--`, then command args.
fn parse_args(args: &[String]) -> Result<ParsedArgs, String> {
    let mut config_path = None;
    let mut repeat_n = None;
    let mut i = 1usize;

    while i < args.len() {
        match args[i].as_str() {
            "--" => {
                i += 1;
                break;
            }
            "--config" => {
                let Some(path) = args.get(i + 1) else {
                    return Err("--config requires a path".into());
                };
                config_path = Some(PathBuf::from(path));
                i += 2;
            }
            "--repeat" => {
                let Some(n) = args.get(i + 1) else {
                    return Err("--repeat requires a number".into());
                };
                repeat_n = Some(
                    n.parse::<u32>()
                        .map_err(|_| format!("invalid --repeat value: {}", n))?,
                );
                i += 2;
            }
            s if s.starts_with("--") => {
                return Err(format!(
                    "unknown flag: {} (expected --config, --repeat, or --)",
                    s
                ));
            }
            _ => break,
        }
    }

    let rest: Vec<String> = args[i..].to_vec();
    Ok((config_path, repeat_n, rest))
}

fn run_child(argv: &[String]) -> Result<i32, BoxErr> {
    let (prog, rest) = (&argv[0], &argv[1..]);
    let status = Command::new(prog).args(rest).status()?;
    Ok(status.code().unwrap_or(1))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(s: &[&str]) -> Vec<String> {
        s.iter().map(|x| (*x).to_string()).collect()
    }

    #[test]
    fn parse_positional_command_without_double_dash() {
        let a = args(&["pg", "--config", "f.toml", "true"]);
        let (c, r, rest) = parse_args(&a).unwrap();
        assert_eq!(c, Some(PathBuf::from("f.toml")));
        assert_eq!(r, None);
        assert_eq!(rest, vec!["true"]);
    }

    #[test]
    fn parse_double_dash_still_works() {
        let a = args(&["pg", "--config", "f.toml", "--", "sh", "-c", "true"]);
        let (_, _, rest) = parse_args(&a).unwrap();
        assert_eq!(rest, vec!["sh", "-c", "true"]);
    }

    #[test]
    fn parse_unknown_flag_errors() {
        let a = args(&["pg", "--config", "f.toml", "--weird", "x"]);
        assert!(parse_args(&a).is_err());
    }
}
