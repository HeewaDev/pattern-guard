//! CLI. `pattern-guard --config path -- cmd [args]`. Optional `--repeat N`.

use std::path::PathBuf;
use std::process::Command;
use std::time::SystemTime;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    let (config_path, repeat_n, rest) = parse_args(&args)?;

    let guard = if let Some(p) = config_path {
        pattern_guard::Guard::from_config_path(p)?
    } else {
        eprintln!("pattern-guard: no --config given; running without guard");
        let code = run_child(rest)?;
        std::process::exit(code);
    };

    if rest.is_empty() {
        eprintln!("pattern-guard: no command after --");
        std::process::exit(1);
    }

    let target = rest.join(" ");
    let runs = repeat_n.unwrap_or(1);
    let mut last_code = 0i32;

    for _ in 1..=runs {
        let event = pattern_guard::Event::new("cli", "run", target.clone(), SystemTime::now());
        let (decision, risk) = guard.check_with_risk(&event);

        match decision {
            pattern_guard::Decision::Block => {
                let msg = format!("pattern-guard: block (risk {:.2})", risk);
                eprintln!("{}", msg);
                log::warn!("{}", msg);
                std::process::exit(2);
            }
            pattern_guard::Decision::Delay(d) => {
                let msg = format!("pattern-guard: delay {:?} (risk {:.2})", d, risk);
                eprintln!("{}", msg);
                log::info!("{}", msg);
                std::thread::sleep(d);
            }
            pattern_guard::Decision::Warn => {
                let msg = format!("pattern-guard: warn (risk {:.2}) — proceeding", risk);
                eprintln!("{}", msg);
                log::info!("{}", msg);
            }
            pattern_guard::Decision::Allow => {}
        }

        last_code = run_child(rest)?;
    }

    std::process::exit(last_code);
}

fn parse_args(
    args: &[String],
) -> Result<(Option<PathBuf>, Option<u32>, &[String]), Box<dyn std::error::Error>> {
    let mut config_path = None;
    let mut repeat_n = None;
    let mut i = 1;
    while i < args.len() {
        if args[i] == "--config" && i + 1 < args.len() {
            config_path = Some(PathBuf::from(&args[i + 1]));
            i += 2;
        } else if args[i] == "--repeat" && i + 1 < args.len() {
            repeat_n = Some(args[i + 1].parse().unwrap_or(1));
            i += 2;
        } else if args[i] == "--" {
            i += 1;
            break;
        } else {
            i += 1;
        }
    }
    Ok((config_path, repeat_n, &args[i..]))
}

fn run_child(argv: &[String]) -> Result<i32, Box<dyn std::error::Error>> {
    let (prog, rest) = (&argv[0], &argv[1..]);
    let status = Command::new(prog).args(rest).status()?;
    Ok(status.code().unwrap_or(1))
}
