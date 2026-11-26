//! `pattern-guard-gateway --config gateway.toml [--check]`

use pattern_guard_gateway::config::GatewayConfig;

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut config = None;
    let mut check = false;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--config" | "-c" => {
                config = args.get(i + 1).cloned();
                i += 2;
            }
            "--check" => {
                check = true;
                i += 1;
            }
            "-h" | "--help" => {
                println!(
                    "pattern-guard-gateway --config gateway.toml [--check]\n\nReverse proxy with WAF, behavioural ML, bot challenge and threat intel.\nSee docs/GATEWAY.md."
                );
                return;
            }
            other => {
                eprintln!("pattern-guard-gateway: unknown argument {other}");
                std::process::exit(2);
            }
        }
    }
    let path = config.unwrap_or_else(|| "gateway.toml".into());
    let cfg = match GatewayConfig::load(&path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("pattern-guard-gateway: {e}");
            std::process::exit(1);
        }
    };
    if check {
        let mut cfg = cfg;
        cfg.log.decisions = None; // validation must not create files
        match pattern_guard_gateway::build_state(cfg) {
            Ok(_) => println!("config OK"),
            Err(e) => {
                eprintln!("pattern-guard-gateway: {e}");
                std::process::exit(1);
            }
        }
        return;
    }
    if let Err(e) = pattern_guard_gateway::run(cfg, Some(path.into())).await {
        eprintln!("pattern-guard-gateway: {e}");
        std::process::exit(1);
    }
}
