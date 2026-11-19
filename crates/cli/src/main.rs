//! CLI.
//!
//! ```text
//! pattern-guard replay [--config F] [--model M] [--format auto|jsonl|combined] [--top N] LOG
//! pattern-guard train  [--config F] [--epochs N] [--l2 X] [--lr X] [--no-balance] [--no-augment] [--augment-weight W] -o OUT LOG
//! pattern-guard --config F [--repeat N] [--] cmd [args]      (wrap a command)
//! ```

mod args;
mod replay;
mod train;
mod wrap;

pub(crate) type BoxErr = Box<dyn std::error::Error>;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let result = match args.get(1).map(String::as_str) {
        Some("replay") => replay::replay(&args[2..]),
        Some("train") => train::train(&args[2..]),
        Some("-h") | Some("--help") | Some("help") => {
            print!("{}", USAGE);
            Ok(())
        }
        _ => wrap::wrap(&args),
    };
    if let Err(e) = result {
        eprintln!("pattern-guard: {e}");
        std::process::exit(1);
    }
}

pub(crate) const USAGE: &str = "\
pattern-guard — adaptive request-abuse detection

USAGE:
  pattern-guard replay [--config F] [--model M] [--format auto|jsonl|combined] [--top N] LOG
      Replay an access log (JSONL or nginx/Apache combined, '-' for stdin) through the
      guard and report decisions. With labelled JSONL, also reports false positives and
      detection per scenario.

  pattern-guard train [--config F] [--epochs N] [--l2 X] [--lr X] [--no-balance] [--no-augment] [--augment-weight W] -o OUT LOG
      Train a model on labelled JSONL (`label`: 1 = abusive, 0 = legitimate) and write
      it as TOML. Use it with `model = \"OUT\"` in guard.toml or `replay --model OUT`.

  pattern-guard --config F [--repeat N] [--] CMD [ARGS...]
      Run CMD under the guard (one event per run).
";
