//! Flag parsing and log-reading helpers shared by the subcommands.

use std::collections::HashMap;
use std::io::{BufRead, BufReader};

use pattern_guard::Config;
use pattern_guard::logs::{LogFormat, LogRecord, Ordered, ReplayOrder, parse_line};

use crate::BoxErr;

pub(crate) struct Flags {
    pub(crate) values: HashMap<String, String>,
    pub(crate) switches: Vec<String>,
    pub(crate) positional: Vec<String>,
}

pub(crate) fn parse_flags(
    args: &[String],
    with_value: &[&str],
    switches: &[&str],
) -> Result<Flags, BoxErr> {
    let mut f = Flags {
        values: HashMap::new(),
        switches: Vec::new(),
        positional: Vec::new(),
    };
    let mut i = 0;
    while i < args.len() {
        let a = args[i].as_str();
        if with_value.contains(&a) {
            let v = args
                .get(i + 1)
                .ok_or_else(|| format!("{a} requires a value"))?;
            f.values.insert(a.to_string(), v.clone());
            i += 2;
        } else if switches.contains(&a) {
            f.switches.push(a.to_string());
            i += 1;
        } else if a.starts_with("--") || (a.starts_with('-') && a.len() > 1) {
            return Err(format!("unknown flag: {a}").into());
        } else {
            f.positional.push(a.to_string());
            i += 1;
        }
    }
    Ok(f)
}

pub(crate) fn load_config(path: Option<&String>) -> Result<Config, BoxErr> {
    Ok(match path {
        Some(p) => Config::load(p)?,
        None => Config::default(),
    })
}

pub(crate) fn open_log(path: &str) -> Result<Box<dyn BufRead>, BoxErr> {
    Ok(if path == "-" {
        Box::new(BufReader::new(std::io::stdin()))
    } else {
        Box::new(BufReader::new(
            std::fs::File::open(path).map_err(|e| format!("cannot open {path}: {e}"))?,
        ))
    })
}

/// Counts skipped lines and prints the first few.
#[derive(Default)]
struct Skipped(usize);

impl Skipped {
    fn note(&mut self, line_no: usize, why: &str) {
        self.0 += 1;
        if self.0 <= 5 {
            eprintln!("pattern-guard: line {line_no}: {why} (skipped)");
        }
    }
}

/// Streams records in time order, auto-detecting the format from the first data line.
/// Unparseable lines and records whose timestamps would corrupt the event-time replay
/// (see [`ReplayOrder`]) are skipped and counted.
pub(crate) fn for_each_record(
    path: &str,
    format: Option<LogFormat>,
    mut f: impl FnMut(LogRecord),
) -> Result<usize, BoxErr> {
    let mut format = format;
    let mut skipped = Skipped::default();
    let mut order = ReplayOrder::new();
    let mut deliver = |o: Ordered<(usize, LogRecord)>, skipped: &mut Skipped| match o {
        Ordered::Keep((_, r)) => f(r),
        Ordered::Skip((n, _), why) => skipped.note(n, &why),
    };
    for (n, line) in open_log(path)?.lines().enumerate() {
        let line = line?;
        let fmt = *format.get_or_insert_with(|| LogFormat::detect(&line));
        match parse_line(&line, fmt) {
            Ok(Some(r)) => {
                if let Some(o) = order.push(r.event.unix_secs(), (n + 1, r)) {
                    deliver(o, &mut skipped);
                }
            }
            Ok(None) => {}
            Err(e) => skipped.note(n + 1, &e),
        }
    }
    while let Some(o) = order.finish() {
        deliver(o, &mut skipped);
    }
    if skipped.0 > 5 {
        eprintln!("pattern-guard: {} lines skipped in total", skipped.0);
    }
    Ok(skipped.0)
}

pub(crate) fn format_flag(f: &Flags) -> Result<Option<LogFormat>, BoxErr> {
    match f.values.get("--format").map(String::as_str) {
        None | Some("auto") => Ok(None),
        Some(s) => Ok(Some(
            LogFormat::parse(s).ok_or_else(|| format!("unknown --format {s}"))?,
        )),
    }
}

pub(crate) fn pct(n: usize, d: usize) -> f64 {
    if d == 0 {
        0.0
    } else {
        100.0 * n as f64 / d as f64
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(s: &[&str]) -> Vec<String> {
        s.iter().map(|x| (*x).to_string()).collect()
    }

    #[test]
    fn subcommand_flags() {
        let f = parse_flags(&args(&["--top", "3", "access.log"]), &["--top"], &[]).unwrap();
        assert_eq!(f.values["--top"], "3");
        assert_eq!(f.positional, vec!["access.log"]);
        assert!(parse_flags(&args(&["--nope"]), &[], &[]).is_err());
        assert!(parse_flags(&args(&["-"]), &[], &[]).unwrap().positional == vec!["-"]);
    }
}
