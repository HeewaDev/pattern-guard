//! Evaluation gates: the evaluation binaries write their summary numbers as a metrics
//! file (`--metrics FILE`), and `check_gates` compares them with `tools/eval/gates.toml`.
//!
//! Metrics file (JSON): `{"tool": "waf_eval", "metrics": {"attacks_blocked_pct": 82.4, …}}`.
//!
//! Gates file (TOML): one table per metric set, one `{ min = x }` or `{ max = x }` per
//! gated metric:
//!
//! ```toml
//! [waf_dev]
//! attacks_blocked_pct = { min = 81.9 }
//! benign_false_blocks = { max = 1 }
//! ```
//!
//! A set is named on the `check_gates` command line (`waf_dev=metrics/waf_dev.json`). A
//! gated set or metric that is missing fails, so a gate can't be skipped by accident; a
//! set without a table (the hold-out lists) is reported as not gated.

use std::collections::BTreeMap;
use std::fmt::Write as _;

/// Named numbers from one evaluation run, written with [`Metrics::write`].
#[derive(Debug, Default, Clone)]
pub struct Metrics {
    pub tool: String,
    pub values: BTreeMap<String, f64>,
}

impl Metrics {
    pub fn new(tool: &str) -> Self {
        Self {
            tool: tool.to_string(),
            values: BTreeMap::new(),
        }
    }

    pub fn set(&mut self, name: impl Into<String>, value: f64) {
        self.values.insert(name.into(), value);
    }

    pub fn to_json(&self) -> String {
        serde_json::json!({ "tool": self.tool, "metrics": self.values }).to_string()
    }

    pub fn from_json(text: &str) -> Result<Self, String> {
        let v: serde_json::Value = serde_json::from_str(text).map_err(|e| e.to_string())?;
        let tool = v["tool"].as_str().unwrap_or("").to_string();
        let map = v["metrics"]
            .as_object()
            .ok_or("no \"metrics\" object in the metrics file")?;
        let mut values = BTreeMap::new();
        for (k, x) in map {
            let x = x.as_f64().ok_or(format!("metric {k} is not a number"))?;
            values.insert(k.clone(), x);
        }
        Ok(Self { tool, values })
    }

    /// Writes the JSON file; exits the process with a message if that fails.
    pub fn write(&self, path: &str) {
        if let Err(e) = std::fs::write(path, self.to_json() + "\n") {
            eprintln!("cannot write metrics to {path}: {e}");
            std::process::exit(2);
        }
    }
}

/// `100 · a / b`, 0 when `b` is 0.
pub fn pct(a: usize, b: usize) -> f64 {
    if b == 0 {
        0.0
    } else {
        100.0 * a as f64 / b as f64
    }
}

/// One bound on one metric.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Bound {
    Min(f64),
    Max(f64),
}

impl Bound {
    pub fn holds(self, value: f64) -> bool {
        // a tiny epsilon: a gate set to the measured value must pass on that value
        match self {
            Bound::Min(m) => value >= m - 1e-9,
            Bound::Max(m) => value <= m + 1e-9,
        }
    }
}

impl std::fmt::Display for Bound {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Bound::Min(m) => write!(f, "≥ {}", fmt_num(*m)),
            Bound::Max(m) => write!(f, "≤ {}", fmt_num(*m)),
        }
    }
}

fn fmt_num(x: f64) -> String {
    if x.fract() == 0.0 && x.abs() < 1e15 {
        format!("{x:.0}")
    } else {
        format!("{x:.2}")
    }
}

/// Gates per set, then per metric (sorted, so reports are stable).
pub type Gates = BTreeMap<String, BTreeMap<String, Vec<Bound>>>;

/// Parses `gates.toml`.
pub fn parse_gates(text: &str) -> Result<Gates, String> {
    let table: toml::Table = text.parse().map_err(|e| format!("gates file: {e}"))?;
    let mut out = Gates::new();
    for (set, metrics) in table {
        let metrics = metrics
            .as_table()
            .ok_or(format!("gates file: [{set}] must be a table"))?;
        let mut m = BTreeMap::new();
        for (name, spec) in metrics {
            let spec = spec.as_table().ok_or(format!(
                "gates file: {set}.{name} must be {{ min = x }} or {{ max = x }}"
            ))?;
            let mut bounds = Vec::new();
            for (k, v) in spec {
                let x = v
                    .as_float()
                    .or_else(|| v.as_integer().map(|i| i as f64))
                    .ok_or(format!("gates file: {set}.{name}.{k} must be a number"))?;
                bounds.push(match k.as_str() {
                    "min" => Bound::Min(x),
                    "max" => Bound::Max(x),
                    _ => return Err(format!("gates file: {set}.{name}: unknown key {k}")),
                });
            }
            if bounds.is_empty() {
                return Err(format!("gates file: {set}.{name} has no min or max"));
            }
            m.insert(name.clone(), bounds);
        }
        out.insert(set, m);
    }
    Ok(out)
}

/// One checked gate.
#[derive(Debug, Clone, PartialEq)]
pub struct Check {
    pub set: String,
    pub metric: String,
    pub value: Option<f64>,
    pub bound: Bound,
    pub ok: bool,
}

/// The result of checking every gate against the given metric sets.
#[derive(Debug, Default)]
pub struct Report {
    pub checks: Vec<Check>,
    /// Gated sets that were not given.
    pub missing_sets: Vec<String>,
    /// Sets that were given but have no gates (measured only).
    pub ungated_sets: Vec<String>,
}

impl Report {
    pub fn passed(&self) -> bool {
        self.missing_sets.is_empty() && self.checks.iter().all(|c| c.ok)
    }

    /// A Markdown table (also readable as plain text), failures first.
    pub fn to_markdown(&self) -> String {
        let mut s = String::new();
        let failed = self.checks.iter().filter(|c| !c.ok).count();
        let _ = writeln!(
            s,
            "{} of {} gates passed{}\n",
            self.checks.len() - failed,
            self.checks.len(),
            if self.passed() { "" } else { ": **FAILED**" }
        );
        for set in &self.missing_sets {
            let _ = writeln!(s, "- **missing:** no metrics given for gated set `{set}`");
        }
        for set in &self.ungated_sets {
            let _ = writeln!(s, "- `{set}`: measured only, not gated");
        }
        if !self.missing_sets.is_empty() || !self.ungated_sets.is_empty() {
            s.push('\n');
        }
        let _ = writeln!(s, "| set | metric | measured | gate | |");
        let _ = writeln!(s, "|---|---|---:|---|---|");
        let mut rows: Vec<&Check> = self.checks.iter().collect();
        rows.sort_by_key(|c| c.ok);
        for c in rows {
            let v = c.value.map(fmt_num).unwrap_or_else(|| "missing".into());
            let mark = if c.ok { "ok" } else { "**FAIL**" };
            let _ = writeln!(
                s,
                "| {} | {} | {v} | {} | {mark} |",
                c.set, c.metric, c.bound
            );
        }
        s
    }
}

/// Checks every gate. `given` maps set names to their metrics.
pub fn check(gates: &Gates, given: &BTreeMap<String, Metrics>) -> Report {
    let mut r = Report::default();
    for (set, metrics) in gates {
        let Some(m) = given.get(set) else {
            r.missing_sets.push(set.clone());
            continue;
        };
        for (name, bounds) in metrics {
            let value = m.values.get(name).copied();
            for b in bounds {
                r.checks.push(Check {
                    set: set.clone(),
                    metric: name.clone(),
                    value,
                    bound: *b,
                    ok: value.is_some_and(|v| b.holds(v)),
                });
            }
        }
    }
    for set in given.keys() {
        if !gates.contains_key(set) {
            r.ungated_sets.push(set.clone());
        }
    }
    r
}

#[cfg(test)]
mod tests {
    use super::*;

    fn metrics(pairs: &[(&str, f64)]) -> Metrics {
        let mut m = Metrics::new("t");
        for (k, v) in pairs {
            m.set(*k, *v);
        }
        m
    }

    #[test]
    fn metrics_round_trip_through_json() {
        let m = metrics(&[("a_pct", 82.42), ("false_blocks", 1.0)]);
        let back = Metrics::from_json(&m.to_json()).unwrap();
        assert_eq!(back.tool, "t");
        assert_eq!(back.values, m.values);
        assert!(Metrics::from_json("{\"metrics\": {\"x\": \"no\"}}").is_err());
    }

    #[test]
    fn gates_pass_at_the_bound_and_fail_beyond_it() {
        let g = parse_gates(
            "[waf_dev]\nattacks_blocked_pct = { min = 81.9 }\nbenign_false_blocks = { max = 0 }\n",
        )
        .unwrap();
        let mut given = BTreeMap::new();
        given.insert(
            "waf_dev".to_string(),
            metrics(&[("attacks_blocked_pct", 81.9), ("benign_false_blocks", 0.0)]),
        );
        assert!(check(&g, &given).passed());
        given.insert(
            "waf_dev".to_string(),
            metrics(&[("attacks_blocked_pct", 81.89), ("benign_false_blocks", 0.0)]),
        );
        let r = check(&g, &given);
        assert!(!r.passed());
        assert!(r.to_markdown().contains("**FAIL**"));
        given.insert(
            "waf_dev".to_string(),
            metrics(&[("attacks_blocked_pct", 90.0), ("benign_false_blocks", 1.0)]),
        );
        assert!(!check(&g, &given).passed(), "one false block more fails");
    }

    #[test]
    fn missing_sets_and_metrics_fail_and_ungated_sets_are_listed() {
        let g = parse_gates("[crs]\nattacks_blocked_pct = { min = 50 }\n").unwrap();
        let mut given = BTreeMap::new();
        given.insert("holdout".to_string(), metrics(&[("x", 1.0)]));
        let r = check(&g, &given);
        assert!(!r.passed());
        assert_eq!(r.missing_sets, ["crs"]);
        assert_eq!(r.ungated_sets, ["holdout"]);
        given.insert("crs".to_string(), metrics(&[("other", 1.0)]));
        let r = check(&g, &given);
        assert!(!r.passed(), "a gated metric that is missing fails");
        assert!(r.to_markdown().contains("missing"));
    }

    #[test]
    fn bad_gate_files_are_rejected() {
        assert!(parse_gates("[a]\nm = 3\n").is_err());
        assert!(parse_gates("[a]\nm = { least = 3 }\n").is_err());
        assert!(parse_gates("[a]\nm = { min = \"3\" }\n").is_err());
        assert!(parse_gates("[a]\nm = {}\n").is_err());
        let g = parse_gates("[a]\nm = { min = 1, max = 3 }\n").unwrap();
        assert_eq!(g["a"]["m"].len(), 2);
    }
}
