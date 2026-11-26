//! Evaluation tooling for Pattern-Guard (not published).
//!
//! * [`sim`]: synthetic, labelled web traffic for one site, used to train the built-in
//!   model and to evaluate the behavioural engine.
//! * [`gates`]: metrics files written by the evaluation binaries (`--metrics`) and the
//!   CI gates in `tools/eval/gates.toml` they are checked against.
//! * `src/bin/`: `realworld_eval`, `gen_traffic`, `waf_eval`, `crs_eval`, `check_gates`.

pub mod gates;
pub mod sim;
