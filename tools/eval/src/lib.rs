//! Evaluation tooling for Pattern-Guard (not published).
//!
//! * [`sim`]: synthetic, labelled web traffic for one site, used to train the built-in
//!   model and to evaluate the behavioural engine.
//! * `src/bin/`: `realworld_eval`, `gen_traffic`, `waf_eval`, `crs_eval`.

pub mod sim;
