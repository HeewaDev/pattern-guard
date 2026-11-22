#!/usr/bin/env bash
# Runs the WAF evaluations on the datasets built by scripts/fetch_eval_data.sh and prints
# one summary: development set + benign corpus, hold-out per class, OWASP CRS tests.
#
#   scripts/eval_waf.sh                 evaluate the current checkout
#   DATA=/path/to/data scripts/eval_waf.sh
#                                       other data directory (e.g. to evaluate an older
#                                       checkout with the same data: run this script from
#                                       that checkout's root)
#   SHOW=1 scripts/eval_waf.sh          also list false blocks and misses
set -euo pipefail

DATA=${DATA:-tools/eval/data}
[[ -d "$DATA/dev" ]] || { echo "No datasets in $DATA: run scripts/fetch_eval_data.sh first." >&2; exit 1; }
cargo build -q --release -p pattern-guard-eval --bin waf_eval --bin crs_eval
BIN=target/release

args=()
for f in "$DATA"/dev/*.txt; do args+=(--attack "$f"); done
for f in "$DATA"/benign/*.txt; do
    [[ "$f" == */user-agents.txt ]] || args+=(--benign "$f")
done
# user agents are inspected where they occur: the User-Agent header
args+=(--location header:user-agent --benign "$DATA/benign/user-agents.txt")
echo "## Development attacks (PayloadsAllTheThings) and benign corpus"
"$BIN/waf_eval" "${args[@]}"

echo
echo "## Hold-out (SecLists, fuzzdb): measured only, never tuned on"
args=()
for f in "$DATA"/holdout/*.txt; do args+=(--attack "$f"); done
"$BIN/waf_eval" "${args[@]}"

echo
echo "## OWASP CRS regression tests (development data)"
"$BIN/crs_eval" "$DATA/crs_tests.jsonl" | tail -n 25
echo
echo "## OWASP CRS regression tests, paranoia level 1 rules only"
"$BIN/crs_eval" "$DATA/crs_tests.jsonl" --pl 1 | tail -n 6
