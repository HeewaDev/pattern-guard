#!/usr/bin/env bash
# Runs every evaluation and checks the numbers against tools/eval/gates.toml (CI:
# .github/workflows/eval.yml). Gated: development attacks + benign corpus (waf_eval), OWASP
# CRS regression tests at all paranoia levels and at PL1 (crs_eval), and the behavioural
# engine on simulated traffic (realworld_eval). The hold-out lists (SecLists, fuzzdb) are
# measured and printed but never gated: a failing gate must not invite tuning on them.
#
#   scripts/eval_gates.sh                   needs scripts/fetch_eval_data.sh first
#   DATA=/path/to/data scripts/eval_gates.sh
#   GATES=other.toml scripts/eval_gates.sh
#   METRICS_DIR=out scripts/eval_gates.sh  keep every output and metrics file in out/
#
# Exit status: 0 when every gate holds, 1 when one fails. With $GITHUB_STEP_SUMMARY set,
# the gate table and every evaluation's output also go to the job summary.
set -euo pipefail

DATA=${DATA:-tools/eval/data}
GATES=${GATES:-tools/eval/gates.toml}
[[ -d "$DATA/dev" ]] || { echo "No datasets in $DATA: run scripts/fetch_eval_data.sh first." >&2; exit 1; }
cargo build -q --release -p pattern-guard-eval --bin waf_eval --bin crs_eval --bin realworld_eval --bin check_gates
BIN=target/release
if [[ -n "${METRICS_DIR:-}" ]]; then
    OUT=$METRICS_DIR # keep the outputs and metrics files
    mkdir -p "$OUT"
else
    OUT=$(mktemp -d)
    trap 'rm -rf "$OUT"' EXIT
fi

args=()
for f in "$DATA"/dev/*.txt; do args+=(--attack "$f"); done
for f in "$DATA"/benign/*.txt; do
    [[ "$f" == */user-agents.txt ]] || args+=(--benign "$f")
done
args+=(--location header:user-agent --benign "$DATA/benign/user-agents.txt")
"$BIN/waf_eval" "${args[@]}" --metrics "$OUT/waf_dev.json" >"$OUT/waf_dev.txt"

args=()
for f in "$DATA"/holdout/*.txt; do args+=(--attack "$f"); done
"$BIN/waf_eval" "${args[@]}" >"$OUT/holdout.txt" # no --metrics: never gated

"$BIN/crs_eval" "$DATA/crs_tests.jsonl" --metrics "$OUT/crs.json" >"$OUT/crs.txt"
"$BIN/crs_eval" "$DATA/crs_tests.jsonl" --pl 1 --metrics "$OUT/crs_pl1.json" >"$OUT/crs_pl1.txt"
"$BIN/realworld_eval" --metrics "$OUT/realworld.json" >"$OUT/realworld.txt"

status=0
"$BIN/check_gates" "$GATES" waf_dev="$OUT/waf_dev.json" crs="$OUT/crs.json" \
    crs_pl1="$OUT/crs_pl1.json" realworld="$OUT/realworld.json" >"$OUT/gates.md" || status=$?

sections=(
    "waf_dev.txt|Development attacks (PayloadsAllTheThings) and benign corpus: gated"
    "holdout.txt|Hold-out (SecLists, fuzzdb): measured only, not gated, never tuned on"
    "crs.txt|OWASP CRS regression tests (development data): gated"
    "crs_pl1.txt|OWASP CRS regression tests, paranoia level 1 rules: gated"
    "realworld.txt|Behavioural engine on simulated traffic (realworld_eval): the adaptive engine is gated"
)
report() {
    echo "## Evaluation gates ($GATES)"
    echo
    cat "$OUT/gates.md"
    for s in "${sections[@]}"; do
        echo
        echo "### ${s#*|}"
        echo
        echo '```text'
        cat "$OUT/${s%%|*}"
        echo '```'
    done
}
report
if [[ -n "${GITHUB_STEP_SUMMARY:-}" ]]; then
    report >>"$GITHUB_STEP_SUMMARY"
fi
exit "$status"
