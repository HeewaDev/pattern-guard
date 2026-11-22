#!/usr/bin/env bash
# Fetches the WAF evaluation datasets at pinned commits into tools/eval/data/ (git-ignored;
# nothing here is redistributed) and checks every downloaded file against
# tools/eval/datasets.sha256. Then builds the evaluation sets:
#
#   dev/<class>.txt      development attacks (PayloadsAllTheThings), used to fix categories
#   holdout/<class>.txt  hold-out attacks (SecLists, fuzzdb): measure only, NEVER tune on them
#   benign/<kind>.txt    benign values (names, English words, user agents, doc lines with code)
#   crs_tests.jsonl      OWASP CRS regression tests (development data since WAF 2.0)
#
# Any development line that also appears in a hold-out list is removed, so the hold-out
# stays a hold-out (PayloadsAllTheThings copies some SecLists / fuzzdb lists).
#
#   scripts/fetch_eval_data.sh            download, verify, build
#   scripts/fetch_eval_data.sh --update   after changing a pin: rewrite the checksum file
#
# Needs: curl, git, python3 with PyYAML (for the CRS tests). Run from anywhere.
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
DATA="$ROOT/tools/eval/data"
SUMS="$ROOT/tools/eval/datasets.sha256"
SRC="$DATA/sources"

PATT="swisskyrepo/PayloadsAllTheThings@08ea40e77db3f42ef8f20c65196f3936a19b6c86" # MIT
SECLISTS="danielmiessler/SecLists@a9679c2d7018af36f03ad26b52a8618e2f8057c3"      # MIT
FUZZDB="fuzzdb-project/fuzzdb@5656ab25dc6bb43bae32236fab775658a90d7380"          # BSD-3-Clause
BOOK="rust-lang/book@5c23042f85595490ad9f7412c4c6f57fe0b330d5"                    # MIT OR Apache-2.0
CRS="coreruleset/coreruleset@2de4afca0aab985fd1bca8d23f0425c771235758"           # Apache-2.0, same commit as crates/waf/data/crs

# fetch REPO@SHA PATH: one file from raw.githubusercontent.com into sources/REPO/PATH
fetch() {
    local repo=${1%@*} sha=${1#*@} path=$2
    local out="$SRC/$repo/$path"
    if [[ ! -s "$out" ]]; then
        mkdir -p "$(dirname "$out")"
        curl -fsSL --retry 3 "https://raw.githubusercontent.com/$repo/$sha/${path// /%20}" -o "$out.part"
        mv "$out.part" "$out"
    fi
    printf '%s\n' "$out"
}

# --- development attacks: PayloadsAllTheThings payload lists per WAF class -----------------
# Left out: FUZZDB_* and JHADDIX_* / RSNAKE_* (copies of the hold-out lists), bare file-name
# word lists, event-handler name lists, machine-generated variant lists (xss_alert*), the
# 1.8 MB dotdotpwn list, and classes the WAF doesn't cover (LDAP, open redirect).
declare -A DEV=(
    [sqli]="SQL Injection/Intruder/Auth_Bypass.txt|SQL Injection/Intruder/Auth_Bypass2.txt|SQL Injection/Intruder/Generic_ErrorBased.txt|SQL Injection/Intruder/Generic_Fuzz.txt|SQL Injection/Intruder/Generic_TimeBased.txt|SQL Injection/Intruder/Generic_UnionSelect.txt|SQL Injection/Intruder/SQLi_Polyglots.txt|SQL Injection/Intruder/SQL-Injection|SQL Injection/Intruder/payloads-sql-blind-MSSQL-INSERT|SQL Injection/Intruder/payloads-sql-blind-MSSQL-WHERE|SQL Injection/Intruder/payloads-sql-blind-MySQL-INSERT|SQL Injection/Intruder/payloads-sql-blind-MySQL-ORDER_BY|SQL Injection/Intruder/payloads-sql-blind-MySQL-WHERE"
    [xss]="XSS Injection/Intruders/BRUTELOGIC-XSS-JS.txt|XSS Injection/Intruders/BRUTELOGIC-XSS-STRINGS.txt|XSS Injection/Intruders/IntrudersXSS.txt|XSS Injection/Intruders/MarioXSSVectors.txt|XSS Injection/Intruders/XSSDetection.txt|XSS Injection/Intruders/XSS_Polyglots.txt|XSS Injection/Intruders/xss_payloads_quick.txt"
    [cmdi]="Command Injection/Intruder/command-execution-unix.txt|Command Injection/Intruder/command_exec.txt"
    [traversal]="Directory Traversal/Intruder/directory_traversal.txt|Directory Traversal/Intruder/deep_traversal.txt|Directory Traversal/Intruder/traversals-8-deep-exotic-encoding.txt"
    [lfi]="File Inclusion/Intruders/simple-check.txt|File Inclusion/Intruders/LFI-FD-check.txt|File Inclusion/Intruders/php-filter-iconv.txt|File Inclusion/Intruders/dot-slash-PathTraversal_and_LFI_pairing.txt"
    [nosql]="NoSQL Injection/Intruder/NoSQL.txt|NoSQL Injection/Intruder/MongoDB.txt"
    [ssti]="Server Side Template Injection/Intruder/ssti.fuzz"
)

# --- hold-out attacks: SecLists (S:) and fuzzdb (F:) ---------------------------------------
declare -A HOLDOUT=(
    [sqli]="S:Fuzzing/Databases/SQLi/Generic-SQLi.txt|S:Fuzzing/Databases/SQLi/quick-SQLi.txt|S:Fuzzing/Databases/SQLi/Generic-BlindSQLi.fuzzdb.txt|S:Fuzzing/Databases/SQLi/sqli.auth.bypass.txt|F:attack/sql-injection/detect/GenericBlind.txt|F:attack/sql-injection/detect/MSSQL.txt|F:attack/sql-injection/detect/MSSQL_blind.txt|F:attack/sql-injection/detect/MySQL.txt|F:attack/sql-injection/detect/MySQL_MSSQL.txt|F:attack/sql-injection/detect/oracle.txt|F:attack/sql-injection/detect/xplatform.txt"
    [xss]="S:Fuzzing/XSS/robot-friendly/XSS-Jhaddix.txt|S:Fuzzing/XSS/robot-friendly/XSS-RSNAKE.txt|S:Fuzzing/XSS/robot-friendly/XSS-Somdev.txt|S:Fuzzing/XSS/Polyglots/XSS-Polyglots-Dmiessler.txt|F:attack/xss/xss-rsnake.txt|F:attack/xss/xss-other.txt|F:attack/xss/xss-uri.txt|F:attack/xss/XSSPolyglot.txt"
    [lfi]="S:Fuzzing/LFI/LFI-Jhaddix.txt|F:attack/lfi/JHADDIX_LFI.txt"
    [cmdi]="S:Fuzzing/command-injection-commix.txt|F:attack/os-cmd-execution/command-execution-unix.txt|F:attack/os-cmd-execution/command-injection-template.txt"
)

# --- benign values --------------------------------------------------------------------------
NAMES="Usernames/Names/familynames-usa-top1000.txt|Usernames/Names/femalenames-usa-top1000.txt|Usernames/Names/malenames-usa-top1000.txt|Usernames/Names/forenames-india-top1000.txt"
WORDS="Miscellaneous/lang-english.txt"
AGENTS="Fuzzing/User-Agents/user-agents-whatismybrowserdotcom-mid.txt"
BOOK_CHAPTERS="ch01-01-installation ch01-02-hello-world ch01-03-hello-cargo ch02-00-guessing-game-tutorial ch03-01-variables-and-mutability ch03-02-data-types ch03-03-how-functions-work ch03-05-control-flow ch04-01-what-is-ownership ch04-02-references-and-borrowing ch04-03-slices ch05-01-defining-structs ch05-03-method-syntax ch06-01-defining-an-enum ch06-02-match ch07-02-defining-modules-to-control-scope-and-privacy ch08-01-vectors ch08-02-strings ch08-03-hash-maps ch09-02-recoverable-errors-with-result"

split() { tr '|' '\n' <<<"$1"; }

echo "Downloading pinned sources into $SRC …"
mkdir -p "$SRC" "$DATA/dev" "$DATA/holdout" "$DATA/benign"
for class in "${!DEV[@]}"; do
    split "${DEV[$class]}" | while IFS= read -r p; do fetch "$PATT" "$p" >/dev/null; done
done
for class in "${!HOLDOUT[@]}"; do
    split "${HOLDOUT[$class]}" | while IFS= read -r p; do
        case "$p" in S:*) fetch "$SECLISTS" "${p#S:}" ;; F:*) fetch "$FUZZDB" "${p#F:}" ;; esac >/dev/null
    done
done
split "$NAMES" | while IFS= read -r p; do fetch "$SECLISTS" "$p" >/dev/null; done
fetch "$SECLISTS" "$WORDS" >/dev/null
fetch "$SECLISTS" "$AGENTS" >/dev/null
for ch in $BOOK_CHAPTERS; do fetch "$BOOK" "src/$ch.md" >/dev/null; done

# OWASP CRS regression tests: a sparse checkout of the pinned commit
crs_dir="$SRC/coreruleset"
if [[ ! -d "$crs_dir/tests/regression/tests" ]]; then
    rm -rf "$crs_dir"
    git -c advice.detachedHead=false clone -q --filter=blob:none --no-checkout \
        "https://github.com/${CRS%@*}.git" "$crs_dir"
    git -C "$crs_dir" sparse-checkout set --no-cone /rules/ /tests/regression/tests/
    git -C "$crs_dir" -c advice.detachedHead=false checkout -q "${CRS#*@}"
fi

# --- verify downloads -----------------------------------------------------------------------
cd "$DATA"
list_sources() {
    {
        find sources -type f ! -path 'sources/coreruleset/*' ! -name '*.part'
        find sources/coreruleset/rules sources/coreruleset/tests/regression/tests -type f
    } | LC_ALL=C sort
}
if [[ "${1:-}" == "--update" ]]; then
    list_sources | xargs -d '\n' sha256sum >"$SUMS"
    echo "Wrote $(wc -l <"$SUMS") checksums to $SUMS"
else
    if [[ ! -s "$SUMS" ]]; then
        echo "No checksum file at $SUMS; run with --update to create it." >&2
        exit 1
    fi
    sha256sum --quiet -c "$SUMS"
    echo "All $(wc -l <"$SUMS") downloaded files match $SUMS"
fi

# --- build the evaluation sets ----------------------------------------------------------------
build() {
    local out=$1 repo spec
    shift
    : >"$out"
    for spec in "$@"; do
        case "$spec" in
            S:*) repo=${SECLISTS%@*}; spec=${spec#S:} ;;
            F:*) repo=${FUZZDB%@*}; spec=${spec#F:} ;;
            *) repo=${PATT%@*} ;;
        esac
        # one value per line; CRLF and blank lines dropped
        tr -d '\r' <"sources/$repo/$spec" | sed '/^[[:space:]]*$/d' >>"$out"
    done
    python3 -I - "$out" <<'EOF'
import sys
p = sys.argv[1]
seen, out = set(), []
for line in open(p, encoding="utf-8", errors="replace"):
    line = line.rstrip("\n")
    if line not in seen:
        seen.add(line)
        out.append(line)
open(p, "w", encoding="utf-8").write("\n".join(out) + "\n")
EOF
}
for class in "${!HOLDOUT[@]}"; do
    mapfile -t files < <(split "${HOLDOUT[$class]}")
    build "holdout/$class.txt" "${files[@]}"
done
for class in "${!DEV[@]}"; do
    mapfile -t files < <(split "${DEV[$class]}")
    build "dev/$class.txt" "${files[@]}"
done
# drop development lines that are in any hold-out list
python3 -I - <<'EOF'
import glob
held = set()
for p in glob.glob("holdout/*.txt"):
    held.update(l.rstrip("\n") for l in open(p, encoding="utf-8"))
for p in sorted(glob.glob("dev/*.txt")):
    lines = [l.rstrip("\n") for l in open(p, encoding="utf-8")]
    kept = [l for l in lines if l not in held]
    open(p, "w", encoding="utf-8").write("\n".join(kept) + "\n")
    if len(kept) != len(lines):
        print(f"  {p}: {len(lines) - len(kept)} lines also in a hold-out list removed")
EOF

mapfile -t name_files < <(split "$NAMES")
: >benign/names.txt
for p in "${name_files[@]}"; do tr -d '\r' <"sources/${SECLISTS%@*}/$p" | sed '/^[[:space:]]*$/d' >>benign/names.txt; done
# every n-th word of the English list, for ~10 000 words
total=$(sed '/^[[:space:]]*$/d' "sources/${SECLISTS%@*}/$WORDS" | wc -l)
step=$(( total / 10000 > 0 ? total / 10000 : 1 ))
tr -d '\r' <"sources/${SECLISTS%@*}/$WORDS" | sed '/^[[:space:]]*$/d' | awk -v s="$step" 'NR % s == 0' | head -n 10000 >benign/words.txt
tr -d '\r' <"sources/${SECLISTS%@*}/$AGENTS" | sed '/^[[:space:]]*$/d' >benign/user-agents.txt
# documentation lines with code: inline `code` or lines inside ``` blocks (not the fences,
# not mdBook {{#include}} directives), first 2 100 in chapter order
python3 -I - "sources/${BOOK%@*}/src" $BOOK_CHAPTERS <<'EOF'
import sys
src, chapters = sys.argv[1], sys.argv[2:]
out = []
for ch in chapters:
    fence = False
    for line in open(f"{src}/{ch}.md", encoding="utf-8"):
        line = line.rstrip("\n")
        if line.lstrip().startswith("```"):
            fence = not fence
            continue
        if not line.strip() or "{{#" in line:
            continue
        if fence or "`" in line:
            out.append(line.strip())
open("benign/doc-lines.txt", "w", encoding="utf-8").write("\n".join(out[:2100]) + "\n")
EOF

python3 -I "$ROOT/scripts/extract_crs_tests.py" "$SRC/coreruleset" crs_tests.jsonl

echo
echo "Evaluation sets in $DATA:"
for f in dev/*.txt holdout/*.txt benign/*.txt crs_tests.jsonl; do
    printf '  %-22s %6s lines\n' "$f" "$(wc -l <"$f")"
done
echo
echo "Run them with scripts/eval_waf.sh"
