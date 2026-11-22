# WAF internals (`crates/waf`, crate `pattern-guard-waf`)

The WAF decides whether *a value inside a request* is an attack payload. It is
synchronous and stateless per request. An `Inspector` is built once (compiling ~110
regexes and five Aho-Corasick automata) and shared across threads.

Detection results and their history are in [../FEATURES.md](../FEATURES.md) and
[../RESEARCH.md](../RESEARCH.md). Tuning from the operator's side is in
[../GATEWAY.md](../GATEWAY.md#waf-tuning).

## Public API

| Item | Purpose |
|---|---|
| `Inspector::new()` | Compile all indicators. Expensive: do it once |
| `Inspector::inspect(&HttpRequest) -> Inspection` | Walk a whole request and return one `Finding` per suspicious value |
| `Inspector::inspect_value(location, raw, form) -> Option<Finding>` | Score a single value (`form = true`: `+` means space) |
| `Inspector.min_score` (3.0), `Inspector.max_value_len` (8 192) | Findings below `min_score` are dropped; longer values are truncated |
| `HttpRequest { path_and_query, headers, content_type, body }` | What the inspector needs. Borrowed, so the caller decides how much body to pass |
| `Finding { class, score, location, indicators, sample }` | `score` is 0–10; `sample` is the decoded value, truncated to 160 bytes |
| `Inspection::{max_score, top}` | Helpers |
| `AttackClass` + `as_str()` | 17 classes. The names are logged and used as metric labels |
| `decode(raw, form)` | The normaliser on its own |

Suggested thresholds: log at ≥ 4, block at ≥ 7. These are the gateway defaults, `waf.log_score` and `waf.block_score`.

## Module map

| Path | Responsibility |
|---|---|
| `inspect.rs` | `Inspector`: request walking, the per-value pipeline, scoring, multipart, session fixation, JSON walking |
| `decode.rs` | Server-like decoding (`%XX` ×≤4 with overlong UTF-8 folded to ASCII, `%uXXXX`, HTML entities, `\uXXXX` / `\xHH`), base64 variants, UTF-7, look-alike bracket folding |
| `body.rs` | A body as text: byte-order marks, the declared charset, UTF-16 / UTF-32 transcoding (also undeclared, by RFC 4627 null-byte detection), `body_charset` for charsets that hide content (EBCDIC, UTF-7, unknown) |
| `indicators.rs` | `AttackClass` and ~110 weighted regex indicators (`Indicator { class, name, weight, pattern }`) |
| `lexicon.rs` | OWASP CRS phrase lists with Aho-Corasick, each with a scope (`Values`, `Path`, `Call`) |
| `sql.rs` | SQL tokenizer and structural scoring: breakouts, whole-value expressions, function calls |
| `shell.rs` | Shell-command analyser: undoes evasions, splits commands, scores command words by position (Unix and Windows) |
| `ssrf.rs` | URL analyser: host normalisation, internal / metadata / obfuscated targets, remote file inclusion |
| `multipart.rs` | RFC 7578 parser with limits and anomaly detection; upload file-name and content checks |
| `data/crs/*.data` | CRS lists, vendored unchanged (Apache-2.0, pinned commit in `data/crs/README.md`), compiled in with `include_str!` |

## Walking a request (`Inspector::inspect`)

| Source | Location string | `form` | Notes |
|---|---|---|---|
| Path | `path` | no | Some indicators are exempt in the path (`dom_sink`, `js_cookie_domain`, `generic_event_handler`); no shell or SSRF analysis |
| Query name / value | `query-name`, `query:<name>` | yes | Names are collected for session-fixation detection |
| `User-Agent`, `Referer`, `X-Forwarded-Host`, `X-Original-URL`, `X-Rewrite-URL` | `header:<name>` | no | Full analysis |
| `X-Forwarded-For`, `X-Real-IP`, `True-Client-IP`, `X-Client-IP`, `Forwarded`, `Origin` | `header:<name>` | no | Full analysis: applications log and reflect them (second-order SQLi, stored XSS) |
| | | | `Referer`, `Origin` and the client-address headers carry the client's own, often internal, addresses: no SSRF / RFI analysis or indicators there |
| `Cookie` | `cookie:<name>` per pair | yes | |
| Every other header | `header:<name>` | no | **Only** JNDI / Java indicators (`jndi_only`), so arbitrary headers can't cause false positives |
| Form body | `body-name`, `body:<name>` | yes | `application/x-www-form-urlencoded`. Every non-multipart body is first decoded to text by `body.rs` |
| JSON body | `json.<path>`, `json.<path>-key`, `json.items[2]` | no | Walked recursively: depth ≤ 32, ≤ 1 000 items per level. Invalid JSON is inspected as text |
| Multipart body | `body:<field>`, `filename:<field>`, `json.<field>…`, `multipart` | no | See [Multipart](#multipart) |
| XML, `text/*` | `body` | no | The whole (truncated) body as one value |
| No or an unknown content type | `json…` or `body` | no | Inspected anyway (frameworks often parse bodies whatever the declared type): walked as JSON if it starts with `{` / `[` and parses, otherwise one value. Binary content (a raw upload) is only searched for embedded server code (`upload_embedded_php`: 8) |

## The per-value pipeline (`inspect_value_filtered`)

```
raw ─► truncate (8 KiB) ─► decode: URL ×≤4 · %uXXXX · HTML entities · JS escapes · lowercase · collapse whitespace
     │
     ├─ variants:  [comments removed] [comments → space] [Log4j lookups resolved ×≤3] [decoded]
     │             + UTF-7 decoding (if it decodes) + look-alike brackets folded (＜ « ‹ ¼ → <)
     │             + base64 decodings (whole value and fragments, 4 alignments)
     │             + check: javascript:/vbscript: split by tabs or newlines → js_uri_split (7)
     │
     ├─ RegexSet      over every variant           (header values: JNDI / Java only)
     ├─ Lexicons      over decoded, comment-free and base64 variants
     ├─ SQL           over decoded                  (not for headers limited to JNDI)
     ├─ Shell         over lowercased, newlines kept (not in the path)
     ├─ URL/SSRF      over decoded, with the parameter name (not in the path or Referer)
     ├─ extras        NUL byte (7, not for raw bodies) · encoded traversal (3) · /*! (4) · /* */ (2)
     │
     ▼
per class: Σ weights of DISTINCT indicator names ─► strongest class ─► cap at 10 ─► ≥ min_score → Finding
```

Scoring rules:

- An indicator counts **once per value**, however many variants it matches in.
- Classes are not added together. A value yields **one** finding, for its strongest class.
- At request level, the gateway blocks on the highest finding score (≥ `block_score`).
- Weights encode confidence. A weight of 7 or more blocks on its own, so it is reserved for
  patterns that only appear in attacks. Weak signals (2–4) must combine with others to block. That is
  how "O'Brien" and a sentence starting with "rm -rf" stay below the threshold.

## Analysers

| Analyser | Class(es) | What it recognises | Indicator names |
|---|---|---|---|
| Regex indicators | all | Signatures per class: tags and event handlers, traversal sequences, template syntax, JNDI lookups, XXE entities, Mongo operators, PHP tags and wrappers, Java serialisation, Node / Perl / EL code, prototype pollution | ~110, e.g. `script_tag`, `jndi_lookup` (see `indicators.rs`) |
| Lexicons (CRS) | PathTraversal, CommandInjection, PhpInjection, JavaInjection | OS files (3, values), restricted files (7, path only), Unix shell words (4), PHP functions followed by `(` (5), Java classes (7) | `lfi_os_file`, `restricted_file`, `unix_shell`, `php_function_call`, `java_class` |
| SQL tokenizer | SqlInjection | A quote breaking out of a string into SQL (7); numeric-context continuation (`1) or (1=1`), also into a comparison on a column (`1 or username='admin'`, `0 or id in (`, `1 or name is not null`: 7); the whole value is a SQL expression (3–4); database functions (3, dangerous ones 5). Values with three plain words in a row are prose | `sql_string_breakout`, `sql_numeric_breakout`, `sql_column_breakout`, `sql_expression`, `sql_known_function`, `sql_dangerous_function` |
| Shell | CommandInjection | Undoes quotes, `${IFS}`, `{a,b}`, `[x]` and empty expansions, splits on `; \n \| & ( ) { }`, scores command words by position and arguments; Windows `FOR` and `IF` | `shell_chained_command` (5), `shell_command_word`, `shell_command_args`, `windows_for_loop` (7), … |
| URL / SSRF | Ssrf, RemoteFileInclusion | Decimal, hex and octal IPv4, IPv4-mapped IPv6, Unicode look-alikes; internal ranges and names; cloud metadata; parser confusion (several `@`, or a space, `&` or `#` right before the `@`; backslashes in the authority); remote scripts on RFI-typical parameters | `ssrf_cloud_metadata`, `ssrf_internal_address`, `ssrf_obfuscated_ip`, `url_parser_confusion`, `rfi_remote_script`, `rfi_known_parameter`, … |
| Session fixation | SessionFixation | A framework session-id parameter name (`jsessionid`, `phpsessid`, …) without a same-site Referer: 8 | `session_id_parameter_without_referer`, `…_foreign_referer` |

## Multipart

`multipart::parse` enforces 256 parts and 8 KiB of headers per part, and records **structural
anomalies** that parsers disagree on: duplicate `Content-Disposition`, invalid or malformed
header names, parameter evasions (quotes, encodings), part charsets, `_charset_` fields,
`Content-Transfer-Encoding`. These anomalies are scored as `ProtocolViolation` at location `multipart`.

Per part:
- The field name is inspected (`body-name`), and its value as `body:<field>`. A JSON part is walked as JSON.
- **Files.** The file name is inspected as a value (`filename:<field>`) and also checked by
  `filename_indicators`: server scripts (7), double extensions (6), server config files
  (8), PHP session files (7), absolute paths, traversal, NUL bytes, executables. Names
  matching the CRS restricted-files list add `upload_restricted_file` (7).
- **Binary files** are not scanned as text. They are only searched for embedded server code
  (`upload_embedded_php`, `upload_embedded_server_code`: 8). Text files are inspected like
  any other value.

A body that fails to parse as multipart falls back to whole-body inspection.

## Performance

- Typical cost: ~17–20 µs per request (`benches/inspect_bench.rs`).
- **The lazy-DFA cache.** The indicator `RegexSet` is built with `dfa_size_limit(16 <<
  20)`. With the regex crate's default 2 MiB, varied attack traffic makes the cache thrash and the
  crate falls back to the PikeVM, about 60× slower (~1.4 ms per request). The cache is per
  thread, so budget about 16 MiB of WAF cache per worker thread.
- The number of variants drives the cost. Each new variant means one more pass of the `RegexSet`. Decoders that run
  only when a trigger is present (base64 needs ≥ 12 base64 characters including a digit or upper-case
  letter; UTF-7 needs `+…-`) keep the common case cheap.
- Input caps: 8 KiB per value, the body window set by the caller (gateway: 64 KiB), JSON depth and width,
  multipart part count and header size, base64 candidates ≤ 16 KiB.

## Testing

- Unit tests in each analyser pair **attacks that must score high** with **prose, names and code
  that must stay low** (e.g. `injections_score_high` / `prose_names_and_code_stay_low` in
  `sql.rs`).
- `tests/corpus.rs`: a hand-built corpus of real-world attack payloads and tricky benign
  values. The benign side must stay at 0 blocks. To print the misses, run `cargo test -p pattern-guard-waf --test corpus -- --nocapture`.
- `tools/eval`: `waf_eval` (payload and benign lists) and `crs_eval` (OWASP CRS regression
  tests). See [tooling.md](tooling.md).
