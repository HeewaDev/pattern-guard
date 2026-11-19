# Phrase lists from the OWASP Core Rule Set

These files are copied unchanged from the OWASP CRS project:

- Source: https://github.com/coreruleset/coreruleset, directory `rules/`
- Commit: `2de4afca0aab985fd1bca8d23f0425c771235758` (2026-11-17, 4.31.0-dev)
- Licence: Apache License 2.0 (see `LICENSE-APACHE-2.0` at the repository root).
  Copyright the OWASP CRS project and its contributors.

| File | Used for |
|---|---|
| `lfi-os-files.data` | OS / application files that path-traversal attacks try to read |
| `restricted-files.data` | Files a client should never request directly (VCS, configs, backups) |
| `unix-shell.data` | Unix shells, binaries and shell variables used in command injection |
| `php-function-names-933150.data` | High-risk PHP function names |
| `java-classes.data` | Java classes abused in deserialization / expression-injection attacks |

Pattern-Guard reads them at build time (`include_str!`) and matches them with
Aho-Corasick; see `crates/waf/src/lexicon.rs` for how each list is scored.
