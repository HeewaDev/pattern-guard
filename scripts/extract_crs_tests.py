"""Extract OWASP CRS go-ftw regression tests into JSONL (data-only parsing, no code execution).

The CRS tests are Apache-2.0: https://github.com/coreruleset/coreruleset (tests/regression/tests).
Usage:
  git clone --depth 1 https://github.com/coreruleset/coreruleset /tmp/coreruleset
  python3 -I scripts/extract_crs_tests.py /tmp/coreruleset crs_tests.jsonl   # needs PyYAML
  cargo run --release --example crs_eval -- crs_tests.jsonl
"""
import base64
import collections
import glob
import json
import os
import re
import sys
from urllib.parse import urlsplit

import yaml

DEFAULT_HDRS = {"host", "user-agent", "accept"}
DEFAULT_UA = "OWASP CRS test agent"


def rule_index(crs):
    """Map rule id -> {pl, file, msg, severity} from rules/*.conf (text parse only)."""
    idx = {}
    for path in sorted(glob.glob(os.path.join(crs, "rules", "*.conf"))):
        text = open(path, encoding="utf-8", errors="replace").read()
        text = re.sub(r"\\\r?\n", " ", text)  # join continuation lines
        # split into directives
        for m in re.finditer(r"^\s*(SecRule|SecAction)\b(.*)$", text, re.M):
            body = m.group(2)
            idm = re.search(r"\bid:(\d+)", body)
            if not idm:
                continue
            rid = int(idm.group(1))
            pl = re.search(r"paranoia-level/(\d)", body)
            msg = re.search(r"msg:'([^']*)'", body)
            sev = re.search(r"severity:'([^']*)'", body)
            idx[rid] = {
                "pl": int(pl.group(1)) if pl else None,
                "file": os.path.basename(path),
                "msg": msg.group(1) if msg else None,
                "severity": sev.group(1) if sev else None,
            }
    return idx


def parse_raw(raw):
    """Parse a raw HTTP request (bytes) into method, uri, headers, body."""
    txt = raw.decode("latin-1")
    head, _, body = txt.partition("\r\n\r\n")
    if not _ and "\n\n" in txt:
        head, _, body = txt.partition("\n\n")
    lines = re.split(r"\r?\n", head)
    parts = lines[0].split(" ")
    method = parts[0] if parts else None
    uri = parts[1] if len(parts) > 1 else None
    hdrs = {}
    for ln in lines[1:]:
        if ":" in ln:
            k, v = ln.split(":", 1)
            hdrs[k.strip()] = v.strip()
    return method, uri, hdrs, (body if body else None)


def locations(method, uri, headers, body):
    loc = []
    if uri:
        try:
            sp = urlsplit(uri if not uri.startswith("//") else "http:" + uri)
            path, query = sp.path, sp.query
        except ValueError:
            path, query = uri, ""
        if query or "?" in uri:
            loc.append("query")
        if path not in ("", "/", "/get", "/post", "/index.html", "/anything"):
            loc.append("path")
    if body:
        loc.append("body")
    for k, v in (headers or {}).items():
        kl = k.lower()
        if kl == "user-agent" and v == DEFAULT_UA:
            continue
        if kl in ("host", "accept") or kl == "content-type" or kl == "content-length":
            continue
        loc.append("header:" + kl)
    return loc


def main(crs, out):
    idx = rule_index(crs)
    tdir = os.path.join(crs, "tests", "regression", "tests")
    files = sorted(glob.glob(os.path.join(tdir, "**", "*.yaml"), recursive=True))
    stats = collections.Counter()
    by_cat = collections.defaultdict(collections.Counter)
    by_pl = collections.defaultdict(collections.Counter)
    n = 0
    with open(out, "w", encoding="utf-8") as fo:
        for f in files:
            rel = os.path.relpath(f, crs)
            doc = yaml.safe_load(open(f, encoding="utf-8"))
            if not isinstance(doc, dict) or "tests" not in doc:
                continue
            file_rule = doc.get("rule_id")
            catm = re.search(r"(REQUEST|RESPONSE)-(\d{3})", rel)
            cat = int(catm.group(2)) if catm else None
            for t in doc["tests"]:
                stages = t.get("stages") or []
                st = stages[-1] if stages else {}
                st = st.get("stage", st)  # tolerate older nesting
                inp = st.get("input", {}) or {}
                outp = st.get("output", {}) or {}
                log = outp.get("log", {}) or {}
                method = inp.get("method", "GET")
                uri = inp.get("uri", "/")
                headers = inp.get("headers") or {}
                if isinstance(headers, list):
                    headers = {h.get("name"): h.get("value") for h in headers}
                headers = {str(k): ("" if v is None else str(v)) for k, v in headers.items()}
                body = inp.get("data")
                body_encoding = None
                if isinstance(body, list):
                    body = "\r\n".join(str(x) for x in body)
                    body_encoding = "joined_list"
                if inp.get("encoded_data"):
                    body = base64.b64decode(inp["encoded_data"]).decode("latin-1")
                    body_encoding = "base64_encoded_data"
                raw_req = inp.get("encoded_request") or inp.get("raw_request")
                if raw_req:
                    raw = (base64.b64decode(raw_req) if inp.get("encoded_request")
                           else str(raw_req).encode("latin-1"))
                    method, uri, headers, body = parse_raw(raw)
                    body_encoding = "parsed_from_encoded_request"
                if body is not None:
                    body = str(body)
                exp = log.get("expect_ids") or ([log["expect_id"]] if log.get("expect_id") else [])
                nexp = log.get("no_expect_ids") or ([log["no_expect_id"]] if log.get("no_expect_id") else [])
                exp = [int(x) for x in exp]
                nexp = [int(x) for x in nexp]
                if file_rule in exp:
                    trig, basis = True, "expect_ids:target"
                elif file_rule in nexp:
                    trig, basis = False, "no_expect_ids:target"
                elif exp:
                    trig, basis = True, "expect_ids:other"
                elif nexp:
                    trig, basis = False, "no_expect_ids:other"
                elif log.get("match_regex"):
                    trig, basis = True, "match_regex"
                elif log.get("no_match_regex"):
                    trig, basis = False, "no_match_regex"
                else:
                    trig, basis = None, "status_only" if "status" in outp else "none"
                rinfo = idx.get(file_rule, {})
                tid = t.get("test_id")
                rec = {
                    "id": f"{file_rule}-{tid}",
                    "file": rel,
                    "category": cat,
                    "rule_id": file_rule,
                    "rule_pl": rinfo.get("pl"),
                    "rule_severity": rinfo.get("severity"),
                    "rule_msg": rinfo.get("msg"),
                    "desc": t.get("desc") or t.get("description"),
                    "method": method,
                    "uri": uri,
                    "headers": headers,
                    "body": body,
                    "body_encoding": body_encoding,
                    "locations": locations(method, uri, headers, body),
                    "expect_trigger": trig,
                    "assertion_basis": basis,
                    "expect_ids": exp,
                    "no_expect_ids": nexp,
                    "expect_ids_max_pl": max((idx.get(i, {}).get("pl") or 0 for i in exp), default=None),
                    "status": outp.get("status"),
                    "num_stages": len(stages),
                    "autocomplete_headers": inp.get("autocomplete_headers", True),
                }
                fo.write(json.dumps(rec, ensure_ascii=False) + "\n")
                n += 1
                stats[basis] += 1
                by_cat[cat][trig] += 1
                by_pl[rinfo.get("pl")][trig] += 1
                if len(stages) > 1:
                    stats["multi_stage"] += 1
                if body_encoding:
                    stats["body_" + body_encoding] += 1
    print("files", len(files), "tests", n)
    print("assertion basis / misc:", dict(stats))
    print("category: True/False/None")
    for c in sorted(by_cat, key=lambda x: (x is None, x)):
        d = by_cat[c]
        print(f"  {c}: {d[True]}/{d[False]}/{d[None]}")
    print("rule PL: True/False/None")
    for p in sorted(by_pl, key=lambda x: (x is None, x)):
        d = by_pl[p]
        print(f"  PL{p}: {d[True]}/{d[False]}/{d[None]}")


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2])
