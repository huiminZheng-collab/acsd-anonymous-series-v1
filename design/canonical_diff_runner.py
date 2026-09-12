"""Differential canonical-JSON tests: Python (pec_core) vs Node (v1 reference).

Design constraint (per task assignment): this file READS the project's
pec_core but never modifies it. It emits a machine-readable report and the
test-vector set. Each vector carries an expected verdict (ACCEPT/REJECT) at
the TEXT layer: a text is ACCEPT iff canonical(parse(text)) == text bytes.

All backslashes inside vector texts are built by concatenation with BS, and
astral characters with chr(), to avoid multi-level source-escaping mistakes.

Exit code 0 = no unexpected divergence (known divergences are reported, not
failed). Exit code 2 = a vector violated its expected verdict or the two
implementations disagree.
"""
import json
import pathlib
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parent
PROJECT = ROOT.parent
sys.path.insert(0, str(PROJECT))
from pec_core import _check_json, canonical as py_canonical  # noqa: E402

REF_JS = ROOT / "canonical_ref.cjs"

BS = chr(92)  # one literal backslash
EMOJI = chr(0x1F600)  # U+1F600, to avoid surrogate literals in source
COMBINING = chr(0x0301)  # combining acute accent
PRECOMPOSED = chr(0x00E9)  # e-acute
DEL = chr(0x7F)
U2028 = chr(0x2028)
U2029 = chr(0x2029)

# Each vector: (id, json_text, expect_accept, note)
VECTORS = [
    # --- basic structure -------------------------------------------------
    ("empty-object", "{}", True, "smallest valid object"),
    ("empty-array", "[]", True, "smallest valid array"),
    ("null-root", "null", True, "null is a valid root"),
    ("true-root", "true", True, "boolean root"),
    ("false-root", "false", True, "boolean root"),
    ("string-root", '"x"', True, "string root"),
    # --- integers ---------------------------------------------------------
    ("int-zero", '{"a":0}', True, "zero"),
    ("int-positive", '{"a":42}', True, "positive safe int"),
    ("int-negative", '{"a":-42}', True, "negative safe int"),
    ("int-safe-max", '{"a":9007199254740991}', True, "2^53-1 accepted"),
    ("int-safe-min", '{"a":-9007199254740991}', True, "-(2^53-1) accepted"),
    ("int-unsafe-over", '{"a":9007199254740992}', False, "2^53 rejected"),
    ("int-unsafe-under", '{"a":-9007199254740992}', False, "-2^53 rejected"),
    ("bignum", '{"a":123456789012345678901234567890}', False, "far beyond safe range"),
    # --- floats (all rejected at text layer) ------------------------------
    ("float-decimal", '{"a":1.5}', False, "fractional"),
    ("float-1.0", '{"a":1.0}', False, "decimal point even when integral"),
    ("float-exponent", '{"a":1e3}', False, "exponent form"),
    ("float-small", '{"a":0.1}', False, "small fraction"),
    ("negative-zero-int", '{"a":-0}', False, "-0 is not the canonical form; canonical is 0"),
    ("negative-zero-float", '{"a":-0.0}', False, "float -0.0 rejected"),
    ("nan-literal", '{"a":NaN}', False, "NaN is not JSON"),
    ("infinity-literal", '{"a":Infinity}', False, "Infinity is not JSON"),
    # --- string values ----------------------------------------------------
    ("str-empty", '{"s":""}', True, "empty string"),
    ("str-ascii", '{"s":"hello world"}', True, "plain ASCII"),
    ("str-cjk", '{"s":"匿名"}', True, "CJK kept as raw UTF-8 bytes"),
    ("str-combining", '{"s":"e' + COMBINING + '"}', True, "combining sequence untouched"),
    ("str-precomposed", '{"s":"' + PRECOMPOSED + '"}', True, "precomposed untouched"),
    ("str-emoji-pair", '{"s":"' + EMOJI + '"}', True, "astral character kept raw"),
    ("str-lone-high-esc", '{"s":"' + BS + 'ud800"}', False, "lone high surrogate must be rejected"),
    ("str-lone-low-esc", '{"s":"' + BS + 'udfff"}', False, "lone low surrogate must be rejected"),
    ("str-quote-backslash", '{"s":"a' + BS + '"b' + BS + BS + 'c"}', True, "quote and backslash escaping"),
    ("str-newline", '{"s":"a' + BS + 'nb"}', True, "backslash-n shorthand"),
    ("str-tab", '{"s":"a' + BS + 'tb"}', True, "backslash-t shorthand"),
    ("str-cr", '{"s":"a' + BS + 'rb"}', True, "backslash-r shorthand"),
    ("str-backspace-u-esc", '{"s":"a' + BS + 'u0008b"}', False, "backslash-u0008 is NOT the canonical form; both sides emit backslash-b"),
    ("str-backspace-abbrev", '{"s":"a' + BS + 'bb"}', True, "backslash-b shorthand IS the canonical form (both sides agree)"),
    ("str-formfeed-u-esc", '{"s":"a' + BS + 'u000cb"}', False, "backslash-u000c is NOT the canonical form; both sides emit backslash-f"),
    ("str-formfeed-abbrev", '{"s":"a' + BS + 'fb"}', True, "backslash-f shorthand IS the canonical form (both sides agree)"),
    ("str-nul-esc", '{"s":"a' + BS + 'u0000b"}', True, "NUL as backslash-u0000"),
    ("str-us-esc", '{"s":"a' + BS + 'u001fb"}', True, "US as backslash-u001f"),
    ("str-del-raw", '{"s":"' + DEL + '"}', True, "DEL is printable-range, kept raw"),
    ("str-u2028-raw", '{"s":"' + U2028 + '"}', True, "U+2028 kept raw (ES2019+)"),
    ("str-u2029-raw", '{"s":"' + U2029 + '"}', True, "U+2029 kept raw (ES2019+)"),
    ("str-solidus", '{"s":"a' + BS + '/b"}', False, "escaped solidus is NOT canonical"),
    ("str-solidus-raw", '{"s":"a/b"}', True, "raw solidus is canonical"),
    # --- keys -------------------------------------------------------------
    ("key-order-simple", '{"b":1,"a":2}', False, "unsorted keys are not canonical"),
    ("key-order-many", '{"z":1,"a":2,"m":3,"B":4,"0":5}', False, "multi-key ordering"),
    ("key-sorted-ok", '{"a":1,"b":2,"c":3}', True, "already sorted"),
    ("key-nonascii", '{"键":1}', False, "non-ASCII key rejected"),
    ("key-control-char", '{"a' + BS + 'u0001b":1}', True, "control char in ASCII key accepted; escaped form is canonical"),
    ("key-with-escape", '{"a' + BS + 'nb":1}', True, "escaped newline in ASCII key accepted; shorthand is canonical"),
    ("key-empty", '{"":1}', True, "empty key is legal and canonical"),
    # --- mixed structures --------------------------------------------------
    ("nested-mixed", '{"n":null,"b":true,"i":42,"s":"x","l":["匿名",1,{"k":"v"}],"o":{}}', False, "unsorted top-level"),
    ("nested-sorted", '{"a":{"c":1,"b":2},"d":[1,2,3]}', False, "inner object unsorted"),
    ("deep-nesting", '{"a":{"b":{"c":{"d":[1,2,3]}}}}', True, "single-key chain is sorted"),
    ("array-of-strings", '["匿名","test","' + PRECOMPOSED + '"]', True, "array with non-ASCII values"),
    ("duplicate-key", '{"a":1,"a":2}', False, "duplicate keys rejected at text layer"),
    ("whitespace-padded", '  {"a":1}  ', False, "insignificant whitespace is not canonical"),
    ("whitespace-inside", '{"a" : 1}', False, "inner whitespace not canonical"),
    ("trailing-comma-array", '{"a":[1,2,]}', False, "trailing comma is not JSON"),
    ("trailing-comma-object", '{"a":1,}', False, "trailing comma is not JSON"),
    ("single-quoted", "{'a':1}", False, "single quotes are not JSON"),
    ("invalid-json", '{"a":', False, "truncated"),
    ("comma-only", ",", False, "garbage"),
]

KNOWN_DIVERGENCES = {
    # vector ids where Python and Node are known to disagree today;
    # CANONICAL-SPEC.md adjudicates each and proposes patches.
    "float-1.0", "float-exponent", "negative-zero-float",
    "str-lone-high-esc", "str-lone-low-esc",
}


def py_side(text: str) -> dict:
    raw = text.encode("utf-8")
    try:
        obj = json.loads(text)
        _check_json(obj)
        b = py_canonical(obj)
        return {"ok": True, "hex": b.hex(), "is_canonical": b == raw}
    except ValueError as e:
        return {"ok": False, "err": str(e), "is_canonical": False}
    except Exception as e:  # e.g. UnicodeEncodeError on lone surrogates
        return {"ok": False, "err": f"{type(e).__name__}: {e}", "is_canonical": False}


def node_side(texts: list) -> list:
    payload = json.dumps(texts, ensure_ascii=False).encode("utf-8")
    tmp = ROOT / "_vectors_input.tmp.json"
    tmp.write_bytes(payload)
    try:
        r = subprocess.run(["node", str(REF_JS), str(tmp)], capture_output=True, check=True)
    finally:
        tmp.unlink(missing_ok=True)
    return json.loads(r.stdout)


def main() -> int:
    ids = [v[0] for v in VECTORS]
    texts = [v[1] for v in VECTORS]
    py = [py_side(t) for t in texts]
    node = node_side(texts)

    rows = []
    failures = 0
    for (vid, text, expect, note), p, n in zip(VECTORS, py, node):
        p_accept = p["is_canonical"]
        n_accept = n["is_canonical"]
        if p["ok"] and n["ok"] and p["hex"] == n["hex"]:
            impl_agree = "AGREE-BYTES"
        elif not p["ok"] and not n["ok"]:
            impl_agree = "AGREE-REJECT"
        elif p["ok"] != n["ok"]:
            impl_agree = "DIVERGE-TYPE"
        else:
            impl_agree = "DIVERGE-BYTES"
        exp_ok = (p_accept == expect) and (n_accept == expect)
        if not exp_ok or (impl_agree.startswith("DIVERGE") and vid not in KNOWN_DIVERGENCES):
            failures += 1
        rows.append({
            "id": vid, "expect_accept": expect, "note": note,
            "py": {"accept": p_accept, "err": p.get("err"), "hex": p.get("hex")},
            "node": {"accept": n_accept, "err": n.get("err"), "hex": n.get("hex")},
            "verdict": impl_agree,
            "expectation_ok": exp_ok,
            "known_divergence": vid in KNOWN_DIVERGENCES,
        })

    report = {
        "implementations": {
            "python": "pec_core.canonical (v2, ensure_ascii=False after fix b882149)",
            "node": "canonical_ref.cjs (semantics of v1 verify-standalone.cjs)",
        },
        "vectors": rows,
        "summary": {
            "total": len(rows),
            "agree_bytes": sum(r["verdict"] == "AGREE-BYTES" for r in rows),
            "agree_reject": sum(r["verdict"] == "AGREE-REJECT" for r in rows),
            "diverge_type": sum(r["verdict"] == "DIVERGE-TYPE" for r in rows),
            "diverge_bytes": sum(r["verdict"] == "DIVERGE-BYTES" for r in rows),
            "unexpected_failures": failures,
        },
    }
    (ROOT / "canonical_diff_report.json").write_text(
        json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    (ROOT / "canonical_diff_vectors.json").write_text(
        json.dumps([{"id": v[0], "text": v[1], "expect_accept": v[2], "note": v[3]} for v in VECTORS],
                   ensure_ascii=False, indent=2), encoding="utf-8")

    s = report["summary"]
    print(f"total={s['total']} agree_bytes={s['agree_bytes']} agree_reject={s['agree_reject']} "
          f"diverge_type={s['diverge_type']} diverge_bytes={s['diverge_bytes']} "
          f"unexpected_failures={failures}")
    for r in rows:
        if r["verdict"] != "AGREE-BYTES":
            print(f"  {r['id']:28s} {r['verdict']:14s} expect_ok={r['expectation_ok']!s:5s} known={r['known_divergence']!s:5s}")
    return 2 if failures else 0


if __name__ == "__main__":
    sys.exit(main())