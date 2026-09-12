#!/usr/bin/env python3
"""ACSD CLI — anonymous scholarly claim and disclosure tool.

Stage 3: init / verify / inspect. Signing (approve/finalize) arrives in stage 4,
RFC 3161 in stage 5. This file reuses pec_core for canonicalization and
binding checks and never invents cryptography of its own.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import sys
import uuid

ROOT = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

from pec_core import adapt_v1_release, canonical, digest, require  # noqa: E402

TEAM_SCHEMA = "acsd-team/v1"
RELEASE_SCHEMA = "acsd-v1.6.0-paper-release/v1"
GOVERNANCE_SCHEMA = "acsd-v1.6.0-authorship-governance/v1"
NON_CLAIMS = [
    "natural_person_authorship",
    "contribution_truth",
    "originality_truth",
    "legal_nonrepudiation",
    "peer_review",
]

EXIT_OK = 0
EXIT_VERIFY_FAIL = 1
EXIT_USAGE = 2
EXIT_STATE_CONFLICT = 3
EXIT_EXTERNAL = 4
EXIT_INCOMPLETE = 5


def read_canonical(path: pathlib.Path):
    """Read a JSON file and require it to be byte-exact canonical.

    A single trailing newline (POSIX file convention) is tolerated; canonical
    JSON itself has no insignificant whitespace, so any other difference fails.
    """
    raw = path.read_bytes()
    if raw.endswith(b"\n"):
        raw = raw[:-1]
    try:
        obj = json.loads(raw)
    except ValueError as e:
        raise ValueError(f"NONCANONICAL:{path.name}") from e
    if canonical(obj) != raw:
        raise ValueError(f"NONCANONICAL:{path.name}")
    return obj


def load_team(path):
    team = json.loads(pathlib.Path(path).read_text(encoding="utf-8"))
    require(team.get("schema") == TEAM_SCHEMA, "TEAM_INVALID")
    authors = team.get("authors") or []
    require(len(authors) >= 1, "TEAM_INVALID")
    key_ids = [a.get("key_id") for a in authors]
    require(all(isinstance(k, str) and k for k in key_ids), "TEAM_INVALID")
    require(len(set(key_ids)) == len(key_ids), "TEAM_DUPLICATE_KEY")
    return team


def build_release(work_id, content_sha256, content_path, team):
    authors = []
    for i, a in enumerate(team["authors"], 1):
        authors.append({
            "slot": i,
            "key_id": a["key_id"],
            "role": a.get("role", "co-first"),
            "corresponding": bool(a.get("corresponding")),
            "contributions": a.get("contributions", []),
            "issuer": a.get("issuer", f"urn:acsd:pseudonym:{a['key_id']}"),
            "kid_hex": hashlib.sha256(a["key_id"].encode()).hexdigest()[:16],
            "public_key_path": a.get("public_key_path", f"public-keys/{a['key_id']}.pem"),
        })
    return {
        "schema": RELEASE_SCHEMA,
        "work_id": work_id,
        "slot": {"line": "main", "version": 1, "work_id": work_id},
        "content": {"path": content_path, "sha256": content_sha256},
        "authors": authors,
        "citation_witnesses": [],
        "reference_work_ids": [],
        "ai_use": {"used": False, "purposes": [], "tools": [], "human_review_key_ids": []},
        "parent_release_id": None,
        "issued_at": 0,
        "standalone_semantics": (
            "Every listed author key endorses this exact release payload; "
            "series membership is optional."
        ),
    }


def build_governance(work_id, content_sha256, team):
    byline = [
        {"key_id": a["key_id"], "slot": i, "role": a.get("role", "co-first")}
        for i, a in enumerate(team["authors"], 1)
    ]
    corresponding = next(
        (a["key_id"] for a in team["authors"] if a.get("corresponding")),
        team["authors"][0]["key_id"],
    )
    return {
        "schema": GOVERNANCE_SCHEMA,
        "work_id": work_id,
        "manuscript_sha256": content_sha256,
        "byline": byline,
        "corresponding_author": {"key_id": corresponding},
        "ai_use_declaration": {"used": False},
    }


def build_pec(work_id, adapted, gov_digest, content_sha256, ai_digest, key_ids):
    return {
        "schema": "acsd-pec/v0.1",
        "pec_id": "pec-" + uuid.uuid4().hex[:8],
        "subject": {
            "work_id": work_id,
            "release_digest": adapted["digest"],
            "version": "v1",
            "line": "main",
            "predecessor_pec_digest": None,
            "series_package_digest": None,
        },
        "governance": {
            "statement_digest": gov_digest,
            "manuscript_sha256": content_sha256,
            "required_pec_approval_key_ids": sorted(key_ids),
            "ai_use_declaration_digest": ai_digest,
        },
        "events": [],
        "claim_policy": {
            "permitted_outcomes": ["KEY_ASSENT", "GOVERNANCE_ASSENT"],
            "global_non_claims": list(NON_CLAIMS),
        },
        "issuer_key_id": key_ids[0],
    }


def check_bindings(pec, adapted, gov_digest, content_sha256):
    """Structural bindings only (no signature check — that is stage 4)."""
    require(pec.get("schema") == "acsd-pec/v0.1", "PEC_SCHEMA")
    subject, gov = pec["subject"], pec["governance"]
    require(subject["release_digest"] == adapted["digest"], "SUBJECT_RELEASE_MISMATCH")
    require(gov["statement_digest"] == gov_digest, "GOVERNANCE_BINDING_MISMATCH")
    require(gov["manuscript_sha256"] == content_sha256, "GOVERNANCE_BINDING_MISMATCH")
    require(
        gov["required_pec_approval_key_ids"] == sorted(adapted["author_key_ids"]),
        "GOVERNANCE_BINDING_MISMATCH",
    )
    require(pec.get("issuer_key_id") in adapted["author_key_ids"], "PEC_ISSUER_UNAUTHORIZED")


def cmd_init(args):
    content = pathlib.Path(args.content)
    if not content.is_file():
        return EXIT_USAGE, "CONTENT_MISSING", {}
    try:
        team = load_team(args.team)
    except ValueError as e:
        return EXIT_USAGE, str(e), {}
    content_bytes = content.read_bytes()
    if len(content_bytes) == 0:
        return EXIT_USAGE, "CONTENT_EMPTY", {}
    content_sha256 = hashlib.sha256(content_bytes).hexdigest()
    key_ids = [a["key_id"] for a in team["authors"]]
    work_id = "urn:uuid:" + str(uuid.uuid4())
    content_rel = f"paper/{content_sha256}"
    out = pathlib.Path(args.out)
    if out.exists() and any(out.iterdir()):
        return EXIT_STATE_CONFLICT, "OUTPUT_EXISTS", {}

    release = build_release(work_id, content_sha256, content_rel, team)
    adapted = adapt_v1_release(release)
    governance = build_governance(work_id, content_sha256, team)
    gov_digest = digest(governance)
    ai_digest = digest(governance["ai_use_declaration"])
    pec = build_pec(work_id, adapted, gov_digest, content_sha256, ai_digest, key_ids)
    check_bindings(pec, adapted, gov_digest, content_sha256)

    out.mkdir(parents=True, exist_ok=True)
    for d in ("paper", "release", "governance", "pec"):
        (out / d).mkdir(exist_ok=True)
    (out / content_rel).write_bytes(content_bytes)
    (out / "release/release.json").write_bytes(canonical(release) + b"\n")
    (out / "governance/statement.json").write_bytes(canonical(governance) + b"\n")
    (out / "pec/pec.json").write_bytes(canonical(pec) + b"\n")
    (out / "team.json").write_bytes(canonical(team) + b"\n")
    state = {
        "schema": "acsd-state/v1",
        "state": "awaiting-approvals",
        "work_id": work_id,
        "release_digest": adapted["digest"],
        "required_approvals": key_ids,
        "received_approvals": [],
    }
    (out / "state.json").write_bytes(canonical(state) + b"\n")
    return EXIT_OK, "initialized", {
        "work_id": work_id,
        "release_digest": adapted["digest"],
        "state": "awaiting-approvals",
    }


def verify_release_dir(root: pathlib.Path):
    state = read_canonical(root / "state.json")
    release = read_canonical(root / "release/release.json")
    governance = read_canonical(root / "governance/statement.json")
    pec = read_canonical(root / "pec/pec.json")
    adapted = adapt_v1_release(release)
    content_bytes = (root / release["content"]["path"]).read_bytes()
    if hashlib.sha256(content_bytes).hexdigest() != release["content"]["sha256"]:
        return EXIT_VERIFY_FAIL, "TAMPERED", {"error_code": "CONTENT_DIGEST_MISMATCH"}
    gov_digest = digest(governance)
    try:
        check_bindings(pec, adapted, gov_digest, release["content"]["sha256"])
    except ValueError as e:
        return EXIT_VERIFY_FAIL, "TAMPERED", {"error_code": str(e)}
    key_ids = sorted(adapted["author_key_ids"])
    received = state.get("received_approvals", [])
    missing = [k for k in key_ids if k not in received]
    data = {
        "work_id": adapted["work_id"],
        "release_digest": adapted["digest"],
        "pec_digest": digest(pec),
        "state": state.get("state"),
        "missing_approvals": missing,
        "granted_outcomes": pec["claim_policy"]["permitted_outcomes"],
        "non_claims": pec["claim_policy"]["global_non_claims"],
    }
    if missing:
        return EXIT_INCOMPLETE, "INCOMPLETE", data
    return EXIT_OK, "VALID", data


def cmd_verify(args):
    root = pathlib.Path(args.release_dir)
    try:
        return verify_release_dir(root)
    except FileNotFoundError as e:
        return EXIT_USAGE, f"MISSING:{e.filename}", {}


def cmd_inspect(args):
    root = pathlib.Path(args.release_dir)
    state = read_canonical(root / "state.json")
    release = read_canonical(root / "release/release.json")
    adapted = adapt_v1_release(release)
    received = state.get("received_approvals", [])
    missing = [k for k in sorted(adapted["author_key_ids"]) if k not in received]
    return EXIT_OK, "inspected", {
        "state": state.get("state"),
        "work_id": adapted["work_id"],
        "release_digest": adapted["digest"],
        "required_approvals": state.get("required_approvals"),
        "received_approvals": received,
        "missing_approvals": missing,
    }


def emit_json(command, code, message, data):
    print(json.dumps({
        "command": command,
        "status": "ok" if code == EXIT_OK else "error",
        "exit_code": code,
        "message": message,
        "data": data,
    }, ensure_ascii=False))


def emit_human(command, code, message, data):
    print(f"{command}: {message} (exit {code})")
    for k, v in data.items():
        print(f"  {k}: {v}")


def main(argv=None):
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--json", action="store_true", help="machine-readable output")

    p = argparse.ArgumentParser(prog="acsd", description="ACSD provenance evidence capsule CLI")
    sub = p.add_subparsers(dest="command", required=True)

    pi = sub.add_parser("init", parents=[common], help="create a release directory from a manuscript and team file")
    pi.add_argument("content", help="manuscript file (PDF or text)")
    pi.add_argument("--team", required=True, help="team.json")
    pi.add_argument("--out", default="release-dir", help="output directory")
    pi.set_defaults(func=cmd_init)

    pv = sub.add_parser("verify", parents=[common], help="verify a release directory offline")
    pv.add_argument("release_dir")
    pv.set_defaults(func=cmd_verify)

    pn = sub.add_parser("inspect", parents=[common], help="show state and missing approvals")
    pn.add_argument("release_dir")
    pn.set_defaults(func=cmd_inspect)

    args = p.parse_args(argv)
    try:
        code, message, data = args.func(args)
    except ValueError as e:
        code, message, data = EXIT_VERIFY_FAIL, str(e), {}
    except FileNotFoundError as e:
        code, message, data = EXIT_USAGE, f"MISSING:{e.filename}", {}

    if args.json:
        emit_json(args.command, code, message, data)
    else:
        emit_human(args.command, code, message, data)
    return code


if __name__ == "__main__":
    sys.exit(main())
