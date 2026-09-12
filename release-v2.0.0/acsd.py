#!/usr/bin/env python3
"""ACSD CLI — anonymous scholarly claim and disclosure tool.

Commands: keygen / init / approve / finalize / verify / inspect.

Signing uses Ed25519 via `cryptography` and a minimal COSE Sign1 encoding
(cose.py). The canonical/digest/binding core (pec_core) stays dependency-free.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import secrets
import shutil
import sys
import urllib.request
import uuid

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

ROOT = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

import cose  # noqa: E402
import tsa  # noqa: E402
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


# --- key helpers -----------------------------------------------------------


def key_id_of(pub: Ed25519PublicKey) -> str:
    der = pub.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return hashlib.sha256(der).hexdigest()


def load_private_key(path) -> Ed25519PrivateKey:
    data = pathlib.Path(path).read_bytes()
    return serialization.load_pem_private_key(data, password=None)


def load_public_key_bytes(data: bytes) -> Ed25519PublicKey:
    return serialization.load_pem_public_key(data)


def public_pem(pub: Ed25519PublicKey) -> bytes:
    return pub.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


# --- canonical read --------------------------------------------------------


def read_canonical(path: pathlib.Path):
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


def write_canonical(path: pathlib.Path, obj):
    path.write_bytes(canonical(obj) + b"\n")


# --- object builders -------------------------------------------------------


def load_team(path):
    team = json.loads(pathlib.Path(path).read_text(encoding="utf-8"))
    require(team.get("schema") == TEAM_SCHEMA, "TEAM_INVALID")
    authors = team.get("authors") or []
    require(len(authors) >= 1, "TEAM_INVALID")
    for a in authors:
        pub_pem = a.get("public_key")
        require(isinstance(pub_pem, str) and "PUBLIC KEY" in pub_pem, "TEAM_INVALID")
        kid = key_id_of(load_public_key_bytes(pub_pem.encode()))
        if "key_id" in a:
            require(a["key_id"] == kid, "TEAM_KEY_ID_MISMATCH")
        a["key_id"] = kid
    key_ids = [a["key_id"] for a in authors]
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
            "issuer": a.get("issuer", f"urn:acsd:pseudonym:{a['key_id'][:12]}"),
            "kid_hex": a["key_id"][:16],
            "public_key_path": f"public-keys/{a['key_id']}.pub",
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


def manifest_entries(root: pathlib.Path) -> str:
    entries = []
    for p in sorted(root.rglob("*")):
        if p.is_file() and p.name != "MANIFEST.sha256":
            rel = p.relative_to(root).as_posix()
            entries.append(f"{hashlib.sha256(p.read_bytes()).hexdigest()}  {rel}")
    return "\n".join(entries) + "\n"


def _send_tsq(tsq: bytes, url: str) -> bytes:
    req = urllib.request.Request(url, data=tsq, headers={"Content-Type": "application/timestamp-query"})
    with urllib.request.urlopen(req, timeout=30) as resp:
        return resp.read()


# --- commands --------------------------------------------------------------


def cmd_keygen(args):
    out_dir = pathlib.Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    name = args.name or "author"
    key_path = out_dir / f"{name}.key"
    if key_path.exists():
        return EXIT_STATE_CONFLICT, "KEY_EXISTS", {"path": str(key_path)}
    key = Ed25519PrivateKey.generate()
    pub = key.public_key()
    kid = key_id_of(pub)
    private_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    key_path.write_bytes(private_pem)
    (out_dir / f"{name}.pub").write_bytes(public_pem(pub))
    try:
        key_path.chmod(0o600)
    except OSError:
        pass
    return EXIT_OK, "key generated", {
        "name": name,
        "key_id": kid,
        "private_key": str(key_path),
        "public_key": (out_dir / f"{name}.pub").read_text(),
    }


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
    for d in ("paper", "release", "governance", "pec", "public-keys", "endorsements"):
        (out / d).mkdir(exist_ok=True)
    (out / content_rel).write_bytes(content_bytes)
    for a in team["authors"]:
        (out / f"public-keys/{a['key_id']}.pub").write_bytes(a["public_key"].encode())
    write_canonical(out / "release/release.json", release)
    write_canonical(out / "governance/statement.json", governance)
    write_canonical(out / "pec/pec.json", pec)
    write_canonical(out / "team.json", team)
    write_canonical(out / "state.json", {
        "schema": "acsd-state/v1",
        "state": "awaiting-approvals",
        "work_id": work_id,
        "release_digest": adapted["digest"],
        "required_approvals": key_ids,
        "received_approvals": [],
    })
    return EXIT_OK, "initialized", {
        "work_id": work_id,
        "release_digest": adapted["digest"],
        "state": "awaiting-approvals",
    }


def cmd_approve(args):
    root = pathlib.Path(args.release_dir)
    key = load_private_key(args.key)
    kid = key_id_of(key.public_key())
    release = read_canonical(root / "release/release.json")
    adapted = adapt_v1_release(release)
    if kid not in adapted["author_key_ids"]:
        return EXIT_VERIFY_FAIL, "UNKNOWN_AUTHOR_KEY", {"key_id": kid}
    state = read_canonical(root / "state.json")
    if state.get("state") != "awaiting-approvals":
        return EXIT_STATE_CONFLICT, "STATE_CONFLICT", {"state": state.get("state")}
    received = set(state.get("received_approvals", []))
    if kid in received:
        return EXIT_STATE_CONFLICT, "DUPLICATE_APPROVAL", {"key_id": kid}
    endorsement = cose.cose_sign1(canonical(release), key)
    (root / f"endorsements/{kid}.cose").write_bytes(endorsement)
    received.add(kid)
    state["received_approvals"] = sorted(received)
    write_canonical(root / "state.json", state)
    return EXIT_OK, "approved", {"key_id": kid, "remaining": sorted(set(adapted["author_key_ids"]) - received)}


def cmd_finalize(args):
    root = pathlib.Path(args.release_dir)
    state = read_canonical(root / "state.json")
    release = read_canonical(root / "release/release.json")
    governance = read_canonical(root / "governance/statement.json")
    pec = read_canonical(root / "pec/pec.json")
    adapted = adapt_v1_release(release)
    required = sorted(adapted["author_key_ids"])
    received = sorted(state.get("received_approvals", []))
    missing = [k for k in required if k not in received]
    if missing:
        return EXIT_INCOMPLETE, "APPROVALS_INCOMPLETE", {"missing_keys": missing}
    # verify every endorsement signature against the release bytes
    release_bytes = canonical(release)
    for kid in required:
        pub = load_public_key_bytes((root / f"public-keys/{kid}.pub").read_bytes())
        endo = (root / f"endorsements/{kid}.cose").read_bytes()
        try:
            cose.cose_verify(endo, pub, expected_payload=release_bytes)
        except Exception as e:
            return EXIT_VERIFY_FAIL, "ENDORSEMENT_INVALID", {"key_id": kid, "error": str(e)}

    # atomic finalize: stage a complete package, then swap it in
    staging = root.with_name(root.name + ".staging")
    if staging.exists():
        shutil.rmtree(staging)
    shutil.copytree(root, staging)

    # optional RFC 3161 timestamp over the exact PEC digest
    timestamped = False
    tsa_url = getattr(args, "tsa", None)
    if tsa_url:
        pec_digest_bytes = bytes.fromhex(digest(pec))
        nonce = secrets.token_bytes(16)
        tsq = tsa.build_tsq(pec_digest_bytes, nonce)
        try:
            if tsa_url == "local":
                local_tsa = tsa.LocalTSA()
                tsr = local_tsa.respond(tsq)
                tsa_cert_der = local_tsa.cert.public_bytes(serialization.Encoding.DER)
                tsa_cert_fp = local_tsa.cert.fingerprint(hashes.SHA256()).hex()
            else:
                tsr = _send_tsq(tsq, tsa_url)
                cert_der = tsa._parse_cms(tsr)["cert_der"]
                if cert_der is None:
                    cert_path = getattr(args, "tsa_cert", None)
                    if not cert_path:
                        shutil.rmtree(staging)
                        return EXIT_EXTERNAL, "TSA_CERT_REQUIRED", {}
                    cert_pem = pathlib.Path(cert_path).read_bytes()
                    cert_der = x509.load_pem_x509_certificate(cert_pem).public_bytes(serialization.Encoding.DER)
                tsa_cert_der = cert_der
                tsa_cert_fp = x509.load_der_x509_certificate(cert_der).fingerprint(hashes.SHA256()).hex()
        except Exception as e:
            if not getattr(args, "allow_untimestamped", False):
                shutil.rmtree(staging)
                return EXIT_EXTERNAL, "TSA_FAILED", {"error": str(e)}
            timestamped = False
        else:
            (staging / "receipts").mkdir(exist_ok=True)
            (staging / "receipts/request.tsq").write_bytes(tsq)
            (staging / "receipts/response.tsr").write_bytes(tsr)
            (staging / "receipts/tsa-cert.der").write_bytes(tsa_cert_der)
            write_canonical(staging / "receipts/report.json", {
                "schema": "acsd-receipt-report/v1",
                "pec_digest": digest(pec),
                "nonce": nonce.hex(),
                "tsa_url": tsa_url,
                "tsa_cert_fingerprint": tsa_cert_fp,
            })
            timestamped = True

    (staging / "MANIFEST.sha256").write_text(manifest_entries(staging), encoding="ascii")
    final_state = dict(state)
    final_state["state"] = "finalized" if timestamped else "finalized-untimestamped"
    write_canonical(staging / "state.json", final_state)
    # re-write manifest now that state.json changed
    (staging / "MANIFEST.sha256").write_text(manifest_entries(staging), encoding="ascii")

    backup = root.with_name(root.name + ".old")
    if backup.exists():
        shutil.rmtree(backup)
    root.rename(backup)
    staging.rename(root)
    shutil.rmtree(backup)
    return EXIT_OK, "finalized", {
        "state": final_state["state"],
        "release_digest": adapted["digest"],
        "pec_digest": digest(pec),
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
    release_bytes = canonical(release)
    valid = {}
    for kid in key_ids:
        endo_path = root / f"endorsements/{kid}.cose"
        if not endo_path.exists():
            continue
        pub = load_public_key_bytes((root / f"public-keys/{kid}.pub").read_bytes())
        try:
            cose.cose_verify(endo_path.read_bytes(), pub, expected_payload=release_bytes)
            valid[kid] = True
        except Exception:
            valid[kid] = False
    missing = [k for k in key_ids if not valid.get(k)]
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
    # optional timestamp verification (imprint binding + genTime)
    tsr_path = root / "receipts/response.tsr"
    if tsr_path.exists():
        pec_digest_bytes = bytes.fromhex(digest(pec))
        report = read_canonical(root / "receipts/report.json")
        fp = report.get("tsa_cert_fingerprint")
        tsa_cert_der = (root / "receipts/tsa-cert.der").read_bytes()
        try:
            info = tsa.verify_tsr(tsr_path.read_bytes(), pec_digest_bytes,
                                  trusted_cert_der=tsa_cert_der, trusted_fingerprint=fp)
        except ValueError as e:
            return EXIT_VERIFY_FAIL, "TAMPERED", {"error_code": str(e)}
        data["externally_not_after"] = str(info["genTime"])
        data["granted_outcomes"] = list(data["granted_outcomes"]) + ["EXTERNALLY_NOT_AFTER"]
    # manifest verification for finalized states
    if state.get("state") in ("finalized", "finalized-untimestamped"):
        expected = manifest_entries(root)
        actual = (root / "MANIFEST.sha256").read_text(encoding="ascii")
        if expected != actual:
            return EXIT_VERIFY_FAIL, "TAMPERED", {"error_code": "MANIFEST_MISMATCH"}
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


# --- output -----------------------------------------------------------------


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

    pk = sub.add_parser("keygen", parents=[common], help="generate an Ed25519 keypair")
    pk.add_argument("--name", help="key base name (default author)")
    pk.add_argument("--out-dir", default="keys", help="output directory")
    pk.set_defaults(func=cmd_keygen)

    pi = sub.add_parser("init", parents=[common], help="create a release directory")
    pi.add_argument("content", help="manuscript file (PDF or text)")
    pi.add_argument("--team", required=True, help="team.json")
    pi.add_argument("--out", default="release-dir", help="output directory")
    pi.set_defaults(func=cmd_init)

    pa = sub.add_parser("approve", parents=[common], help="endorse a release with a private key")
    pa.add_argument("release_dir")
    pa.add_argument("--key", required=True, help="author private key PEM")
    pa.set_defaults(func=cmd_approve)

    pf = sub.add_parser("finalize", parents=[common], help="assemble the final package")
    pf.add_argument("release_dir")
    pf.add_argument("--tsa", help="RFC 3161 TSA URL, or 'local' for the built-in test TSA")
    pf.add_argument("--tsa-cert", help="TSA signer certificate (PEM), required when the TSA response has no embedded certificate")
    pf.add_argument("--allow-untimestamped", action="store_true", help="finalize without a timestamp if the TSA fails")
    pf.set_defaults(func=cmd_finalize)

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
