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
import tempfile
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
APPROVAL_TARGET_SCHEMA = "acsd-approval-target/v1"
NON_CLAIMS = [
    "natural_person_authorship",
    "contribution_truth",
    "originality_truth",
    "legal_nonrepudiation",
    "peer_review",
]
ALLOWED_OUTCOMES = {
    "KEY_ASSENT",
    "GOVERNANCE_ASSENT",
    "COMMITTED_EVIDENCE_MATCH",
    "EXTERNALLY_NOT_AFTER",
}

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
    key_path = pathlib.Path(path)
    if not key_path.is_file():
        raise ValueError("PRIVATE_KEY_NOT_FILE")
    try:
        data = key_path.read_bytes()
    except OSError as exc:
        raise ValueError("PRIVATE_KEY_UNREADABLE") from exc
    return serialization.load_pem_private_key(data, password=None)


def load_public_key_bytes(data: bytes) -> Ed25519PublicKey:
    return serialization.load_pem_public_key(data)


def public_pem(pub: Ed25519PublicKey) -> bytes:
    return pub.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def load_certificate_der(path) -> bytes:
    raw = pathlib.Path(path).read_bytes()
    try:
        cert = x509.load_pem_x509_certificate(raw)
    except ValueError:
        cert = x509.load_der_x509_certificate(raw)
    return cert.public_bytes(serialization.Encoding.DER)


def load_bound_public_key(root: pathlib.Path, kid: str) -> Ed25519PublicKey:
    """Load the public key stored under *kid* and verify the name binding."""
    pub = load_public_key_bytes((root / f"public-keys/{kid}.pub").read_bytes())
    require(key_id_of(pub) == kid, "PUBLIC_KEY_ID_MISMATCH")
    return pub


def path_is_within(path, directory) -> bool:
    try:
        pathlib.Path(path).resolve().relative_to(pathlib.Path(directory).resolve())
        return True
    except ValueError:
        return False


def check_release_key_paths(release):
    for author in release.get("authors", []):
        kid = author.get("key_id")
        require(
            author.get("public_key_path") == f"public-keys/{kid}.pub",
            "PUBLIC_KEY_PATH_MISMATCH",
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
            "permitted_outcomes": ["KEY_ASSENT", "GOVERNANCE_ASSENT", "EXTERNALLY_NOT_AFTER"],
            "global_non_claims": list(NON_CLAIMS),
            "required_capabilities": {
                "EXTERNALLY_NOT_AFTER": ["rfc3161-exact-approval-target-imprint"],
            },
        },
        "issuer_key_id": key_ids[0],
    }


def build_approval_target(release, governance, pec):
    """Build the acyclic object jointly signed by every author key."""
    return {
        "schema": APPROVAL_TARGET_SCHEMA,
        "work_id": release["work_id"],
        "release_digest": digest(release),
        "governance_digest": digest(governance),
        "pec_digest": digest(pec),
        "required_key_ids": sorted(a["key_id"] for a in release["authors"]),
    }


def check_approval_target(target, release, governance, pec, adapted):
    require(target.get("schema") == APPROVAL_TARGET_SCHEMA, "APPROVAL_TARGET_SCHEMA")
    require(target.get("work_id") == adapted["work_id"], "APPROVAL_TARGET_BINDING_MISMATCH")
    require(target.get("release_digest") == adapted["digest"], "APPROVAL_TARGET_BINDING_MISMATCH")
    require(target.get("governance_digest") == digest(governance), "APPROVAL_TARGET_BINDING_MISMATCH")
    require(target.get("pec_digest") == digest(pec), "APPROVAL_TARGET_BINDING_MISMATCH")
    require(
        target.get("required_key_ids") == sorted(adapted["author_key_ids"]),
        "APPROVAL_TARGET_BINDING_MISMATCH",
    )


def check_bindings(pec, adapted, governance):
    require(pec.get("schema") == "acsd-pec/v0.1", "PEC_SCHEMA")
    subject, gov = pec["subject"], pec["governance"]
    require(subject["release_digest"] == adapted["digest"], "SUBJECT_RELEASE_MISMATCH")
    require(subject["work_id"] == adapted["work_id"], "SUBJECT_WORK_ID_MISMATCH")
    require(gov["statement_digest"] == digest(governance), "GOVERNANCE_BINDING_MISMATCH")
    require(gov["manuscript_sha256"] == adapted["content_sha256"], "GOVERNANCE_BINDING_MISMATCH")
    require(gov["ai_use_declaration_digest"] == digest(governance["ai_use_declaration"]), "AI_USE_BINDING_MISMATCH")
    require(
        gov["required_pec_approval_key_ids"] == sorted(adapted["author_key_ids"]),
        "GOVERNANCE_BINDING_MISMATCH",
    )
    require(pec.get("issuer_key_id") in adapted["author_key_ids"], "PEC_ISSUER_UNAUTHORIZED")
    require(
        len(adapted["author_key_ids"]) == len(set(adapted["author_key_ids"])),
        "RELEASE_DUPLICATE_AUTHOR_KEY",
    )
    events = pec.get("events", [])
    previous = None
    event_ids = set()
    for i, event in enumerate(events):
        require(event["sequence"] == i, "EVENT_CHAIN_BROKEN")
        require(event["event_id"] not in event_ids, "EVENT_CHAIN_BROKEN")
        event_ids.add(event["event_id"])
        require(event["previous_event_digest"] == previous, "EVENT_CHAIN_BROKEN")
        previous = digest(event)
    policy = pec["claim_policy"]
    required = {"natural_person_authorship", "contribution_truth", "originality_truth", "legal_nonrepudiation", "peer_review"}
    require(required.issubset(set(policy["global_non_claims"])), "CLAIM_POLICY_INCOMPLETE")
    outcomes = policy.get("permitted_outcomes", [])
    require(len(outcomes) == len(set(outcomes)), "CLAIM_POLICY_DUPLICATE")
    require(set(outcomes).issubset(ALLOWED_OUTCOMES), "CLAIM_POLICY_UNKNOWN_OUTCOME")
    required_caps = policy.get("required_capabilities", {})
    require(
        required_caps.get("EXTERNALLY_NOT_AFTER") == ["rfc3161-exact-approval-target-imprint"],
        "CLAIM_POLICY_CAPABILITY_MISMATCH",
    )


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
    check_bindings(pec, adapted, governance)
    target = build_approval_target(release, governance, pec)
    check_approval_target(target, release, governance, pec, adapted)

    out.mkdir(parents=True, exist_ok=True)
    for d in ("paper", "release", "governance", "pec", "approval", "public-keys", "approvals"):
        (out / d).mkdir(exist_ok=True)
    (out / content_rel).write_bytes(content_bytes)
    for a in team["authors"]:
        (out / f"public-keys/{a['key_id']}.pub").write_bytes(a["public_key"].encode())
    write_canonical(out / "release/release.json", release)
    write_canonical(out / "governance/statement.json", governance)
    write_canonical(out / "pec/pec.json", pec)
    write_canonical(out / "approval/target.json", target)
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
    if path_is_within(args.key, root):
        return EXIT_USAGE, "PRIVATE_KEY_INSIDE_RELEASE", {}
    try:
        key = load_private_key(args.key)
    except (TypeError, ValueError) as e:
        return EXIT_USAGE, "PRIVATE_KEY_INVALID", {"error": str(e)}
    kid = key_id_of(key.public_key())
    release = read_canonical(root / "release/release.json")
    governance = read_canonical(root / "governance/statement.json")
    pec = read_canonical(root / "pec/pec.json")
    target = read_canonical(root / "approval/target.json")
    adapted = adapt_v1_release(release)
    check_release_key_paths(release)
    check_bindings(pec, adapted, governance)
    check_approval_target(target, release, governance, pec, adapted)
    if kid not in adapted["author_key_ids"]:
        return EXIT_VERIFY_FAIL, "UNKNOWN_AUTHOR_KEY", {"key_id": kid}
    state = read_canonical(root / "state.json")
    if state.get("state") != "awaiting-approvals":
        return EXIT_STATE_CONFLICT, "STATE_CONFLICT", {"state": state.get("state")}
    approval_path = root / f"approvals/{kid}.cose"
    if approval_path.exists():
        return EXIT_STATE_CONFLICT, "DUPLICATE_APPROVAL", {"key_id": kid}
    approval = cose.cose_sign1(canonical(target), key)
    approval_path.write_bytes(approval)
    received = {
        required_kid for required_kid in adapted["author_key_ids"]
        if (root / f"approvals/{required_kid}.cose").is_file()
    }
    state["received_approvals"] = sorted(received)
    write_canonical(root / "state.json", state)
    return EXIT_OK, "approved", {"key_id": kid, "remaining": sorted(set(adapted["author_key_ids"]) - received)}


def cmd_finalize(args):
    root = pathlib.Path(args.release_dir)
    state = read_canonical(root / "state.json")
    if state.get("state") != "awaiting-approvals":
        return EXIT_STATE_CONFLICT, "STATE_CONFLICT", {"state": state.get("state")}
    release = read_canonical(root / "release/release.json")
    governance = read_canonical(root / "governance/statement.json")
    pec = read_canonical(root / "pec/pec.json")
    target = read_canonical(root / "approval/target.json")
    adapted = adapt_v1_release(release)
    check_release_key_paths(release)
    check_bindings(pec, adapted, governance)
    check_approval_target(target, release, governance, pec, adapted)
    required = sorted(adapted["author_key_ids"])
    target_bytes = canonical(target)
    missing = []
    for kid in required:
        approval_path = root / f"approvals/{kid}.cose"
        try:
            pub = load_bound_public_key(root, kid)
        except Exception as e:
            return EXIT_VERIFY_FAIL, "APPROVAL_INVALID", {"key_id": kid, "error": str(e)}
        if not approval_path.is_file():
            missing.append(kid)
            continue
        try:
            cose.cose_verify(approval_path.read_bytes(), pub, expected_payload=target_bytes)
        except Exception as e:
            return EXIT_VERIFY_FAIL, "APPROVAL_INVALID", {"key_id": kid, "error": str(e)}
    if missing:
        return EXIT_INCOMPLETE, "APPROVALS_INCOMPLETE", {"missing_keys": missing}

    # atomic finalize: stage a complete package, then swap it in
    staging = root.with_name(root.name + ".staging")
    if staging.exists():
        shutil.rmtree(staging)
    shutil.copytree(root, staging)

    # optional RFC 3161 timestamp over the exact author-approved target digest
    timestamped = False
    tsa_url = getattr(args, "tsa", None)
    if tsa_url:
        target_digest = digest(target)
        target_digest_bytes = bytes.fromhex(target_digest)
        nonce = secrets.token_bytes(16)
        tsq = tsa.build_tsq(target_digest_bytes, nonce)
        try:
            if tsa_url == "local":
                local_tsa = tsa.LocalTSA()
                tsr = local_tsa.respond(tsq)
                tsa_cert_der = local_tsa.cert.public_bytes(serialization.Encoding.DER)
                tsa_cert_fp = local_tsa.cert.fingerprint(hashes.SHA256()).hex()
            else:
                tsr = _send_tsq(tsq, tsa_url)
                cert_der = tsa.extract_signer_cert_der(tsr)
                if cert_der is None:
                    cert_path = getattr(args, "tsa_cert", None)
                    if not cert_path:
                        shutil.rmtree(staging)
                        return EXIT_EXTERNAL, "TSA_CERT_REQUIRED", {}
                    cert_der = load_certificate_der(cert_path)
                tsa_cert_der = cert_der
                tsa_cert_fp = x509.load_der_x509_certificate(cert_der).fingerprint(hashes.SHA256()).hex()
            # Consistency check at acquisition time.  This does not turn the
            # packaged certificate into a verifier trust anchor.
            tsa.verify_tsr(
                tsr,
                target_digest_bytes,
                trusted_cert_der=tsa_cert_der,
                trusted_fingerprint=tsa_cert_fp,
                expected_nonce=int.from_bytes(nonce, "big"),
                allow_self_signed=(tsa_url == "local"),
            )
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
                "subject": "approval/target.json",
                "subject_digest": target_digest,
                "nonce": nonce.hex(),
                "tsa_url": tsa_url,
                "tsa_cert_fingerprint": tsa_cert_fp,
                "capability": "rfc3161-exact-approval-target-imprint",
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
        "approval_target_digest": digest(target),
    }


def cmd_release(args):
    """One-command init + unanimous approval + finalize for locally held keys."""
    out = pathlib.Path(args.out)
    for key_path in args.key:
        if path_is_within(key_path, out):
            return EXIT_USAGE, "PRIVATE_KEY_INSIDE_RELEASE", {}
    try:
        keys = [load_private_key(path) for path in args.key]
    except (TypeError, ValueError) as e:
        return EXIT_USAGE, "PRIVATE_KEY_INVALID", {"error": str(e)}
    key_ids = [key_id_of(key.public_key()) for key in keys]
    if len(set(key_ids)) != len(key_ids):
        return EXIT_USAGE, "DUPLICATE_AUTHOR_KEY", {}
    authors = []
    for index, (key, kid) in enumerate(zip(keys, key_ids)):
        authors.append({
            "key_id": kid,
            "public_key": public_pem(key.public_key()).decode("ascii"),
            "role": "sole" if len(keys) == 1 else "co-first",
            "corresponding": index == 0,
        })
    team = {"schema": TEAM_SCHEMA, "authors": authors}
    with tempfile.TemporaryDirectory(prefix="acsd-team-") as temp_dir:
        team_path = pathlib.Path(temp_dir) / "team.json"
        team_path.write_text(json.dumps(team), encoding="utf-8")
        code, message, initialized = cmd_init(argparse.Namespace(
            content=args.content, team=str(team_path), out=str(out),
        ))
    if code != EXIT_OK:
        return code, message, initialized
    for key_path in args.key:
        code, message, approved = cmd_approve(argparse.Namespace(
            release_dir=str(out), key=key_path,
        ))
        if code != EXIT_OK:
            return code, message, approved
    code, message, finalized = cmd_finalize(argparse.Namespace(
        release_dir=str(out), tsa=args.tsa, tsa_cert=args.tsa_cert,
        allow_untimestamped=args.allow_untimestamped,
    ))
    if code == EXIT_OK:
        finalized["author_key_ids"] = key_ids
        finalized["work_id"] = initialized["work_id"]
    return code, message, finalized


def verify_release_dir(root: pathlib.Path, trusted_tsa_cert_der: bytes = None,
                       trusted_tsa_fingerprint: str = None,
                       allow_local_test_tsa: bool = False,
                       require_external_time: bool = False):
    state = read_canonical(root / "state.json")
    release = read_canonical(root / "release/release.json")
    governance = read_canonical(root / "governance/statement.json")
    pec = read_canonical(root / "pec/pec.json")
    target = read_canonical(root / "approval/target.json")
    adapted = adapt_v1_release(release)
    check_release_key_paths(release)
    content_bytes = (root / release["content"]["path"]).read_bytes()
    if hashlib.sha256(content_bytes).hexdigest() != release["content"]["sha256"]:
        return EXIT_VERIFY_FAIL, "TAMPERED", {"error_code": "CONTENT_DIGEST_MISMATCH"}
    try:
        check_bindings(pec, adapted, governance)
        check_approval_target(target, release, governance, pec, adapted)
    except ValueError as e:
        return EXIT_VERIFY_FAIL, "TAMPERED", {"error_code": str(e)}

    key_ids = sorted(adapted["author_key_ids"])
    target_bytes = canonical(target)
    valid = {}
    for kid in key_ids:
        approval_path = root / f"approvals/{kid}.cose"
        try:
            pub = load_bound_public_key(root, kid)
        except ValueError as e:
            return EXIT_VERIFY_FAIL, "TAMPERED", {"error_code": str(e)}
        if not approval_path.exists():
            continue
        try:
            cose.cose_verify(approval_path.read_bytes(), pub, expected_payload=target_bytes)
            valid[kid] = True
        except ValueError as e:
            return EXIT_VERIFY_FAIL, "TAMPERED", {"error_code": str(e)}
        except Exception:
            return EXIT_VERIFY_FAIL, "TAMPERED", {"error_code": "APPROVAL_SIGNATURE_INVALID"}
    missing = [k for k in key_ids if not valid.get(k)]
    permitted = set(pec["claim_policy"]["permitted_outcomes"])
    granted = []
    if not missing:
        granted = [o for o in ("KEY_ASSENT", "GOVERNANCE_ASSENT") if o in permitted]
    data = {
        "work_id": adapted["work_id"],
        "release_digest": adapted["digest"],
        "pec_digest": digest(pec),
        "approval_target_digest": digest(target),
        "state": state.get("state"),
        "missing_approvals": missing,
        "granted_outcomes": granted,
        "non_claims": pec["claim_policy"]["global_non_claims"],
    }
    if missing:
        return EXIT_INCOMPLETE, "INCOMPLETE", data
    # optional timestamp verification (imprint binding + genTime)
    tsr_path = root / "receipts/response.tsr"
    if tsr_path.exists():
        target_digest_bytes = bytes.fromhex(digest(target))
        report = read_canonical(root / "receipts/report.json")
        if (report.get("subject") != "approval/target.json"
                or report.get("subject_digest") != digest(target)
                or report.get("capability") != "rfc3161-exact-approval-target-imprint"):
            return EXIT_VERIFY_FAIL, "TAMPERED", {"error_code": "RECEIPT_REPORT_BINDING_MISMATCH"}
        tsq_info = tsa.parse_tsq((root / "receipts/request.tsq").read_bytes())
        if tsq_info["imprint"] != target_digest_bytes:
            return EXIT_VERIFY_FAIL, "TAMPERED", {"error_code": "TSQ_IMPRINT_MISMATCH"}
        if int(report.get("nonce", ""), 16) != tsq_info["nonce"]:
            return EXIT_VERIFY_FAIL, "TAMPERED", {"error_code": "TSQ_NONCE_MISMATCH"}

        is_local_test = report.get("tsa_url") == "local"
        verify_cert = trusted_tsa_cert_der
        verify_fingerprint = trusted_tsa_fingerprint
        allow_self_signed = False
        if is_local_test and allow_local_test_tsa:
            verify_cert = (root / "receipts/tsa-cert.der").read_bytes()
            allow_self_signed = True
        if verify_cert is None and verify_fingerprint is None:
            data["timestamp_status"] = "PRESENT_UNVERIFIED_NO_EXTERNAL_TRUST"
            if require_external_time:
                return EXIT_INCOMPLETE, "EXTERNAL_TIME_UNVERIFIED", data
        else:
            try:
                info = tsa.verify_tsr(
                    tsr_path.read_bytes(), target_digest_bytes,
                    trusted_cert_der=verify_cert,
                    trusted_fingerprint=verify_fingerprint,
                    expected_nonce=tsq_info["nonce"],
                    allow_self_signed=allow_self_signed,
                )
            except ValueError as e:
                return EXIT_VERIFY_FAIL, "TAMPERED", {"error_code": str(e)}
            data["timestamp_status"] = "LOCAL_TEST_VERIFIED" if is_local_test else "EXTERNAL_PIN_VERIFIED"
            data["timestamp_gen_time"] = info["genTime"].isoformat()
            data["timestamp_signer_fingerprint"] = info["signer_fingerprint"]
            if not is_local_test and "EXTERNALLY_NOT_AFTER" in permitted:
                data["granted_outcomes"].append("EXTERNALLY_NOT_AFTER")
    elif require_external_time:
        return EXIT_INCOMPLETE, "EXTERNAL_TIME_MISSING", data
    # Verify a manifest whenever it is present; mutable state must not be able
    # to downgrade verification by changing the package-state label.
    manifest_path = root / "MANIFEST.sha256"
    if manifest_path.exists():
        expected = manifest_entries(root)
        actual = manifest_path.read_text(encoding="ascii")
        if expected != actual:
            return EXIT_VERIFY_FAIL, "TAMPERED", {"error_code": "MANIFEST_MISMATCH"}
    elif state.get("state") in ("finalized", "finalized-untimestamped"):
        return EXIT_VERIFY_FAIL, "TAMPERED", {"error_code": "MANIFEST_MISSING"}
    return EXIT_OK, "VALID", data


def cmd_verify(args):
    root = pathlib.Path(args.release_dir)
    try:
        trust_cert = load_certificate_der(args.tsa_trust_cert) if args.tsa_trust_cert else None
        return verify_release_dir(
            root,
            trusted_tsa_cert_der=trust_cert,
            trusted_tsa_fingerprint=args.tsa_trust_fingerprint,
            allow_local_test_tsa=args.allow_local_test_tsa,
            require_external_time=args.require_external_time,
        )
    except FileNotFoundError as e:
        return EXIT_USAGE, f"MISSING:{e.filename}", {}


def cmd_inspect(args):
    root = pathlib.Path(args.release_dir)
    state = read_canonical(root / "state.json")
    release = read_canonical(root / "release/release.json")
    adapted = adapt_v1_release(release)
    received = [
        kid for kid in sorted(adapted["author_key_ids"])
        if (root / f"approvals/{kid}.cose").is_file()
    ]
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

    pr = sub.add_parser("release", parents=[common], help="one-command release using locally held author keys")
    pr.add_argument("content", help="manuscript file (PDF or text)")
    pr.add_argument("--key", action="append", required=True, help="author private key PEM; repeat for co-authors")
    pr.add_argument("--out", default="release-dir", help="output directory")
    pr.add_argument("--tsa", help="RFC 3161 TSA URL, or 'local' for protocol testing")
    pr.add_argument("--tsa-cert", help="TSA signer certificate when the response omits it")
    pr.add_argument("--allow-untimestamped", action="store_true", help="finalize without a timestamp if the TSA fails")
    pr.set_defaults(func=cmd_release)

    pv = sub.add_parser("verify", parents=[common], help="verify a release directory offline")
    pv.add_argument("release_dir")
    pv.add_argument("--tsa-trust-cert", help="out-of-band trusted TSA signer certificate (PEM or DER)")
    pv.add_argument("--tsa-trust-fingerprint", help="out-of-band SHA-256 pin for an embedded TSA signer certificate")
    pv.add_argument("--allow-local-test-tsa", action="store_true", help="verify the bundled self-signed local test TSA; never grants external time")
    pv.add_argument("--require-external-time", action="store_true", help="fail unless externally pinned RFC 3161 evidence verifies")
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
