#!/usr/bin/env python3
"""ACSD CLI — anonymous scholarly claim and disclosure tool.

Commands: keygen / init / authorize / approve / finalize / release / revise /
verify / inspect.

Signing uses Ed25519 via `cryptography` and a minimal COSE Sign1 encoding
(`cose.py`). Canonical bytes, protocol objects, and claim derivation live in
separate I/O-free modules.
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

# ACSD verification must not mutate the artifact it is inspecting merely by
# importing local modules from inside that artifact.
sys.dont_write_bytecode = True

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ROOT = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

import cose  # noqa: E402
import tsa  # noqa: E402
import approval_set  # noqa: E402
import identity_disclosure  # noqa: E402
from acsd_version import __version__  # noqa: E402
from artifact_io import path_is_within, read_canonical, write_canonical  # noqa: E402
from canonical_json import canonical, digest, require  # noqa: E402
from cli_output import (  # noqa: E402
    EXIT_EXTERNAL,
    EXIT_INCOMPLETE,
    EXIT_OK,
    EXIT_STATE_CONFLICT,
    EXIT_USAGE,
    EXIT_VERIFY_FAIL,
    emit_human,
    emit_json,
)
from key_identity import key_id_of  # noqa: E402
from key_material import (  # noqa: E402
    check_release_key_paths,
    load_bound_public_key,
    load_certificate_der,
    load_private_key,
    load_public_key_bytes,
    public_pem,
)
from lineage_adapter import (  # noqa: E402
    load_lineage_structure,
    verify_lineage_authorization,
)
from package_manifest import (  # noqa: E402
    build_manifest_text,
    iter_payload_files,
)
from protocol_objects import (  # noqa: E402
    APPROVAL_TARGET_SCHEMA,
    LEGACY_APPROVAL_TARGET_SCHEMA,
    LEGACY_RELEASE_SCHEMA,
    LINEAGE_AUTHORITY_SCHEMA,
    LINEAGE_TRANSITION_SCHEMA,
    PEC_SCHEMA,
    RELEASE_SCHEMA,
    TEAM_SCHEMA,
    build_approval_target,
    build_governance,
    build_lineage_transition,
    build_pec,
    build_release,
    check_approval_target,
    check_bindings,
    lineage_authority_of,
    lineage_claim_subject,
)
from release_adapter import adapt_release  # noqa: E402
from release_verifier import validate_receipt_report, verify_release_dir  # noqa: E402

# --- team input ------------------------------------------------------------


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


def manifest_entries(root: pathlib.Path) -> str:
    """Compatibility wrapper around the single strict manifest engine."""
    return build_manifest_text(root)


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
    parent_root = pathlib.Path(args.parent) if getattr(args, "parent", None) else None
    parent_release = None
    parent_pec = None
    line = getattr(args, "line", None) or "main"
    if not line or any(ord(c) > 127 or c.isspace() for c in line):
        return EXIT_USAGE, "LINE_INVALID", {}
    if parent_root is not None:
        parent_code, _, parent_data = verify_release_dir(parent_root)
        if parent_code != EXIT_OK:
            return EXIT_VERIFY_FAIL, "PARENT_RELEASE_INVALID", parent_data
        parent_release = read_canonical(parent_root / "release/release.json")
        parent_pec = read_canonical(parent_root / "pec/pec.json")
        work_id = parent_release["work_id"]
        if getattr(args, "line", None) is None:
            line = parent_release["slot"]["line"]
    else:
        work_id = "urn:uuid:" + str(uuid.uuid4())
    content_rel = f"paper/{content_sha256}"
    out = pathlib.Path(args.out)
    if out.exists() and any(out.iterdir()):
        return EXIT_STATE_CONFLICT, "OUTPUT_EXISTS", {}

    release = build_release(
        work_id, content_sha256, content_rel, team,
        parent_release=parent_release,
        line=line,
        lineage_threshold=getattr(args, "lineage_threshold", None),
    )
    adapted = adapt_release(release)
    governance = build_governance(work_id, content_sha256, team)
    gov_digest = digest(governance)
    ai_digest = digest(governance["ai_use_declaration"])
    pec = build_pec(
        work_id, adapted, gov_digest, content_sha256, ai_digest, key_ids,
        predecessor_pec=parent_pec,
    )
    check_bindings(pec, adapted, governance, release)
    transition = (
        build_lineage_transition(parent_release, parent_pec, release, governance, pec)
        if parent_release is not None else None
    )
    target = build_approval_target(release, governance, pec, transition)
    check_approval_target(target, release, governance, pec, adapted, transition)

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
    parent_authority = None
    if parent_release is not None:
        (out / "lineage/parent-public-keys").mkdir(parents=True)
        (out / "lineage/authorizations").mkdir(parents=True)
        write_canonical(out / "lineage/parent-release.json", parent_release)
        write_canonical(out / "lineage/parent-pec.json", parent_pec)
        write_canonical(out / "lineage/transition.json", transition)
        parent_authority = lineage_authority_of(parent_release)
        for kid in parent_authority["key_ids"]:
            source = parent_root / f"public-keys/{kid}.pub"
            pub = load_public_key_bytes(source.read_bytes())
            require(key_id_of(pub) == kid, "PUBLIC_KEY_ID_MISMATCH")
            (out / f"lineage/parent-public-keys/{kid}.pub").write_bytes(source.read_bytes())
    write_canonical(out / "state.json", {
        "schema": "acsd-state/v1",
        "state": "awaiting-approvals",
        "work_id": work_id,
        "release_digest": adapted["digest"],
        "required_approvals": key_ids,
        "received_approvals": [],
        "required_lineage_authorization_threshold": (
            parent_authority["threshold"] if parent_authority is not None else 0
        ),
        "received_lineage_authorizations": [],
    })
    return EXIT_OK, "initialized", {
        "work_id": work_id,
        "release_digest": adapted["digest"],
        "version": adapted["version"],
        "line": adapted["line"],
        "parent_release_id": release["parent_release_id"],
        "state": "awaiting-approvals",
    }


def cmd_authorize(args):
    """Authorize an exact authority-changing lineage transition with an old key."""
    root = pathlib.Path(args.release_dir)
    if path_is_within(args.key, root):
        return EXIT_USAGE, "PRIVATE_KEY_INSIDE_RELEASE", {}
    state = read_canonical(root / "state.json")
    if state.get("state") != "awaiting-approvals":
        return EXIT_STATE_CONFLICT, "STATE_CONFLICT", {"state": state.get("state")}
    try:
        key = load_private_key(args.key)
    except (TypeError, ValueError) as exc:
        return EXIT_USAGE, "PRIVATE_KEY_INVALID", {"error": str(exc)}
    release = read_canonical(root / "release/release.json")
    governance = read_canonical(root / "governance/statement.json")
    pec = read_canonical(root / "pec/pec.json")
    lineage = load_lineage_structure(root, release, governance, pec)
    if lineage is None:
        return EXIT_STATE_CONFLICT, "GENESIS_HAS_NO_LINEAGE_TRANSITION", {}
    if lineage["parent_authority"] == lineage["child_authority"]:
        return EXIT_STATE_CONFLICT, "SEPARATE_LINEAGE_AUTHORIZATION_NOT_REQUIRED", {}
    kid = key_id_of(key.public_key())
    if kid not in lineage["parent_authority"]["key_ids"]:
        return EXIT_VERIFY_FAIL, "UNKNOWN_PARENT_AUTHORITY_KEY", {"key_id": kid}
    path = root / f"lineage/authorizations/{kid}.cose"
    if path.exists():
        return EXIT_STATE_CONFLICT, "DUPLICATE_LINEAGE_AUTHORIZATION", {"key_id": kid}
    path.write_bytes(cose.cose_sign1(canonical(lineage["transition"]), key))
    received = sorted(p.stem for p in (root / "lineage/authorizations").glob("*.cose"))
    state["received_lineage_authorizations"] = received
    write_canonical(root / "state.json", state)
    return EXIT_OK, "lineage transition authorized", {
        "key_id": kid,
        "received": len(received),
        "required_threshold": lineage["parent_authority"]["threshold"],
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
    adapted = adapt_release(release)
    check_release_key_paths(release)
    check_bindings(pec, adapted, governance, release)
    lineage = load_lineage_structure(root, release, governance, pec)
    transition = lineage["transition"] if lineage is not None else None
    check_approval_target(target, release, governance, pec, adapted, transition)
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
    adapted = adapt_release(release)
    check_release_key_paths(release)
    check_bindings(pec, adapted, governance, release)
    lineage = load_lineage_structure(root, release, governance, pec)
    transition = lineage["transition"] if lineage is not None else None
    check_approval_target(target, release, governance, pec, adapted, transition)
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
    try:
        lineage_result = verify_lineage_authorization(root, lineage, set(required))
    except ValueError as exc:
        if str(exc) == "UNAUTHORIZED_SUCCESSOR":
            return EXIT_INCOMPLETE, "LINEAGE_AUTHORIZATION_INCOMPLETE", {
                "required_threshold": lineage["parent_authority"]["threshold"],
            }
        return EXIT_VERIFY_FAIL, "LINEAGE_AUTHORIZATION_INVALID", {"error_code": str(exc)}

    # Reject links and other non-portable filesystem objects before copying.
    # copytree follows directory links by default, which is unsafe here.
    list(iter_payload_files(root))

    # atomic finalize: stage a complete package, then swap it in
    staging = root.with_name(root.name + ".staging")
    if staging.exists():
        shutil.rmtree(staging)
    shutil.copytree(root, staging)

    # Close the acceptance evidence over the exact COSE byte strings.  A
    # timestamp over the target alone would prove only that the unsigned
    # target existed; it would not prove that its approvals existed then.
    separate_lineage_keys = (
        lineage_result["valid"]
        if lineage is not None
        and lineage["parent_authority"] != lineage["child_authority"]
        else []
    )
    approval_set_obj = approval_set.build(
        staging, target, required, separate_lineage_keys
    )
    write_canonical(staging / "approval/approval-set.json", approval_set_obj)
    approval_set_digest = digest(approval_set_obj)

    # Optional RFC 3161 timestamp over the closed approval set, after every
    # required signature exists.
    timestamped = False
    tsa_url = getattr(args, "tsa", None)
    if tsa_url:
        timestamp_digest_bytes = bytes.fromhex(approval_set_digest)
        nonce = secrets.token_bytes(16)
        tsq = tsa.build_tsq(timestamp_digest_bytes, nonce)
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
                timestamp_digest_bytes,
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
                "subject": "approval/approval-set.json",
                "subject_digest": approval_set_digest,
                "nonce": nonce.hex(),
                "tsa_url": tsa_url,
                "tsa_cert_fingerprint": tsa_cert_fp,
                "capability": "rfc3161-exact-approval-set-imprint",
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
        "approval_set_digest": approval_set_digest,
        "lineage_status": lineage_result["status"],
    }


def team_from_private_keys(key_paths):
    """Build the public team declaration used by one-command flows."""
    try:
        keys = [load_private_key(path) for path in key_paths]
    except (TypeError, ValueError) as e:
        raise ValueError("PRIVATE_KEY_INVALID") from e
    key_ids = [key_id_of(key.public_key()) for key in keys]
    require(len(set(key_ids)) == len(key_ids), "DUPLICATE_AUTHOR_KEY")
    authors = []
    for index, (key, kid) in enumerate(zip(keys, key_ids)):
        authors.append({
            "key_id": kid,
            "public_key": public_pem(key.public_key()).decode("ascii"),
            "role": "sole" if len(keys) == 1 else "co-first",
            "corresponding": index == 0,
        })
    return {"schema": TEAM_SCHEMA, "authors": authors}, key_ids


def cmd_release(args):
    """One-command init + unanimous approval + finalize for locally held keys."""
    out = pathlib.Path(args.out)
    for key_path in args.key:
        if path_is_within(key_path, out):
            return EXIT_USAGE, "PRIVATE_KEY_INSIDE_RELEASE", {}
    try:
        team, key_ids = team_from_private_keys(args.key)
    except ValueError as exc:
        return EXIT_USAGE, str(exc), {}
    with tempfile.TemporaryDirectory(prefix="acsd-team-") as temp_dir:
        team_path = pathlib.Path(temp_dir) / "team.json"
        team_path.write_text(json.dumps(team), encoding="utf-8")
        code, message, initialized = cmd_init(argparse.Namespace(
            content=args.content, team=str(team_path), out=str(out), parent=None,
            line="main", lineage_threshold=getattr(args, "lineage_threshold", None),
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


def cmd_revise(args):
    """One-command authorized successor for locally held old and new keys."""
    out = pathlib.Path(args.out)
    for key_path in list(args.key) + list(args.parent_key or []):
        if path_is_within(key_path, out):
            return EXIT_USAGE, "PRIVATE_KEY_INSIDE_RELEASE", {}
    try:
        team, key_ids = team_from_private_keys(args.key)
    except ValueError as exc:
        return EXIT_USAGE, str(exc), {}
    with tempfile.TemporaryDirectory(prefix="acsd-team-") as temp_dir:
        team_path = pathlib.Path(temp_dir) / "team.json"
        team_path.write_text(json.dumps(team), encoding="utf-8")
        code, message, initialized = cmd_init(argparse.Namespace(
            content=args.content,
            team=str(team_path),
            out=str(out),
            parent=args.parent_dir,
            line=args.line,
            lineage_threshold=args.lineage_threshold,
        ))
    if code != EXIT_OK:
        return code, message, initialized
    release = read_canonical(out / "release/release.json")
    governance = read_canonical(out / "governance/statement.json")
    pec = read_canonical(out / "pec/pec.json")
    lineage = load_lineage_structure(out, release, governance, pec)
    if lineage["parent_authority"] != lineage["child_authority"]:
        for key_path in args.parent_key or []:
            code, message, authorized = cmd_authorize(argparse.Namespace(
                release_dir=str(out), key=key_path,
            ))
            if code != EXIT_OK:
                return code, message, authorized
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
        finalized.update({
            "author_key_ids": key_ids,
            "work_id": initialized["work_id"],
            "version": initialized["version"],
            "line": initialized["line"],
        })
    return code, message, finalized


def cmd_verify(args):
    root = pathlib.Path(args.release_dir)
    try:
        if args.tsa_trust_cert and path_is_within(args.tsa_trust_cert, root):
            return EXIT_USAGE, "TSA_TRUST_MUST_BE_EXTERNAL", {}
        trust_cert = load_certificate_der(args.tsa_trust_cert) if args.tsa_trust_cert else None
        return verify_release_dir(
            root,
            trusted_tsa_cert_der=trust_cert,
            trusted_tsa_fingerprint=args.tsa_trust_fingerprint,
            allow_local_test_tsa=args.allow_local_test_tsa,
            require_external_time=args.require_external_time,
            expected_parent_release_id=args.expected_parent_release_id,
        )
    except FileNotFoundError as e:
        return EXIT_USAGE, f"MISSING:{e.filename}", {}


def cmd_inspect(args):
    root = pathlib.Path(args.release_dir)
    state = read_canonical(root / "state.json")
    release = read_canonical(root / "release/release.json")
    adapted = adapt_release(release)
    received = [
        kid for kid in sorted(adapted["author_key_ids"])
        if (root / f"approvals/{kid}.cose").is_file()
    ]
    missing = [k for k in sorted(adapted["author_key_ids"]) if k not in received]
    return EXIT_OK, "inspected", {
        "state": state.get("state"),
        "work_id": adapted["work_id"],
        "release_digest": adapted["digest"],
        "version": adapted["version"],
        "line": adapted["line"],
        "parent_release_id": release.get("parent_release_id"),
        "lineage_authority": lineage_authority_of(release),
        "required_approvals": state.get("required_approvals"),
        "received_approvals": received,
        "missing_approvals": missing,
        "received_lineage_authorizations": state.get("received_lineage_authorizations", []),
    }


def cmd_disclose_identity(args):
    """Create a signed sidecar without mutating the finalized release."""
    root = pathlib.Path(args.release_dir)
    code, message, verification = verify_release_dir(root)
    if code != EXIT_OK:
        return code, "RELEASE_NOT_ACCEPTED", {
            "verifier_message": message, "verifier_data": verification
        }
    if verification.get("state") not in {"finalized", "finalized-untimestamped"}:
        return EXIT_STATE_CONFLICT, "RELEASE_NOT_FINALIZED", {
            "state": verification.get("state")
        }
    if path_is_within(args.key, root):
        return EXIT_USAGE, "PRIVATE_KEY_INSIDE_RELEASE", {}
    out = pathlib.Path(args.out)
    if path_is_within(out, root):
        return EXIT_USAGE, "DISCLOSURE_OUTPUT_INSIDE_RELEASE", {}
    key = load_private_key(args.key)
    key_id = key_id_of(key.public_key())
    release = read_canonical(root / "release/release.json")
    slots = [
        author["slot"] for author in release["authors"]
        if author["key_id"] == key_id
    ]
    if len(slots) != 1:
        return EXIT_VERIFY_FAIL, "UNKNOWN_AUTHOR_KEY", {"key_id": key_id}
    body = identity_disclosure.build(
        release,
        slots[0],
        args.display_name,
        persistent_identifier=args.persistent_identifier,
        publication_ref=args.publication_ref,
    )
    body_path = out / f"identity-slot-{slots[0]}.json"
    signature_path = out / f"identity-slot-{slots[0]}.cose"
    if body_path.exists() or signature_path.exists():
        return EXIT_STATE_CONFLICT, "IDENTITY_DISCLOSURE_EXISTS", {
            "author_slot": slots[0]
        }
    out.mkdir(parents=True, exist_ok=True)
    write_canonical(body_path, body)
    signature_path.write_bytes(cose.cose_sign1(canonical(body), key))
    return EXIT_OK, "identity disclosure created", {
        "status": "SLOT_KEY_ASSENT_TO_IDENTITY_ASSERTION",
        "author_slot": slots[0],
        "author_key_id": key_id,
        "disclosure": str(body_path),
        "signature": str(signature_path),
    }


def cmd_verify_identity(args):
    root = pathlib.Path(args.release_dir)
    code, message, verification = verify_release_dir(root)
    if code != EXIT_OK:
        return code, "RELEASE_NOT_ACCEPTED", {
            "verifier_message": message, "verifier_data": verification
        }
    body = read_canonical(pathlib.Path(args.disclosure))
    key_id = body.get("author_key_id")
    if not isinstance(key_id, str):
        return EXIT_VERIFY_FAIL, "IDENTITY_SLOT_KEY_MISMATCH", {}
    release = read_canonical(root / "release/release.json")
    public_key = load_bound_public_key(root, key_id)
    result = identity_disclosure.verify(
        body, pathlib.Path(args.signature).read_bytes(), release, public_key
    )
    return EXIT_OK, "identity disclosure valid", result


def cmd_compare_successors(args):
    """Detect a same-parent, same-slot fork without choosing a winner."""
    left_root = pathlib.Path(args.left)
    right_root = pathlib.Path(args.right)
    for label, root in (("left", left_root), ("right", right_root)):
        code, message, data = verify_release_dir(root)
        if code != EXIT_OK:
            return EXIT_VERIFY_FAIL, "SUCCESSOR_NOT_VALID", {
                "side": label, "verifier_message": message, "verifier_data": data,
            }
    left = read_canonical(left_root / "release/release.json")
    right = read_canonical(right_root / "release/release.json")
    left_adapted = adapt_release(left)
    right_adapted = adapt_release(right)
    same_work = left_adapted["work_id"] == right_adapted["work_id"]
    same_parent = left.get("parent_release_id") == right.get("parent_release_id")
    same_slot = (
        left_adapted["line"] == right_adapted["line"]
        and left_adapted["version"] == right_adapted["version"]
    )
    distinct = left_adapted["digest"] != right_adapted["digest"]
    conflict = same_work and same_parent and same_slot and distinct
    if conflict:
        status = "LINEAGE_EQUIVOCATION_DETECTED"
    elif same_work and same_parent and left_adapted["line"] != right_adapted["line"]:
        status = "AUTHORIZED_BRANCHES"
    else:
        status = "NO_DIRECT_SIBLING_CONFLICT"
    return EXIT_OK, status, {
        "conflict": conflict,
        "same_work": same_work,
        "same_parent": same_parent,
        "same_slot": same_slot,
        "left_release_digest": left_adapted["digest"],
        "right_release_digest": right_adapted["digest"],
        "winner": None,
    }


def main(argv=None):
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--json", action="store_true", help="machine-readable output")

    p = argparse.ArgumentParser(prog="acsd", description="ACSD provenance evidence capsule CLI")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    pk = sub.add_parser("keygen", parents=[common], help="generate an Ed25519 keypair")
    pk.add_argument("--name", help="key base name (default author)")
    pk.add_argument("--out-dir", default="keys", help="output directory")
    pk.set_defaults(func=cmd_keygen)

    pi = sub.add_parser("init", parents=[common], help="create a release directory")
    pi.add_argument("content", help="manuscript file (PDF or text)")
    pi.add_argument("--team", required=True, help="team.json")
    pi.add_argument("--out", default="release-dir", help="output directory")
    pi.add_argument("--parent", help="verified predecessor release directory")
    pi.add_argument("--line", help="line name; defaults to the parent's line or main")
    pi.add_argument("--lineage-threshold", type=int, help="future successor authorization threshold (default: all authors)")
    pi.set_defaults(func=cmd_init)

    pl = sub.add_parser("authorize", parents=[common], help="authorize a key-set or threshold-changing lineage transition with a predecessor key")
    pl.add_argument("release_dir")
    pl.add_argument("--key", required=True, help="predecessor-authority private key PEM")
    pl.set_defaults(func=cmd_authorize)

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
    pr.add_argument("--lineage-threshold", type=int, help="future successor authorization threshold (default: all authors)")
    pr.set_defaults(func=cmd_release)

    px = sub.add_parser("revise", parents=[common], help="one-command authorized successor using locally held keys")
    px.add_argument("parent_dir", help="verified predecessor release directory")
    px.add_argument("content", help="new manuscript file (PDF or text)")
    px.add_argument("--key", action="append", required=True, help="new-version author private key; repeat for co-authors")
    px.add_argument("--parent-key", action="append", help="predecessor-authority key; required up to the old threshold when the key set or threshold changes")
    px.add_argument("--out", default="revision-dir", help="output directory")
    px.add_argument("--line", help="line name; omit to continue the parent line")
    px.add_argument("--lineage-threshold", type=int, help="future successor authorization threshold (default: all new authors)")
    px.add_argument("--tsa", help="RFC 3161 TSA URL, or 'local' for protocol testing")
    px.add_argument("--tsa-cert", help="TSA signer certificate when the response omits it")
    px.add_argument("--allow-untimestamped", action="store_true", help="finalize without a timestamp if the TSA fails")
    px.set_defaults(func=cmd_revise)

    pv = sub.add_parser("verify", parents=[common], help="verify a release directory offline")
    pv.add_argument("release_dir")
    pv.add_argument("--tsa-trust-cert", help="out-of-band trusted TSA signer certificate (PEM or DER)")
    pv.add_argument("--tsa-trust-fingerprint", help="out-of-band SHA-256 pin for an embedded TSA signer certificate")
    pv.add_argument("--allow-local-test-tsa", action="store_true", help="verify the bundled self-signed local test TSA; never grants external time")
    pv.add_argument("--require-external-time", action="store_true", help="fail unless externally pinned RFC 3161 evidence verifies")
    pv.add_argument("--expected-parent-release-id", help="pin the exact previously accepted parent urn:sha256 identifier")
    pv.set_defaults(func=cmd_verify)

    pn = sub.add_parser("inspect", parents=[common], help="show state and missing approvals")
    pn.add_argument("release_dir")
    pn.set_defaults(func=cmd_inspect)

    pd = sub.add_parser(
        "disclose-identity", parents=[common],
        help="selectively unblind one author slot into an external signed sidecar",
    )
    pd.add_argument("release_dir")
    pd.add_argument("--key", required=True, help="private key for the exact author slot")
    pd.add_argument("--display-name", required=True)
    pd.add_argument("--persistent-identifier", help="optional ORCID or other identifier assertion")
    pd.add_argument("--publication-ref", help="optional DOI, proceedings URL, or submission reference")
    pd.add_argument("--out", required=True, help="external sidecar directory (must be outside the release)")
    pd.set_defaults(func=cmd_disclose_identity)

    pdi = sub.add_parser(
        "verify-identity", parents=[common],
        help="verify one author-slot identity assertion against an exact release",
    )
    pdi.add_argument("release_dir")
    pdi.add_argument("--disclosure", required=True, help="identity disclosure JSON")
    pdi.add_argument("--signature", required=True, help="matching COSE signature")
    pdi.set_defaults(func=cmd_verify_identity)

    pc = sub.add_parser("compare-successors", parents=[common], help="detect a same-parent, same-slot authorized fork")
    pc.add_argument("left", help="first finalized successor directory")
    pc.add_argument("right", help="second finalized successor directory")
    pc.set_defaults(func=cmd_compare_successors)

    args = p.parse_args(argv)
    try:
        code, message, data = args.func(args)
    except ValueError as e:
        code, message, data = EXIT_VERIFY_FAIL, str(e), {}
    except FileNotFoundError as e:
        code, message, data = EXIT_USAGE, f"MISSING:{e.filename}", {}
    except (KeyError, TypeError):
        code, message, data = EXIT_VERIFY_FAIL, "MALFORMED_INPUT", {
            "error_code": "MALFORMED_INPUT"
        }
    except UnicodeError:
        code, message, data = EXIT_VERIFY_FAIL, "INVALID_ENCODING", {
            "error_code": "INVALID_ENCODING"
        }
    except OSError:
        code, message, data = EXIT_USAGE, "IO_ERROR", {"error_code": "IO_ERROR"}

    if args.json:
        emit_json(args.command, code, message, data)
    else:
        emit_human(args.command, code, message, data)
    return code


if __name__ == "__main__":
    sys.exit(main())
