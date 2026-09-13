#!/usr/bin/env python3
"""ACSD CLI — anonymous scholarly claim and disclosure tool.

Commands: keygen / init / authorize / approve / finalize / release / revise /
verify / inspect.

Signing uses Ed25519 via `cryptography` and a minimal COSE Sign1 encoding
(cose.py). The canonical/digest/binding core (pec_core) stays dependency-free.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import re
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
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

ROOT = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

import cose  # noqa: E402
import tsa  # noqa: E402
import approval_set  # noqa: E402
import claim_derivation as claim_core  # noqa: E402
import identity_disclosure  # noqa: E402
from bundle_validation import (  # noqa: E402
    CURRENT_PEC_SCHEMA as PEC_SCHEMA,
    GLOBAL_NON_CLAIMS,
    GOVERNANCE_SCHEMA,
    new_disclosure_policy,
    validate_pec_bundle,
)
from acsd_version import __version__  # noqa: E402
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
from key_identity import KEY_ID_RE, key_id_of, validate_key_id  # noqa: E402
from package_manifest import (  # noqa: E402
    build_manifest_text,
    iter_payload_files,
    payload_path,
    verify_manifest,
)
from release_adapter import adapt_release  # noqa: E402

TEAM_SCHEMA = "acsd-team/v1"
RELEASE_SCHEMA = "acsd-v3-paper-release/v1"
LEGACY_RELEASE_SCHEMA = "acsd-v1.6.0-paper-release/v1"
APPROVAL_TARGET_SCHEMA = "acsd-approval-target/v2"
LEGACY_APPROVAL_TARGET_SCHEMA = "acsd-approval-target/v1"
LINEAGE_AUTHORITY_SCHEMA = "acsd-lineage-authority/v1"
LINEAGE_TRANSITION_SCHEMA = "acsd-lineage-transition/v1"
DEFAULT_AI_USE = {
    "used": False,
    "purposes": [],
    "tools": [],
    "human_review_key_ids": [],
}

# --- key helpers -----------------------------------------------------------


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


def validate_receipt_report(report):
    expected_fields = {
        "schema", "subject", "subject_digest", "nonce", "tsa_url",
        "tsa_cert_fingerprint", "capability",
    }
    require(isinstance(report, dict) and set(report) == expected_fields, "RECEIPT_REPORT_FIELDS")
    require(report.get("schema") == "acsd-receipt-report/v1", "RECEIPT_REPORT_SCHEMA")
    require(
        isinstance(report.get("subject"), str)
        and isinstance(report.get("subject_digest"), str)
        and KEY_ID_RE.fullmatch(report["subject_digest"])
        and isinstance(report.get("nonce"), str)
        and re.fullmatch(r"[0-9a-f]{32}", report["nonce"])
        and isinstance(report.get("tsa_url"), str)
        and bool(report["tsa_url"])
        and isinstance(report.get("tsa_cert_fingerprint"), str)
        and KEY_ID_RE.fullmatch(report["tsa_cert_fingerprint"])
        and isinstance(report.get("capability"), str),
        "RECEIPT_REPORT_INVALID",
    )


def load_bound_public_key(root: pathlib.Path, kid: str) -> Ed25519PublicKey:
    """Load the public key stored under *kid* and verify the name binding."""
    validate_key_id(kid)
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
        kid = validate_key_id(author.get("key_id"))
        require(
            author.get("public_key_path") == f"public-keys/{kid}.pub",
            "PUBLIC_KEY_PATH_MISMATCH",
        )


def lineage_authority_of(release):
    """Return and validate the authority controlling the next lineage edge.

    Published v1/v2 releases did not carry an explicit authority object.  They
    migrate conservatively: every listed author key is required.
    """
    author_keys = sorted(validate_key_id(a["key_id"]) for a in release.get("authors", []))
    require(author_keys and len(author_keys) == len(set(author_keys)), "LINEAGE_AUTHORITY_INVALID")
    authority = release.get("lineage_authority")
    if authority is None:
        return {
            "schema": LINEAGE_AUTHORITY_SCHEMA,
            "key_ids": author_keys,
            "threshold": len(author_keys),
        }
    require(authority.get("schema") == LINEAGE_AUTHORITY_SCHEMA, "LINEAGE_AUTHORITY_INVALID")
    keys = authority.get("key_ids")
    threshold = authority.get("threshold")
    require(keys == sorted(keys or []) and len(keys) == len(set(keys or [])), "LINEAGE_AUTHORITY_INVALID")
    require(all(isinstance(key, str) and KEY_ID_RE.fullmatch(key) for key in keys), "KEY_ID_INVALID")
    require(keys == author_keys, "LINEAGE_AUTHORITY_KEY_SET_MISMATCH")
    require(isinstance(threshold, int) and not isinstance(threshold, bool), "LINEAGE_THRESHOLD_INVALID")
    require(1 <= threshold <= len(keys), "LINEAGE_THRESHOLD_INVALID")
    return authority


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


def build_release(work_id, content_sha256, content_path, team, *, parent_release=None,
                  line="main", lineage_threshold=None):
    corresponding_key = next(
        (a["key_id"] for a in team["authors"] if a.get("corresponding")),
        team["authors"][0]["key_id"],
    )
    authors = []
    for i, a in enumerate(team["authors"], 1):
        authors.append({
            "slot": i,
            "key_id": a["key_id"],
            "role": a.get("role", "co-first"),
            "corresponding": a["key_id"] == corresponding_key,
            "contributions": a.get("contributions", []),
            "issuer": a.get("issuer", f"urn:acsd:pseudonym:{a['key_id'][:12]}"),
            "kid_hex": a["key_id"][:16],
            "public_key_path": f"public-keys/{a['key_id']}.pub",
        })
    key_ids = sorted(a["key_id"] for a in team["authors"])
    threshold = len(key_ids) if lineage_threshold is None else lineage_threshold
    require(isinstance(threshold, int) and not isinstance(threshold, bool), "LINEAGE_THRESHOLD_INVALID")
    require(1 <= threshold <= len(key_ids), "LINEAGE_THRESHOLD_INVALID")
    if parent_release is None:
        version = 1
        parent_release_id = None
    else:
        parent_slot = parent_release["slot"]
        version = parent_slot["version"] + 1 if line == parent_slot["line"] else 1
        parent_release_id = "urn:sha256:" + digest(parent_release)
    release = {
        "schema": RELEASE_SCHEMA,
        "work_id": work_id,
        "slot": {"line": line, "version": version, "work_id": work_id},
        "content": {"path": content_path, "sha256": content_sha256},
        "authors": authors,
        "lineage_authority": {
            "schema": LINEAGE_AUTHORITY_SCHEMA,
            "key_ids": key_ids,
            "threshold": threshold,
        },
        "citation_witnesses": [],
        "reference_work_ids": [],
        "ai_use": dict(DEFAULT_AI_USE),
        "parent_release_id": parent_release_id,
        "issued_at": 0,
        "standalone_semantics": (
            "Every listed author key endorses this exact release payload; "
            "series membership is optional."
        ),
    }
    lineage_authority_of(release)
    return release


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
        "ai_use_declaration": dict(DEFAULT_AI_USE),
    }


def build_pec(work_id, adapted, gov_digest, content_sha256, ai_digest, key_ids,
              predecessor_pec=None):
    return {
        "schema": PEC_SCHEMA,
        "pec_id": "pec-" + uuid.uuid4().hex[:8],
        "subject": {
            "work_id": work_id,
            "release_digest": adapted["digest"],
            "version": f"v{adapted['version']}",
            "line": adapted["line"],
            "predecessor_pec_digest": digest(predecessor_pec) if predecessor_pec is not None else None,
            "series_package_digest": None,
        },
        "governance": {
            "statement_digest": gov_digest,
            "manuscript_sha256": content_sha256,
            "required_pec_approval_key_ids": sorted(key_ids),
            "ai_use_declaration_digest": ai_digest,
        },
        "events": [],
        "disclosure_policy": new_disclosure_policy(),
        "claim_policy": {
            "permitted_outcomes": [
                "KEY_ASSENT",
                "GOVERNANCE_ASSENT",
                "APPROVAL_SET_EXISTED_NOT_AFTER",
                "AUTHORIZED_SUCCESSOR",
            ],
            "global_non_claims": list(GLOBAL_NON_CLAIMS),
            "required_capabilities": {
                "APPROVAL_SET_EXISTED_NOT_AFTER": [
                    "rfc3161-exact-approval-set-imprint"
                ],
                "AUTHORIZED_SUCCESSOR": [
                    "predecessor-authority-exact-transition"
                ],
            },
        },
        "issuer_key_id": key_ids[0],
    }


def build_lineage_transition(parent_release, parent_pec, release, governance, pec):
    """Build the acyclic parent-to-child authorization body.

    Old-authority signatures cover this body.  New-author approvals cover an
    approval target which includes this body's digest, avoiding a hash cycle.
    """
    parent = adapt_release(parent_release)
    child = adapt_release(release)
    parent_authority = lineage_authority_of(parent_release)
    child_authority = lineage_authority_of(release)
    if parent["line"] != child["line"]:
        kind = "branch"
    elif parent_authority["key_ids"] != child_authority["key_ids"]:
        kind = "team-change"
    elif parent_authority["threshold"] != child_authority["threshold"]:
        kind = "threshold-change"
    else:
        kind = "continuation"
    return {
        "schema": LINEAGE_TRANSITION_SCHEMA,
        "kind": kind,
        "work_id": child["work_id"],
        "parent": {
            "release_digest": parent["digest"],
            "pec_digest": digest(parent_pec),
            "line": parent["line"],
            "version": parent["version"],
            "authority": parent_authority,
        },
        "child": {
            "release_digest": child["digest"],
            "governance_digest": digest(governance),
            "pec_digest": digest(pec),
            "line": child["line"],
            "version": child["version"],
            "authority": child_authority,
        },
    }


def build_approval_target(release, governance, pec, lineage_transition=None):
    """Build the acyclic object jointly signed by every author key."""
    return {
        "schema": APPROVAL_TARGET_SCHEMA,
        "work_id": release["work_id"],
        "release_digest": digest(release),
        "governance_digest": digest(governance),
        "pec_digest": digest(pec),
        "required_key_ids": sorted(a["key_id"] for a in release["authors"]),
        "lineage_transition_digest": (
            digest(lineage_transition) if lineage_transition is not None else None
        ),
    }


def check_approval_target(target, release, governance, pec, adapted, lineage_transition=None):
    schema = target.get("schema")
    require(schema in {APPROVAL_TARGET_SCHEMA, LEGACY_APPROVAL_TARGET_SCHEMA}, "APPROVAL_TARGET_SCHEMA")
    require(
        schema != LEGACY_APPROVAL_TARGET_SCHEMA or lineage_transition is None,
        "APPROVAL_TARGET_SCHEMA",
    )
    require(target.get("work_id") == adapted["work_id"], "APPROVAL_TARGET_BINDING_MISMATCH")
    require(target.get("release_digest") == adapted["digest"], "APPROVAL_TARGET_BINDING_MISMATCH")
    require(target.get("governance_digest") == digest(governance), "APPROVAL_TARGET_BINDING_MISMATCH")
    require(target.get("pec_digest") == digest(pec), "APPROVAL_TARGET_BINDING_MISMATCH")
    require(
        target.get("required_key_ids") == sorted(adapted["author_key_ids"]),
        "APPROVAL_TARGET_BINDING_MISMATCH",
    )
    require(
        target.get("lineage_transition_digest") == (
            digest(lineage_transition) if lineage_transition is not None else None
        ),
        "APPROVAL_TARGET_BINDING_MISMATCH",
    )


def check_bindings(pec, adapted, governance, release=None):
    return validate_pec_bundle(
        pec,
        adapted,
        digest(governance),
        governance=governance,
        release=release,
        require_slot_bindings=True,
    )


def load_lineage_structure(root, release, governance, pec):
    """Validate an optional parent-to-child edge, excluding signatures."""
    adapted = adapt_release(release)
    parent_id = release.get("parent_release_id")
    predecessor_pec = pec["subject"].get("predecessor_pec_digest")
    if parent_id is None:
        require(adapted["version"] == 1, "LINEAGE_GENESIS_VERSION")
        require(predecessor_pec is None, "PREDECESSOR_MISMATCH")
        return None

    lineage_root = root / "lineage"
    parent_release = read_canonical(lineage_root / "parent-release.json")
    parent_pec = read_canonical(lineage_root / "parent-pec.json")
    transition = read_canonical(lineage_root / "transition.json")
    parent = adapt_release(parent_release)
    require(parent_id == "urn:sha256:" + parent["digest"], "PARENT_RELEASE_MISMATCH")
    require(parent["work_id"] == adapted["work_id"], "LINEAGE_WORK_ID_MISMATCH")
    if parent["line"] == adapted["line"]:
        require(adapted["version"] == parent["version"] + 1, "LINEAGE_VERSION_NOT_CONSECUTIVE")
    else:
        require(adapted["version"] == 1, "LINEAGE_BRANCH_VERSION")
    require(predecessor_pec == digest(parent_pec), "PREDECESSOR_MISMATCH")
    expected = build_lineage_transition(parent_release, parent_pec, release, governance, pec)
    require(transition == expected, "LINEAGE_TRANSITION_MISMATCH")
    return {
        "parent_release": parent_release,
        "parent_pec": parent_pec,
        "transition": transition,
        "parent_authority": lineage_authority_of(parent_release),
        "child_authority": lineage_authority_of(release),
    }


def verify_lineage_authorization(root, lineage, valid_child_approvals):
    """Verify authority continuity for one exact parent-to-child edge."""
    if lineage is None:
        return {"status": "GENESIS", "required": 0, "valid": []}
    old = lineage["parent_authority"]
    new = lineage["child_authority"]
    old_keys = set(old["key_ids"])
    if old == new:
        inherited = sorted(old_keys.intersection(valid_child_approvals))
        require(len(inherited) >= old["threshold"], "UNAUTHORIZED_SUCCESSOR")
        return {"status": "AUTHORIZED_CONTINUATION", "required": old["threshold"], "valid": inherited}

    auth_dir = root / "lineage/authorizations"
    if auth_dir.exists():
        for path in auth_dir.glob("*.cose"):
            require(path.stem in old_keys, "LINEAGE_AUTHORIZATION_UNKNOWN_KEY")
    valid = []
    payload = canonical(lineage["transition"])
    for kid in old["key_ids"]:
        approval_path = auth_dir / f"{kid}.cose"
        if not approval_path.is_file():
            continue
        pub_path = root / f"lineage/parent-public-keys/{kid}.pub"
        try:
            pub = load_public_key_bytes(pub_path.read_bytes())
            require(key_id_of(pub) == kid, "PUBLIC_KEY_ID_MISMATCH")
            cose.cose_verify(approval_path.read_bytes(), pub, expected_payload=payload)
        except FileNotFoundError:
            raise ValueError("PARENT_PUBLIC_KEY_MISSING")
        except ValueError:
            raise
        except Exception as exc:
            raise ValueError("LINEAGE_AUTHORIZATION_SIGNATURE_INVALID") from exc
        valid.append(kid)
    require(len(valid) >= old["threshold"], "UNAUTHORIZED_SUCCESSOR")
    return {"status": "AUTHORIZED_TRANSITION", "required": old["threshold"], "valid": valid}


def lineage_claim_subject(lineage):
    """Project one validated exact transition into the typed claim subject."""
    transition = lineage["transition"]
    parent = transition["parent"]
    child = transition["child"]
    text_digest = lambda value: hashlib.sha256(value.encode("utf-8")).hexdigest()
    return claim_core.LineageSubject(
        text_digest(transition["work_id"]),
        parent["release_digest"],
        parent["pec_digest"],
        text_digest(parent["line"]),
        parent["version"],
        child["release_digest"],
        child["pec_digest"],
        text_digest(child["line"]),
        child["version"],
        digest(transition),
    )


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


def verify_release_dir(root: pathlib.Path, trusted_tsa_cert_der: bytes = None,
                       trusted_tsa_fingerprint: str = None,
                       allow_local_test_tsa: bool = False,
                       require_external_time: bool = False,
                       expected_parent_release_id: str = None):
    # Validate the closed package boundary before interpreting any attacker-
    # controlled path or signed object.  A present manifest can never be
    # downgraded by editing state.json.
    manifest_path = root / "MANIFEST.sha256"
    if manifest_path.exists() or manifest_path.is_symlink():
        try:
            verify_manifest(root)
        except (OSError, UnicodeError, ValueError) as exc:
            return EXIT_VERIFY_FAIL, "TAMPERED", {"error_code": str(exc)}

    state = read_canonical(root / "state.json")
    release = read_canonical(root / "release/release.json")
    governance = read_canonical(root / "governance/statement.json")
    pec = read_canonical(root / "pec/pec.json")
    target = read_canonical(root / "approval/target.json")
    adapted = adapt_release(release)
    check_release_key_paths(release)
    try:
        content_file = payload_path(root, release["content"]["path"])
        content_bytes = content_file.read_bytes()
    except (OSError, ValueError) as exc:
        return EXIT_VERIFY_FAIL, "TAMPERED", {"error_code": str(exc)}
    if hashlib.sha256(content_bytes).hexdigest() != release["content"]["sha256"]:
        return EXIT_VERIFY_FAIL, "TAMPERED", {"error_code": "CONTENT_DIGEST_MISMATCH"}
    try:
        check_bindings(pec, adapted, governance, release)
        lineage = load_lineage_structure(root, release, governance, pec)
        transition = lineage["transition"] if lineage is not None else None
        check_approval_target(target, release, governance, pec, adapted, transition)
    except ValueError as e:
        return EXIT_VERIFY_FAIL, "TAMPERED", {"error_code": str(e)}

    key_ids = sorted(adapted["author_key_ids"])
    target_bytes = canonical(target)
    valid = {}
    approval_certificate_digests = {}
    for kid in key_ids:
        approval_path = root / f"approvals/{kid}.cose"
        try:
            pub = load_bound_public_key(root, kid)
        except ValueError as e:
            return EXIT_VERIFY_FAIL, "TAMPERED", {"error_code": str(e)}
        if not approval_path.exists():
            continue
        try:
            approval_bytes = approval_path.read_bytes()
            cose.cose_verify(approval_bytes, pub, expected_payload=target_bytes)
            valid[kid] = True
            approval_certificate_digests[kid] = hashlib.sha256(approval_bytes).hexdigest()
        except ValueError as e:
            return EXIT_VERIFY_FAIL, "TAMPERED", {"error_code": str(e)}
        except Exception:
            return EXIT_VERIFY_FAIL, "TAMPERED", {"error_code": "APPROVAL_SIGNATURE_INVALID"}
    missing = [k for k in key_ids if not valid.get(k)]
    permitted = set(pec["claim_policy"]["permitted_outcomes"])
    permitted_claim_kinds = claim_core.permitted_claims(permitted)
    appraised_evidence = []
    data = {
        "work_id": adapted["work_id"],
        "release_digest": adapted["digest"],
        "parent_release_id": release.get("parent_release_id"),
        "pec_digest": digest(pec),
        "approval_target_digest": digest(target),
        "state": state.get("state"),
        "missing_approvals": missing,
        "granted_outcomes": [],
        "non_claims": pec["claim_policy"]["global_non_claims"],
    }
    if missing:
        return EXIT_INCOMPLETE, "INCOMPLETE", data
    if expected_parent_release_id is not None and release.get("parent_release_id") != expected_parent_release_id:
        return EXIT_VERIFY_FAIL, "TAMPERED", {**data, "error_code": "PARENT_PIN_MISMATCH"}
    try:
        lineage_result = verify_lineage_authorization(root, lineage, set(valid))
    except ValueError as exc:
        if str(exc) == "UNAUTHORIZED_SUCCESSOR":
            data["lineage_status"] = "UNAUTHORIZED_SUCCESSOR"
            return EXIT_VERIFY_FAIL, "VALID_OBJECT_BUT_UNAUTHORIZED_SUCCESSOR", data
        return EXIT_VERIFY_FAIL, "TAMPERED", {**data, "error_code": str(exc)}
    data["lineage_status"] = lineage_result["status"]
    data["lineage_anchor_status"] = (
        "GENESIS" if lineage is None else
        "PIN_MATCHED" if expected_parent_release_id is not None else
        "UNPINNED_EXACT_PARENT"
    )
    separate_lineage_keys = (
        lineage_result["valid"]
        if lineage is not None
        and lineage["parent_authority"] != lineage["child_authority"]
        else []
    )
    approval_set_path = root / "approval/approval-set.json"
    approval_set_obj = None
    if approval_set_path.exists():
        try:
            approval_set_obj = read_canonical(approval_set_path)
            approval_set.verify(
                approval_set_obj, root, target, key_ids, separate_lineage_keys
            )
        except (OSError, ValueError) as exc:
            return EXIT_VERIFY_FAIL, "TAMPERED", {**data, "error_code": str(exc)}
        data["approval_set_digest"] = digest(approval_set_obj)
    elif pec.get("schema") == PEC_SCHEMA and state.get("state") in (
        "finalized", "finalized-untimestamped"
    ):
        return EXIT_VERIFY_FAIL, "TAMPERED", {
            **data, "error_code": "APPROVAL_SET_MISSING"
        }

    approval_support_digest = (
        digest(approval_set_obj) if approval_set_obj is not None else
        digest({
            "target_digest": digest(target),
            "approval_certificate_digests": [
                {"key_id": kid, "sha256": approval_certificate_digests[kid]}
                for kid in key_ids
            ],
        })
    )
    appraised_evidence.append(claim_core.AppraisedEvidence(
        claim_core.EvidenceKind.UNANIMOUS_APPROVAL,
        claim_core.ApprovalTargetSubject(digest(target)),
        approval_support_digest,
    ))
    if lineage is not None and approval_set_obj is not None:
        appraised_evidence.append(claim_core.AppraisedEvidence(
            claim_core.EvidenceKind.LINEAGE_AUTHORIZATION,
            lineage_claim_subject(lineage),
            digest(approval_set_obj),
        ))

    def refresh_granted_outcomes() -> None:
        derivations = claim_core.derive(appraised_evidence, permitted_claim_kinds)
        data["granted_outcomes"] = list(claim_core.wire_outcomes(derivations))

    refresh_granted_outcomes()

    # Optional timestamp verification (imprint binding + genTime).  v0.3
    # timestamps the complete approval set; legacy PECs retain target-only
    # semantics and can never be upgraded to approval-set existence.
    tsr_path = root / "receipts/response.tsr"
    if tsr_path.exists():
        report = read_canonical(root / "receipts/report.json")
        validate_receipt_report(report)
        if pec.get("schema") == PEC_SCHEMA:
            if approval_set_obj is None:
                return EXIT_VERIFY_FAIL, "TAMPERED", {"error_code": "APPROVAL_SET_MISSING"}
            subject_path = "approval/approval-set.json"
            subject_digest = digest(approval_set_obj)
            capability = "rfc3161-exact-approval-set-imprint"
        else:
            subject_path = "approval/target.json"
            subject_digest = digest(target)
            capability = "rfc3161-exact-approval-target-imprint"
        subject_digest_bytes = bytes.fromhex(subject_digest)
        if (report.get("subject") != subject_path
                or report.get("subject_digest") != subject_digest
                or report.get("capability") != capability):
            return EXIT_VERIFY_FAIL, "TAMPERED", {"error_code": "RECEIPT_REPORT_BINDING_MISMATCH"}
        tsq_info = tsa.parse_tsq((root / "receipts/request.tsq").read_bytes())
        if tsq_info["imprint"] != subject_digest_bytes:
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
                    tsr_path.read_bytes(), subject_digest_bytes,
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
            if not is_local_test:
                if pec.get("schema") == PEC_SCHEMA:
                    time_kind = claim_core.EvidenceKind.APPROVAL_SET_TIMESTAMP
                    time_subject = claim_core.ApprovalSetTimeSubject(
                        subject_digest, info["genTime"].isoformat()
                    )
                    expected_outcome = "APPROVAL_SET_EXISTED_NOT_AFTER"
                else:
                    time_kind = claim_core.EvidenceKind.APPROVAL_TARGET_TIMESTAMP
                    time_subject = claim_core.ApprovalTargetTimeSubject(
                        subject_digest, info["genTime"].isoformat()
                    )
                    expected_outcome = "EXTERNALLY_NOT_AFTER"
                appraised_evidence.append(claim_core.AppraisedEvidence(
                    time_kind,
                    time_subject,
                    hashlib.sha256(tsr_path.read_bytes()).hexdigest(),
                ))
                refresh_granted_outcomes()
                if (expected_outcome not in data["granted_outcomes"]
                        and require_external_time):
                    return EXIT_INCOMPLETE, "EXTERNAL_TIME_NOT_AUTHORIZED", data
    elif require_external_time:
        return EXIT_INCOMPLETE, "EXTERNAL_TIME_MISSING", data
    if not manifest_path.exists() and state.get("state") in ("finalized", "finalized-untimestamped"):
        return EXIT_VERIFY_FAIL, "TAMPERED", {"error_code": "MANIFEST_MISSING"}
    return EXIT_OK, "VALID", data


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
