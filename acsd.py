#!/usr/bin/env python3
"""ACSD CLI — anonymous scholarly claim and disclosure tool.

Commands: keygen / init / review / authorize / recover / approve / finalize /
release / revise / verify / inspect / verify-identity-set / audit-key-reuse.

Signing uses Ed25519 via `cryptography` and a minimal COSE Sign1 encoding
(`cose.py`). Canonical bytes, protocol objects, and claim derivation live in
separate I/O-free modules.
"""
from __future__ import annotations

import argparse
import getpass
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
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

ROOT = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

import cose  # noqa: E402
import tsa  # noqa: E402
import approval_set  # noqa: E402
import approval_delegation  # noqa: E402
import approval_exchange  # noqa: E402
from approval_delegation_adapter import verify_approval_records  # noqa: E402
import identity_disclosure  # noqa: E402
import linkability_audit  # noqa: E402
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
from key_identity import key_id_of, validate_key_id  # noqa: E402
from key_material import (  # noqa: E402
    check_release_key_paths,
    load_bound_public_key,
    load_certificate_der,
    load_private_key,
    load_public_key_bytes,
    PrivateKeyPassphraseInvalid,
    PrivateKeyPassphraseRequired,
    public_pem,
)
from lineage_adapter import (  # noqa: E402
    load_lineage_structure,
    verify_lineage_authorization,
)
from package_manifest import (  # noqa: E402
    build_manifest_text,
    iter_payload_files,
    verify_manifest,
)
from protocol_objects import (  # noqa: E402
    APPROVAL_TARGET_SCHEMA,
    LEGACY_APPROVAL_TARGET_SCHEMA,
    LEGACY_RELEASE_SCHEMA,
    LINEAGE_AUTHORITY_SCHEMA,
    LINEAGE_TRANSITION_SCHEMA,
    PEC_SCHEMA,
    RECOVERY_AUTHORITY_SCHEMA,
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
    online_lineage_authority,
    recovery_authority_of,
)
from release_adapter import adapt_release  # noqa: E402
from release_verifier import validate_receipt_report, verify_release_dir  # noqa: E402

# --- team input ------------------------------------------------------------


def _prompt_existing_private_key_passphrase(path):
    """Read one private-key passphrase only from an interactive terminal."""
    if not sys.stdin.isatty():
        raise ValueError("PRIVATE_KEY_PASSPHRASE_REQUIRED")
    try:
        phrase = getpass.getpass(f"Passphrase for {path}: ")
    except (EOFError, KeyboardInterrupt) as exc:
        raise ValueError("PRIVATE_KEY_PASSPHRASE_CANCELLED") from exc
    if not phrase:
        raise ValueError("PRIVATE_KEY_PASSPHRASE_REQUIRED")
    return phrase.encode("utf-8")


def _prompt_new_private_key_passphrase():
    """Read and confirm a new private-key passphrase without serializing it."""
    if not sys.stdin.isatty():
        raise ValueError("PRIVATE_KEY_PASSPHRASE_REQUIRED")
    try:
        first = getpass.getpass("New private-key passphrase: ")
        second = getpass.getpass("Confirm private-key passphrase: ")
    except (EOFError, KeyboardInterrupt) as exc:
        raise ValueError("PRIVATE_KEY_PASSPHRASE_CANCELLED") from exc
    if not first:
        raise ValueError("PRIVATE_KEY_PASSPHRASE_REQUIRED")
    if first != second:
        raise ValueError("PRIVATE_KEY_PASSPHRASE_CONFIRMATION_MISMATCH")
    return first.encode("utf-8")


def load_signing_key(path, passphrase_cache=None):
    """Load a key, prompting once per command invocation when it is encrypted."""
    try:
        return load_private_key(path)
    except PrivateKeyPassphraseRequired:
        cache_key = str(pathlib.Path(path).resolve())
        password = (
            passphrase_cache.get(cache_key)
            if passphrase_cache is not None
            else None
        )
        if password is None:
            password = _prompt_existing_private_key_passphrase(path)
    try:
        key = load_private_key(path, password=password)
    except PrivateKeyPassphraseInvalid as exc:
        if passphrase_cache is not None:
            passphrase_cache.pop(cache_key, None)
        raise ValueError("PRIVATE_KEY_PASSPHRASE_INVALID") from exc
    if passphrase_cache is not None:
        passphrase_cache[cache_key] = password
    return key


def private_key_error_code(exc):
    """Keep expected passphrase failures distinct from malformed key material."""
    code = str(exc)
    if code in {
        "PRIVATE_KEY_PASSPHRASE_REQUIRED",
        "PRIVATE_KEY_PASSPHRASE_CANCELLED",
        "PRIVATE_KEY_PASSPHRASE_INVALID",
        "PRIVATE_KEY_PASSPHRASE_CONFIRMATION_MISMATCH",
    }:
        return code
    return "PRIVATE_KEY_INVALID"


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


def team_from_public_keys(key_paths, roles=None, corresponding=None):
    """Build an ordered public team declaration without handling private keys."""
    require(bool(key_paths), "TEAM_PUBLIC_KEYS_REQUIRED")
    roles = list(roles or [])
    require(not roles or len(roles) == len(key_paths), "TEAM_ROLE_COUNT_MISMATCH")
    corresponding = 1 if corresponding is None else corresponding
    require(
        isinstance(corresponding, int)
        and not isinstance(corresponding, bool)
        and 1 <= corresponding <= len(key_paths),
        "TEAM_CORRESPONDING_SLOT_INVALID",
    )
    authors = []
    for index, raw_path in enumerate(key_paths, 1):
        path = pathlib.Path(raw_path)
        require(path.is_file(), "TEAM_PUBLIC_KEY_NOT_FILE")
        try:
            public_key = load_public_key_bytes(path.read_bytes())
        except (OSError, TypeError, ValueError) as exc:
            raise ValueError("TEAM_PUBLIC_KEY_INVALID") from exc
        require(isinstance(public_key, Ed25519PublicKey), "TEAM_PUBLIC_KEY_INVALID")
        role = roles[index - 1].strip() if roles else (
            "sole" if len(key_paths) == 1 else "co-author"
        )
        require(bool(role), "TEAM_ROLE_INVALID")
        authors.append({
            "key_id": key_id_of(public_key),
            "public_key": public_pem(public_key).decode("ascii"),
            "role": role,
            "corresponding": index == corresponding,
        })
    key_ids = [author["key_id"] for author in authors]
    require(len(key_ids) == len(set(key_ids)), "TEAM_DUPLICATE_KEY")
    return {"schema": TEAM_SCHEMA, "authors": authors}


def resolve_team_input(args):
    """Resolve either an existing declaration or ordered public-key inputs."""
    if getattr(args, "team", None):
        require(
            not getattr(args, "role", None)
            and getattr(args, "corresponding", None) is None,
            "TEAM_OPTIONS_REQUIRE_PUBLIC_KEYS",
        )
        return load_team(args.team)
    return team_from_public_keys(
        getattr(args, "public_key", None),
        getattr(args, "role", None),
        getattr(args, "corresponding", None),
    )


def apply_contribution_specs(team, specs):
    """Apply repeatable SLOT:CONTRIBUTION declarations to an ordered team."""
    for spec in list(specs or []):
        require(isinstance(spec, str) and ":" in spec, "CONTRIBUTION_FORMAT")
        slot_text, contribution = spec.split(":", 1)
        try:
            slot = int(slot_text)
        except ValueError as exc:
            raise ValueError("CONTRIBUTION_SLOT_INVALID") from exc
        contribution = contribution.strip()
        require(1 <= slot <= len(team["authors"]), "CONTRIBUTION_SLOT_INVALID")
        require(bool(contribution), "CONTRIBUTION_INVALID")
        values = team["authors"][slot - 1].setdefault("contributions", [])
        require(contribution not in values, "CONTRIBUTION_DUPLICATE")
        values.append(contribution)
    return team


def ai_use_from_args(args, author_key_ids):
    """Create a validated AI-use declaration from ergonomic CLI arguments."""
    tools = list(getattr(args, "ai_tool", None) or [])
    purposes = list(getattr(args, "ai_purpose", None) or [])
    reviewer_slots = list(getattr(args, "ai_reviewed_by", None) or [])
    for values, code in (
        (tools, "AI_TOOL_INVALID"),
        (purposes, "AI_PURPOSE_INVALID"),
    ):
        require(
            all(isinstance(value, str) and value.strip() == value and value for value in values)
            and len(values) == len(set(values)),
            code,
        )
    require(len(reviewer_slots) == len(set(reviewer_slots)), "AI_REVIEWER_DUPLICATE")
    require(
        all(
            isinstance(slot, int)
            and not isinstance(slot, bool)
            and 1 <= slot <= len(author_key_ids)
            for slot in reviewer_slots
        ),
        "AI_REVIEWER_SLOT_INVALID",
    )
    used = bool(tools or purposes or reviewer_slots)
    require(not used or (tools and purposes), "AI_USE_DETAILS_REQUIRED")
    return {
        "used": used,
        "purposes": purposes,
        "tools": tools,
        "human_review_key_ids": [author_key_ids[slot - 1] for slot in reviewer_slots],
    }


def resolve_recovery_authority(args, parent_root, parent_release, author_key_ids):
    """Resolve an explicit, inherited, or cleared recovery-key commitment."""
    paths = list(getattr(args, "recovery_public_key", None) or [])
    threshold = getattr(args, "recovery_threshold", None)
    clear = bool(getattr(args, "clear_recovery", False))
    require(
        not (clear and (paths or threshold is not None)),
        "RECOVERY_OPTIONS_CONFLICT",
    )
    require(
        not clear or parent_release is not None,
        "RECOVERY_CLEAR_WITHOUT_PARENT",
    )
    parent_recovery = (
        recovery_authority_of(parent_release)
        if parent_release is not None
        else None
    )
    public_keys = {}
    if paths:
        for raw_path in paths:
            path = pathlib.Path(raw_path)
            require(path.is_file(), "RECOVERY_PUBLIC_KEY_NOT_FILE")
            try:
                public_key = load_public_key_bytes(path.read_bytes())
            except (OSError, TypeError, ValueError) as exc:
                raise ValueError("RECOVERY_PUBLIC_KEY_INVALID") from exc
            require(
                isinstance(public_key, Ed25519PublicKey),
                "RECOVERY_PUBLIC_KEY_INVALID",
            )
            key_id = key_id_of(public_key)
            require(key_id not in public_keys, "RECOVERY_DUPLICATE_KEY")
            public_keys[key_id] = public_pem(public_key)
        resolved_threshold = len(public_keys) if threshold is None else threshold
    elif parent_recovery is not None and not clear:
        require(parent_root is not None, "RECOVERY_PARENT_ROOT_MISSING")
        for key_id in parent_recovery["key_ids"]:
            path = parent_root / f"recovery-public-keys/{key_id}.pub"
            try:
                public_key = load_public_key_bytes(path.read_bytes())
            except (OSError, TypeError, ValueError) as exc:
                raise ValueError("PARENT_RECOVERY_PUBLIC_KEY_INVALID") from exc
            require(key_id_of(public_key) == key_id, "PUBLIC_KEY_ID_MISMATCH")
            public_keys[key_id] = public_pem(public_key)
        resolved_threshold = (
            parent_recovery["threshold"] if threshold is None else threshold
        )
    else:
        require(threshold is None, "RECOVERY_THRESHOLD_WITHOUT_KEYS")
        return None, {}
    require(
        isinstance(resolved_threshold, int)
        and not isinstance(resolved_threshold, bool)
        and 1 <= resolved_threshold <= len(public_keys),
        "RECOVERY_THRESHOLD_INVALID",
    )
    require(
        set(public_keys).isdisjoint(author_key_ids),
        "RECOVERY_AUTHORITY_NOT_DISJOINT",
    )
    authority = {
        "schema": RECOVERY_AUTHORITY_SCHEMA,
        "key_ids": sorted(public_keys),
        "threshold": resolved_threshold,
    }
    return authority, public_keys


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
    name = args.name or "author"
    key_path = out_dir / f"{name}.key"
    if key_path.exists():
        return EXIT_STATE_CONFLICT, "KEY_EXISTS", {"path": str(key_path)}
    try:
        password = (
            _prompt_new_private_key_passphrase()
            if getattr(args, "encrypt", False)
            else None
        )
    except ValueError as exc:
        return EXIT_USAGE, private_key_error_code(exc), {}
    out_dir.mkdir(parents=True, exist_ok=True)
    key = Ed25519PrivateKey.generate()
    pub = key.public_key()
    kid = key_id_of(pub)
    private_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=(
            serialization.BestAvailableEncryption(password)
            if password is not None
            else serialization.NoEncryption()
        ),
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
        "encrypted": password is not None,
    }


def cmd_init(args):
    content = pathlib.Path(args.content)
    if not content.is_file():
        return EXIT_USAGE, "CONTENT_MISSING", {}
    try:
        team = resolve_team_input(args)
        apply_contribution_specs(team, getattr(args, "contribution", None))
    except ValueError as e:
        return EXIT_USAGE, str(e), {}
    content_bytes = content.read_bytes()
    if len(content_bytes) == 0:
        return EXIT_USAGE, "CONTENT_EMPTY", {}
    content_sha256 = hashlib.sha256(content_bytes).hexdigest()
    key_ids = [a["key_id"] for a in team["authors"]]
    try:
        ai_use = ai_use_from_args(args, key_ids)
    except ValueError as e:
        return EXIT_USAGE, str(e), {}
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
    recovery_authority, recovery_public_keys = resolve_recovery_authority(
        args,
        parent_root,
        parent_release,
        key_ids,
    )
    content_rel = f"paper/{content_sha256}"
    out = pathlib.Path(args.out)
    if out.exists() and any(out.iterdir()):
        return EXIT_STATE_CONFLICT, "OUTPUT_EXISTS", {}

    release = build_release(
        work_id, content_sha256, content_rel, team,
        parent_release=parent_release,
        line=line,
        lineage_threshold=getattr(args, "lineage_threshold", None),
        recovery_authority=recovery_authority,
        ai_use=ai_use,
    )
    adapted = adapt_release(release)
    governance = build_governance(
        work_id, content_sha256, team, ai_use=ai_use
    )
    gov_digest = digest(governance)
    ai_digest = digest(governance["ai_use_declaration"])
    pec = build_pec(
        work_id, adapted, gov_digest, content_sha256, ai_digest, key_ids,
        predecessor_pec=parent_pec,
        allow_delegated_approval=bool(
            getattr(args, "allow_delegated_approval", False)
        ),
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
    if recovery_public_keys:
        (out / "recovery-public-keys").mkdir(exist_ok=True)
        for key_id, public_key_bytes in recovery_public_keys.items():
            (out / f"recovery-public-keys/{key_id}.pub").write_bytes(
                public_key_bytes
            )
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
        parent_recovery = recovery_authority_of(parent_release)
        if parent_recovery is not None:
            (out / "lineage/parent-recovery-public-keys").mkdir(parents=True)
            (out / "lineage/recovery-authorizations").mkdir(parents=True)
            for kid in parent_recovery["key_ids"]:
                source = parent_root / f"recovery-public-keys/{kid}.pub"
                public_key = load_public_key_bytes(source.read_bytes())
                require(key_id_of(public_key) == kid, "PUBLIC_KEY_ID_MISMATCH")
                (out / f"lineage/parent-recovery-public-keys/{kid}.pub").write_bytes(
                    source.read_bytes()
                )
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
        "required_recovery_authorization_threshold": (
            parent_recovery["threshold"]
            if parent_release is not None and parent_recovery is not None
            else 0
        ),
        "received_recovery_authorizations": [],
    })
    return EXIT_OK, "initialized", {
        "work_id": work_id,
        "release_digest": adapted["digest"],
        "version": adapted["version"],
        "line": adapted["line"],
        "parent_release_id": release["parent_release_id"],
        "state": "awaiting-approvals",
        "recovery_authority": recovery_authority,
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
        key = load_signing_key(args.key, getattr(args, "passphrase_cache", None))
    except (TypeError, ValueError) as exc:
        return EXIT_USAGE, private_key_error_code(exc), {}
    release = read_canonical(root / "release/release.json")
    governance = read_canonical(root / "governance/statement.json")
    pec = read_canonical(root / "pec/pec.json")
    lineage = load_lineage_structure(root, release, governance, pec)
    if lineage is None:
        return EXIT_STATE_CONFLICT, "GENESIS_HAS_NO_LINEAGE_TRANSITION", {}
    if (
        lineage["parent_authority"] == lineage["child_authority"]
        and "AUTHORIZED_TARGET_APPROVAL"
        not in pec["claim_policy"]["permitted_outcomes"]
    ):
        return EXIT_STATE_CONFLICT, "SEPARATE_LINEAGE_AUTHORIZATION_NOT_REQUIRED", {}
    recovery_dir = root / "lineage/recovery-authorizations"
    if recovery_dir.is_dir() and any(recovery_dir.glob("*.cose")):
        return EXIT_STATE_CONFLICT, "LINEAGE_AUTHORIZATION_METHOD_AMBIGUOUS", {}
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


def cmd_recover(args):
    """Authorize one exact authority-changing edge with precommitted recovery."""
    root = pathlib.Path(args.release_dir)
    if path_is_within(args.key, root):
        return EXIT_USAGE, "PRIVATE_KEY_INSIDE_RELEASE", {}
    state = read_canonical(root / "state.json")
    if state.get("state") != "awaiting-approvals":
        return EXIT_STATE_CONFLICT, "STATE_CONFLICT", {"state": state.get("state")}
    try:
        key = load_signing_key(args.key, getattr(args, "passphrase_cache", None))
    except (TypeError, ValueError) as exc:
        return EXIT_USAGE, private_key_error_code(exc), {}
    release = read_canonical(root / "release/release.json")
    governance = read_canonical(root / "governance/statement.json")
    pec = read_canonical(root / "pec/pec.json")
    lineage = load_lineage_structure(root, release, governance, pec)
    if lineage is None:
        return EXIT_STATE_CONFLICT, "GENESIS_HAS_NO_LINEAGE_TRANSITION", {}
    if (
        online_lineage_authority(lineage["parent_authority"])
        == online_lineage_authority(lineage["child_authority"])
    ):
        return EXIT_STATE_CONFLICT, "RECOVERY_REQUIRES_ONLINE_AUTHORITY_CHANGE", {}
    recovery = lineage["parent_recovery_authority"]
    if recovery is None:
        return EXIT_VERIFY_FAIL, "RECOVERY_AUTHORITY_NOT_PRECOMMITTED", {}
    ordinary_dir = root / "lineage/authorizations"
    if ordinary_dir.is_dir() and any(ordinary_dir.glob("*.cose")):
        return EXIT_STATE_CONFLICT, "LINEAGE_AUTHORIZATION_METHOD_AMBIGUOUS", {}
    kid = key_id_of(key.public_key())
    if kid not in recovery["key_ids"]:
        return EXIT_VERIFY_FAIL, "UNKNOWN_RECOVERY_AUTHORITY_KEY", {"key_id": kid}
    directory = root / "lineage/recovery-authorizations"
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / f"{kid}.cose"
    if path.exists():
        return EXIT_STATE_CONFLICT, "DUPLICATE_RECOVERY_AUTHORIZATION", {"key_id": kid}
    path.write_bytes(cose.cose_sign1(canonical(lineage["transition"]), key))
    received = sorted(p.stem for p in directory.glob("*.cose"))
    state["received_recovery_authorizations"] = received
    write_canonical(root / "state.json", state)
    return EXIT_OK, "recovery transition authorized", {
        "key_id": kid,
        "received": len(received),
        "required_threshold": recovery["threshold"],
    }


def cmd_approve(args):
    root = pathlib.Path(args.release_dir)
    if path_is_within(args.key, root):
        return EXIT_USAGE, "PRIVATE_KEY_INSIDE_RELEASE", {}
    try:
        key = load_signing_key(args.key, getattr(args, "passphrase_cache", None))
    except (TypeError, ValueError) as e:
        return EXIT_USAGE, private_key_error_code(e), {}
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
    delegated_path = root / f"delegated-approvals/{kid}.cose"
    delegation_path = root / f"delegations/{kid}.json"
    if approval_path.exists() or delegated_path.exists() or delegation_path.exists():
        return EXIT_STATE_CONFLICT, "DUPLICATE_APPROVAL", {"key_id": kid}
    approval = cose.cose_sign1(canonical(target), key)
    approval_path.parent.mkdir(exist_ok=True)
    approval_path.write_bytes(approval)
    records, _ = verify_approval_records(root, adapted["author_key_ids"], target)
    received = {record["author_key_id"] for record in records}
    state["received_approvals"] = sorted(received)
    write_canonical(root / "state.json", state)
    return EXIT_OK, "approved", {"key_id": kid, "remaining": sorted(set(adapted["author_key_ids"]) - received)}


def cmd_delegate_approval(args):
    """Let an author authorize a distinct key for this exact approval target."""
    root = pathlib.Path(args.release_dir)
    if path_is_within(args.author_key, root):
        return EXIT_USAGE, "PRIVATE_KEY_INSIDE_RELEASE", {}
    state = read_canonical(root / "state.json")
    if state.get("state") != "awaiting-approvals":
        return EXIT_STATE_CONFLICT, "STATE_CONFLICT", {"state": state.get("state")}
    try:
        author_key = load_signing_key(
            args.author_key, getattr(args, "passphrase_cache", None)
        )
        delegate_public_bytes = pathlib.Path(args.delegate_public_key).read_bytes()
        delegate_public_key = load_public_key_bytes(delegate_public_bytes)
    except (TypeError, ValueError) as exc:
        return EXIT_USAGE, private_key_error_code(exc), {}
    author_key_id = key_id_of(author_key.public_key())
    delegate_key_id = key_id_of(delegate_public_key)
    release = read_canonical(root / "release/release.json")
    governance = read_canonical(root / "governance/statement.json")
    pec = read_canonical(root / "pec/pec.json")
    target = read_canonical(root / "approval/target.json")
    adapted = adapt_release(release)
    check_release_key_paths(release)
    check_bindings(pec, adapted, governance, release)
    lineage = load_lineage_structure(root, release, governance, pec)
    check_approval_target(
        target, release, governance, pec, adapted,
        lineage["transition"] if lineage is not None else None,
    )
    if author_key_id not in adapted["author_key_ids"]:
        return EXIT_VERIFY_FAIL, "UNKNOWN_AUTHOR_KEY", {"key_id": author_key_id}
    if "AUTHORIZED_TARGET_APPROVAL" not in pec["claim_policy"]["permitted_outcomes"]:
        return EXIT_STATE_CONFLICT, "DELEGATED_APPROVAL_NOT_ENABLED", {}
    if delegate_key_id in adapted["author_key_ids"]:
        return EXIT_USAGE, "DELEGATE_IS_AUTHOR_KEY", {"key_id": delegate_key_id}
    if (root / f"approvals/{author_key_id}.cose").exists():
        return EXIT_STATE_CONFLICT, "DIRECT_APPROVAL_ALREADY_EXISTS", {
            "key_id": author_key_id
        }
    delegation_json = root / f"delegations/{author_key_id}.json"
    delegation_cose = root / f"delegations/{author_key_id}.cose"
    if delegation_json.exists() or delegation_cose.exists():
        return EXIT_STATE_CONFLICT, "DELEGATION_ALREADY_EXISTS", {
            "key_id": author_key_id
        }
    delegation = approval_delegation.build(
        author_key_id, delegate_key_id, target
    )
    (root / "delegations").mkdir(exist_ok=True)
    (root / "delegated-approvals").mkdir(exist_ok=True)
    (root / "delegate-public-keys").mkdir(exist_ok=True)
    write_canonical(delegation_json, delegation)
    delegation_cose.write_bytes(
        cose.cose_sign1(canonical(delegation), author_key)
    )
    delegate_path = root / f"delegate-public-keys/{delegate_key_id}.pub"
    if delegate_path.exists():
        existing = load_public_key_bytes(delegate_path.read_bytes())
        require(key_id_of(existing) == delegate_key_id, "DELEGATE_PUBLIC_KEY_ID_MISMATCH")
    else:
        delegate_path.write_bytes(public_pem(delegate_public_key))
    return EXIT_OK, "exact-target approval delegated", {
        "author_key_id": author_key_id,
        "delegate_key_id": delegate_key_id,
        "approval_target_digest": digest(target),
        "scope": "approve-exact-target",
        "redelegation": False,
    }


def cmd_approve_as(args):
    """Exercise one exact-target approval delegation."""
    root = pathlib.Path(args.release_dir)
    if path_is_within(args.key, root):
        return EXIT_USAGE, "PRIVATE_KEY_INSIDE_RELEASE", {}
    state = read_canonical(root / "state.json")
    if state.get("state") != "awaiting-approvals":
        return EXIT_STATE_CONFLICT, "STATE_CONFLICT", {"state": state.get("state")}
    try:
        delegate_key = load_signing_key(
            args.key, getattr(args, "passphrase_cache", None)
        )
    except (TypeError, ValueError) as exc:
        return EXIT_USAGE, private_key_error_code(exc), {}
    author_key_id = validate_key_id(args.for_author)
    target = read_canonical(root / "approval/target.json")
    delegation = read_canonical(root / f"delegations/{author_key_id}.json")
    delegate_key_id = key_id_of(delegate_key.public_key())
    approval_delegation.validate(
        delegation,
        target,
        author_key_id=author_key_id,
        delegate_key_id=delegate_key_id,
    )
    # Validate the author's certificate and the bound delegate public key
    # before allowing the delegated signature to be written.
    release = read_canonical(root / "release/release.json")
    governance = read_canonical(root / "governance/statement.json")
    pec = read_canonical(root / "pec/pec.json")
    adapted = adapt_release(release)
    check_release_key_paths(release)
    check_bindings(pec, adapted, governance, release)
    lineage = load_lineage_structure(root, release, governance, pec)
    check_approval_target(
        target, release, governance, pec, adapted,
        lineage["transition"] if lineage is not None else None,
    )
    records, _ = verify_approval_records(root, adapted["author_key_ids"], target)
    if any(record["author_key_id"] == author_key_id for record in records):
        return EXIT_STATE_CONFLICT, "DUPLICATE_APPROVAL", {"key_id": author_key_id}
    path = root / f"delegated-approvals/{author_key_id}.cose"
    if path.exists() or (root / f"approvals/{author_key_id}.cose").exists():
        return EXIT_STATE_CONFLICT, "DUPLICATE_APPROVAL", {"key_id": author_key_id}
    path.write_bytes(cose.cose_sign1(canonical(target), delegate_key))
    records, missing = verify_approval_records(root, adapted["author_key_ids"], target)
    state["received_approvals"] = sorted(
        record["author_key_id"] for record in records
    )
    write_canonical(root / "state.json", state)
    return EXIT_OK, "approved by exact-target delegate", {
        "author_key_id": author_key_id,
        "delegate_key_id": delegate_key_id,
        "remaining": missing,
    }


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
    try:
        approval_records, missing = verify_approval_records(root, required, target)
    except Exception as exc:
        return EXIT_VERIFY_FAIL, "APPROVAL_INVALID", {"error": str(exc)}
    if missing:
        return EXIT_INCOMPLETE, "APPROVALS_INCOMPLETE", {"missing_keys": missing}
    try:
        direct_approvals = {
            record["author_key_id"] for record in approval_records
            if record["mode"] == "direct"
        }
        lineage_result = verify_lineage_authorization(
            root, lineage, direct_approvals
        )
    except ValueError as exc:
        if str(exc) == "UNAUTHORIZED_SUCCESSOR":
            recovery_files = (
                list((root / "lineage/recovery-authorizations").glob("*.cose"))
                if (root / "lineage/recovery-authorizations").is_dir()
                else []
            )
            recovery = (
                lineage.get("parent_recovery_authority")
                if lineage is not None
                else None
            )
            return EXIT_INCOMPLETE, "LINEAGE_AUTHORIZATION_INCOMPLETE", {
                "authorization_method": (
                    "recovery" if recovery_files else "predecessor"
                ),
                "required_threshold": (
                    recovery["threshold"]
                    if recovery_files and recovery is not None
                    else lineage["parent_authority"]["threshold"]
                ),
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
        if lineage_result["authorization_directory"] is not None else []
    )
    lineage_directory = (
        lineage_result["authorization_directory"] or "lineage/authorizations"
    )
    if all(record["mode"] == "direct" for record in approval_records):
        approval_set_obj = approval_set.build(
            staging, target, required, separate_lineage_keys,
            lineage_directory=lineage_directory,
        )
    else:
        approval_set_obj = approval_set.build_with_approval_records(
            staging, target, approval_records, separate_lineage_keys,
            lineage_directory=lineage_directory,
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


def team_from_private_keys(key_paths, passphrase_cache=None):
    """Build the public team declaration used by one-command flows."""
    try:
        keys = [load_signing_key(path, passphrase_cache) for path in key_paths]
    except (TypeError, ValueError) as e:
        raise ValueError(private_key_error_code(e)) from e
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
        passphrase_cache = {}
        team, key_ids = team_from_private_keys(args.key, passphrase_cache)
    except ValueError as exc:
        return EXIT_USAGE, str(exc), {}
    with tempfile.TemporaryDirectory(prefix="acsd-team-") as temp_dir:
        team_path = pathlib.Path(temp_dir) / "team.json"
        team_path.write_text(json.dumps(team), encoding="utf-8")
        code, message, initialized = cmd_init(argparse.Namespace(
            content=args.content, team=str(team_path), out=str(out), parent=None,
            line="main", lineage_threshold=getattr(args, "lineage_threshold", None),
            recovery_public_key=getattr(args, "recovery_public_key", None),
            recovery_threshold=getattr(args, "recovery_threshold", None),
            clear_recovery=False,
            contribution=getattr(args, "contribution", None),
            ai_tool=getattr(args, "ai_tool", None),
            ai_purpose=getattr(args, "ai_purpose", None),
            ai_reviewed_by=getattr(args, "ai_reviewed_by", None),
        ))
    if code != EXIT_OK:
        return code, message, initialized
    for key_path in args.key:
        code, message, approved = cmd_approve(argparse.Namespace(
            release_dir=str(out), key=key_path, passphrase_cache=passphrase_cache,
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
    parent_keys = list(getattr(args, "parent_key", None) or [])
    recovery_keys = list(getattr(args, "recovery_key", None) or [])
    if parent_keys and recovery_keys:
        return EXIT_USAGE, "LINEAGE_AUTHORIZATION_METHOD_AMBIGUOUS", {}
    for key_path in (
        list(args.key)
        + parent_keys
        + recovery_keys
    ):
        if path_is_within(key_path, out):
            return EXIT_USAGE, "PRIVATE_KEY_INSIDE_RELEASE", {}
    try:
        passphrase_cache = {}
        team, key_ids = team_from_private_keys(args.key, passphrase_cache)
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
            recovery_public_key=getattr(args, "recovery_public_key", None),
            recovery_threshold=getattr(args, "recovery_threshold", None),
            clear_recovery=getattr(args, "clear_recovery", False),
            contribution=getattr(args, "contribution", None),
            ai_tool=getattr(args, "ai_tool", None),
            ai_purpose=getattr(args, "ai_purpose", None),
            ai_reviewed_by=getattr(args, "ai_reviewed_by", None),
        ))
    if code != EXIT_OK:
        return code, message, initialized
    release = read_canonical(out / "release/release.json")
    governance = read_canonical(out / "governance/statement.json")
    pec = read_canonical(out / "pec/pec.json")
    lineage = load_lineage_structure(out, release, governance, pec)
    if recovery_keys and (
        online_lineage_authority(lineage["parent_authority"])
        == online_lineage_authority(lineage["child_authority"])
    ):
        return EXIT_STATE_CONFLICT, "RECOVERY_REQUIRES_ONLINE_AUTHORITY_CHANGE", {}
    if lineage["parent_authority"] != lineage["child_authority"]:
        for key_path in parent_keys:
            code, message, authorized = cmd_authorize(argparse.Namespace(
                release_dir=str(out), key=key_path, passphrase_cache=passphrase_cache,
            ))
            if code != EXIT_OK:
                return code, message, authorized
        for key_path in recovery_keys:
            code, message, authorized = cmd_recover(argparse.Namespace(
                release_dir=str(out), key=key_path, passphrase_cache=passphrase_cache,
            ))
            if code != EXIT_OK:
                return code, message, authorized
    for key_path in args.key:
        code, message, approved = cmd_approve(argparse.Namespace(
            release_dir=str(out), key=key_path, passphrase_cache=passphrase_cache,
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
            include_appraisal_transcript=getattr(
                args, "emit_appraisal_transcript", False
            ),
        )
    except FileNotFoundError as e:
        return EXIT_USAGE, f"MISSING:{e.filename}", {}


def cmd_review(args):
    """Show the exact human-relevant facts bound by an approval signature."""
    root = pathlib.Path(args.release_dir)
    code, message, verification = verify_release_dir(root)
    if code not in {EXIT_OK, EXIT_INCOMPLETE}:
        return code, "RELEASE_NOT_REVIEWABLE", {
            "verifier_message": message,
            "verifier_data": verification,
        }
    release = read_canonical(root / "release/release.json")
    governance = read_canonical(root / "governance/statement.json")
    pec = read_canonical(root / "pec/pec.json")
    target = read_canonical(root / "approval/target.json")
    content = root / release["content"]["path"]
    by_key = {author["key_id"]: author for author in release["authors"]}
    authors = []
    for entry in governance["byline"]:
        release_author = by_key[entry["key_id"]]
        authors.append({
            "slot": entry["slot"],
            "key_id": entry["key_id"],
            "role": entry["role"],
            "corresponding": (
                entry["key_id"]
                == governance["corresponding_author"]["key_id"]
            ),
            "contributions": release_author.get("contributions", []),
        })
    selected_author = None
    if getattr(args, "for_author", None):
        requested = validate_key_id(args.for_author)
        selected_author = next(
            (author for author in authors if author["key_id"] == requested),
            None,
        )
        if selected_author is None:
            return EXIT_USAGE, "UNKNOWN_AUTHOR_KEY", {"key_id": requested}
    return EXIT_OK, "approval target reviewed", {
        "verification_status": message,
        "state": verification.get("state"),
        "work_id": release["work_id"],
        "version": release["slot"]["version"],
        "line": release["slot"]["line"],
        "parent_release_id": release.get("parent_release_id"),
        "manuscript_path": release["content"]["path"],
        "manuscript_sha256": release["content"]["sha256"],
        "manuscript_bytes": content.stat().st_size,
        "approval_target_digest": digest(target),
        "authors": authors,
        "selected_author": selected_author,
        "ai_use_declaration": governance["ai_use_declaration"],
        "permitted_outcomes": pec["claim_policy"]["permitted_outcomes"],
        "non_claims": pec["claim_policy"]["global_non_claims"],
        "signature_scope": (
            "A direct approval signs this exact target: manuscript digest, "
            "ordered byline and roles, corresponding-author choice, AI-use "
            "declaration, claim policy, and any lineage transition."
        ),
    }


def emit_review_human(message, data):
    """Render a compact signing checklist while JSON keeps structured data."""
    print(f"review: {message} (exit 0)")
    print(f"  Work: {data['work_id']}  line={data['line']}  version={data['version']}")
    print(f"  State: {data['state']} ({data['verification_status']})")
    print(f"  Manuscript: {data['manuscript_path']} ({data['manuscript_bytes']} bytes)")
    print(f"  SHA-256: {data['manuscript_sha256']}")
    print(f"  Approval target: sha256:{data['approval_target_digest']}")
    if data["parent_release_id"] is not None:
        print(f"  Parent: {data['parent_release_id']}")
    print("  Ordered byline:")
    selected = data.get("selected_author")
    selected_key = selected["key_id"] if selected is not None else None
    for author in data["authors"]:
        flags = []
        if author["corresponding"]:
            flags.append("corresponding")
        if author["key_id"] == selected_key:
            flags.append("selected")
        suffix = f" [{', '.join(flags)}]" if flags else ""
        print(
            f"    {author['slot']}. {author['role']}  {author['key_id']}{suffix}"
        )
        if author["contributions"]:
            print(f"       contributions: {', '.join(author['contributions'])}")
    ai = data["ai_use_declaration"]
    print(f"  AI use declared: {'yes' if ai.get('used') else 'no'}")
    if ai.get("used"):
        print(f"    purposes: {', '.join(ai.get('purposes', [])) or '(none listed)'}")
        print(f"    tools: {', '.join(ai.get('tools', [])) or '(none listed)'}")
    print(f"  Signature scope: {data['signature_scope']}")
    print(f"  Explicit non-claims: {', '.join(data['non_claims'])}")


def cmd_author_approve(args):
    """Validate, summarize, confirm, then approve directly or delegate once."""
    root = pathlib.Path(args.release_dir)
    code, message, review = cmd_review(argparse.Namespace(
        release_dir=str(root), for_author=None
    ))
    if code != EXIT_OK:
        return code, message, review
    if path_is_within(args.key, root):
        return EXIT_USAGE, "PRIVATE_KEY_INSIDE_RELEASE", {}
    passphrase_cache = {}
    try:
        author_key = load_signing_key(args.key, passphrase_cache)
    except (TypeError, ValueError) as exc:
        return EXIT_USAGE, private_key_error_code(exc), {}
    author_key_id = key_id_of(author_key.public_key())
    selected = next(
        (author for author in review["authors"] if author["key_id"] == author_key_id),
        None,
    )
    if selected is None:
        return EXIT_VERIFY_FAIL, "UNKNOWN_AUTHOR_KEY", {"key_id": author_key_id}
    review["selected_author"] = selected
    delegated = bool(getattr(args, "delegate_public_key", None))
    confirmation_word = "DELEGATE" if delegated else "APPROVE"
    if not getattr(args, "yes", False):
        if getattr(args, "json", False) or not sys.stdin.isatty():
            return EXIT_USAGE, "APPROVAL_CONFIRMATION_REQUIRED", {
                "approval_target_digest": review["approval_target_digest"],
                "required_confirmation": confirmation_word,
            }
        emit_review_human("approval target reviewed", review)
        action = (
            "delegate approval of only this exact target"
            if delegated else "approve this exact target directly"
        )
        print(f"  Requested action: {action}")
        try:
            entered = input(f"Type {confirmation_word} to continue: ").strip()
        except (EOFError, KeyboardInterrupt):
            entered = ""
        if entered != confirmation_word:
            return EXIT_STATE_CONFLICT, "APPROVAL_NOT_CONFIRMED", {
                "approval_target_digest": review["approval_target_digest"]
            }
    if delegated:
        code, message, result = cmd_delegate_approval(argparse.Namespace(
            release_dir=str(root),
            author_key=args.key,
            delegate_public_key=args.delegate_public_key,
            passphrase_cache=passphrase_cache,
        ))
    else:
        code, message, result = cmd_approve(argparse.Namespace(
            release_dir=str(root), key=args.key, passphrase_cache=passphrase_cache
        ))
    result = dict(result)
    result["reviewed_approval_target_digest"] = review["approval_target_digest"]
    result["author_slot"] = selected["slot"]
    result["action"] = "delegate-exact-target" if delegated else "direct-approval"
    return code, message, result


def _copy_payload_tree(source, destination):
    """Copy only strict regular payload files, never links or a stale manifest."""
    source = pathlib.Path(source)
    destination = pathlib.Path(destination)
    destination.mkdir(parents=True, exist_ok=True)
    for name, path in iter_payload_files(source):
        target = destination.joinpath(*name.split("/"))
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(path, target)


def _request_candidate_names(release):
    """Return the exact public object set needed to review one candidate."""
    names = {
        "state.json",
        "team.json",
        "release/release.json",
        "governance/statement.json",
        "pec/pec.json",
        "approval/target.json",
        release["content"]["path"],
    }
    names.update(
        f"public-keys/{author['key_id']}.pub" for author in release["authors"]
    )
    recovery = recovery_authority_of(release)
    if recovery is not None:
        names.update(
            f"recovery-public-keys/{key_id}.pub"
            for key_id in recovery["key_ids"]
        )
    if release.get("parent_release_id") is not None:
        names.update({
            "lineage/parent-release.json",
            "lineage/parent-pec.json",
            "lineage/transition.json",
        })
    return names


def _copy_request_candidate(source, destination):
    """Copy an allowlisted review surface and normalize its mutable state."""
    source = pathlib.Path(source)
    destination = pathlib.Path(destination)
    release = read_canonical(source / "release/release.json")
    names = _request_candidate_names(release)
    if release.get("parent_release_id") is not None:
        parent_release = read_canonical(source / "lineage/parent-release.json")
        parent_authority = lineage_authority_of(parent_release)
        names.update(
            f"lineage/parent-public-keys/{key_id}.pub"
            for key_id in parent_authority["key_ids"]
        )
        parent_recovery = recovery_authority_of(parent_release)
        if parent_recovery is not None:
            names.update(
                f"lineage/parent-recovery-public-keys/{key_id}.pub"
                for key_id in parent_recovery["key_ids"]
            )
    available = dict(iter_payload_files(source))
    require(names <= set(available), "APPROVAL_REQUEST_SOURCE_FILE_MISSING")
    destination.mkdir(parents=True, exist_ok=True)
    private_markers = (b"-----BEGIN PRIVATE KEY-----", b"-----BEGIN ENCRYPTED PRIVATE KEY-----")
    for name in sorted(names):
        raw = available[name].read_bytes()
        require(
            not any(marker in raw for marker in private_markers),
            "PRIVATE_KEY_MATERIAL_IN_RELEASE",
        )
        target = destination.joinpath(*name.split("/"))
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(raw)
    state = read_canonical(destination / "state.json")
    state["received_approvals"] = []
    state["received_lineage_authorizations"] = []
    state["received_recovery_authorizations"] = []
    write_canonical(destination / "state.json", state)


def _exchange_payload_names(root):
    return {name for name, _ in iter_payload_files(pathlib.Path(root))}


def cmd_export_approval_request(args):
    """Create a manifest-covered, private-key-free candidate snapshot."""
    root = pathlib.Path(args.release_dir)
    out = pathlib.Path(args.out)
    if out.exists():
        return EXIT_STATE_CONFLICT, "OUTPUT_EXISTS", {"path": str(out)}
    if path_is_within(out, root):
        return EXIT_USAGE, "REQUEST_OUTPUT_INSIDE_RELEASE", {}
    code, message, review = cmd_review(argparse.Namespace(
        release_dir=str(root), for_author=args.for_author
    ))
    if code != EXIT_OK:
        return code, message, review
    if review["state"] != "awaiting-approvals":
        return EXIT_STATE_CONFLICT, "STATE_CONFLICT", {"state": review["state"]}
    author_key_id = review["selected_author"]["key_id"]
    evidence_paths = (
        root / f"approvals/{author_key_id}.cose",
        root / f"delegated-approvals/{author_key_id}.cose",
        root / f"delegations/{author_key_id}.json",
        root / f"delegations/{author_key_id}.cose",
    )
    if any(path.exists() for path in evidence_paths):
        return EXIT_STATE_CONFLICT, "AUTHOR_ACTION_ALREADY_RECORDED", {
            "author_key_id": author_key_id
        }
    release = read_canonical(root / "release/release.json")
    adapted = adapt_release(release)
    request = approval_exchange.build_request(
        author_key_id,
        adapted["work_id"],
        adapted["digest"],
        review["approval_target_digest"],
    )
    out.parent.mkdir(parents=True, exist_ok=True)
    staging = pathlib.Path(tempfile.mkdtemp(prefix=".acsd-request-", dir=out.parent))
    try:
        _copy_request_candidate(root, staging / "candidate")
        write_canonical(staging / "request.json", request)
        (staging / "MANIFEST.sha256").write_bytes(
            build_manifest_text(staging).encode("ascii")
        )
        verify_manifest(staging)
        check_code, _, checked = cmd_review(argparse.Namespace(
            release_dir=str(staging / "candidate"), for_author=author_key_id
        ))
        require(check_code == EXIT_OK, "EXPORTED_REQUEST_SELF_CHECK_FAILED")
        require(
            checked["approval_target_digest"] == request["approval_target_digest"],
            "EXPORTED_REQUEST_TARGET_MISMATCH",
        )
        staging.rename(out)
    except Exception:
        shutil.rmtree(staging, ignore_errors=True)
        raise
    return EXIT_OK, "approval request exported", {
        "path": str(out),
        "author_key_id": author_key_id,
        "approval_target_digest": request["approval_target_digest"],
        "files": verify_manifest(out),
    }


def _load_approval_request(root):
    root = pathlib.Path(root)
    verify_manifest(root)
    require(
        all(name == "request.json" or name.startswith("candidate/")
            for name in _exchange_payload_names(root)),
        "APPROVAL_REQUEST_FILE_SET",
    )
    request = approval_exchange.validate_request(read_canonical(root / "request.json"))
    candidate_root = root / "candidate"
    candidate_release = read_canonical(candidate_root / "release/release.json")
    expected_candidate_names = _request_candidate_names(candidate_release)
    if candidate_release.get("parent_release_id") is not None:
        parent_release = read_canonical(candidate_root / "lineage/parent-release.json")
        parent_authority = lineage_authority_of(parent_release)
        expected_candidate_names.update(
            f"lineage/parent-public-keys/{key_id}.pub"
            for key_id in parent_authority["key_ids"]
        )
        parent_recovery = recovery_authority_of(parent_release)
        if parent_recovery is not None:
            expected_candidate_names.update(
                f"lineage/parent-recovery-public-keys/{key_id}.pub"
                for key_id in parent_recovery["key_ids"]
            )
    actual_candidate_names = {
        name[len("candidate/"):]
        for name in _exchange_payload_names(root)
        if name.startswith("candidate/")
    }
    require(
        actual_candidate_names == expected_candidate_names,
        "APPROVAL_REQUEST_CANDIDATE_FILE_SET",
    )
    code, message, review = cmd_review(argparse.Namespace(
        release_dir=str(candidate_root),
        for_author=request["author_key_id"],
    ))
    require(code == EXIT_OK, "APPROVAL_REQUEST_CANDIDATE_INVALID")
    require(review["work_id"] == request["work_id"], "APPROVAL_REQUEST_WORK_MISMATCH")
    require(
        review["approval_target_digest"] == request["approval_target_digest"],
        "APPROVAL_REQUEST_TARGET_MISMATCH",
    )
    release = candidate_release
    require(
        adapt_release(release)["digest"] == request["release_digest"],
        "APPROVAL_REQUEST_RELEASE_MISMATCH",
    )
    return request, review


def cmd_respond_approval_request(args):
    """Review a transported candidate and emit only the author's response."""
    request_root = pathlib.Path(args.request_dir)
    out = pathlib.Path(args.out)
    if out.exists():
        return EXIT_STATE_CONFLICT, "OUTPUT_EXISTS", {"path": str(out)}
    if path_is_within(out, request_root):
        return EXIT_USAGE, "RESPONSE_OUTPUT_INSIDE_REQUEST", {}
    request, _ = _load_approval_request(request_root)
    out.parent.mkdir(parents=True, exist_ok=True)
    work = pathlib.Path(tempfile.mkdtemp(prefix=".acsd-response-work-", dir=out.parent))
    staging = pathlib.Path(tempfile.mkdtemp(prefix=".acsd-response-", dir=out.parent))
    try:
        candidate = work / "candidate"
        _copy_payload_tree(request_root / "candidate", candidate)
        code, message, result = cmd_author_approve(argparse.Namespace(
            release_dir=str(candidate),
            key=args.key,
            delegate_public_key=getattr(args, "delegate_public_key", None),
            yes=getattr(args, "yes", False),
            json=getattr(args, "json", False),
        ))
        if code != EXIT_OK:
            return code, message, result
        require(
            result.get("author_slot") is not None,
            "APPROVAL_RESPONSE_AUTHOR_SLOT_MISSING",
        )
        mode = "delegation" if result["action"] == "delegate-exact-target" else "direct"
        author_key_id = request["author_key_id"]
        require(
            result.get("author_key_id", result.get("key_id")) == author_key_id,
            "APPROVAL_RESPONSE_AUTHOR_MISMATCH",
        )
        signer_key_id = (
            result["delegate_key_id"] if mode == "delegation" else author_key_id
        )
        response = approval_exchange.build_response(request, mode, signer_key_id)
        write_canonical(staging / "response.json", response)
        if mode == "direct":
            shutil.copyfile(
                candidate / f"approvals/{author_key_id}.cose",
                staging / "approval.cose",
            )
        else:
            shutil.copyfile(
                candidate / f"delegations/{author_key_id}.json",
                staging / "delegation.json",
            )
            shutil.copyfile(
                candidate / f"delegations/{author_key_id}.cose",
                staging / "delegation.cose",
            )
            shutil.copyfile(
                candidate / f"delegate-public-keys/{signer_key_id}.pub",
                staging / "delegate.pub",
            )
        (staging / "MANIFEST.sha256").write_bytes(
            build_manifest_text(staging).encode("ascii")
        )
        verify_manifest(staging)
        staging.rename(out)
    finally:
        shutil.rmtree(work, ignore_errors=True)
        if staging.exists():
            shutil.rmtree(staging, ignore_errors=True)
    return EXIT_OK, "approval response created", {
        "path": str(out),
        "mode": mode,
        "author_key_id": author_key_id,
        "signer_key_id": signer_key_id,
        "approval_target_digest": request["approval_target_digest"],
        "files": verify_manifest(out),
    }


def cmd_import_approval_response(args):
    """Verify and merge one minimal author response into the live candidate."""
    root = pathlib.Path(args.release_dir)
    response_root = pathlib.Path(args.response_dir)
    verify_manifest(response_root)
    response = approval_exchange.validate_response(
        read_canonical(response_root / "response.json")
    )
    expected_files = (
        {"response.json", "approval.cose"}
        if response["mode"] == "direct"
        else {"response.json", "delegation.json", "delegation.cose", "delegate.pub"}
    )
    require(_exchange_payload_names(response_root) == expected_files, "APPROVAL_RESPONSE_FILE_SET")
    code, message, review = cmd_review(argparse.Namespace(
        release_dir=str(root), for_author=response["author_key_id"]
    ))
    if code != EXIT_OK:
        return code, message, review
    release = read_canonical(root / "release/release.json")
    adapted = adapt_release(release)
    require(response["work_id"] == adapted["work_id"], "APPROVAL_RESPONSE_WORK_MISMATCH")
    require(response["release_digest"] == adapted["digest"], "APPROVAL_RESPONSE_RELEASE_MISMATCH")
    require(
        response["approval_target_digest"] == review["approval_target_digest"],
        "APPROVAL_RESPONSE_TARGET_MISMATCH",
    )
    author_key_id = response["author_key_id"]
    target = read_canonical(root / "approval/target.json")
    target_bytes = canonical(target)
    conflict_paths = (
        root / f"approvals/{author_key_id}.cose",
        root / f"delegated-approvals/{author_key_id}.cose",
        root / f"delegations/{author_key_id}.json",
        root / f"delegations/{author_key_id}.cose",
    )
    if any(path.exists() for path in conflict_paths):
        return EXIT_STATE_CONFLICT, "AUTHOR_ACTION_ALREADY_RECORDED", {
            "author_key_id": author_key_id
        }
    if response["mode"] == "direct":
        approval_bytes = (response_root / "approval.cose").read_bytes()
        try:
            cose.cose_verify(
                approval_bytes,
                load_bound_public_key(root, author_key_id),
                expected_payload=target_bytes,
            )
        except Exception as exc:
            raise ValueError("APPROVAL_RESPONSE_SIGNATURE_INVALID") from exc
        (root / "approvals").mkdir(exist_ok=True)
        (root / f"approvals/{author_key_id}.cose").write_bytes(approval_bytes)
    else:
        pec = read_canonical(root / "pec/pec.json")
        require(
            "AUTHORIZED_TARGET_APPROVAL" in pec["claim_policy"]["permitted_outcomes"],
            "DELEGATED_APPROVAL_NOT_ENABLED",
        )
        delegation = read_canonical(response_root / "delegation.json")
        delegate_public_bytes = (response_root / "delegate.pub").read_bytes()
        delegate_public_key = load_public_key_bytes(delegate_public_bytes)
        delegate_key_id = key_id_of(delegate_public_key)
        require(
            delegate_key_id == response["signer_key_id"],
            "APPROVAL_RESPONSE_DELEGATE_KEY_MISMATCH",
        )
        require(delegate_key_id not in adapted["author_key_ids"], "DELEGATE_IS_AUTHOR_KEY")
        approval_delegation.validate(
            delegation, target,
            author_key_id=author_key_id,
            delegate_key_id=delegate_key_id,
        )
        delegation_bytes = (response_root / "delegation.cose").read_bytes()
        try:
            cose.cose_verify(
                delegation_bytes,
                load_bound_public_key(root, author_key_id),
                expected_payload=canonical(delegation),
            )
        except Exception as exc:
            raise ValueError("APPROVAL_RESPONSE_DELEGATION_SIGNATURE_INVALID") from exc
        delegate_path = root / f"delegate-public-keys/{delegate_key_id}.pub"
        if delegate_path.exists():
            require(
                key_id_of(load_public_key_bytes(delegate_path.read_bytes()))
                == delegate_key_id,
                "DELEGATE_PUBLIC_KEY_ID_MISMATCH",
            )
        else:
            delegate_path.parent.mkdir(exist_ok=True)
            delegate_path.write_bytes(public_pem(delegate_public_key))
        (root / "delegations").mkdir(exist_ok=True)
        write_canonical(root / f"delegations/{author_key_id}.json", delegation)
        (root / f"delegations/{author_key_id}.cose").write_bytes(delegation_bytes)
        (root / "delegated-approvals").mkdir(exist_ok=True)
    records, missing = verify_approval_records(root, adapted["author_key_ids"], target)
    state = read_canonical(root / "state.json")
    state["received_approvals"] = sorted(
        record["author_key_id"] for record in records
    )
    write_canonical(root / "state.json", state)
    return EXIT_OK, "approval response imported", {
        "mode": response["mode"],
        "author_key_id": author_key_id,
        "signer_key_id": response["signer_key_id"],
        "approval_target_digest": response["approval_target_digest"],
        "remaining": missing,
    }


def _atomic_replace_directory(root, staging):
    """Commit a same-parent staged tree, restoring the original on rename failure."""
    root = pathlib.Path(root)
    staging = pathlib.Path(staging)
    backup = root.with_name(f".{root.name}.backup-{secrets.token_hex(8)}")
    root.rename(backup)
    try:
        staging.rename(root)
    except Exception:
        backup.rename(root)
        raise
    shutil.rmtree(backup)


def _response_directories(parent):
    parent = pathlib.Path(parent)
    require(parent.is_dir() and not parent.is_symlink(), "RESPONSE_COLLECTION_INVALID")
    directories = []
    for child in sorted(parent.iterdir()):
        if child.is_symlink():
            raise ValueError("RESPONSE_COLLECTION_SYMLINK")
        if child.is_dir() and (child / "response.json").is_file():
            directories.append(child)
    require(bool(directories), "RESPONSE_COLLECTION_EMPTY")
    return directories


def _stage_response_imports(root, response_directories):
    """Return a fully validated staged candidate or one non-mutating failure."""
    root = pathlib.Path(root)
    staging = pathlib.Path(tempfile.mkdtemp(
        prefix=f".{root.name}.import-", dir=root.parent
    ))
    imported = []
    try:
        _copy_payload_tree(root, staging)
        for response_dir in response_directories:
            try:
                code, message, data = cmd_import_approval_response(argparse.Namespace(
                    release_dir=str(staging), response_dir=str(response_dir)
                ))
            except (ValueError, KeyError, TypeError, UnicodeError) as exc:
                shutil.rmtree(staging, ignore_errors=True)
                return EXIT_VERIFY_FAIL, str(exc), {
                    "response_dir": str(response_dir),
                    "original_unchanged": True,
                }, None
            except OSError as exc:
                shutil.rmtree(staging, ignore_errors=True)
                return EXIT_USAGE, "RESPONSE_IO_ERROR", {
                    "response_dir": str(response_dir),
                    "original_unchanged": True,
                    "error_code": type(exc).__name__,
                }, None
            if code != EXIT_OK:
                shutil.rmtree(staging, ignore_errors=True)
                return code, message, {
                    "response_dir": str(response_dir),
                    "response_error": data,
                    "original_unchanged": True,
                }, None
            imported.append({
                "response_dir": str(response_dir),
                "author_key_id": data["author_key_id"],
                "mode": data["mode"],
            })
        return EXIT_OK, "responses staged", {"imported": imported}, staging
    except Exception:
        shutil.rmtree(staging, ignore_errors=True)
        raise


def _exercise_delegations_in_place(root, key_paths):
    """Exercise every pending exact delegation addressed to supplied keys."""
    root = pathlib.Path(root)
    state = read_canonical(root / "state.json")
    require(state.get("state") == "awaiting-approvals", "STATE_CONFLICT")
    release = read_canonical(root / "release/release.json")
    governance = read_canonical(root / "governance/statement.json")
    pec = read_canonical(root / "pec/pec.json")
    target = read_canonical(root / "approval/target.json")
    adapted = adapt_release(release)
    check_release_key_paths(release)
    check_bindings(pec, adapted, governance, release)
    lineage = load_lineage_structure(root, release, governance, pec)
    check_approval_target(
        target, release, governance, pec, adapted,
        lineage["transition"] if lineage is not None else None,
    )
    passphrase_cache = {}
    exercised = []
    signatures = []
    for key_path in key_paths:
        if path_is_within(key_path, root):
            raise ValueError("PRIVATE_KEY_INSIDE_RELEASE")
        try:
            key = load_signing_key(key_path, passphrase_cache)
        except (TypeError, ValueError) as exc:
            raise ValueError(private_key_error_code(exc)) from exc
        delegate_key_id = key_id_of(key.public_key())
        pending = []
        directory = root / "delegations"
        if directory.is_dir():
            for path in sorted(directory.glob("*.json")):
                author_key_id = validate_key_id(path.stem)
                delegation = read_canonical(path)
                if (
                    delegation.get("delegate_key_id") == delegate_key_id
                    and not (root / f"delegated-approvals/{author_key_id}.cose").exists()
                ):
                    pending.append(author_key_id)
        require(bool(pending), "DELEGATE_KEY_HAS_NO_PENDING_APPROVAL")
        for author_key_id in pending:
            require(author_key_id in adapted["author_key_ids"], "APPROVAL_AUTHOR_UNKNOWN")
            require(
                not (root / f"approvals/{author_key_id}.cose").exists(),
                "APPROVAL_METHOD_AMBIGUOUS",
            )
            delegation = read_canonical(root / f"delegations/{author_key_id}.json")
            approval_delegation.validate(
                delegation, target,
                author_key_id=author_key_id,
                delegate_key_id=delegate_key_id,
            )
            signatures.append((author_key_id, key))
            exercised.append({
                "author_key_id": author_key_id,
                "delegate_key_id": delegate_key_id,
            })
    (root / "delegated-approvals").mkdir(exist_ok=True)
    for author_key_id, delegate_key in signatures:
        (root / f"delegated-approvals/{author_key_id}.cose").write_bytes(
            cose.cose_sign1(canonical(target), delegate_key)
        )
    records, _ = verify_approval_records(root, adapted["author_key_ids"], target)
    state["received_approvals"] = sorted(
        record["author_key_id"] for record in records
    )
    write_canonical(root / "state.json", state)
    return exercised


def cmd_approve_delegations(args):
    """Transactionally exercise all pending delegations for local agent keys."""
    root = pathlib.Path(args.release_dir)
    staging = pathlib.Path(tempfile.mkdtemp(
        prefix=f".{root.name}.delegate-", dir=root.parent
    ))
    try:
        _copy_payload_tree(root, staging)
        exercised = _exercise_delegations_in_place(staging, args.key)
        _atomic_replace_directory(root, staging)
    except Exception:
        shutil.rmtree(staging, ignore_errors=True)
        raise
    return EXIT_OK, "delegated approvals exercised atomically", {
        "exercised": exercised,
        "count": len(exercised),
    }


def cmd_export_approval_requests(args):
    """Export one self-contained request for every author still needing action."""
    root = pathlib.Path(args.release_dir)
    out = pathlib.Path(args.out)
    if out.exists():
        return EXIT_STATE_CONFLICT, "OUTPUT_EXISTS", {"path": str(out)}
    code, message, inspected = cmd_inspect(argparse.Namespace(release_dir=str(root)))
    if code != EXIT_OK:
        return code, message, inspected
    if inspected["state"] != "awaiting-approvals":
        return EXIT_STATE_CONFLICT, "STATE_CONFLICT", {"state": inspected["state"]}
    release = read_canonical(root / "release/release.json")
    missing = set(inspected["missing_approvals"])
    pending_delegations = {
        author["key_id"] for author in release["authors"]
        if (root / f"delegations/{author['key_id']}.json").is_file()
    }
    request_authors = [
        author for author in release["authors"]
        if author["key_id"] in missing and author["key_id"] not in pending_delegations
    ]
    if not request_authors:
        return EXIT_INCOMPLETE, "NO_EXPORTABLE_APPROVAL_REQUESTS", {
            "missing_approvals": sorted(missing),
            "pending_delegated_approvals": sorted(pending_delegations & missing),
        }
    out.parent.mkdir(parents=True, exist_ok=True)
    staging = pathlib.Path(tempfile.mkdtemp(prefix=".acsd-requests-", dir=out.parent))
    entries = []
    try:
        for author in request_authors:
            key_id = author["key_id"]
            # The request body and collection index already bind the full key
            # identifier.  Keeping it out of the directory name avoids making
            # otherwise portable exchanges exceed legacy Windows path limits.
            name = f"slot-{author['slot']:02d}"
            code, message, data = cmd_export_approval_request(argparse.Namespace(
                release_dir=str(root), for_author=key_id, out=str(staging / name)
            ))
            require(code == EXIT_OK, "BATCH_REQUEST_EXPORT_FAILED")
            entries.append({
                "slot": author["slot"],
                "author_key_id": key_id,
                "path": name,
                "approval_target_digest": data["approval_target_digest"],
            })
        write_canonical(staging / "requests.json", {
            "schema": "acsd-approval-request-collection/v1",
            "requests": entries,
            "pending_delegated_approvals": sorted(pending_delegations & missing),
        })
        (staging / "MANIFEST.sha256").write_bytes(
            build_manifest_text(staging).encode("ascii")
        )
        verify_manifest(staging)
        staging.rename(out)
    except Exception:
        shutil.rmtree(staging, ignore_errors=True)
        raise
    return EXIT_OK, "approval requests exported", {
        "path": str(out),
        "request_count": len(entries),
        "requests": entries,
        "pending_delegated_approvals": sorted(pending_delegations & missing),
    }


def cmd_import_approval_responses(args):
    """Atomically import every response found immediately below one directory."""
    root = pathlib.Path(args.release_dir)
    response_directories = _response_directories(args.from_dir)
    code, message, data, staging = _stage_response_imports(root, response_directories)
    if code != EXIT_OK:
        return code, message, data
    _, _, inspected = cmd_inspect(argparse.Namespace(release_dir=str(staging)))
    _atomic_replace_directory(root, staging)
    return EXIT_OK, "approval responses imported atomically", {
        **data,
        "remaining": inspected["missing_approvals"],
        "original_unchanged_on_validation_failure": True,
    }


def cmd_coordinator_finalize(args):
    """Atomically import collected responses and finalize with explicit time policy."""
    if not args.tsa and not args.allow_untimestamped:
        return EXIT_USAGE, "TSA_OR_EXPLICIT_UNTIMESTAMPED_REQUIRED", {}
    root = pathlib.Path(args.release_dir)
    if args.responses_dir:
        response_directories = _response_directories(args.responses_dir)
        code, message, import_data, staging = _stage_response_imports(
            root, response_directories
        )
        if code != EXIT_OK:
            return code, message, import_data
    else:
        staging = pathlib.Path(tempfile.mkdtemp(
            prefix=f".{root.name}.finalize-", dir=root.parent
        ))
        _copy_payload_tree(root, staging)
        import_data = {"imported": []}
    try:
        delegate_keys = list(getattr(args, "delegate_key", None) or [])
        exercised = _exercise_delegations_in_place(
            staging, delegate_keys
        ) if delegate_keys else []
    except Exception:
        shutil.rmtree(staging, ignore_errors=True)
        raise
    code, message, finalized = cmd_finalize(argparse.Namespace(
        release_dir=str(staging),
        tsa=args.tsa,
        tsa_cert=args.tsa_cert,
        allow_untimestamped=args.allow_untimestamped,
    ))
    if code != EXIT_OK:
        shutil.rmtree(staging, ignore_errors=True)
        return code, message, {
            **finalized,
            "original_unchanged": True,
        }
    _atomic_replace_directory(root, staging)
    return EXIT_OK, "responses imported and release finalized atomically", {
        **finalized,
        **import_data,
        "delegated_approvals_exercised": exercised,
        "time_policy": "rfc3161" if args.tsa else "explicit-untimestamped",
    }


def cmd_inspect(args):
    root = pathlib.Path(args.release_dir)
    state = read_canonical(root / "state.json")
    release = read_canonical(root / "release/release.json")
    target = read_canonical(root / "approval/target.json")
    adapted = adapt_release(release)
    records, missing = verify_approval_records(
        root, adapted["author_key_ids"], target
    )
    received = sorted(record["author_key_id"] for record in records)
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
        "approval_modes": {
            record["author_key_id"]: record["mode"] for record in records
        },
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
    try:
        key = load_signing_key(args.key)
    except (TypeError, ValueError) as exc:
        return EXIT_USAGE, private_key_error_code(exc), {}
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
        "non_claims": [
            "natural_person_identity_verified",
            "contribution_truth_verified",
            "publication_acceptance_verified",
        ],
        "safety_notice": (
            "Publishing this sidecar is practically irreversible and may "
            "help infer undisclosed coauthors. Verify its exact release, slot, "
            "and identity string before publication."
        ),
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


def cmd_verify_identity_set(args):
    """Verify partial or complete per-slot unblinding for one exact release."""
    if len(args.disclosure) != len(args.signature):
        return EXIT_USAGE, "IDENTITY_SIDECAR_COUNT_MISMATCH", {
            "disclosure_count": len(args.disclosure),
            "signature_count": len(args.signature),
        }
    root = pathlib.Path(args.release_dir)
    code, message, verification = verify_release_dir(root)
    if code != EXIT_OK:
        return code, "RELEASE_NOT_ACCEPTED", {
            "verifier_message": message, "verifier_data": verification
        }
    release = read_canonical(root / "release/release.json")
    public_keys = {
        author["key_id"]: load_bound_public_key(root, author["key_id"])
        for author in release["authors"]
    }
    disclosures = [
        (
            read_canonical(pathlib.Path(body_path)),
            pathlib.Path(signature_path).read_bytes(),
        )
        for body_path, signature_path in zip(args.disclosure, args.signature)
    ]
    result = identity_disclosure.verify_set(disclosures, release, public_keys)
    if args.require_full_byline and not result["full_byline"]:
        return EXIT_INCOMPLETE, result["status"], result
    return EXIT_OK, result["status"], result


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


def cmd_audit_key_reuse(args):
    """Report observable author-key equality across verified releases."""
    if len(args.release_dirs) < 2:
        return EXIT_USAGE, "AT_LEAST_TWO_RELEASES_REQUIRED", {}
    releases = []
    for release_index, release_dir in enumerate(args.release_dirs, 1):
        root = pathlib.Path(release_dir)
        code, message, verification = verify_release_dir(root)
        if code != EXIT_OK:
            return code, "RELEASE_NOT_ACCEPTED", {
                "release_index": release_index,
                "verifier_message": message,
                "verifier_data": verification,
            }
        releases.append(read_canonical(root / "release/release.json"))
    result = linkability_audit.audit_releases(releases)
    if args.fail_on_cross_work and result["cross_work_reuse_groups"]:
        return EXIT_VERIFY_FAIL, result["status"], result
    return EXIT_OK, result["status"], result


def add_declaration_arguments(parser):
    """Add author-facing contribution and AI-use inputs to a build command."""
    parser.add_argument(
        "--contribution", action="append", metavar="SLOT:TERM",
        help="declared contribution for a 1-based author slot; repeat as needed",
    )
    parser.add_argument(
        "--ai-tool", action="append", metavar="TOOL",
        help="AI tool used; requires at least one --ai-purpose",
    )
    parser.add_argument(
        "--ai-purpose", action="append", metavar="PURPOSE",
        help="purpose of AI use; requires at least one --ai-tool",
    )
    parser.add_argument(
        "--ai-reviewed-by", action="append", type=int, metavar="SLOT",
        help="1-based author slot that human-reviewed AI-assisted work",
    )


def main(argv=None):
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--json", action="store_true", help="machine-readable output")

    p = argparse.ArgumentParser(prog="acsd", description="ACSD provenance evidence capsule CLI")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    pk = sub.add_parser("keygen", parents=[common], help="generate an Ed25519 keypair")
    pk.add_argument("--name", help="key base name (default author)")
    pk.add_argument("--out-dir", default="keys", help="output directory")
    pk.add_argument(
        "--encrypt",
        action="store_true",
        help="prompt for a passphrase and encrypt the PKCS#8 private key",
    )
    pk.set_defaults(func=cmd_keygen)

    pi = sub.add_parser("init", parents=[common], help="create a release directory")
    pi.add_argument("content", help="manuscript file (PDF or text)")
    team_source = pi.add_mutually_exclusive_group(required=True)
    team_source.add_argument("--team", help="existing team.json")
    team_source.add_argument(
        "--public-key", action="append",
        help="author Ed25519 public key in byline order; repeat for coauthors",
    )
    pi.add_argument(
        "--role", action="append",
        help="role for each --public-key in the same order; repeat for every author",
    )
    pi.add_argument(
        "--corresponding", type=int,
        help="1-based corresponding-author slot for --public-key input (default: 1)",
    )
    pi.add_argument("--out", default="release-dir", help="output directory")
    pi.add_argument("--parent", help="verified predecessor release directory")
    pi.add_argument("--line", help="line name; defaults to the parent's line or main")
    pi.add_argument("--lineage-threshold", type=int, help="future successor authorization threshold (default: all authors)")
    pi.add_argument("--recovery-public-key", action="append", help="precommitted Ed25519 recovery public key; repeat for a threshold set")
    pi.add_argument("--recovery-threshold", type=int, help="recovery signature threshold (default: all recovery keys)")
    pi.add_argument("--clear-recovery", action="store_true", help="remove an inherited recovery authority through an authorized transition")
    pi.add_argument(
        "--allow-delegated-approval", action="store_true",
        help="permit exact-target author-signed approval delegation for this candidate",
    )
    add_declaration_arguments(pi)
    pi.set_defaults(func=cmd_init)

    pl = sub.add_parser("authorize", parents=[common], help="authorize a key-set or threshold-changing lineage transition with a predecessor key")
    pl.add_argument("release_dir")
    pl.add_argument("--key", required=True, help="predecessor-authority private key PEM")
    pl.set_defaults(func=cmd_authorize)

    pg = sub.add_parser("recover", parents=[common], help="authorize an exact authority-changing transition with a precommitted recovery key")
    pg.add_argument("release_dir")
    pg.add_argument("--key", required=True, help="precommitted recovery-authority private key PEM")
    pg.set_defaults(func=cmd_recover)

    pa = sub.add_parser("approve", parents=[common], help="endorse a release with a private key")
    pa.add_argument("release_dir")
    pa.add_argument("--key", required=True, help="author private key PEM")
    pa.set_defaults(func=cmd_approve)

    pda = sub.add_parser(
        "delegate-approval", parents=[common],
        help="authorize a distinct key to approve this exact target for one author",
    )
    pda.add_argument("release_dir")
    pda.add_argument("--author-key", required=True, help="delegating author private key PEM")
    pda.add_argument("--delegate-public-key", required=True, help="delegate public key PEM")
    pda.set_defaults(func=cmd_delegate_approval)

    paa = sub.add_parser(
        "approve-as", parents=[common],
        help="approve an exact target using an author-authorized delegate key",
    )
    paa.add_argument("release_dir")
    paa.add_argument("--key", required=True, help="delegate private key PEM")
    paa.add_argument("--for-author", required=True, help="author key id covered by the delegation")
    paa.set_defaults(func=cmd_approve_as)

    par = sub.add_parser(
        "author-approve", parents=[common],
        help="review and confirm a direct approval or exact-target delegation",
    )
    par.add_argument("release_dir")
    par.add_argument("--key", required=True, help="author private key PEM")
    par.add_argument(
        "--delegate-public-key",
        help="instead of direct approval, delegate this exact target to this public key",
    )
    par.add_argument(
        "--yes", action="store_true",
        help="skip the interactive confirmation (required with --json)",
    )
    par.set_defaults(func=cmd_author_approve)

    per = sub.add_parser(
        "export-approval-request", parents=[common],
        help="export a manifest-covered candidate folder for one remote author",
    )
    per.add_argument("release_dir")
    per.add_argument("--for-author", required=True, help="author key id to request")
    per.add_argument("--out", required=True, help="new approval-request directory")
    per.set_defaults(func=cmd_export_approval_request)

    peb = sub.add_parser(
        "export-approval-requests", parents=[common],
        help="export separate request folders for all authors still needing action",
    )
    peb.add_argument("release_dir")
    peb.add_argument("--out", required=True, help="new request-collection directory")
    peb.set_defaults(func=cmd_export_approval_requests)

    prr = sub.add_parser(
        "respond-approval-request", parents=[common],
        help="review a transported request and create a minimal signed response",
    )
    prr.add_argument("request_dir")
    prr.add_argument("--key", required=True, help="requested author private key PEM")
    prr.add_argument("--out", required=True, help="new approval-response directory")
    prr.add_argument(
        "--delegate-public-key",
        help="respond with an exact-target delegation instead of direct approval",
    )
    prr.add_argument(
        "--yes", action="store_true",
        help="skip the interactive confirmation (required with --json)",
    )
    prr.set_defaults(func=cmd_respond_approval_request)

    pir = sub.add_parser(
        "import-approval-response", parents=[common],
        help="verify and import one remote author's minimal response",
    )
    pir.add_argument("release_dir")
    pir.add_argument("response_dir")
    pir.set_defaults(func=cmd_import_approval_response)

    pib = sub.add_parser(
        "import-approval-responses", parents=[common],
        help="atomically import all response folders immediately below a directory",
    )
    pib.add_argument("release_dir")
    pib.add_argument("--from-dir", required=True, help="directory containing response folders")
    pib.set_defaults(func=cmd_import_approval_responses)

    pad = sub.add_parser(
        "approve-delegations", parents=[common],
        help="atomically exercise all pending exact delegations for local agent keys",
    )
    pad.add_argument("release_dir")
    pad.add_argument(
        "--key", action="append", required=True,
        help="delegate agent private key; repeat for multiple agents",
    )
    pad.set_defaults(func=cmd_approve_delegations)

    pf = sub.add_parser("finalize", parents=[common], help="assemble the final package")
    pf.add_argument("release_dir")
    pf.add_argument("--tsa", help="RFC 3161 TSA URL, or 'local' for the built-in test TSA")
    pf.add_argument("--tsa-cert", help="TSA signer certificate (PEM), required when the TSA response has no embedded certificate")
    pf.add_argument("--allow-untimestamped", action="store_true", help="finalize without a timestamp if the TSA fails")
    pf.set_defaults(func=cmd_finalize)

    pcf = sub.add_parser(
        "coordinator-finalize", parents=[common],
        help="atomically import responses and finalize under an explicit time policy",
    )
    pcf.add_argument("release_dir")
    pcf.add_argument(
        "--responses-dir",
        help="optional directory containing response folders to import first",
    )
    pcf.add_argument("--tsa", help="RFC 3161 TSA URL, or 'local' for protocol testing")
    pcf.add_argument(
        "--tsa-cert",
        help="TSA signer certificate when the response omits it",
    )
    pcf.add_argument(
        "--allow-untimestamped", action="store_true",
        help="explicitly finalize without independent time if no TSA succeeds",
    )
    pcf.add_argument(
        "--delegate-key", action="append",
        help="exercise every pending exact delegation for this local agent key; repeat as needed",
    )
    pcf.set_defaults(func=cmd_coordinator_finalize)

    pr = sub.add_parser("release", parents=[common], help="one-command release using locally held author keys")
    pr.add_argument("content", help="manuscript file (PDF or text)")
    pr.add_argument("--key", action="append", required=True, help="author private key PEM; repeat for co-authors")
    pr.add_argument("--out", default="release-dir", help="output directory")
    pr.add_argument("--tsa", help="RFC 3161 TSA URL, or 'local' for protocol testing")
    pr.add_argument("--tsa-cert", help="TSA signer certificate when the response omits it")
    pr.add_argument("--allow-untimestamped", action="store_true", help="finalize without a timestamp if the TSA fails")
    pr.add_argument("--lineage-threshold", type=int, help="future successor authorization threshold (default: all authors)")
    pr.add_argument("--recovery-public-key", action="append", help="precommitted Ed25519 recovery public key; repeat for a threshold set")
    pr.add_argument("--recovery-threshold", type=int, help="recovery signature threshold (default: all recovery keys)")
    add_declaration_arguments(pr)
    pr.set_defaults(func=cmd_release)

    px = sub.add_parser("revise", parents=[common], help="one-command authorized successor using locally held keys")
    px.add_argument("parent_dir", help="verified predecessor release directory")
    px.add_argument("content", help="new manuscript file (PDF or text)")
    px.add_argument("--key", action="append", required=True, help="new-version author private key; repeat for co-authors")
    px.add_argument("--parent-key", action="append", help="predecessor-authority key; required up to the old threshold when the key set or threshold changes")
    px.add_argument("--recovery-key", action="append", help="precommitted recovery private key; alternative to --parent-key")
    px.add_argument("--out", default="revision-dir", help="output directory")
    px.add_argument("--line", help="line name; omit to continue the parent line")
    px.add_argument("--lineage-threshold", type=int, help="future successor authorization threshold (default: all new authors)")
    px.add_argument("--recovery-public-key", action="append", help="replace the inherited recovery public-key set")
    px.add_argument("--recovery-threshold", type=int, help="set the inherited or replacement recovery threshold")
    px.add_argument("--clear-recovery", action="store_true", help="remove the inherited recovery authority")
    px.add_argument("--tsa", help="RFC 3161 TSA URL, or 'local' for protocol testing")
    px.add_argument("--tsa-cert", help="TSA signer certificate when the response omits it")
    px.add_argument("--allow-untimestamped", action="store_true", help="finalize without a timestamp if the TSA fails")
    add_declaration_arguments(px)
    px.set_defaults(func=cmd_revise)

    pv = sub.add_parser("verify", parents=[common], help="verify a release directory offline")
    pv.add_argument("release_dir")
    pv.add_argument("--tsa-trust-cert", help="out-of-band trusted TSA signer certificate (PEM or DER)")
    pv.add_argument("--tsa-trust-fingerprint", help="out-of-band SHA-256 pin for an embedded TSA signer certificate")
    pv.add_argument("--allow-local-test-tsa", action="store_true", help="verify the bundled self-signed local test TSA; never grants external time")
    pv.add_argument("--require-external-time", action="store_true", help="fail unless externally pinned RFC 3161 evidence verifies")
    pv.add_argument("--expected-parent-release-id", help="pin the exact previously accepted parent urn:sha256 identifier")
    pv.add_argument("--emit-appraisal-transcript", action="store_true", help="include the claim-free typed appraisal transcript in verifier output")
    pv.set_defaults(func=cmd_verify)

    prv = sub.add_parser(
        "review", parents=[common],
        help="validate and display the exact facts an author would approve",
    )
    prv.add_argument("release_dir")
    prv.add_argument(
        "--for-author",
        help="highlight one author key id without using its private key",
    )
    prv.set_defaults(func=cmd_review)

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

    pdis = sub.add_parser(
        "verify-identity-set", parents=[common],
        help="verify a partial or complete set of exact-slot identity sidecars",
    )
    pdis.add_argument("release_dir")
    pdis.add_argument(
        "--disclosure", action="append", required=True,
        help="identity disclosure JSON; repeat once per slot",
    )
    pdis.add_argument(
        "--signature", action="append", required=True,
        help="matching COSE signature; repeat in disclosure order",
    )
    pdis.add_argument(
        "--require-full-byline", action="store_true",
        help="exit 5 unless every author slot has one valid disclosure",
    )
    pdis.set_defaults(func=cmd_verify_identity_set)

    pc = sub.add_parser("compare-successors", parents=[common], help="detect a same-parent, same-slot authorized fork")
    pc.add_argument("left", help="first finalized successor directory")
    pc.add_argument("right", help="second finalized successor directory")
    pc.set_defaults(func=cmd_compare_successors)

    pkr = sub.add_parser(
        "audit-key-reuse", parents=[common],
        help="report public signing keys reused across verified WorkID lineages",
    )
    pkr.add_argument(
        "release_dirs", nargs="+", help="two or more finalized release directories"
    )
    pkr.add_argument(
        "--fail-on-cross-work", action="store_true",
        help="exit 1 when a key occurs under more than one WorkID",
    )
    pkr.set_defaults(func=cmd_audit_key_reuse)

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
    elif args.command == "review" and code == EXIT_OK:
        emit_review_human(message, data)
    else:
        emit_human(args.command, code, message, data)
    return code


if __name__ == "__main__":
    sys.exit(main())
