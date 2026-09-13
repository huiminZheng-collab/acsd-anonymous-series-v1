"""Generate a deterministic, public-key-only authorized-lineage fixture."""

from __future__ import annotations

import argparse
import hashlib
import pathlib

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import approval_set
import cose
from acsd import (
    load_lineage_structure,
    verify_lineage_authorization,
    write_canonical,
)
from event_disclosure import key_id_of
from package_manifest import write_manifest
from canonical_json import canonical, digest
from protocol_objects import (
    build_approval_target,
    build_governance,
    build_lineage_transition,
    build_pec,
    build_release,
    check_approval_target,
    check_bindings,
    lineage_authority_of,
)
from release_adapter import adapt_release


WORK_ID = "urn:uuid:2a7f9af8-2148-4f92-92f0-1f3df4af8e4b"
PARENT_MANUSCRIPT = b"ACSD deterministic lineage parent.\n"
CHILD_MANUSCRIPT = b"ACSD deterministic authorized n+1 child.\n"
PARENT_KEYS = [
    Ed25519PrivateKey.from_private_bytes(bytes([0x31]) * 32),
    Ed25519PrivateKey.from_private_bytes(bytes([0x32]) * 32),
]
CHILD_KEYS = [Ed25519PrivateKey.from_private_bytes(bytes([0x41]) * 32)]


def _public_pem(key: Ed25519PrivateKey) -> bytes:
    return key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def _team(keys, role: str):
    return {
        "schema": "acsd-team/v1",
        "authors": [
            {
                "key_id": key_id_of(key.public_key()),
                "public_key": _public_pem(key).decode("ascii"),
                "role": role,
                "corresponding": index == 0,
                "contributions": [],
            }
            for index, key in enumerate(keys)
        ],
    }


def generate(destination: pathlib.Path) -> dict:
    destination = pathlib.Path(destination)
    if destination.exists():
        raise FileExistsError(f"refusing to overwrite {destination}")
    staging = destination.with_name(destination.name + ".staging")
    if staging.exists():
        raise FileExistsError(f"refusing to overwrite stale staging directory {staging}")

    parent_team = _team(PARENT_KEYS, "co-first")
    child_team = _team(CHILD_KEYS, "sole")
    parent_release = build_release(
        WORK_ID, hashlib.sha256(PARENT_MANUSCRIPT).hexdigest(),
        "parent-manuscript.txt", parent_team, lineage_threshold=2,
    )
    parent_governance = build_governance(
        WORK_ID, hashlib.sha256(PARENT_MANUSCRIPT).hexdigest(), parent_team
    )
    parent_pec = build_pec(
        WORK_ID,
        adapt_release(parent_release),
        digest(parent_governance),
        hashlib.sha256(PARENT_MANUSCRIPT).hexdigest(),
        digest(parent_governance["ai_use_declaration"]),
        [key_id_of(key.public_key()) for key in PARENT_KEYS],
    )
    parent_pec["pec_id"] = "pec-lineage-parent"

    child_release = build_release(
        WORK_ID, hashlib.sha256(CHILD_MANUSCRIPT).hexdigest(),
        "manuscript.txt", child_team, parent_release=parent_release,
        lineage_threshold=1,
    )
    child_governance = build_governance(
        WORK_ID, hashlib.sha256(CHILD_MANUSCRIPT).hexdigest(), child_team
    )
    child_pec = build_pec(
        WORK_ID,
        adapt_release(child_release),
        digest(child_governance),
        hashlib.sha256(CHILD_MANUSCRIPT).hexdigest(),
        digest(child_governance["ai_use_declaration"]),
        [key_id_of(key.public_key()) for key in CHILD_KEYS],
        predecessor_pec=parent_pec,
    )
    child_pec["pec_id"] = "pec-lineage-child"
    transition = build_lineage_transition(
        parent_release, parent_pec, child_release, child_governance, child_pec
    )
    target = build_approval_target(
        child_release, child_governance, child_pec, transition
    )

    adapted = adapt_release(child_release)
    check_bindings(child_pec, adapted, child_governance, child_release)
    check_approval_target(
        target, child_release, child_governance, child_pec, adapted, transition
    )

    child_signatures = {
        key_id_of(key.public_key()): cose.cose_sign1(canonical(target), key)
        for key in CHILD_KEYS
    }
    parent_signatures = {
        key_id_of(key.public_key()): cose.cose_sign1(canonical(transition), key)
        for key in PARENT_KEYS
    }
    set_object = approval_set.build_from_signatures(
        target, child_signatures, parent_signatures
    )

    (staging / "release").mkdir(parents=True)
    (staging / "governance").mkdir()
    (staging / "pec").mkdir()
    (staging / "approval").mkdir()
    (staging / "approvals").mkdir()
    (staging / "public-keys").mkdir()
    (staging / "lineage" / "authorizations").mkdir(parents=True)
    (staging / "lineage" / "parent-public-keys").mkdir()
    (staging / "manuscript.txt").write_bytes(CHILD_MANUSCRIPT)
    write_canonical(staging / "release" / "release.json", child_release)
    write_canonical(staging / "governance" / "statement.json", child_governance)
    write_canonical(staging / "pec" / "pec.json", child_pec)
    write_canonical(staging / "approval" / "target.json", target)
    write_canonical(staging / "approval" / "approval-set.json", set_object)
    write_canonical(staging / "lineage" / "parent-release.json", parent_release)
    write_canonical(staging / "lineage" / "parent-pec.json", parent_pec)
    write_canonical(staging / "lineage" / "transition.json", transition)
    for key_id, raw in child_signatures.items():
        (staging / "approvals" / f"{key_id}.cose").write_bytes(raw)
    for key in CHILD_KEYS:
        key_id = key_id_of(key.public_key())
        (staging / "public-keys" / f"{key_id}.pub").write_bytes(_public_pem(key))
    for key_id, raw in parent_signatures.items():
        (staging / "lineage" / "authorizations" / f"{key_id}.cose").write_bytes(raw)
    for key in PARENT_KEYS:
        key_id = key_id_of(key.public_key())
        (staging / "lineage" / "parent-public-keys" / f"{key_id}.pub").write_bytes(
            _public_pem(key)
        )

    lineage = load_lineage_structure(
        staging, child_release, child_governance, child_pec
    )
    result = verify_lineage_authorization(
        staging, lineage, set(child_signatures)
    )
    if result["status"] != "AUTHORIZED_TRANSITION":
        raise ValueError("LINEAGE_DEMO_NOT_AUTHORIZED")
    if lineage_authority_of(parent_release)["threshold"] != 2:
        raise ValueError("LINEAGE_DEMO_PARENT_THRESHOLD")
    write_canonical(staging / "state.json", {
        "schema": "acsd-state/v1",
        "state": "finalized-untimestamped",
        "work_id": WORK_ID,
        "release_digest": adapted["digest"],
        "required_approvals": sorted(child_signatures),
        "received_approvals": sorted(child_signatures),
        "required_lineage_authorization_threshold": 2,
        "received_lineage_authorizations": sorted(parent_signatures),
    })
    write_manifest(staging)
    staging.replace(destination)
    return {
        "status": result["status"],
        "transition_digest": digest(transition),
        "approval_set_digest": digest(set_object),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("out")
    args = parser.parse_args()
    print(generate(pathlib.Path(args.out)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
