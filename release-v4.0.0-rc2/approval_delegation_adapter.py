"""Filesystem and signature adapter for direct and exact-target approvals."""

from __future__ import annotations

import pathlib

import approval_delegation
import cose
from artifact_io import read_canonical
from canonical_json import canonical, require
from key_identity import key_id_of
from key_material import load_bound_public_key, load_public_key_bytes


def _files(root, directory, suffix, *, allowed_suffixes=None):
    location = root / directory
    if not location.exists():
        return set()
    require(location.is_dir(), "APPROVAL_EVIDENCE_DIRECTORY_INVALID")
    names = set()
    allowed = tuple(allowed_suffixes or (suffix,))
    for path in location.iterdir():
        require(
            path.is_file() and any(path.name.endswith(item) for item in allowed),
            "APPROVAL_EVIDENCE_FILE_INVALID",
        )
        if path.name.endswith(suffix):
            names.add(path.name[:-len(suffix)])
    return names


def verify_approval_records(root, author_key_ids, approval_target):
    """Validate all present approval evidence and report uncovered authors."""
    root = pathlib.Path(root)
    authors = set(author_key_ids)
    direct = _files(root, "approvals", ".cose")
    delegated = _files(root, "delegated-approvals", ".cose")
    delegation_json = _files(
        root, "delegations", ".json", allowed_suffixes=(".json", ".cose")
    )
    delegation_cose = _files(
        root, "delegations", ".cose", allowed_suffixes=(".json", ".cose")
    )
    require(direct <= authors and delegated <= authors, "APPROVAL_AUTHOR_UNKNOWN")
    require(delegation_json == delegation_cose, "DELEGATION_FILE_SET_MISMATCH")
    require(delegation_json <= authors, "DELEGATION_AUTHOR_UNKNOWN")
    require(direct.isdisjoint(delegated), "APPROVAL_METHOD_AMBIGUOUS")
    require(delegated <= delegation_json, "DELEGATED_APPROVAL_WITHOUT_DELEGATION")

    target_bytes = canonical(approval_target)
    records = []
    expected_delegate_keys = set()
    for author_key_id in sorted(authors):
        if author_key_id in direct:
            approval_bytes = (root / "approvals" / f"{author_key_id}.cose").read_bytes()
            cose.cose_verify(
                approval_bytes,
                load_bound_public_key(root, author_key_id),
                expected_payload=target_bytes,
            )
            records.append({
                "author_key_id": author_key_id,
                "signer_key_id": author_key_id,
                "mode": "direct",
                "approval_bytes": approval_bytes,
                "delegation_bytes": None,
            })
            continue
        if author_key_id not in delegation_json:
            continue
        delegation = read_canonical(root / "delegations" / f"{author_key_id}.json")
        approval_delegation.validate(
            delegation, approval_target, author_key_id=author_key_id
        )
        delegate_key_id = delegation["delegate_key_id"]
        require(delegate_key_id not in authors, "DELEGATE_IS_AUTHOR_KEY")
        expected_delegate_keys.add(delegate_key_id)
        delegate_key_path = root / "delegate-public-keys" / f"{delegate_key_id}.pub"
        delegate_public_key = load_public_key_bytes(delegate_key_path.read_bytes())
        require(key_id_of(delegate_public_key) == delegate_key_id, "DELEGATE_PUBLIC_KEY_ID_MISMATCH")
        delegation_bytes = (root / "delegations" / f"{author_key_id}.cose").read_bytes()
        cose.cose_verify(
            delegation_bytes,
            load_bound_public_key(root, author_key_id),
            expected_payload=canonical(delegation),
        )
        if author_key_id not in delegated:
            continue
        approval_bytes = (
            root / "delegated-approvals" / f"{author_key_id}.cose"
        ).read_bytes()
        cose.cose_verify(
            approval_bytes, delegate_public_key, expected_payload=target_bytes
        )
        records.append({
            "author_key_id": author_key_id,
            "signer_key_id": delegate_key_id,
            "mode": "delegated",
            "approval_bytes": approval_bytes,
            "delegation_bytes": delegation_bytes,
        })

    actual_delegate_keys = _files(root, "delegate-public-keys", ".pub")
    require(actual_delegate_keys == expected_delegate_keys, "DELEGATE_PUBLIC_KEY_FILE_SET_MISMATCH")
    covered = {record["author_key_id"] for record in records}
    return records, sorted(authors - covered)
