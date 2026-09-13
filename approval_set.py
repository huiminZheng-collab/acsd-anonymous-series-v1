"""Canonical closure over the exact signature bytes completing an approval."""

from __future__ import annotations

import hashlib
import pathlib
from typing import Dict, Iterable, List

from pec_core import digest, require


SCHEMA = "acsd-approval-set/v1"


def _sha256_file(path: pathlib.Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _entries(root: pathlib.Path, directory: str, key_ids: Iterable[str]) -> List[Dict[str, str]]:
    return [
        {"key_id": key_id, "cose_sha256": _sha256_file(root / directory / f"{key_id}.cose")}
        for key_id in sorted(key_ids)
    ]


def _require_exact_files(root: pathlib.Path, directory: str, key_ids, code: str) -> None:
    location = root / directory
    actual = sorted(path.name for path in location.iterdir()) if location.is_dir() else []
    expected = sorted(f"{key_id}.cose" for key_id in key_ids)
    require(actual == expected, code)


def build(root: pathlib.Path, approval_target, author_key_ids, lineage_key_ids):
    """Bind the target and every signature byte string used for acceptance."""
    root = pathlib.Path(root)
    _require_exact_files(
        root, "approvals", author_key_ids, "APPROVAL_SET_AUTHOR_FILE_SET_MISMATCH"
    )
    _require_exact_files(
        root, "lineage/authorizations", lineage_key_ids,
        "APPROVAL_SET_LINEAGE_FILE_SET_MISMATCH",
    )
    return {
        "schema": SCHEMA,
        "approval_target_digest": digest(approval_target),
        "author_approvals": _entries(root, "approvals", author_key_ids),
        "lineage_authorizations": _entries(
            root, "lineage/authorizations", lineage_key_ids
        ),
    }


def verify(obj, root: pathlib.Path, approval_target, author_key_ids, lineage_key_ids):
    """Verify exact membership and byte digests; signature validity is separate."""
    require(obj.get("schema") == SCHEMA, "APPROVAL_SET_SCHEMA")
    require(
        obj.get("approval_target_digest") == digest(approval_target),
        "APPROVAL_SET_TARGET_MISMATCH",
    )
    expected = build(root, approval_target, author_key_ids, lineage_key_ids)
    require(
        obj.get("author_approvals") == expected["author_approvals"],
        "APPROVAL_SET_AUTHOR_SIGNATURE_MISMATCH",
    )
    require(
        obj.get("lineage_authorizations") == expected["lineage_authorizations"],
        "APPROVAL_SET_LINEAGE_SIGNATURE_MISMATCH",
    )
    require(set(obj) == set(expected), "APPROVAL_SET_FIELDS")
    return {"approval_set_digest": digest(obj)}
