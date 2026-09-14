"""Canonical closure over the exact signature bytes completing an approval."""

from __future__ import annotations

import hashlib
import pathlib
from typing import Dict, Iterable, List, Mapping

from canonical_json import HEX, digest, require


SCHEMA = "acsd-approval-set/v1"


def _validated_key_ids(key_ids: Iterable[str]) -> List[str]:
    values = list(key_ids)
    require(
        len(values) == len(set(values))
        and all(isinstance(key_id, str) and HEX.fullmatch(key_id) for key_id in values),
        "APPROVAL_SET_KEY_ID_INVALID",
    )
    return values


def entries_from_signatures(signatures: Mapping[str, bytes]) -> List[Dict[str, str]]:
    """Pure projection from an exact key-to-COSE byte map."""
    require(isinstance(signatures, Mapping), "APPROVAL_SET_SIGNATURE_MAP_INVALID")
    key_ids = _validated_key_ids(signatures.keys())
    require(
        all(isinstance(signatures[key_id], bytes) for key_id in key_ids),
        "APPROVAL_SET_SIGNATURE_BYTES_INVALID",
    )
    return [
        {
            "key_id": key_id,
            "cose_sha256": hashlib.sha256(signatures[key_id]).hexdigest(),
        }
        for key_id in sorted(key_ids)
    ]


def build_from_signatures(
    approval_target,
    author_signatures: Mapping[str, bytes],
    lineage_signatures: Mapping[str, bytes],
):
    """Pure approval-set construction, independent of filesystem layout."""
    return {
        "schema": SCHEMA,
        "approval_target_digest": digest(approval_target),
        "author_approvals": entries_from_signatures(author_signatures),
        "lineage_authorizations": entries_from_signatures(lineage_signatures),
    }


def verify_from_signatures(
    obj,
    approval_target,
    author_signatures: Mapping[str, bytes],
    lineage_signatures: Mapping[str, bytes],
):
    """Pure verification against exact signature byte maps."""
    require(obj.get("schema") == SCHEMA, "APPROVAL_SET_SCHEMA")
    expected = build_from_signatures(
        approval_target, author_signatures, lineage_signatures
    )
    require(
        obj.get("approval_target_digest") == expected["approval_target_digest"],
        "APPROVAL_SET_TARGET_MISMATCH",
    )
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


def _require_exact_files(root: pathlib.Path, directory: str, key_ids, code: str) -> None:
    key_ids = _validated_key_ids(key_ids)
    location = root / directory
    actual = sorted(path.name for path in location.iterdir()) if location.is_dir() else []
    expected = sorted(f"{key_id}.cose" for key_id in key_ids)
    require(actual == expected, code)


def build(
    root: pathlib.Path,
    approval_target,
    author_key_ids,
    lineage_key_ids,
    *,
    lineage_directory="lineage/authorizations",
):
    """Bind the target and every signature byte string used for acceptance."""
    root = pathlib.Path(root)
    _require_exact_files(
        root, "approvals", author_key_ids, "APPROVAL_SET_AUTHOR_FILE_SET_MISMATCH"
    )
    _require_exact_files(
        root, lineage_directory, lineage_key_ids,
        "APPROVAL_SET_LINEAGE_FILE_SET_MISMATCH",
    )
    return build_from_signatures(
        approval_target,
        {
            key_id: (root / "approvals" / f"{key_id}.cose").read_bytes()
            for key_id in author_key_ids
        },
        {
            key_id: (root / lineage_directory / f"{key_id}.cose").read_bytes()
            for key_id in lineage_key_ids
        },
    )


def verify(
    obj,
    root: pathlib.Path,
    approval_target,
    author_key_ids,
    lineage_key_ids,
    *,
    lineage_directory="lineage/authorizations",
):
    """Verify exact membership and byte digests; signature validity is separate."""
    root = pathlib.Path(root)
    _require_exact_files(
        root, "approvals", author_key_ids, "APPROVAL_SET_AUTHOR_FILE_SET_MISMATCH"
    )
    _require_exact_files(
        root, lineage_directory, lineage_key_ids,
        "APPROVAL_SET_LINEAGE_FILE_SET_MISMATCH",
    )
    return verify_from_signatures(
        obj,
        approval_target,
        {
            key_id: (root / "approvals" / f"{key_id}.cose").read_bytes()
            for key_id in author_key_ids
        },
        {
            key_id: (root / lineage_directory / f"{key_id}.cose").read_bytes()
            for key_id in lineage_key_ids
        },
    )
