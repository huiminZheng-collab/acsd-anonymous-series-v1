"""Exact-target, non-redelegable author approval delegation.

The delegating author signs the delegation object with the author key.  The
delegate then signs the already-fixed approval target with a distinct key.
This module deliberately grants no lineage, recovery, disclosure, or further
delegation capability.
"""

from __future__ import annotations

from canonical_json import digest, require
from key_identity import KEY_ID_RE


SCHEMA = "acsd-approval-delegation/v1"
ACTION = "approve-exact-target"


def build(author_key_id, delegate_key_id, approval_target):
    require(
        isinstance(author_key_id, str) and KEY_ID_RE.fullmatch(author_key_id),
        "DELEGATION_AUTHOR_KEY_ID_INVALID",
    )
    require(
        isinstance(delegate_key_id, str) and KEY_ID_RE.fullmatch(delegate_key_id),
        "DELEGATION_DELEGATE_KEY_ID_INVALID",
    )
    require(author_key_id != delegate_key_id, "DELEGATION_KEY_NOT_DISTINCT")
    return {
        "schema": SCHEMA,
        "action": ACTION,
        "author_key_id": author_key_id,
        "delegate_key_id": delegate_key_id,
        "work_id": approval_target["work_id"],
        "approval_target_digest": digest(approval_target),
        "release_digest": approval_target["release_digest"],
        "governance_digest": approval_target["governance_digest"],
        "pec_digest": approval_target["pec_digest"],
        "lineage_transition_digest": approval_target["lineage_transition_digest"],
        "redelegation": False,
    }


def validate(obj, approval_target, *, author_key_id=None, delegate_key_id=None):
    require(isinstance(obj, dict), "DELEGATION_INVALID")
    expected_fields = {
        "schema", "action", "author_key_id", "delegate_key_id", "work_id",
        "approval_target_digest", "release_digest", "governance_digest",
        "pec_digest", "lineage_transition_digest", "redelegation",
    }
    require(set(obj) == expected_fields, "DELEGATION_FIELDS")
    require(obj.get("schema") == SCHEMA, "DELEGATION_SCHEMA")
    require(obj.get("action") == ACTION, "DELEGATION_ACTION")
    require(obj.get("redelegation") is False, "DELEGATION_REDELEGATION_FORBIDDEN")
    expected = build(
        obj.get("author_key_id"), obj.get("delegate_key_id"), approval_target
    )
    require(obj == expected, "DELEGATION_TARGET_MISMATCH")
    if author_key_id is not None:
        require(obj["author_key_id"] == author_key_id, "DELEGATION_AUTHOR_MISMATCH")
    if delegate_key_id is not None:
        require(obj["delegate_key_id"] == delegate_key_id, "DELEGATION_DELEGATE_MISMATCH")
    return obj
