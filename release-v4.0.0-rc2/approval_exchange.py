"""Pure schemas for portable approval-request and approval-response folders."""

from __future__ import annotations

from canonical_json import HEX, require
from key_identity import KEY_ID_RE


REQUEST_SCHEMA = "acsd-approval-request/v1"
RESPONSE_SCHEMA = "acsd-approval-response/v1"


def build_request(author_key_id, work_id, release_digest, target_digest):
    return {
        "schema": REQUEST_SCHEMA,
        "author_key_id": author_key_id,
        "work_id": work_id,
        "release_digest": release_digest,
        "approval_target_digest": target_digest,
    }


def validate_request(obj):
    require(isinstance(obj, dict), "APPROVAL_REQUEST_INVALID")
    require(obj.get("schema") == REQUEST_SCHEMA, "APPROVAL_REQUEST_SCHEMA")
    require(
        set(obj) == {
            "schema", "author_key_id", "work_id", "release_digest",
            "approval_target_digest",
        },
        "APPROVAL_REQUEST_FIELDS",
    )
    require(
        isinstance(obj.get("author_key_id"), str)
        and KEY_ID_RE.fullmatch(obj["author_key_id"]),
        "APPROVAL_REQUEST_AUTHOR_KEY_ID",
    )
    require(
        isinstance(obj.get("work_id"), str)
        and obj["work_id"].startswith("urn:uuid:"),
        "APPROVAL_REQUEST_WORK_ID",
    )
    require(
        isinstance(obj.get("release_digest"), str)
        and HEX.fullmatch(obj["release_digest"]),
        "APPROVAL_REQUEST_RELEASE_DIGEST",
    )
    require(
        isinstance(obj.get("approval_target_digest"), str)
        and HEX.fullmatch(obj["approval_target_digest"]),
        "APPROVAL_REQUEST_TARGET_DIGEST",
    )
    return obj


def build_response(request, mode, signer_key_id):
    validate_request(request)
    require(mode in {"direct", "delegation"}, "APPROVAL_RESPONSE_MODE")
    require(
        isinstance(signer_key_id, str) and KEY_ID_RE.fullmatch(signer_key_id),
        "APPROVAL_RESPONSE_SIGNER_KEY_ID",
    )
    return {
        "schema": RESPONSE_SCHEMA,
        "mode": mode,
        "author_key_id": request["author_key_id"],
        "signer_key_id": signer_key_id,
        "work_id": request["work_id"],
        "release_digest": request["release_digest"],
        "approval_target_digest": request["approval_target_digest"],
    }


def validate_response(obj):
    require(isinstance(obj, dict), "APPROVAL_RESPONSE_INVALID")
    require(obj.get("schema") == RESPONSE_SCHEMA, "APPROVAL_RESPONSE_SCHEMA")
    require(
        set(obj) == {
            "schema", "mode", "author_key_id", "signer_key_id", "work_id",
            "release_digest", "approval_target_digest",
        },
        "APPROVAL_RESPONSE_FIELDS",
    )
    require(obj.get("mode") in {"direct", "delegation"}, "APPROVAL_RESPONSE_MODE")
    request_projection = {
        "schema": REQUEST_SCHEMA,
        "author_key_id": obj.get("author_key_id"),
        "work_id": obj.get("work_id"),
        "release_digest": obj.get("release_digest"),
        "approval_target_digest": obj.get("approval_target_digest"),
    }
    validate_request(request_projection)
    require(
        isinstance(obj.get("signer_key_id"), str)
        and KEY_ID_RE.fullmatch(obj["signer_key_id"]),
        "APPROVAL_RESPONSE_SIGNER_KEY_ID",
    )
    if obj["mode"] == "direct":
        require(
            obj["signer_key_id"] == obj["author_key_id"],
            "APPROVAL_RESPONSE_DIRECT_SIGNER_MISMATCH",
        )
    else:
        require(
            obj["signer_key_id"] != obj["author_key_id"],
            "APPROVAL_RESPONSE_DELEGATE_NOT_DISTINCT",
        )
    return obj
