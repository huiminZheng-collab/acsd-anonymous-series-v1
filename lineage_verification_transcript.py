"""Pure closure checker for one claim-free lineage verification certificate."""

from __future__ import annotations

import re

import claim_derivation as claims


SCHEMA = "acsd-lineage-verification-certificate/v1"
HEX64 = re.compile(r"[0-9a-f]{64}")
MAX_SAFE_INTEGER = 9_007_199_254_740_991
INPUT_ROLES = {
    "parent-release", "parent-pec", "child-release", "child-governance",
    "child-pec", "child-approval-target", "lineage-transition",
    "approval-set", "child-public-key", "child-approval-cose",
    "parent-public-key", "predecessor-authorization-cose",
}


def _require(condition, code):
    if not condition:
        raise ValueError(code)


def _digest(value, code):
    _require(isinstance(value, str) and HEX64.fullmatch(value), code)
    return value


def _nat(value, code):
    _require(
        isinstance(value, int) and not isinstance(value, bool)
        and 0 <= value <= MAX_SAFE_INTEGER,
        code,
    )
    return value


def _authority(value, code):
    _require(isinstance(value, dict) and set(value) == {"key_ids", "threshold"}, code)
    keys = value["key_ids"]
    _require(
        isinstance(keys, list) and bool(keys)
        and keys == sorted(set(keys))
        and all(isinstance(key, str) and HEX64.fullmatch(key) for key in keys),
        code,
    )
    threshold = _nat(value["threshold"], code)
    _require(1 <= threshold <= len(keys), code)
    return keys, threshold


def _inputs(certificate):
    values = certificate["inputs"]
    _require(isinstance(values, list), "LINEAGE_TRANSCRIPT_INPUTS")
    _require(
        values == sorted(values, key=lambda item: (item.get("path", ""), item.get("role", ""))),
        "LINEAGE_TRANSCRIPT_INPUT_ORDER",
    )
    paths = []
    by_role = {}
    for item in values:
        _require(
            isinstance(item, dict) and set(item) == {"role", "path", "sha256"},
            "LINEAGE_TRANSCRIPT_INPUT",
        )
        _require(item["role"] in INPUT_ROLES, "LINEAGE_TRANSCRIPT_INPUT_ROLE")
        _require(isinstance(item["path"], str) and item["path"], "LINEAGE_TRANSCRIPT_INPUT")
        paths.append(item["path"])
        by_role.setdefault(item["role"], []).append(
            _digest(item["sha256"], "LINEAGE_TRANSCRIPT_INPUT")
        )
    _require(len(paths) == len(set(paths)), "LINEAGE_TRANSCRIPT_DUPLICATE_INPUT")
    return by_role


def _single(inputs, role, expected):
    return inputs.get(role, []) == [expected]


def _approval_entries(value, code):
    _require(isinstance(value, list), code)
    parsed = []
    for item in value:
        _require(isinstance(item, dict) and set(item) == {"key_id", "cose_sha256"}, code)
        parsed.append((
            _digest(item["key_id"], code),
            _digest(item["cose_sha256"], code),
        ))
    _require(parsed == sorted(set(parsed)), code)
    return parsed


def appraised_evidence(certificate: dict, certificate_digest: str):
    _digest(certificate_digest, "LINEAGE_TRANSCRIPT_CERTIFICATE_DIGEST")
    _require(isinstance(certificate, dict) and set(certificate) == {
        "schema", "inputs", "policy", "lineage_edge", "approval_set",
        "signature_facts",
    }, "LINEAGE_TRANSCRIPT_FIELDS")
    _require(certificate["schema"] == SCHEMA, "LINEAGE_TRANSCRIPT_SCHEMA")
    inputs = _inputs(certificate)

    policy = certificate["policy"]
    _require(isinstance(policy, dict) and set(policy) == {
        "pec_digest", "permitted_outcomes"
    }, "LINEAGE_TRANSCRIPT_POLICY")
    policy_pec = _digest(policy["pec_digest"], "LINEAGE_TRANSCRIPT_POLICY_PEC")
    permitted = claims.permitted_claims(policy["permitted_outcomes"])

    edge = certificate["lineage_edge"]
    _require(isinstance(edge, dict) and set(edge) == {
        "work_id_digest", "transition_digest", "transition_input_digest",
        "transition_kind", "authorization_mode", "parent", "child",
    }, "LINEAGE_TRANSCRIPT_EDGE")
    work = _digest(edge["work_id_digest"], "LINEAGE_TRANSCRIPT_WORK")
    transition = _digest(edge["transition_digest"], "LINEAGE_TRANSCRIPT_TRANSITION")
    transition_input = _digest(
        edge["transition_input_digest"], "LINEAGE_TRANSCRIPT_TRANSITION_INPUT"
    )
    _require(
        edge["transition_kind"] in {
            "continuation", "branch", "team-change", "threshold-change"
        }
        and edge["authorization_mode"] in {"continuity", "transition"},
        "LINEAGE_TRANSCRIPT_MODE",
    )

    parent = edge["parent"]
    child = edge["child"]
    _require(isinstance(parent, dict) and set(parent) == {
        "release_digest", "pec_digest", "line_digest", "version", "authority",
        "release_input_digest", "pec_input_digest",
    }, "LINEAGE_TRANSCRIPT_PARENT")
    _require(isinstance(child, dict) and set(child) == {
        "release_digest", "pec_digest", "line_digest",
        "version", "authority", "approval_target_digest",
        "bound_transition_digest", "release_input_digest",
        "governance_input_digest", "pec_input_digest",
        "approval_target_input_digest",
    }, "LINEAGE_TRANSCRIPT_CHILD")
    parent_release = _digest(parent["release_digest"], "LINEAGE_TRANSCRIPT_PARENT")
    parent_pec = _digest(parent["pec_digest"], "LINEAGE_TRANSCRIPT_PARENT")
    parent_line = _digest(parent["line_digest"], "LINEAGE_TRANSCRIPT_PARENT")
    parent_version = _nat(parent["version"], "LINEAGE_TRANSCRIPT_PARENT")
    child_release = _digest(child["release_digest"], "LINEAGE_TRANSCRIPT_CHILD")
    child_pec = _digest(child["pec_digest"], "LINEAGE_TRANSCRIPT_CHILD")
    child_line = _digest(child["line_digest"], "LINEAGE_TRANSCRIPT_CHILD")
    child_version = _nat(child["version"], "LINEAGE_TRANSCRIPT_CHILD")
    _require(parent_version > 0 and child_version > 0, "LINEAGE_TRANSCRIPT_VERSION")
    parent_keys, parent_threshold = _authority(
        parent["authority"], "LINEAGE_TRANSCRIPT_PARENT_AUTHORITY"
    )
    child_keys, _ = _authority(
        child["authority"], "LINEAGE_TRANSCRIPT_CHILD_AUTHORITY"
    )
    target = _digest(
        child["approval_target_digest"], "LINEAGE_TRANSCRIPT_TARGET"
    )
    bound_transition = _digest(
        child["bound_transition_digest"], "LINEAGE_TRANSCRIPT_BOUND_TRANSITION"
    )
    for item, names, code in (
        (parent, ("release_input_digest", "pec_input_digest"), "LINEAGE_TRANSCRIPT_PARENT_INPUT"),
        (child, ("release_input_digest", "governance_input_digest", "pec_input_digest",
                 "approval_target_input_digest"), "LINEAGE_TRANSCRIPT_CHILD_INPUT"),
    ):
        for name in names:
            _digest(item[name], code)

    same_line = parent_line == child_line
    structural = (
        (same_line and child_version == parent_version + 1)
        or (not same_line and child_version == 1)
    )
    expected_kind = (
        "branch" if not same_line else
        "team-change" if parent_keys != child_keys else
        "threshold-change" if parent["authority"]["threshold"] != child["authority"]["threshold"] else
        "continuation"
    )

    facts = certificate["signature_facts"]
    _require(isinstance(facts, list), "LINEAGE_TRANSCRIPT_SIGNATURES")
    parsed_facts = []
    for item in facts:
        _require(isinstance(item, dict) and set(item) == {
            "purpose", "key_id", "payload_digest", "cose_digest",
            "public_key_digest",
        }, "LINEAGE_TRANSCRIPT_SIGNATURE")
        _require(item["purpose"] in {
            "child-approval", "predecessor-authorization"
        }, "LINEAGE_TRANSCRIPT_SIGNATURE_PURPOSE")
        parsed_facts.append({
            "purpose": item["purpose"],
            "key_id": _digest(item["key_id"], "LINEAGE_TRANSCRIPT_SIGNATURE"),
            "payload_digest": _digest(
                item["payload_digest"], "LINEAGE_TRANSCRIPT_SIGNATURE"
            ),
            "cose_digest": _digest(item["cose_digest"], "LINEAGE_TRANSCRIPT_SIGNATURE"),
            "public_key_digest": _digest(
                item["public_key_digest"], "LINEAGE_TRANSCRIPT_SIGNATURE"
            ),
        })
    _require(
        parsed_facts == sorted(
            parsed_facts, key=lambda item: (item["purpose"], item["key_id"])
        ),
        "LINEAGE_TRANSCRIPT_SIGNATURE_ORDER",
    )
    child_facts = [item for item in parsed_facts if item["purpose"] == "child-approval"]
    predecessor_facts = [
        item for item in parsed_facts
        if item["purpose"] == "predecessor-authorization"
    ]
    child_closed = (
        [item["key_id"] for item in child_facts] == child_keys
        and all(item["payload_digest"] == target for item in child_facts)
        and inputs.get("child-approval-cose", []) == [
            item["cose_digest"] for item in child_facts
        ]
        and inputs.get("child-public-key", []) == [
            item["public_key_digest"] for item in child_facts
        ]
    )

    same_authority = parent["authority"] == child["authority"]
    if edge["authorization_mode"] == "continuity":
        predecessor_closed = (
            same_authority and predecessor_facts == []
            and inputs.get("predecessor-authorization-cose", []) == []
            and inputs.get("parent-public-key", []) == []
            and len([item for item in child_facts if item["key_id"] in parent_keys])
                >= parent_threshold
        )
    else:
        predecessor_signers = [item["key_id"] for item in predecessor_facts]
        predecessor_closed = (
            not same_authority
            and predecessor_signers == sorted(set(predecessor_signers))
            and all(key in parent_keys for key in predecessor_signers)
            and len(predecessor_signers) >= parent_threshold
            and all(item["payload_digest"] == transition for item in predecessor_facts)
            and inputs.get("predecessor-authorization-cose", []) == [
                item["cose_digest"] for item in predecessor_facts
            ]
            and inputs.get("parent-public-key", []) == [
                item["public_key_digest"] for item in predecessor_facts
            ]
        )

    set_object = certificate["approval_set"]
    _require(isinstance(set_object, dict) and set(set_object) == {
        "approval_target_digest", "author_approvals",
        "lineage_authorizations", "input_digest",
    }, "LINEAGE_TRANSCRIPT_APPROVAL_SET")
    set_input = _digest(
        set_object["input_digest"], "LINEAGE_TRANSCRIPT_APPROVAL_SET"
    )
    author_entries = _approval_entries(
        set_object["author_approvals"], "LINEAGE_TRANSCRIPT_APPROVAL_SET_AUTHORS"
    )
    lineage_entries = _approval_entries(
        set_object["lineage_authorizations"], "LINEAGE_TRANSCRIPT_APPROVAL_SET_LINEAGE"
    )
    set_closed = (
        set_object["approval_target_digest"] == target
        and author_entries == [
            (item["key_id"], item["cose_digest"]) for item in child_facts
        ]
        and lineage_entries == [
            (item["key_id"], item["cose_digest"]) for item in predecessor_facts
        ]
        and _single(inputs, "approval-set", set_input)
    )

    input_closed = (
        _single(inputs, "parent-release", parent["release_input_digest"])
        and _single(inputs, "parent-pec", parent["pec_input_digest"])
        and _single(inputs, "child-release", child["release_input_digest"])
        and _single(inputs, "child-governance", child["governance_input_digest"])
        and _single(inputs, "child-pec", child["pec_input_digest"])
        and _single(inputs, "child-approval-target", child["approval_target_input_digest"])
        and _single(inputs, "lineage-transition", transition_input)
    )
    closed = (
        policy_pec == child_pec
        and claims.ClaimKind.AUTHORIZED_SUCCESSOR in permitted
        and structural
        and edge["transition_kind"] == expected_kind
        and bound_transition == transition
        and child_closed and predecessor_closed and set_closed and input_closed
    )
    if not closed:
        return ()
    subject = claims.LineageSubject(
        work, parent_release, parent_pec, parent_line, parent_version,
        child_release, child_pec, child_line, child_version, transition,
    )
    return (claims.AppraisedEvidence(
        claims.EvidenceKind.LINEAGE_AUTHORIZATION,
        subject,
        certificate_digest,
    ),)


def derive(certificate: dict, certificate_digest: str):
    policy = claims.permitted_claims(certificate["policy"]["permitted_outcomes"])
    return claims.derive(appraised_evidence(certificate, certificate_digest), policy)
