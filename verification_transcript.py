"""Pure structural checker for acsd-verification-certificate/v1.

The byte-level Python and Node adapters emit a transcript without claims. This
module checks closure of the transcript and converts only closed fact groups
into typed evidence for ``claim_derivation``. It performs no I/O and no
cryptographic verification.
"""

from __future__ import annotations

import re
from typing import Iterable, Tuple

import claim_derivation as claims


HEX64 = re.compile(r"[0-9a-f]{64}")
SCHEMA = "acsd-verification-certificate/v1"
TOP_FIELDS = {
    "schema", "inputs", "approval_target", "policy", "event_disclosure",
    "signature_facts", "merkle_facts", "identity_assertions",
    "timestamp_facts", "trusted_inputs",
}


def _require(condition, code):
    if not condition:
        raise ValueError(code)


def _digest(value, code):
    _require(isinstance(value, str) and HEX64.fullmatch(value), code)
    return value


def _keys(value, code):
    _require(
        isinstance(value, list)
        and all(isinstance(item, str) and HEX64.fullmatch(item) for item in value)
        and value == sorted(set(value)),
        code,
    )
    return value


def _input_digests(certificate):
    inputs = certificate["inputs"]
    _require(isinstance(inputs, list), "TRANSCRIPT_INPUTS")
    paths = []
    by_role = {}
    for item in inputs:
        _require(isinstance(item, dict) and set(item) == {"role", "path", "sha256"},
                 "TRANSCRIPT_INPUT")
        _require(isinstance(item["role"], str) and item["role"], "TRANSCRIPT_INPUT")
        _require(isinstance(item["path"], str) and item["path"], "TRANSCRIPT_INPUT")
        digest = _digest(item["sha256"], "TRANSCRIPT_INPUT")
        paths.append(item["path"])
        by_role.setdefault(item["role"], set()).add(digest)
    _require(len(paths) == len(set(paths)), "TRANSCRIPT_DUPLICATE_INPUT")
    return by_role


def _closed_signatures(facts, purpose, required, payload, input_digests):
    selected = [item for item in facts if item["purpose"] == purpose]
    if [item["key_id"] for item in selected] != required:
        return False
    input_role = purpose + "-cose"
    available = input_digests.get(input_role, set())
    return all(
        item["payload_digest"] == payload and item["cose_digest"] in available
        for item in selected
    )


def appraised_evidence(certificate: dict, certificate_digest: str) -> Tuple[claims.AppraisedEvidence, ...]:
    """Return evidence atoms only for transcript groups with exact closure."""
    _digest(certificate_digest, "TRANSCRIPT_CERTIFICATE_DIGEST")
    _require(isinstance(certificate, dict) and set(certificate) == TOP_FIELDS,
             "TRANSCRIPT_FIELDS")
    _require(certificate["schema"] == SCHEMA, "TRANSCRIPT_SCHEMA")
    input_digests = _input_digests(certificate)

    approval = certificate["approval_target"]
    _require(isinstance(approval, dict) and set(approval) == {
        "target_digest", "pec_digest", "required_key_ids"
    }, "TRANSCRIPT_APPROVAL_TARGET")
    target_digest = _digest(approval["target_digest"], "TRANSCRIPT_TARGET_DIGEST")
    pec_digest = _digest(approval["pec_digest"], "TRANSCRIPT_PEC_DIGEST")
    approval_keys = _keys(approval["required_key_ids"], "TRANSCRIPT_APPROVAL_KEYS")

    policy = certificate["policy"]
    _require(isinstance(policy, dict) and set(policy) == {
        "pec_digest", "permitted_outcomes"
    }, "TRANSCRIPT_POLICY")
    _require(policy["pec_digest"] == pec_digest, "TRANSCRIPT_POLICY_SCOPE")
    claims.permitted_claims(policy["permitted_outcomes"])

    facts = certificate["signature_facts"]
    _require(isinstance(facts, list), "TRANSCRIPT_SIGNATURE_FACTS")
    for item in facts:
        _require(isinstance(item, dict) and set(item) == {
            "purpose", "key_id", "payload_digest", "cose_digest"
        }, "TRANSCRIPT_SIGNATURE_FACT")
        _require(item["purpose"] in {"author-approval", "event-disclosure"},
                 "TRANSCRIPT_SIGNATURE_PURPOSE")
        _digest(item["key_id"], "TRANSCRIPT_SIGNATURE_KEY")
        _digest(item["payload_digest"], "TRANSCRIPT_SIGNATURE_PAYLOAD")
        _digest(item["cose_digest"], "TRANSCRIPT_SIGNATURE_COSE")
    facts = sorted(facts, key=lambda item: (item["purpose"], item["key_id"]))

    evidence = []
    if _closed_signatures(
        facts, "author-approval", approval_keys, target_digest, input_digests
    ):
        evidence.append(claims.AppraisedEvidence(
            claims.EvidenceKind.UNANIMOUS_APPROVAL,
            claims.ApprovalTargetSubject(target_digest),
            certificate_digest,
        ))

    event = certificate["event_disclosure"]
    _require(isinstance(event, dict) and set(event) == {
        "body_digest", "pec_digest", "event_id", "event_sequence",
        "commitment_digest", "first_index", "last_index", "required_key_ids"
    }, "TRANSCRIPT_EVENT")
    body_digest = _digest(event["body_digest"], "TRANSCRIPT_EVENT_BODY")
    _require(event["pec_digest"] == pec_digest, "TRANSCRIPT_EVENT_PEC")
    event_keys = _keys(event["required_key_ids"], "TRANSCRIPT_EVENT_KEYS")
    subject = claims.EventSubject(
        pec_digest,
        event["event_id"],
        _digest(event["commitment_digest"], "TRANSCRIPT_EVENT_COMMITMENT"),
        event["first_index"],
        event["last_index"],
    )
    merkle = certificate["merkle_facts"]
    _require(isinstance(merkle, list), "TRANSCRIPT_MERKLE_FACTS")
    exact_merkle = [item for item in merkle if isinstance(item, dict) and item == {
        "body_digest": body_digest,
        "commitment_digest": subject.commitment_digest,
        "first_index": subject.first_index,
        "last_index": subject.last_index,
        "opened_leaf_count": subject.last_index - subject.first_index + 1,
    }]
    if (len(exact_merkle) == 1 and
            _closed_signatures(
                facts, "event-disclosure", event_keys, body_digest, input_digests
            )):
        evidence.append(claims.AppraisedEvidence(
            claims.EvidenceKind.EVENT_DISCLOSURE,
            subject,
            certificate_digest,
        ))

    for name in ("identity_assertions", "timestamp_facts", "trusted_inputs"):
        _require(isinstance(certificate[name], list), "TRANSCRIPT_EXTENSION_FIELD")
    return tuple(evidence)


def derive(certificate: dict, certificate_digest: str):
    policy = claims.permitted_claims(certificate["policy"]["permitted_outcomes"])
    return claims.derive(appraised_evidence(certificate, certificate_digest), policy)
