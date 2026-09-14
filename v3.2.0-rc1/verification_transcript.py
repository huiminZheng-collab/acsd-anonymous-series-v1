"""Pure structural checker for ACSD verification certificates.

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
MAX_SAFE_INTEGER = 9_007_199_254_740_991
SCHEMA_V1 = "acsd-verification-certificate/v1"
SCHEMA_V2 = "acsd-verification-certificate/v2"
SCHEMA_V3 = "acsd-verification-certificate/v3"
INPUT_ROLES = {
    "approval-target", "pec", "event-disclosure", "public-key",
    "author-approval-cose", "event-disclosure-cose",
    "release", "identity-disclosure", "identity-disclosure-cose",
    "approval-set", "time-request", "time-response", "tsa-certificate",
    "time-report",
}
TOP_FIELDS_V1 = {
    "schema", "inputs", "approval_target", "policy", "event_disclosure",
    "signature_facts", "merkle_facts", "identity_assertions",
    "timestamp_facts", "trusted_inputs",
}
TOP_FIELDS_V2 = TOP_FIELDS_V1 | {"release_context"}
TOP_FIELDS_V3 = TOP_FIELDS_V2 | {"approval_set"}


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


def _keys(value, code):
    _require(
        isinstance(value, list)
        and bool(value)
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
        _require(item["role"] in INPUT_ROLES, "TRANSCRIPT_INPUT_ROLE")
        _require(isinstance(item["path"], str) and item["path"], "TRANSCRIPT_INPUT")
        digest = _digest(item["sha256"], "TRANSCRIPT_INPUT")
        paths.append(item["path"])
        by_role.setdefault(item["role"], []).append(digest)
    _require(len(paths) == len(set(paths)), "TRANSCRIPT_DUPLICATE_INPUT")
    _require(
        inputs == sorted(inputs, key=lambda item: (item["path"], item["role"])),
        "TRANSCRIPT_INPUT_ORDER",
    )
    return by_role


def _closed_signatures(facts, purpose, required, payload, input_digests):
    selected = [item for item in facts if item["purpose"] == purpose]
    if [item["key_id"] for item in selected] != required:
        return False
    input_role = purpose + "-cose"
    available = input_digests.get(input_role, [])
    selected_cose = [item["cose_digest"] for item in selected]
    return (
        len(available) == len(set(available))
        and selected_cose == available
        and all(item["payload_digest"] == payload for item in selected)
    )


def appraised_evidence(certificate: dict, certificate_digest: str) -> Tuple[claims.AppraisedEvidence, ...]:
    """Return evidence atoms only for transcript groups with exact closure."""
    _digest(certificate_digest, "TRANSCRIPT_CERTIFICATE_DIGEST")
    _require(isinstance(certificate, dict), "TRANSCRIPT_FIELDS")
    schema = certificate.get("schema")
    _require(schema in {SCHEMA_V1, SCHEMA_V2, SCHEMA_V3}, "TRANSCRIPT_SCHEMA")
    expected_fields = (
        TOP_FIELDS_V3 if schema == SCHEMA_V3 else
        TOP_FIELDS_V2 if schema == SCHEMA_V2 else TOP_FIELDS_V1
    )
    _require(set(certificate) == expected_fields, "TRANSCRIPT_FIELDS")
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
        _require(item["purpose"] in {
            "author-approval", "event-disclosure", "identity-disclosure"
        },
                 "TRANSCRIPT_SIGNATURE_PURPOSE")
        _digest(item["key_id"], "TRANSCRIPT_SIGNATURE_KEY")
        _digest(item["payload_digest"], "TRANSCRIPT_SIGNATURE_PAYLOAD")
        _digest(item["cose_digest"], "TRANSCRIPT_SIGNATURE_COSE")
    _require(
        facts == sorted(facts, key=lambda item: (item["purpose"], item["key_id"])),
        "TRANSCRIPT_SIGNATURE_ORDER",
    )

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
    event_id = event["event_id"]
    _require(isinstance(event_id, str) and bool(event_id), "TRANSCRIPT_EVENT_ID")
    subject = claims.EventSubject(
        pec_digest,
        event_id,
        _nat(event["event_sequence"], "TRANSCRIPT_EVENT_SEQUENCE"),
        _digest(event["commitment_digest"], "TRANSCRIPT_EVENT_COMMITMENT"),
        _nat(event["first_index"], "TRANSCRIPT_EVENT_FIRST_INDEX"),
        _nat(event["last_index"], "TRANSCRIPT_EVENT_LAST_INDEX"),
    )
    merkle = certificate["merkle_facts"]
    _require(isinstance(merkle, list), "TRANSCRIPT_MERKLE_FACTS")
    expected_merkle = {
        "body_digest": body_digest,
        "commitment_digest": subject.commitment_digest,
        "first_index": subject.first_index,
        "last_index": subject.last_index,
        "opened_leaf_count": subject.last_index - subject.first_index + 1,
    }
    for item in merkle:
        _require(isinstance(item, dict) and set(item) == set(expected_merkle),
                 "TRANSCRIPT_MERKLE_FACT")
        _digest(item["body_digest"], "TRANSCRIPT_MERKLE_BODY")
        _digest(item["commitment_digest"], "TRANSCRIPT_MERKLE_COMMITMENT")
        _nat(item["first_index"], "TRANSCRIPT_MERKLE_FIRST_INDEX")
        _nat(item["last_index"], "TRANSCRIPT_MERKLE_LAST_INDEX")
        _nat(item["opened_leaf_count"], "TRANSCRIPT_MERKLE_LEAF_COUNT")
    if (merkle == [expected_merkle] and
            _closed_signatures(
                facts, "event-disclosure", event_keys, body_digest, input_digests
            )):
        evidence.append(claims.AppraisedEvidence(
            claims.EvidenceKind.EVENT_DISCLOSURE,
            subject,
            certificate_digest,
        ))

    if schema != SCHEMA_V3:
        _require(certificate["timestamp_facts"] == [],
                 "TRANSCRIPT_UNSUPPORTED_EXTENSION")
        _require(certificate["trusted_inputs"] == [],
                 "TRANSCRIPT_UNSUPPORTED_EXTENSION")
    if schema == SCHEMA_V1:
        _require(certificate["identity_assertions"] == [],
                 "TRANSCRIPT_UNSUPPORTED_EXTENSION")
    else:
        release = certificate["release_context"]
        _require(isinstance(release, dict) and set(release) == {
            "release_digest", "author_slots"
        }, "TRANSCRIPT_RELEASE_CONTEXT")
        release_digest = _digest(
            release["release_digest"], "TRANSCRIPT_RELEASE_DIGEST"
        )
        slots = release["author_slots"]
        _require(isinstance(slots, list) and bool(slots), "TRANSCRIPT_AUTHOR_SLOTS")
        parsed_slots = []
        for item in slots:
            _require(isinstance(item, dict) and set(item) == {"slot", "key_id"},
                     "TRANSCRIPT_AUTHOR_SLOT")
            slot = _nat(item["slot"], "TRANSCRIPT_AUTHOR_SLOT")
            _require(slot > 0, "TRANSCRIPT_AUTHOR_SLOT")
            parsed_slots.append((
                slot,
                _digest(item["key_id"], "TRANSCRIPT_AUTHOR_SLOT_KEY"),
            ))
        _require(
            parsed_slots == sorted(set(parsed_slots))
            and len({slot for slot, _ in parsed_slots}) == len(parsed_slots)
            and len({key for _, key in parsed_slots}) == len(parsed_slots),
            "TRANSCRIPT_AUTHOR_SLOTS",
        )

        identities = certificate["identity_assertions"]
        _require(isinstance(identities, list) and bool(identities),
                 "TRANSCRIPT_IDENTITY_ASSERTIONS")
        parsed_identities = []
        for item in identities:
            _require(isinstance(item, dict) and set(item) == {
                "body_digest", "release_digest", "author_slot", "author_key_id",
                "assertion_digest", "cose_digest",
            }, "TRANSCRIPT_IDENTITY_ASSERTION")
            author_slot = _nat(item["author_slot"], "TRANSCRIPT_IDENTITY_SLOT")
            _require(author_slot > 0, "TRANSCRIPT_IDENTITY_SLOT")
            parsed_identities.append({
                "body_digest": _digest(item["body_digest"], "TRANSCRIPT_IDENTITY_BODY"),
                "release_digest": _digest(
                    item["release_digest"], "TRANSCRIPT_IDENTITY_RELEASE"
                ),
                "author_slot": author_slot,
                "author_key_id": _digest(
                    item["author_key_id"], "TRANSCRIPT_IDENTITY_KEY"
                ),
                "assertion_digest": _digest(
                    item["assertion_digest"], "TRANSCRIPT_IDENTITY_ASSERTION_DIGEST"
                ),
                "cose_digest": _digest(item["cose_digest"], "TRANSCRIPT_IDENTITY_COSE"),
            })
        _require(
            parsed_identities == sorted(parsed_identities, key=lambda item: item["author_slot"])
            and len({item["author_slot"] for item in parsed_identities})
                == len(parsed_identities),
            "TRANSCRIPT_IDENTITY_ORDER",
        )
        selected = [item for item in facts if item["purpose"] == "identity-disclosure"]
        expected_signatures = [
            {
                "purpose": "identity-disclosure",
                "key_id": item["author_key_id"],
                "payload_digest": item["body_digest"],
                "cose_digest": item["cose_digest"],
            }
            for item in parsed_identities
        ]
        closed = (
            selected == expected_signatures
            and input_digests.get("identity-disclosure-cose", [])
                == [item["cose_digest"] for item in parsed_identities]
            and len({item["cose_digest"] for item in parsed_identities})
                == len(parsed_identities)
            and all(
                item["release_digest"] == release_digest
                and (item["author_slot"], item["author_key_id"]) in parsed_slots
                for item in parsed_identities
            )
        )
        if closed:
            for item in parsed_identities:
                evidence.append(claims.AppraisedEvidence(
                    claims.EvidenceKind.SLOT_IDENTITY_ASSENT,
                    claims.IdentitySubject(
                        release_digest,
                        item["author_slot"],
                        item["author_key_id"],
                        item["assertion_digest"],
                    ),
                    certificate_digest,
                ))

    if schema == SCHEMA_V3:
        approval_set = certificate["approval_set"]
        _require(isinstance(approval_set, dict) and set(approval_set) == {
            "body_digest", "approval_target_digest", "author_approvals",
            "lineage_authorizations",
        }, "TRANSCRIPT_APPROVAL_SET")
        set_digest = _digest(
            approval_set["body_digest"], "TRANSCRIPT_APPROVAL_SET_DIGEST"
        )
        _require(
            approval_set["approval_target_digest"] == target_digest,
            "TRANSCRIPT_APPROVAL_SET_TARGET",
        )
        set_approvals = approval_set["author_approvals"]
        _require(isinstance(set_approvals, list), "TRANSCRIPT_APPROVAL_SET_AUTHORS")
        parsed_set_approvals = []
        for item in set_approvals:
            _require(isinstance(item, dict) and set(item) == {
                "key_id", "cose_sha256"
            }, "TRANSCRIPT_APPROVAL_SET_AUTHOR")
            parsed_set_approvals.append((
                _digest(item["key_id"], "TRANSCRIPT_APPROVAL_SET_KEY"),
                _digest(item["cose_sha256"], "TRANSCRIPT_APPROVAL_SET_COSE"),
            ))
        selected_approvals = [
            (item["key_id"], item["cose_digest"])
            for item in facts if item["purpose"] == "author-approval"
        ]
        approval_set_closed = (
            parsed_set_approvals == selected_approvals
            and [key for key, _ in parsed_set_approvals] == approval_keys
            and approval_set["lineage_authorizations"] == []
        )

        time_facts = certificate["timestamp_facts"]
        trusted = certificate["trusted_inputs"]
        _require(isinstance(time_facts, list) and len(time_facts) == 1,
                 "TRANSCRIPT_TIME_FACTS")
        _require(isinstance(trusted, list) and len(trusted) == 1,
                 "TRANSCRIPT_TRUSTED_INPUTS")
        time_fact = time_facts[0]
        trust = trusted[0]
        expected_time_fields = {
            "schema", "subject_kind", "subject_digest", "not_after_utc",
            "request_digest", "response_digest", "certificate_digest",
            "report_digest", "approval_set_input_digest", "nonce",
            "signer_fingerprint", "trust_model", "authority_class",
            "policy_oid", "serial_hex",
        }
        _require(isinstance(time_fact, dict) and set(time_fact) == expected_time_fields,
                 "TRANSCRIPT_TIME_FACT")
        _require(isinstance(trust, dict) and set(trust) == {
            "kind", "signer_fingerprint", "certificate_digest", "authority_class"
        }, "TRANSCRIPT_TRUSTED_INPUT")
        for field in (
            "subject_digest", "request_digest", "response_digest",
            "certificate_digest", "report_digest", "approval_set_input_digest",
            "signer_fingerprint",
        ):
            _digest(time_fact[field], "TRANSCRIPT_TIME_DIGEST")
        _require(
            isinstance(time_fact["nonce"], str)
            and re.fullmatch(r"[0-9a-f]{32}", time_fact["nonce"]),
            "TRANSCRIPT_TIME_NONCE",
        )
        _require(
            isinstance(time_fact["policy_oid"], str) and time_fact["policy_oid"]
            and isinstance(time_fact["serial_hex"], str)
            and re.fullmatch(r"[0-9a-f]+", time_fact["serial_hex"]),
            "TRANSCRIPT_TIME_METADATA",
        )
        time_subject = claims.ApprovalSetTimeSubject(
            set_digest, time_fact["not_after_utc"]
        )
        time_closed = (
            approval_set_closed
            and time_fact["schema"] == "acsd-rfc3161-appraisal/v1"
            and time_fact["subject_kind"] == "approval-set"
            and time_fact["subject_digest"] == set_digest
            and time_fact["trust_model"] == "exact-signer-pin"
            and time_fact["authority_class"] == "external"
            and trust == {
                "kind": "tsa-exact-signer-pin",
                "signer_fingerprint": time_fact["signer_fingerprint"],
                "certificate_digest": time_fact["certificate_digest"],
                "authority_class": "external",
            }
            and input_digests.get("approval-set", []) == [
                time_fact["approval_set_input_digest"]
            ]
            and input_digests.get("time-request", []) == [time_fact["request_digest"]]
            and input_digests.get("time-response", []) == [time_fact["response_digest"]]
            and input_digests.get("tsa-certificate", []) == [
                time_fact["certificate_digest"]
            ]
            and input_digests.get("time-report", []) == [time_fact["report_digest"]]
        )
        if time_closed:
            evidence.append(claims.AppraisedEvidence(
                claims.EvidenceKind.APPROVAL_SET_TIMESTAMP,
                time_subject,
                certificate_digest,
            ))
    return tuple(evidence)


def derive(certificate: dict, certificate_digest: str):
    policy = claims.permitted_claims(certificate["policy"]["permitted_outcomes"])
    return claims.derive(appraised_evidence(certificate, certificate_digest), policy)
