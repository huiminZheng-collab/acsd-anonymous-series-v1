"""Claim-free wire boundary for already appraised evidence.

Byte-level adapters are responsible for establishing each evidence atom.  This
module performs no I/O or cryptography: it strictly serializes/parses exact
subjects and lets :mod:`claim_derivation` remain the only granting kernel.
"""

from __future__ import annotations

from typing import Iterable, Tuple

import claim_derivation as claims
from canonical_json import canonical


SCHEMA = "acsd-appraisal-transcript/v1"
MAX_SAFE_INTEGER = 9_007_199_254_740_991
TOP_FIELDS = {"schema", "policy", "evidence"}
EVIDENCE_FIELDS = {"index", "kind", "subject", "certificate_digest"}
EVIDENCE_ORDER = tuple(claims.EvidenceKind)
EVIDENCE_RANK = {kind: index for index, kind in enumerate(EVIDENCE_ORDER)}


def _require(condition, code):
    if not condition:
        raise ValueError(code)


def _fields(value, expected, code):
    _require(isinstance(value, dict) and set(value) == set(expected), code)
    return value


def _digest(value, code):
    _require(
        isinstance(value, str) and claims.HEX64.fullmatch(value) is not None,
        code,
    )
    return value


def _nat(value, code, *, positive=False):
    _require(
        isinstance(value, int)
        and not isinstance(value, bool)
        and (value > 0 if positive else value >= 0)
        and value <= MAX_SAFE_INTEGER,
        code,
    )
    return value


def subject_to_wire(subject: claims.Subject) -> dict:
    if isinstance(subject, claims.ApprovalTargetSubject):
        return {"kind": "approval-target", "target_digest": subject.target_digest}
    if isinstance(subject, claims.ApprovalTargetTimeSubject):
        return {
            "kind": "approval-target-time",
            "target_digest": subject.target_digest,
            "not_after_utc": subject.not_after_utc,
        }
    if isinstance(subject, claims.ApprovalSetTimeSubject):
        return {
            "kind": "approval-set-time",
            "approval_set_digest": subject.approval_set_digest,
            "not_after_utc": subject.not_after_utc,
        }
    if isinstance(subject, claims.EventSubject):
        return {
            "kind": "event-window",
            "pec_digest": subject.pec_digest,
            "event_id": subject.event_id,
            "event_sequence": subject.event_sequence,
            "commitment_digest": subject.commitment_digest,
            "first_index": subject.first_index,
            "last_index": subject.last_index,
        }
    if isinstance(subject, claims.IdentitySubject):
        return {
            "kind": "identity-assertion",
            "release_digest": subject.release_digest,
            "author_slot": subject.author_slot,
            "author_key_id": subject.author_key_id,
            "assertion_digest": subject.assertion_digest,
        }
    if isinstance(subject, claims.StatementSubject):
        return {
            "kind": "registered-statement",
            "statement_digest": subject.statement_digest,
        }
    if isinstance(subject, claims.LineageSubject):
        return {
            "kind": "lineage-edge",
            "work_id_digest": subject.work_id_digest,
            "parent_release_digest": subject.parent_release_digest,
            "parent_pec_digest": subject.parent_pec_digest,
            "parent_line_digest": subject.parent_line_digest,
            "parent_version": subject.parent_version,
            "child_release_digest": subject.child_release_digest,
            "child_pec_digest": subject.child_pec_digest,
            "child_line_digest": subject.child_line_digest,
            "child_version": subject.child_version,
            "transition_digest": subject.transition_digest,
        }
    raise ValueError("APPRAISAL_TRANSCRIPT_SUBJECT_TYPE")


def subject_from_wire(value: dict) -> claims.Subject:
    _require(isinstance(value, dict), "APPRAISAL_TRANSCRIPT_SUBJECT")
    kind = value.get("kind")
    if kind == "approval-target":
        _fields(value, {"kind", "target_digest"}, "APPRAISAL_TRANSCRIPT_SUBJECT")
        return claims.ApprovalTargetSubject(
            _digest(value["target_digest"], "APPRAISAL_TRANSCRIPT_SUBJECT")
        )
    if kind == "approval-target-time":
        _fields(
            value,
            {"kind", "target_digest", "not_after_utc"},
            "APPRAISAL_TRANSCRIPT_SUBJECT",
        )
        return claims.ApprovalTargetTimeSubject(
            _digest(value["target_digest"], "APPRAISAL_TRANSCRIPT_SUBJECT"),
            value["not_after_utc"],
        )
    if kind == "approval-set-time":
        _fields(
            value,
            {"kind", "approval_set_digest", "not_after_utc"},
            "APPRAISAL_TRANSCRIPT_SUBJECT",
        )
        return claims.ApprovalSetTimeSubject(
            _digest(value["approval_set_digest"], "APPRAISAL_TRANSCRIPT_SUBJECT"),
            value["not_after_utc"],
        )
    if kind == "event-window":
        _fields(
            value,
            {
                "kind", "pec_digest", "event_id", "event_sequence",
                "commitment_digest", "first_index", "last_index",
            },
            "APPRAISAL_TRANSCRIPT_SUBJECT",
        )
        return claims.EventSubject(
            _digest(value["pec_digest"], "APPRAISAL_TRANSCRIPT_SUBJECT"),
            value["event_id"],
            _nat(value["event_sequence"], "APPRAISAL_TRANSCRIPT_SUBJECT"),
            _digest(value["commitment_digest"], "APPRAISAL_TRANSCRIPT_SUBJECT"),
            _nat(value["first_index"], "APPRAISAL_TRANSCRIPT_SUBJECT"),
            _nat(value["last_index"], "APPRAISAL_TRANSCRIPT_SUBJECT"),
        )
    if kind == "identity-assertion":
        _fields(
            value,
            {
                "kind", "release_digest", "author_slot", "author_key_id",
                "assertion_digest",
            },
            "APPRAISAL_TRANSCRIPT_SUBJECT",
        )
        return claims.IdentitySubject(
            _digest(value["release_digest"], "APPRAISAL_TRANSCRIPT_SUBJECT"),
            _nat(value["author_slot"], "APPRAISAL_TRANSCRIPT_SUBJECT", positive=True),
            _digest(value["author_key_id"], "APPRAISAL_TRANSCRIPT_SUBJECT"),
            _digest(value["assertion_digest"], "APPRAISAL_TRANSCRIPT_SUBJECT"),
        )
    if kind == "registered-statement":
        _fields(
            value,
            {"kind", "statement_digest"},
            "APPRAISAL_TRANSCRIPT_SUBJECT",
        )
        return claims.StatementSubject(
            _digest(value["statement_digest"], "APPRAISAL_TRANSCRIPT_SUBJECT")
        )
    if kind == "lineage-edge":
        fields = {
            "kind", "work_id_digest", "parent_release_digest",
            "parent_pec_digest", "parent_line_digest", "parent_version",
            "child_release_digest", "child_pec_digest", "child_line_digest",
            "child_version", "transition_digest",
        }
        _fields(value, fields, "APPRAISAL_TRANSCRIPT_SUBJECT")
        return claims.LineageSubject(
            _digest(value["work_id_digest"], "APPRAISAL_TRANSCRIPT_SUBJECT"),
            _digest(value["parent_release_digest"], "APPRAISAL_TRANSCRIPT_SUBJECT"),
            _digest(value["parent_pec_digest"], "APPRAISAL_TRANSCRIPT_SUBJECT"),
            _digest(value["parent_line_digest"], "APPRAISAL_TRANSCRIPT_SUBJECT"),
            _nat(value["parent_version"], "APPRAISAL_TRANSCRIPT_SUBJECT", positive=True),
            _digest(value["child_release_digest"], "APPRAISAL_TRANSCRIPT_SUBJECT"),
            _digest(value["child_pec_digest"], "APPRAISAL_TRANSCRIPT_SUBJECT"),
            _digest(value["child_line_digest"], "APPRAISAL_TRANSCRIPT_SUBJECT"),
            _nat(value["child_version"], "APPRAISAL_TRANSCRIPT_SUBJECT", positive=True),
            _digest(value["transition_digest"], "APPRAISAL_TRANSCRIPT_SUBJECT"),
        )
    raise ValueError("APPRAISAL_TRANSCRIPT_SUBJECT_KIND")


def _policy_wire(permitted_outcomes: Iterable[str]) -> list:
    values = list(permitted_outcomes)
    claims.permitted_claims(values)
    _require(len(values) == len(set(values)), "APPRAISAL_TRANSCRIPT_POLICY_DUPLICATE")
    present = set(values)
    return [name for name in claims.WIRE_ORDER if name in present]


def _entry_key(item: dict):
    kind = claims.EvidenceKind(item["kind"])
    return (
        EVIDENCE_RANK[kind],
        canonical(item["subject"]),
        item["certificate_digest"],
    )


def _semantic_encoding(item: dict) -> bytes:
    return canonical(
        {
            "kind": item["kind"],
            "subject": item["subject"],
            "certificate_digest": item["certificate_digest"],
        }
    )


def build(
    permitted_outcomes: Iterable[str],
    evidence: Iterable[claims.AppraisedEvidence],
) -> dict:
    entries = [
        {
            "kind": item.kind.value,
            "subject": subject_to_wire(item.subject),
            "certificate_digest": item.certificate_digest,
        }
        for item in evidence
    ]
    entries.sort(key=_entry_key)
    for index, entry in enumerate(entries):
        entry["index"] = index
    result = {
        "schema": SCHEMA,
        "policy": {"permitted_outcomes": _policy_wire(permitted_outcomes)},
        "evidence": entries,
    }
    parse(result)
    return result


def parse(value: dict) -> Tuple[Tuple[claims.AppraisedEvidence, ...], frozenset]:
    _fields(value, TOP_FIELDS, "APPRAISAL_TRANSCRIPT_FIELDS")
    _require(value["schema"] == SCHEMA, "APPRAISAL_TRANSCRIPT_SCHEMA")
    policy = _fields(
        value["policy"], {"permitted_outcomes"}, "APPRAISAL_TRANSCRIPT_POLICY"
    )
    outcomes = policy["permitted_outcomes"]
    _require(isinstance(outcomes, list), "APPRAISAL_TRANSCRIPT_POLICY")
    _require(
        outcomes == _policy_wire(outcomes),
        "APPRAISAL_TRANSCRIPT_POLICY_ORDER",
    )
    permitted = claims.permitted_claims(outcomes)

    raw_evidence = value["evidence"]
    _require(isinstance(raw_evidence, list), "APPRAISAL_TRANSCRIPT_EVIDENCE")
    parsed = []
    for index, item in enumerate(raw_evidence):
        _fields(item, EVIDENCE_FIELDS, "APPRAISAL_TRANSCRIPT_EVIDENCE_ITEM")
        _require(
            _nat(item["index"], "APPRAISAL_TRANSCRIPT_EVIDENCE_INDEX") == index,
            "APPRAISAL_TRANSCRIPT_EVIDENCE_ORDER",
        )
        try:
            kind = claims.EvidenceKind(item["kind"])
        except (TypeError, ValueError) as exc:
            raise ValueError("APPRAISAL_TRANSCRIPT_EVIDENCE_KIND") from exc
        subject = subject_from_wire(item["subject"])
        certificate = _digest(
            item["certificate_digest"], "APPRAISAL_TRANSCRIPT_CERTIFICATE_DIGEST"
        )
        try:
            parsed.append(claims.AppraisedEvidence(kind, subject, certificate))
        except ValueError as exc:
            if str(exc) == "EVIDENCE_SUBJECT_KIND_MISMATCH":
                raise ValueError("APPRAISAL_TRANSCRIPT_SUBJECT_KIND_MISMATCH") from exc
            raise
    encodings = [_semantic_encoding(item) for item in raw_evidence]
    _require(
        len(encodings) == len(set(encodings)),
        "APPRAISAL_TRANSCRIPT_EVIDENCE_DUPLICATE",
    )
    return tuple(parsed), permitted


def derive(value: dict) -> Tuple[claims.Derivation, ...]:
    evidence, permitted = parse(value)
    return claims.derive(evidence, permitted)
