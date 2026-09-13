"""Closed evidence-to-claim derivation for ACSD verifier consumers.

This module does not verify cryptography.  It consumes already verified,
typed evidence atoms and prevents callers from silently relabelling one kind
of evidence as a stronger or different claim.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import FrozenSet, Iterable


class EvidenceKind(str, Enum):
    UNANIMOUS_APPROVAL = "UNANIMOUS_APPROVAL"
    EVENT_DISCLOSURE = "EVENT_DISCLOSURE"
    APPROVAL_TARGET_TIMESTAMP = "APPROVAL_TARGET_TIMESTAMP"
    APPROVAL_SET_TIMESTAMP = "APPROVAL_SET_TIMESTAMP"
    SCITT_INCLUSION = "SCITT_INCLUSION"
    SLOT_IDENTITY_ASSENT = "SLOT_IDENTITY_ASSENT"


class ClaimKind(str, Enum):
    KEY_ASSENT = "KEY_ASSENT"
    GOVERNANCE_ASSENT = "GOVERNANCE_ASSENT"
    COMMITTED_EVIDENCE_MATCH = "COMMITTED_EVIDENCE_MATCH"
    TARGET_IMPRINT_EXISTED_NOT_AFTER = "TARGET_IMPRINT_EXISTED_NOT_AFTER"
    APPROVAL_SET_IMPRINT_EXISTED_NOT_AFTER = "APPROVAL_SET_IMPRINT_EXISTED_NOT_AFTER"
    STATEMENT_REGISTERED = "STATEMENT_REGISTERED"
    SLOT_KEY_ASSENT_TO_IDENTITY_ASSERTION = "SLOT_KEY_ASSENT_TO_IDENTITY_ASSERTION"
    NATURAL_PERSON_IDENTITY_VERIFIED = "NATURAL_PERSON_IDENTITY_VERIFIED"
    ORIGINALITY_VERIFIED = "ORIGINALITY_VERIFIED"
    SIGNERS_UNCOMPROMISED_AT_TIME = "SIGNERS_UNCOMPROMISED_AT_TIME"


GRANTS = {
    EvidenceKind.UNANIMOUS_APPROVAL: frozenset({
        ClaimKind.KEY_ASSENT,
        ClaimKind.GOVERNANCE_ASSENT,
    }),
    EvidenceKind.EVENT_DISCLOSURE: frozenset({ClaimKind.COMMITTED_EVIDENCE_MATCH}),
    EvidenceKind.APPROVAL_TARGET_TIMESTAMP: frozenset({
        ClaimKind.TARGET_IMPRINT_EXISTED_NOT_AFTER
    }),
    EvidenceKind.APPROVAL_SET_TIMESTAMP: frozenset({
        ClaimKind.APPROVAL_SET_IMPRINT_EXISTED_NOT_AFTER
    }),
    EvidenceKind.SCITT_INCLUSION: frozenset({ClaimKind.STATEMENT_REGISTERED}),
    EvidenceKind.SLOT_IDENTITY_ASSENT: frozenset({
        ClaimKind.SLOT_KEY_ASSENT_TO_IDENTITY_ASSERTION
    }),
}


@dataclass(frozen=True)
class Evidence:
    kind: EvidenceKind
    subject_digest: str
    verified: bool


@dataclass(frozen=True)
class Claim:
    kind: ClaimKind
    subject_digest: str


def derive(evidence: Iterable[Evidence], permitted: Iterable[ClaimKind]) -> FrozenSet[Claim]:
    """Return only exact-subject claims permitted by the closed mapping."""
    allowed = frozenset(permitted)
    return frozenset(
        Claim(kind=claim_kind, subject_digest=item.subject_digest)
        for item in evidence
        if item.verified
        for claim_kind in GRANTS[item.kind]
        if claim_kind in allowed
    )


def decision(
    evidence: Iterable[Evidence], permitted: Iterable[ClaimKind], requested: Claim
) -> str:
    return "GRANTED" if requested in derive(evidence, permitted) else "DENIED"
