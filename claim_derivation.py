"""Pure, typed evidence-to-claim decision kernel.

Cryptographic and parser adapters may construct :class:`AppraisedEvidence`
only after checking the exact bytes named by ``certificate_digest``. This
module performs no I/O and grants no claim without an explicit, exact-subject
compatibility rule. It is the narrow boundary between byte-level verification
and application-visible security claims.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
import re
from typing import FrozenSet, Iterable, Tuple, Union


HEX64 = re.compile(r"[0-9a-f]{64}")


def _require_digest(value: str, field: str) -> None:
    if not isinstance(value, str) or HEX64.fullmatch(value) is None:
        raise ValueError("INVALID_" + field.upper())


def _require_nonnegative(value: int, field: str) -> None:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise ValueError("INVALID_" + field.upper())


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


@dataclass(frozen=True)
class ApprovalTargetSubject:
    target_digest: str

    def __post_init__(self) -> None:
        _require_digest(self.target_digest, "target_digest")


@dataclass(frozen=True)
class ApprovalSetSubject:
    approval_set_digest: str

    def __post_init__(self) -> None:
        _require_digest(self.approval_set_digest, "approval_set_digest")


@dataclass(frozen=True)
class EventSubject:
    pec_digest: str
    event_id: str
    commitment_digest: str
    first_index: int
    last_index: int

    def __post_init__(self) -> None:
        _require_digest(self.pec_digest, "pec_digest")
        _require_digest(self.commitment_digest, "commitment_digest")
        if not isinstance(self.event_id, str) or not self.event_id:
            raise ValueError("INVALID_EVENT_ID")
        _require_nonnegative(self.first_index, "first_index")
        _require_nonnegative(self.last_index, "last_index")
        if self.first_index > self.last_index:
            raise ValueError("INVALID_EVENT_WINDOW")


@dataclass(frozen=True)
class IdentitySubject:
    release_digest: str
    author_slot: int
    author_key_id: str
    assertion_digest: str

    def __post_init__(self) -> None:
        _require_digest(self.release_digest, "release_digest")
        _require_nonnegative(self.author_slot, "author_slot")
        _require_digest(self.author_key_id, "author_key_id")
        _require_digest(self.assertion_digest, "assertion_digest")


@dataclass(frozen=True)
class StatementSubject:
    statement_digest: str

    def __post_init__(self) -> None:
        _require_digest(self.statement_digest, "statement_digest")


Subject = Union[
    ApprovalTargetSubject,
    ApprovalSetSubject,
    EventSubject,
    IdentitySubject,
    StatementSubject,
]


SUBJECT_TYPES = {
    EvidenceKind.UNANIMOUS_APPROVAL: ApprovalTargetSubject,
    EvidenceKind.EVENT_DISCLOSURE: EventSubject,
    EvidenceKind.APPROVAL_TARGET_TIMESTAMP: ApprovalTargetSubject,
    EvidenceKind.APPROVAL_SET_TIMESTAMP: ApprovalSetSubject,
    EvidenceKind.SCITT_INCLUSION: StatementSubject,
    EvidenceKind.SLOT_IDENTITY_ASSENT: IdentitySubject,
}


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


WIRE_TO_CLAIM = {
    "KEY_ASSENT": ClaimKind.KEY_ASSENT,
    "GOVERNANCE_ASSENT": ClaimKind.GOVERNANCE_ASSENT,
    "COMMITTED_EVIDENCE_MATCH": ClaimKind.COMMITTED_EVIDENCE_MATCH,
    "EXTERNALLY_NOT_AFTER": ClaimKind.TARGET_IMPRINT_EXISTED_NOT_AFTER,
    "APPROVAL_SET_EXISTED_NOT_AFTER": ClaimKind.APPROVAL_SET_IMPRINT_EXISTED_NOT_AFTER,
    "STATEMENT_REGISTERED": ClaimKind.STATEMENT_REGISTERED,
    "SLOT_KEY_ASSENT_TO_IDENTITY_ASSERTION": (
        ClaimKind.SLOT_KEY_ASSENT_TO_IDENTITY_ASSERTION
    ),
}

CLAIM_TO_WIRE = {value: key for key, value in WIRE_TO_CLAIM.items()}
WIRE_ORDER = (
    "KEY_ASSENT",
    "GOVERNANCE_ASSENT",
    "COMMITTED_EVIDENCE_MATCH",
    "EXTERNALLY_NOT_AFTER",
    "APPROVAL_SET_EXISTED_NOT_AFTER",
    "STATEMENT_REGISTERED",
    "SLOT_KEY_ASSENT_TO_IDENTITY_ASSERTION",
)


@dataclass(frozen=True)
class AppraisedEvidence:
    """Typed fact emitted by a successful byte-level adapter.

    ``certificate_digest`` names the exact signature, receipt, disclosure, or
    aggregate verification transcript supporting the fact. Adapter soundness
    is an explicit assumption; there is no caller-controlled ``verified`` bit.
    """

    kind: EvidenceKind
    subject: Subject
    certificate_digest: str

    def __post_init__(self) -> None:
        if not isinstance(self.kind, EvidenceKind):
            raise ValueError("INVALID_EVIDENCE_KIND")
        expected = SUBJECT_TYPES[self.kind]
        if not isinstance(self.subject, expected):
            raise ValueError("EVIDENCE_SUBJECT_KIND_MISMATCH")
        _require_digest(self.certificate_digest, "certificate_digest")


@dataclass(frozen=True)
class Claim:
    kind: ClaimKind
    subject: Subject

    def __post_init__(self) -> None:
        if not isinstance(self.kind, ClaimKind):
            raise ValueError("INVALID_CLAIM_KIND")
        expected = {
            ClaimKind.KEY_ASSENT: ApprovalTargetSubject,
            ClaimKind.GOVERNANCE_ASSENT: ApprovalTargetSubject,
            ClaimKind.COMMITTED_EVIDENCE_MATCH: EventSubject,
            ClaimKind.TARGET_IMPRINT_EXISTED_NOT_AFTER: ApprovalTargetSubject,
            ClaimKind.APPROVAL_SET_IMPRINT_EXISTED_NOT_AFTER: ApprovalSetSubject,
            ClaimKind.STATEMENT_REGISTERED: StatementSubject,
            ClaimKind.SLOT_KEY_ASSENT_TO_IDENTITY_ASSERTION: IdentitySubject,
            ClaimKind.NATURAL_PERSON_IDENTITY_VERIFIED: IdentitySubject,
            ClaimKind.ORIGINALITY_VERIFIED: ApprovalTargetSubject,
            ClaimKind.SIGNERS_UNCOMPROMISED_AT_TIME: ApprovalSetSubject,
        }[self.kind]
        if not isinstance(self.subject, expected):
            raise ValueError("CLAIM_SUBJECT_KIND_MISMATCH")


@dataclass(frozen=True)
class Derivation:
    claim: Claim
    supporting_certificate_digests: Tuple[str, ...]


def permitted_claims(wire_names: Iterable[str]) -> FrozenSet[ClaimKind]:
    """Convert the versioned wire vocabulary at the serialization boundary."""
    result = set()
    for name in wire_names:
        try:
            result.add(WIRE_TO_CLAIM[name])
        except KeyError as exc:
            raise ValueError("CLAIM_POLICY_UNKNOWN_OUTCOME") from exc
    return frozenset(result)


def derive(
    evidence: Iterable[AppraisedEvidence], permitted: Iterable[ClaimKind]
) -> Tuple[Derivation, ...]:
    """Derive exact-subject claims and retain a minimal support certificate."""
    allowed = frozenset(permitted)
    by_claim = {}
    for item in evidence:
        for claim_kind in GRANTS[item.kind]:
            if claim_kind not in allowed:
                continue
            claim = Claim(kind=claim_kind, subject=item.subject)
            by_claim.setdefault(claim, set()).add(item.certificate_digest)
    return tuple(
        Derivation(claim, tuple(sorted(support)))
        for claim, support in sorted(
            by_claim.items(), key=lambda pair: (pair[0].kind.value, repr(pair[0].subject))
        )
    )


def derived_claims(
    evidence: Iterable[AppraisedEvidence], permitted: Iterable[ClaimKind]
) -> FrozenSet[Claim]:
    return frozenset(item.claim for item in derive(evidence, permitted))


def wire_outcomes(derivations: Iterable[Derivation]) -> Tuple[str, ...]:
    present = {CLAIM_TO_WIRE[item.claim.kind] for item in derivations}
    return tuple(name for name in WIRE_ORDER if name in present)


def decision(
    evidence: Iterable[AppraisedEvidence], permitted: Iterable[ClaimKind], requested: Claim
) -> str:
    return "GRANTED" if requested in derived_claims(evidence, permitted) else "DENIED"
