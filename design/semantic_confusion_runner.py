"""Reproduce the typed-evidence semantic-confusion challenge."""

from __future__ import annotations

import argparse
import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parent
PROJECT = ROOT.parent
sys.path.insert(0, str(PROJECT))

from claim_derivation import (  # noqa: E402
    AppraisedEvidence,
    ApprovalSetSubject,
    ApprovalTargetSubject,
    Claim,
    ClaimKind,
    EventSubject,
    EvidenceKind,
    IdentitySubject,
    StatementSubject,
    decision,
    derive,
)


SUBJECT = "a" * 64
CERTIFICATE = "b" * 64
TARGET_SUBJECT = ApprovalTargetSubject(SUBJECT)
SET_SUBJECT = ApprovalSetSubject(SUBJECT)
EVENT_SUBJECT = EventSubject(SUBJECT, "event-1", 0, SUBJECT, 0, 1)
IDENTITY_SUBJECT = IdentitySubject(SUBJECT, 0, SUBJECT, SUBJECT)
STATEMENT_SUBJECT = StatementSubject(SUBJECT)
ROWS = [
    EvidenceKind.APPROVAL_TARGET_TIMESTAMP,
    EvidenceKind.APPROVAL_SET_TIMESTAMP,
    EvidenceKind.SCITT_INCLUSION,
    EvidenceKind.SLOT_IDENTITY_ASSENT,
]
COLUMNS = [
    ClaimKind.TARGET_IMPRINT_EXISTED_NOT_AFTER,
    ClaimKind.APPROVAL_SET_IMPRINT_EXISTED_NOT_AFTER,
    ClaimKind.STATEMENT_REGISTERED,
    ClaimKind.SLOT_KEY_ASSENT_TO_IDENTITY_ASSERTION,
]

EVIDENCE_SUBJECTS = {
    EvidenceKind.APPROVAL_TARGET_TIMESTAMP: TARGET_SUBJECT,
    EvidenceKind.APPROVAL_SET_TIMESTAMP: SET_SUBJECT,
    EvidenceKind.SCITT_INCLUSION: STATEMENT_SUBJECT,
    EvidenceKind.SLOT_IDENTITY_ASSENT: IDENTITY_SUBJECT,
    EvidenceKind.UNANIMOUS_APPROVAL: TARGET_SUBJECT,
}

CLAIM_SUBJECTS = {
    ClaimKind.TARGET_IMPRINT_EXISTED_NOT_AFTER: TARGET_SUBJECT,
    ClaimKind.APPROVAL_SET_IMPRINT_EXISTED_NOT_AFTER: SET_SUBJECT,
    ClaimKind.STATEMENT_REGISTERED: STATEMENT_SUBJECT,
    ClaimKind.SLOT_KEY_ASSENT_TO_IDENTITY_ASSERTION: IDENTITY_SUBJECT,
    ClaimKind.NATURAL_PERSON_IDENTITY_VERIFIED: IDENTITY_SUBJECT,
    ClaimKind.ORIGINALITY_VERIFIED: TARGET_SUBJECT,
    ClaimKind.SIGNERS_UNCOMPROMISED_AT_TIME: SET_SUBJECT,
}


def build_report():
    permitted = list(ClaimKind)
    matrix = []
    for evidence_kind in ROWS:
        atom = AppraisedEvidence(
            evidence_kind, EVIDENCE_SUBJECTS[evidence_kind], CERTIFICATE
        )
        matrix.append({
            "evidence": evidence_kind.value,
            "decisions": {
                claim_kind.value: decision(
                    [atom], permitted,
                    Claim(claim_kind, CLAIM_SUBJECTS[claim_kind]),
                )
                for claim_kind in COLUMNS
            },
        })

    at_t0 = [AppraisedEvidence(
        EvidenceKind.APPROVAL_TARGET_TIMESTAMP, TARGET_SUBJECT, CERTIFICATE
    )]
    at_t2 = at_t0 + [AppraisedEvidence(
        EvidenceKind.UNANIMOUS_APPROVAL, TARGET_SUBJECT, "c" * 64
    )]
    return {
        "schema": "acsd-semantic-confusion-report/v1",
        "subject_digest": SUBJECT,
        "matrix": matrix,
        "unsupported_claims": {
            claim.value: decision(
                [AppraisedEvidence(
                    kind, EVIDENCE_SUBJECTS[kind], CERTIFICATE
                ) for kind in ROWS],
                permitted,
                Claim(claim, CLAIM_SUBJECTS[claim]),
            )
            for claim in (
                ClaimKind.NATURAL_PERSON_IDENTITY_VERIFIED,
                ClaimKind.ORIGINALITY_VERIFIED,
                ClaimKind.SIGNERS_UNCOMPROMISED_AT_TIME,
            )
        },
        "timeline": {
            "t0_target_timestamp": sorted(
                item.claim.kind.value for item in derive(at_t0, permitted)
            ),
            "t1_key_compromise_or_revocation": "external fact; no ACSD evidence atom is synthesized",
            "t2_signatures_added": sorted(
                item.claim.kind.value for item in derive(at_t2, permitted)
            ),
            "approval_set_time_at_t0": decision(
                at_t2, permitted,
                Claim(ClaimKind.APPROVAL_SET_IMPRINT_EXISTED_NOT_AFTER, SET_SUBJECT),
            ),
            "signers_uncompromised_at_t0": decision(
                at_t2, permitted,
                Claim(ClaimKind.SIGNERS_UNCOMPROMISED_AT_TIME, SET_SUBJECT),
            ),
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output")
    args = parser.parse_args()
    report = build_report()
    encoded = json.dumps(report, ensure_ascii=False, indent=2) + "\n"
    if args.output:
        pathlib.Path(args.output).write_text(encoded, encoding="utf-8", newline="\n")
    else:
        expected = (ROOT / "semantic_confusion_report.json").read_text(encoding="utf-8")
        if encoded != expected:
            print("semantic confusion report differs from checked-in evidence", file=sys.stderr)
            return 2
    print("semantic-confusion: 4x4 typed matrix and compromise timeline PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
