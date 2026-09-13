"""Reproduce the typed-evidence semantic-confusion challenge."""

from __future__ import annotations

import argparse
import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parent
PROJECT = ROOT.parent
sys.path.insert(0, str(PROJECT))

from claim_derivation import Claim, ClaimKind, Evidence, EvidenceKind, decision, derive  # noqa: E402


SUBJECT = "a" * 64
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


def build_report():
    permitted = list(ClaimKind)
    matrix = []
    for evidence_kind in ROWS:
        atom = Evidence(evidence_kind, SUBJECT, True)
        matrix.append({
            "evidence": evidence_kind.value,
            "decisions": {
                claim_kind.value: decision(
                    [atom], permitted, Claim(claim_kind, SUBJECT)
                )
                for claim_kind in COLUMNS
            },
        })

    at_t0 = [Evidence(EvidenceKind.APPROVAL_TARGET_TIMESTAMP, SUBJECT, True)]
    at_t2 = at_t0 + [Evidence(EvidenceKind.UNANIMOUS_APPROVAL, SUBJECT, True)]
    return {
        "schema": "acsd-semantic-confusion-report/v1",
        "subject_digest": SUBJECT,
        "matrix": matrix,
        "unsupported_claims": {
            claim.value: decision(
                [Evidence(kind, SUBJECT, True) for kind in ROWS],
                permitted,
                Claim(claim, SUBJECT),
            )
            for claim in (
                ClaimKind.NATURAL_PERSON_IDENTITY_VERIFIED,
                ClaimKind.ORIGINALITY_VERIFIED,
                ClaimKind.SIGNERS_UNCOMPROMISED_AT_TIME,
            )
        },
        "timeline": {
            "t0_target_timestamp": sorted(claim.kind.value for claim in derive(at_t0, permitted)),
            "t1_key_compromise_or_revocation": "external fact; no ACSD evidence atom is synthesized",
            "t2_signatures_added": sorted(claim.kind.value for claim in derive(at_t2, permitted)),
            "approval_set_time_at_t0": decision(
                at_t2, permitted,
                Claim(ClaimKind.APPROVAL_SET_IMPRINT_EXISTED_NOT_AFTER, SUBJECT),
            ),
            "signers_uncompromised_at_t0": decision(
                at_t2, permitted,
                Claim(ClaimKind.SIGNERS_UNCOMPROMISED_AT_TIME, SUBJECT),
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
