#!/usr/bin/env python3
"""Differentially compare the production appraisal transcript in Python/Lean."""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import pathlib
import subprocess
import sys
import tempfile


ROOT = pathlib.Path(__file__).resolve().parent
PROJECT = ROOT.parent
sys.path.insert(0, str(PROJECT))

import appraisal_transcript  # noqa: E402
import claim_derivation as claims  # noqa: E402


DIGESTS = [f"{index:064x}" for index in range(1, 40)]


def canonical_bytes(value: object) -> bytes:
    """Encode mutations too, including values the strict parser must reject."""
    return json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")


def complete_evidence():
    return (
        claims.AppraisedEvidence(
            claims.EvidenceKind.UNANIMOUS_APPROVAL,
            claims.ApprovalTargetSubject(DIGESTS[0]), DIGESTS[20],
        ),
        claims.AppraisedEvidence(
            claims.EvidenceKind.AUTHORIZED_APPROVAL,
            claims.ApprovalTargetSubject(DIGESTS[17]), DIGESTS[27],
        ),
        claims.AppraisedEvidence(
            claims.EvidenceKind.EVENT_DISCLOSURE,
            claims.EventSubject(DIGESTS[1], "event-α", 0, DIGESTS[2], 1, 2),
            DIGESTS[21],
        ),
        claims.AppraisedEvidence(
            claims.EvidenceKind.APPROVAL_TARGET_TIMESTAMP,
            claims.ApprovalTargetTimeSubject(
                DIGESTS[3], "2026-09-14T00:00:00+00:00"
            ), DIGESTS[22],
        ),
        claims.AppraisedEvidence(
            claims.EvidenceKind.APPROVAL_SET_TIMESTAMP,
            claims.ApprovalSetTimeSubject(
                DIGESTS[4], "2026-09-14T00:00:01+00:00"
            ), DIGESTS[23],
        ),
        claims.AppraisedEvidence(
            claims.EvidenceKind.SCITT_INCLUSION,
            claims.StatementSubject(DIGESTS[5]), DIGESTS[24],
        ),
        claims.AppraisedEvidence(
            claims.EvidenceKind.SLOT_IDENTITY_ASSENT,
            claims.IdentitySubject(DIGESTS[6], 1, DIGESTS[7], DIGESTS[8]),
            DIGESTS[25],
        ),
        claims.AppraisedEvidence(
            claims.EvidenceKind.LINEAGE_AUTHORIZATION,
            claims.LineageSubject(
                DIGESTS[9], DIGESTS[10], DIGESTS[11], DIGESTS[12], 1,
                DIGESTS[13], DIGESTS[14], DIGESTS[15], 2, DIGESTS[16],
            ), DIGESTS[26],
        ),
    )


def digest_nat(value: str) -> str:
    return str(int(value, 16))


def subject_json(subject: claims.Subject) -> dict:
    if isinstance(subject, claims.ApprovalTargetSubject):
        return {"kind": "approval-target", "target_digest_nat": digest_nat(subject.target_digest)}
    if isinstance(subject, claims.ApprovalTargetTimeSubject):
        return {
            "kind": "approval-target-time",
            "target_digest_nat": digest_nat(subject.target_digest),
            "not_after_utc": subject.not_after_utc,
        }
    if isinstance(subject, claims.ApprovalSetTimeSubject):
        return {
            "kind": "approval-set-time",
            "set_digest_nat": digest_nat(subject.approval_set_digest),
            "not_after_utc": subject.not_after_utc,
        }
    if isinstance(subject, claims.EventSubject):
        return {
            "kind": "event-window", "pec_digest_nat": digest_nat(subject.pec_digest),
            "event_id": subject.event_id, "event_sequence": subject.event_sequence,
            "commitment_digest_nat": digest_nat(subject.commitment_digest),
            "first_index": subject.first_index, "last_index": subject.last_index,
        }
    if isinstance(subject, claims.IdentitySubject):
        return {
            "kind": "identity-assertion",
            "release_digest_nat": digest_nat(subject.release_digest),
            "author_slot": subject.author_slot,
            "key_id_nat": digest_nat(subject.author_key_id),
            "assertion_digest_nat": digest_nat(subject.assertion_digest),
        }
    if isinstance(subject, claims.StatementSubject):
        return {
            "kind": "registered-statement",
            "statement_digest_nat": digest_nat(subject.statement_digest),
        }
    if isinstance(subject, claims.LineageSubject):
        return {
            "kind": "lineage-edge",
            "work_id_digest_nat": digest_nat(subject.work_id_digest),
            "parent_release_digest_nat": digest_nat(subject.parent_release_digest),
            "parent_pec_digest_nat": digest_nat(subject.parent_pec_digest),
            "parent_line_digest_nat": digest_nat(subject.parent_line_digest),
            "parent_version": subject.parent_version,
            "child_release_digest_nat": digest_nat(subject.child_release_digest),
            "child_pec_digest_nat": digest_nat(subject.child_pec_digest),
            "child_line_digest_nat": digest_nat(subject.child_line_digest),
            "child_version": subject.child_version,
            "transition_digest_nat": digest_nat(subject.transition_digest),
        }
    raise AssertionError("unknown subject")


def python_result(transcript: dict, transcript_digest: str) -> dict:
    result = []
    for derivation in appraisal_transcript.derive(transcript):
        result.append({
            "kind": claims.CLAIM_TO_WIRE[derivation.claim.kind],
            "subject": subject_json(derivation.claim.subject),
            "supporting_certificate_digests_nat": [
                digest_nat(item)
                for item in derivation.supporting_certificate_digests
            ],
        })
    return {
        "schema": "acsd-lean-transcript-result/v1",
        "certificate_digest_nat": digest_nat(transcript_digest),
        "claims": result,
    }


def run_lean(checker: pathlib.Path, raw: bytes, directory: pathlib.Path):
    path = directory / "appraisal-transcript.json"
    path.write_bytes(raw)
    transcript_digest = hashlib.sha256(raw).hexdigest()
    return subprocess.run(
        [str(checker), str(path), transcript_digest], cwd=PROJECT,
        capture_output=True, text=True, encoding="utf-8", errors="replace",
    )


def cases(base: dict):
    yield "valid-complete", copy.deepcopy(base)

    value = appraisal_transcript.build(
        ["KEY_ASSENT", "AUTHORIZED_SUCCESSOR"], complete_evidence()
    )
    yield "closed-policy-subset", value

    value = appraisal_transcript.build(
        claims.WIRE_ORDER, complete_evidence()[:-1]
    )
    yield "missing-lineage-evidence", value

    evidence = list(complete_evidence())
    evidence.append(claims.AppraisedEvidence(
        claims.EvidenceKind.UNANIMOUS_APPROVAL,
        claims.ApprovalTargetSubject(DIGESTS[0]), DIGESTS[27],
    ))
    yield "two-distinct-supports", appraisal_transcript.build(
        ["KEY_ASSENT"], evidence
    )

    value = copy.deepcopy(base)
    value["policy"]["permitted_outcomes"].reverse()
    yield "policy-order", value

    value = copy.deepcopy(base)
    value["evidence"].reverse()
    yield "evidence-index-order", value

    value = copy.deepcopy(base)
    duplicate = copy.deepcopy(value["evidence"][-1])
    duplicate["index"] = len(value["evidence"])
    value["evidence"].append(duplicate)
    yield "duplicate-evidence", value

    value = copy.deepcopy(base)
    value["evidence"][0]["kind"] = "EVENT_DISCLOSURE"
    yield "kind-subject-confusion", value

    value = copy.deepcopy(base)
    value["evidence"][0]["kind"] = "UNKNOWN"
    yield "unknown-evidence-kind", value

    value = copy.deepcopy(base)
    value["evidence"][0]["certificate_digest"] = "0" * 63
    yield "short-certificate-digest", value

    value = copy.deepcopy(base)
    value["evidence"][0]["unexpected"] = True
    yield "extra-evidence-field", value

    value = copy.deepcopy(base)
    value["unexpected"] = True
    yield "extra-top-field", value

    value = copy.deepcopy(base)
    event = next(item for item in value["evidence"] if item["kind"] == "EVENT_DISCLOSURE")
    event["subject"]["event_sequence"] = 9_007_199_254_740_992
    yield "unsafe-event-sequence", value

    value = copy.deepcopy(base)
    event = next(item for item in value["evidence"] if item["kind"] == "EVENT_DISCLOSURE")
    event["subject"]["first_index"] = 3
    yield "reversed-event-window", value

    value = copy.deepcopy(base)
    identity = next(item for item in value["evidence"] if item["kind"] == "SLOT_IDENTITY_ASSENT")
    identity["subject"]["author_slot"] = 0
    yield "zero-author-slot", value

    value = copy.deepcopy(base)
    lineage = next(item for item in value["evidence"] if item["kind"] == "LINEAGE_AUTHORIZATION")
    lineage["subject"]["child_version"] = 0
    yield "zero-child-version", value

    value = copy.deepcopy(base)
    timestamp = next(
        item for item in value["evidence"]
        if item["kind"] == "APPROVAL_SET_TIMESTAMP"
    )
    timestamp["subject"]["not_after_utc"] = "sometime"
    yield "malformed-utc-instant", value

    value = copy.deepcopy(base)
    value["evidence"][0]["index"] = True
    yield "boolean-index", value


def normalize(result: dict) -> dict:
    result["claims"] = sorted(
        result["claims"], key=lambda item: (item["kind"], repr(item["subject"]))
    )
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--checker", required=True, type=pathlib.Path)
    args = parser.parse_args()
    checker = args.checker.resolve()
    base = appraisal_transcript.build(claims.WIRE_ORDER, complete_evidence())
    compared = 0
    with tempfile.TemporaryDirectory() as temporary:
        directory = pathlib.Path(temporary)
        for name, transcript in cases(base):
            raw = canonical_bytes(transcript)
            transcript_digest = hashlib.sha256(raw).hexdigest()
            try:
                expected = python_result(transcript, transcript_digest)
                python_error = None
            except ValueError as exc:
                expected = None
                python_error = str(exc)
            lean = run_lean(checker, raw, directory)
            if python_error is not None:
                if lean.returncode == 0:
                    raise AssertionError(
                        f"{name}: Python rejected {python_error}, Lean accepted {lean.stdout}"
                    )
            else:
                if lean.returncode != 0:
                    raise AssertionError(f"{name}: Lean rejected {lean.stderr.strip()}")
                actual = json.loads(lean.stdout)
                if normalize(actual) != normalize(expected):
                    raise AssertionError(
                        f"{name}: Python/Lean mismatch\n{expected!r}\n{actual!r}"
                    )
            compared += 1

        raw = json.dumps(base, indent=2, ensure_ascii=False).encode("utf-8")
        if run_lean(checker, raw, directory).returncode == 0:
            raise AssertionError("noncanonical appraisal transcript accepted by Lean")
        compared += 1

    print(f"lean-appraisal-transcript-differential: {compared}/{compared} cases PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
