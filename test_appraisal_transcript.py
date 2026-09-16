import copy
import unittest

import appraisal_transcript
import claim_derivation as claims


DIGESTS = [f"{index:064x}" for index in range(1, 32)]


def complete_evidence():
    return (
        claims.AppraisedEvidence(
            claims.EvidenceKind.UNANIMOUS_APPROVAL,
            claims.ApprovalTargetSubject(DIGESTS[0]),
            DIGESTS[20],
        ),
        claims.AppraisedEvidence(
            claims.EvidenceKind.AUTHORIZED_APPROVAL,
            claims.ApprovalTargetSubject(DIGESTS[17]),
            DIGESTS[27],
        ),
        claims.AppraisedEvidence(
            claims.EvidenceKind.EVENT_DISCLOSURE,
            claims.EventSubject(DIGESTS[1], "event-1", 0, DIGESTS[2], 1, 2),
            DIGESTS[21],
        ),
        claims.AppraisedEvidence(
            claims.EvidenceKind.APPROVAL_TARGET_TIMESTAMP,
            claims.ApprovalTargetTimeSubject(
                DIGESTS[3], "2026-09-14T00:00:00+00:00"
            ),
            DIGESTS[22],
        ),
        claims.AppraisedEvidence(
            claims.EvidenceKind.APPROVAL_SET_TIMESTAMP,
            claims.ApprovalSetTimeSubject(
                DIGESTS[4], "2026-09-14T00:00:01+00:00"
            ),
            DIGESTS[23],
        ),
        claims.AppraisedEvidence(
            claims.EvidenceKind.SCITT_INCLUSION,
            claims.StatementSubject(DIGESTS[5]),
            DIGESTS[24],
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
            ),
            DIGESTS[26],
        ),
    )


class TestAppraisalTranscript(unittest.TestCase):
    def transcript(self):
        return appraisal_transcript.build(claims.WIRE_ORDER, complete_evidence())

    def test_all_exact_subjects_round_trip_and_derive_only_declared_claims(self):
        transcript = self.transcript()
        evidence, permitted = appraisal_transcript.parse(transcript)
        self.assertEqual(evidence, complete_evidence())
        self.assertEqual(permitted, frozenset(claims.WIRE_TO_CLAIM.values()))
        self.assertEqual(
            claims.wire_outcomes(appraisal_transcript.derive(transcript)),
            claims.WIRE_ORDER,
        )

    def test_transcript_contains_no_verdict_or_claim(self):
        forbidden = {"accepted", "claim", "claims", "granted", "status", "valid", "verdict"}

        def keys(value):
            if isinstance(value, dict):
                for key, child in value.items():
                    yield key
                    yield from keys(child)
            elif isinstance(value, list):
                for child in value:
                    yield from keys(child)

        self.assertTrue(forbidden.isdisjoint(keys(self.transcript())))

    def test_evidence_subject_kind_confusion_is_rejected(self):
        transcript = self.transcript()
        transcript["evidence"][0]["kind"] = "EVENT_DISCLOSURE"
        with self.assertRaisesRegex(
            ValueError, "APPRAISAL_TRANSCRIPT_SUBJECT_KIND_MISMATCH"
        ):
            appraisal_transcript.parse(transcript)

    def test_policy_and_evidence_order_are_closed(self):
        transcript = self.transcript()
        transcript["policy"]["permitted_outcomes"].reverse()
        with self.assertRaisesRegex(ValueError, "APPRAISAL_TRANSCRIPT_POLICY_ORDER"):
            appraisal_transcript.parse(transcript)

        transcript = self.transcript()
        transcript["evidence"].reverse()
        with self.assertRaisesRegex(ValueError, "APPRAISAL_TRANSCRIPT_EVIDENCE_ORDER"):
            appraisal_transcript.parse(transcript)

    def test_duplicate_evidence_is_rejected_but_distinct_support_is_retained(self):
        transcript = self.transcript()
        duplicate = copy.deepcopy(transcript["evidence"][-1])
        duplicate["index"] = len(transcript["evidence"])
        transcript["evidence"].append(duplicate)
        with self.assertRaisesRegex(ValueError, "APPRAISAL_TRANSCRIPT_EVIDENCE_DUPLICATE"):
            appraisal_transcript.parse(transcript)

        subject = claims.ApprovalTargetSubject(DIGESTS[0])
        evidence = [
            claims.AppraisedEvidence(
                claims.EvidenceKind.UNANIMOUS_APPROVAL, subject, DIGESTS[20]
            ),
            claims.AppraisedEvidence(
                claims.EvidenceKind.UNANIMOUS_APPROVAL, subject, DIGESTS[21]
            ),
        ]
        transcript = appraisal_transcript.build(
            ["KEY_ASSENT"], evidence
        )
        derivation = appraisal_transcript.derive(transcript)
        self.assertEqual(len(derivation), 1)
        self.assertEqual(
            derivation[0].supporting_certificate_digests,
            tuple(sorted((DIGESTS[20], DIGESTS[21]))),
        )

    def test_unsafe_integer_and_extra_field_are_rejected(self):
        transcript = self.transcript()
        event = next(
            item for item in transcript["evidence"]
            if item["kind"] == "EVENT_DISCLOSURE"
        )
        event["subject"]["event_sequence"] = 9_007_199_254_740_992
        with self.assertRaisesRegex(ValueError, "APPRAISAL_TRANSCRIPT_SUBJECT"):
            appraisal_transcript.parse(transcript)

        transcript = self.transcript()
        transcript["verdict"] = "VALID"
        with self.assertRaisesRegex(ValueError, "APPRAISAL_TRANSCRIPT_FIELDS"):
            appraisal_transcript.parse(transcript)


if __name__ == "__main__":
    unittest.main()
