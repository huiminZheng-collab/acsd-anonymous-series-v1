import unittest

from claim_derivation import (
    AppraisedEvidence,
    ApprovalSetTimeSubject,
    ApprovalTargetSubject,
    ApprovalTargetTimeSubject,
    Claim,
    ClaimKind,
    EventSubject,
    EvidenceKind,
    GRANTS,
    IdentitySubject,
    LineageSubject,
    StatementSubject,
    decision,
    derive,
    derived_claims,
    permitted_claims,
    wire_outcomes,
)


DIGESTS = [format(index, "064x") for index in range(1, 12)]
TARGET_SUBJECT = ApprovalTargetSubject(DIGESTS[0])
TARGET_TIME_SUBJECT = ApprovalTargetTimeSubject(
    DIGESTS[0], "2026-09-13T00:00:00+00:00"
)
SET_SUBJECT = ApprovalSetTimeSubject(
    DIGESTS[1], "2026-09-13T00:00:01+00:00"
)
EVENT_SUBJECT = EventSubject(DIGESTS[2], "event-1", 0, DIGESTS[3], 2, 4)
IDENTITY_SUBJECT = IdentitySubject(DIGESTS[4], 1, DIGESTS[5], DIGESTS[6])
STATEMENT_SUBJECT = StatementSubject(DIGESTS[7])
LINEAGE_SUBJECT = LineageSubject(
    DIGESTS[0], DIGESTS[1], DIGESTS[2], DIGESTS[3], 1,
    DIGESTS[4], DIGESTS[5], DIGESTS[6], 2, DIGESTS[7],
)


def subject_for(kind):
    if kind in (EvidenceKind.UNANIMOUS_APPROVAL, EvidenceKind.AUTHORIZED_APPROVAL):
        return TARGET_SUBJECT
    if kind == EvidenceKind.APPROVAL_TARGET_TIMESTAMP:
        return TARGET_TIME_SUBJECT
    if kind == EvidenceKind.APPROVAL_SET_TIMESTAMP:
        return SET_SUBJECT
    if kind == EvidenceKind.EVENT_DISCLOSURE:
        return EVENT_SUBJECT
    if kind == EvidenceKind.SLOT_IDENTITY_ASSENT:
        return IDENTITY_SUBJECT
    if kind == EvidenceKind.LINEAGE_AUTHORIZATION:
        return LINEAGE_SUBJECT
    return STATEMENT_SUBJECT


def claim_subject_for(kind):
    if kind in (
        ClaimKind.KEY_ASSENT,
        ClaimKind.GOVERNANCE_ASSENT,
        ClaimKind.AUTHORIZED_TARGET_APPROVAL,
        ClaimKind.ORIGINALITY_VERIFIED,
    ):
        return TARGET_SUBJECT
    if kind == ClaimKind.TARGET_IMPRINT_EXISTED_NOT_AFTER:
        return TARGET_TIME_SUBJECT
    if kind in (
        ClaimKind.APPROVAL_SET_IMPRINT_EXISTED_NOT_AFTER,
        ClaimKind.SIGNERS_UNCOMPROMISED_AT_TIME,
    ):
        return SET_SUBJECT
    if kind == ClaimKind.COMMITTED_EVIDENCE_MATCH:
        return EVENT_SUBJECT
    if kind in (
        ClaimKind.SLOT_KEY_ASSENT_TO_IDENTITY_ASSERTION,
        ClaimKind.NATURAL_PERSON_IDENTITY_VERIFIED,
    ):
        return IDENTITY_SUBJECT
    if kind == ClaimKind.AUTHORIZED_SUCCESSOR:
        return LINEAGE_SUBJECT
    return STATEMENT_SUBJECT


class TestClaimDerivation(unittest.TestCase):
    def evidence(self, kind, certificate=8):
        return AppraisedEvidence(kind, subject_for(kind), DIGESTS[certificate])

    def test_complete_seven_by_eleven_matrix_matches_only_declared_rules(self):
        permitted = list(ClaimKind)
        for evidence_kind in EvidenceKind:
            evidence = self.evidence(evidence_kind)
            for claim_kind in ClaimKind:
                with self.subTest(evidence=evidence_kind, claim=claim_kind):
                    expected = claim_kind in GRANTS[evidence_kind]
                    self.assertEqual(
                        decision(
                            [evidence], permitted,
                            Claim(claim_kind, claim_subject_for(claim_kind)),
                        ),
                        "GRANTED" if expected else "DENIED",
                    )

    def test_composition_is_only_the_union_of_explicit_grants(self):
        target = self.evidence(EvidenceKind.APPROVAL_TARGET_TIMESTAMP)
        identity = self.evidence(EvidenceKind.SLOT_IDENTITY_ASSENT, 9)
        granted = derived_claims([target, identity], list(ClaimKind))
        self.assertEqual(
            {claim.kind for claim in granted},
            {
                ClaimKind.TARGET_IMPRINT_EXISTED_NOT_AFTER,
                ClaimKind.SLOT_KEY_ASSENT_TO_IDENTITY_ASSERTION,
            },
        )
        self.assertFalse(any(
            claim.kind == ClaimKind.NATURAL_PERSON_IDENTITY_VERIFIED
            for claim in granted
        ))

    def test_policy_and_exact_subject_are_both_required(self):
        evidence = self.evidence(EvidenceKind.SCITT_INCLUSION)
        self.assertEqual(
            decision(
                [evidence], [], Claim(ClaimKind.STATEMENT_REGISTERED, evidence.subject)
            ),
            "DENIED",
        )
        other = StatementSubject(DIGESTS[10])
        self.assertEqual(
            decision(
                [evidence], [ClaimKind.STATEMENT_REGISTERED],
                Claim(ClaimKind.STATEMENT_REGISTERED, other),
            ),
            "DENIED",
        )

    def test_evidence_kind_requires_its_exact_subject_type(self):
        with self.assertRaisesRegex(ValueError, "EVIDENCE_SUBJECT_KIND_MISMATCH"):
            AppraisedEvidence(
                EvidenceKind.APPROVAL_SET_TIMESTAMP,
                ApprovalTargetSubject(DIGESTS[0]),
                DIGESTS[1],
            )

    def test_invalid_digest_and_event_window_are_rejected(self):
        with self.assertRaisesRegex(ValueError, "INVALID_TARGET_DIGEST"):
            ApprovalTargetSubject("not-a-digest")
        with self.assertRaisesRegex(ValueError, "INVALID_EVENT_WINDOW"):
            EventSubject(DIGESTS[0], "event", 0, DIGESTS[1], 4, 3)
        with self.assertRaisesRegex(ValueError, "INVALID_NOT_AFTER_UTC"):
            ApprovalSetTimeSubject(DIGESTS[1], "2026-09-13")

    def test_derivation_retains_exact_support_certificate(self):
        evidence = self.evidence(EvidenceKind.UNANIMOUS_APPROVAL)
        derivations = derive(
            [evidence],
            [ClaimKind.KEY_ASSENT, ClaimKind.GOVERNANCE_ASSENT],
        )
        self.assertEqual(len(derivations), 2)
        self.assertTrue(all(
            item.supporting_certificate_digests == (DIGESTS[8],)
            for item in derivations
        ))
        self.assertEqual(
            wire_outcomes(derivations),
            ("KEY_ASSENT", "GOVERNANCE_ASSENT"),
        )

    def test_wire_vocabulary_is_a_boundary_mapping(self):
        claims = permitted_claims([
            "EXTERNALLY_NOT_AFTER", "APPROVAL_SET_EXISTED_NOT_AFTER"
        ])
        self.assertEqual(claims, {
            ClaimKind.TARGET_IMPRINT_EXISTED_NOT_AFTER,
            ClaimKind.APPROVAL_SET_IMPRINT_EXISTED_NOT_AFTER,
        })
        with self.assertRaisesRegex(ValueError, "CLAIM_POLICY_UNKNOWN_OUTCOME"):
            permitted_claims(["HUMAN_AUTHORSHIP_PROVED"])


if __name__ == "__main__":
    unittest.main()
