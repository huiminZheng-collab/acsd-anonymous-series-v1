import unittest

from claim_derivation import Claim, ClaimKind, Evidence, EvidenceKind, decision, derive


class TestClaimDerivation(unittest.TestCase):
    def test_evidence_types_do_not_substitute_for_each_other(self):
        subject = "a" * 64
        permitted = list(ClaimKind)
        target = Evidence(EvidenceKind.APPROVAL_TARGET_TIMESTAMP, subject, True)
        self.assertEqual(
            decision(
                [target], permitted,
                Claim(ClaimKind.TARGET_IMPRINT_EXISTED_NOT_AFTER, subject),
            ),
            "GRANTED",
        )
        self.assertEqual(
            decision(
                [target], permitted,
                Claim(ClaimKind.APPROVAL_SET_IMPRINT_EXISTED_NOT_AFTER, subject),
            ),
            "DENIED",
        )

    def test_composition_is_only_the_union_of_explicit_grants(self):
        subject = "b" * 64
        permitted = list(ClaimKind)
        evidence = [
            Evidence(EvidenceKind.APPROVAL_TARGET_TIMESTAMP, subject, True),
            Evidence(EvidenceKind.SLOT_IDENTITY_ASSENT, subject, True),
        ]
        granted = derive(evidence, permitted)
        self.assertEqual(
            {claim.kind for claim in granted},
            {
                ClaimKind.TARGET_IMPRINT_EXISTED_NOT_AFTER,
                ClaimKind.SLOT_KEY_ASSENT_TO_IDENTITY_ASSERTION,
            },
        )
        self.assertNotIn(
            Claim(ClaimKind.NATURAL_PERSON_IDENTITY_VERIFIED, subject), granted
        )

    def test_policy_and_exact_subject_are_both_required(self):
        subject = "c" * 64
        evidence = [Evidence(EvidenceKind.SCITT_INCLUSION, subject, True)]
        self.assertEqual(
            decision(
                evidence, [], Claim(ClaimKind.STATEMENT_REGISTERED, subject)
            ),
            "DENIED",
        )
        self.assertEqual(
            decision(
                evidence, [ClaimKind.STATEMENT_REGISTERED],
                Claim(ClaimKind.STATEMENT_REGISTERED, "d" * 64),
            ),
            "DENIED",
        )

    def test_unverified_atom_grants_nothing(self):
        subject = "e" * 64
        evidence = [Evidence(EvidenceKind.UNANIMOUS_APPROVAL, subject, False)]
        self.assertEqual(derive(evidence, list(ClaimKind)), frozenset())


if __name__ == "__main__":
    unittest.main()
