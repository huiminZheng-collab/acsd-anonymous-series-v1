import copy
import unittest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import cose
import identity_disclosure
from pec_core import canonical


class TestIdentityDisclosure(unittest.TestCase):
    def setUp(self):
        self.keys = [Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()]
        self.key_ids = [identity_disclosure.key_id_of(k.public_key()) for k in self.keys]
        self.release = {
            "schema": "acsd-v3-paper-release/v1",
            "work_id": "urn:uuid:11111111-1111-4111-8111-111111111111",
            "slot": {"line": "main", "version": 1},
            "content": {"path": "paper.pdf", "sha256": "a" * 64},
            "authors": [
                {"slot": index + 1, "key_id": key_id}
                for index, key_id in enumerate(self.key_ids)
            ],
        }
        self.public = {
            key_id: key.public_key() for key_id, key in zip(self.key_ids, self.keys)
        }

    def signed(self, slot, name):
        body = identity_disclosure.build(self.release, slot, name)
        return body, cose.cose_sign1(canonical(body), self.keys[slot - 1])

    def test_exact_slot_key_assent(self):
        body, signature = self.signed(1, "Alice Example")
        result = identity_disclosure.verify(
            body, signature, self.release, self.public[self.key_ids[0]]
        )
        self.assertEqual(result["status"], "SLOT_KEY_ASSENT_TO_IDENTITY_ASSERTION")
        self.assertIn("natural_person_identity_verified", result["non_claims"])
        self.assertIn("contribution_truth_verified", result["non_claims"])

    def test_cross_release_replay_and_wrong_slot_key_fail(self):
        body, signature = self.signed(1, "Alice Example")
        other_release = copy.deepcopy(self.release)
        other_release["content"]["sha256"] = "b" * 64
        with self.assertRaisesRegex(ValueError, "IDENTITY_RELEASE_MISMATCH"):
            identity_disclosure.verify(
                body, signature, other_release, self.public[self.key_ids[0]]
            )
        with self.assertRaisesRegex(ValueError, "PUBLIC_KEY_ID_MISMATCH"):
            identity_disclosure.verify(
                body, signature, self.release, self.public[self.key_ids[1]]
            )

    def test_body_mutation_and_type_confusion_fail(self):
        body, signature = self.signed(1, "Alice Example")
        altered = copy.deepcopy(body)
        altered["identity_assertion"]["display_name"] = "Mallory"
        with self.assertRaises(ValueError):
            identity_disclosure.verify(
                altered, signature, self.release, self.public[self.key_ids[0]]
            )
        event_body = {"schema": "acsd-event-disclosure/v1"}
        event_signature = cose.cose_sign1(canonical(event_body), self.keys[0])
        with self.assertRaisesRegex(ValueError, "IDENTITY_DISCLOSURE_SCHEMA"):
            identity_disclosure.verify(
                event_body, event_signature, self.release, self.public[self.key_ids[0]]
            )

    def test_partial_is_not_full_and_conflict_has_no_winner(self):
        first = self.signed(1, "Alice Example")
        partial = identity_disclosure.verify_set(
            [first], self.release, self.public
        )
        self.assertFalse(partial["full_byline"])
        self.assertEqual(partial["status"], "PARTIAL_BYLINE_KEY_ASSENT")
        second = self.signed(2, "Bob Example")
        full = identity_disclosure.verify_set(
            [first, second], self.release, self.public
        )
        self.assertTrue(full["full_byline"])
        conflicting = self.signed(1, "Another Alice")
        with self.assertRaisesRegex(ValueError, "VERIFIED_IDENTITY_SLOT_EQUIVOCATION"):
            identity_disclosure.verify_set(
                [first, conflicting], self.release, self.public
            )

    def test_invalid_duplicate_is_not_mislabeled_as_equivocation(self):
        first = self.signed(1, "Alice Example")
        second_body, second_signature = self.signed(1, "Another Alice")
        broken_signature = second_signature[:-1] + bytes([second_signature[-1] ^ 1])
        with self.assertRaises(ValueError) as raised:
            identity_disclosure.verify_set(
                [first, (second_body, broken_signature)], self.release, self.public
            )
        self.assertNotEqual(str(raised.exception), "VERIFIED_IDENTITY_SLOT_EQUIVOCATION")


if __name__ == "__main__":
    unittest.main()
