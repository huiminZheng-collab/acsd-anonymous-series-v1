import copy
from datetime import datetime, timezone
import unittest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import cose
from canonical_json import canonical
from key_identity import key_id_of
import submission_link


NOW = datetime(2026, 9, 21, 6, 0, 0, tzinfo=timezone.utc)


class TestSubmissionLink(unittest.TestCase):
    def setUp(self):
        self.author_keys = [Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()]
        self.author_ids = [key_id_of(key.public_key()) for key in self.author_keys]
        self.venue_key = Ed25519PrivateKey.generate()
        self.release = {
            "schema": "acsd-v3-paper-release/v1",
            "work_id": "urn:uuid:11111111-1111-4111-8111-111111111111",
            "slot": {"line": "main", "version": 1},
            "content": {"path": "anonymous.pdf", "sha256": "a" * 64},
            "authors": [
                {"slot": index + 1, "key_id": key_id}
                for index, key_id in enumerate(self.author_ids)
            ],
        }
        self.byline = [
            {
                "position": 1,
                "author_slot": 1,
                "display_name": "Alice Example",
                "persistent_identifier": "https://orcid.org/0000-0000-0000-0001",
            },
            {
                "position": 2,
                "author_slot": 2,
                "display_name": "Bob Example",
                "persistent_identifier": None,
            },
        ]
        self.manuscript_digest = "b" * 64
        self.handle = "TCJ-2026-0001"
        self.challenge = submission_link.build_challenge(
            self.release,
            self.manuscript_digest,
            "journal.example",
            key_id_of(self.venue_key.public_key()),
            self.handle,
            1,
            "2026-09-21T05:00:00+00:00",
            "2026-09-21T07:00:00+00:00",
            "editor-confidential",
            self.byline,
            challenge_nonce="c" * 64,
        )
        self.challenge_signature = cose.cose_sign1(
            canonical(self.challenge), self.venue_key
        )
        self.public_keys = {
            key_id: key.public_key()
            for key_id, key in zip(self.author_ids, self.author_keys)
        }

    def opening(self, slot, challenge=None):
        challenge = challenge or self.challenge
        body = submission_link.build_opening(challenge, self.release, slot)
        return body, cose.cose_sign1(canonical(body), self.author_keys[slot - 1])

    def verify(self, openings):
        return submission_link.verify_set(
            self.challenge,
            self.challenge_signature,
            openings,
            self.release,
            self.venue_key.public_key(),
            self.public_keys,
            self.manuscript_digest,
            self.handle,
            now_utc=NOW,
        )

    def test_full_exact_link_derives_only_narrow_claim(self):
        result = self.verify([self.opening(1), self.opening(2)])
        self.assertEqual(result["status"], "FULL_BYLINE_SUBMISSION_LINEAGE_LINKED")
        self.assertEqual(result["claim"], "SUBMISSION_LINEAGE_LINKED")
        self.assertTrue(result["full_byline"])
        self.assertIn("natural_person_identity_verified", result["non_claims"])
        self.assertIn("publication_acceptance_verified", result["non_claims"])
        self.assertIn("submission_discoverability_guaranteed", result["non_claims"])

    def test_exact_manuscript_handle_and_venue_key_are_required(self):
        openings = [self.opening(1), self.opening(2)]
        with self.assertRaisesRegex(ValueError, "SUBMITTED_MANUSCRIPT_MISMATCH"):
            submission_link.verify_set(
                self.challenge, self.challenge_signature, openings, self.release,
                self.venue_key.public_key(), self.public_keys, "d" * 64,
                self.handle, now_utc=NOW,
            )
        with self.assertRaisesRegex(ValueError, "SUBMISSION_HANDLE_MISMATCH"):
            submission_link.verify_set(
                self.challenge, self.challenge_signature, openings, self.release,
                self.venue_key.public_key(), self.public_keys,
                self.manuscript_digest, "OTHER-1", now_utc=NOW,
            )
        other_venue = Ed25519PrivateKey.generate()
        with self.assertRaisesRegex(ValueError, "VENUE_KEY_ID_MISMATCH"):
            submission_link.verify_set(
                self.challenge, self.challenge_signature, openings, self.release,
                other_venue.public_key(), self.public_keys,
                self.manuscript_digest, self.handle, now_utc=NOW,
            )

    def test_round_nonce_or_byline_mutation_invalidates_venue_signature(self):
        for field, value in (
            ("review_round", 2),
            ("challenge_nonce", "d" * 64),
        ):
            altered = copy.deepcopy(self.challenge)
            altered[field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                submission_link.verify_challenge(
                    altered, self.challenge_signature, self.release,
                    self.venue_key.public_key(), self.manuscript_digest,
                    self.handle, now_utc=NOW,
                )
        altered = copy.deepcopy(self.challenge)
        altered["ordered_byline"].reverse()
        with self.assertRaises(ValueError):
            submission_link.verify_challenge(
                altered, self.challenge_signature, self.release,
                self.venue_key.public_key(), self.manuscript_digest,
                self.handle, now_utc=NOW,
            )

    def test_openings_from_distinct_challenges_cannot_be_mixed(self):
        other = submission_link.build_challenge(
            self.release, self.manuscript_digest, "journal.example",
            key_id_of(self.venue_key.public_key()), self.handle, 2,
            "2026-09-21T05:00:00+00:00", "2026-09-21T07:00:00+00:00",
            "editor-confidential", self.byline, challenge_nonce="d" * 64,
        )
        first = self.opening(1)
        second = self.opening(2, challenge=other)
        with self.assertRaisesRegex(ValueError, "SUBMISSION_CHALLENGE_MISMATCH"):
            self.verify([first, second])

    def test_partial_opening_is_not_full_and_duplicate_slot_fails(self):
        first = self.opening(1)
        partial = self.verify([first])
        self.assertEqual(partial["status"], "PARTIAL_SUBMISSION_LINK_VERIFIED")
        self.assertEqual(partial["claim"], "PARTIAL_SUBMISSION_SLOT_ASSENT")
        self.assertFalse(partial["full_byline"])
        with self.assertRaisesRegex(ValueError, "VERIFIED_SUBMISSION_SLOT_EQUIVOCATION"):
            self.verify([first, first])

    def test_expired_or_not_yet_valid_challenge_fails(self):
        for instant in (
            datetime(2026, 9, 21, 4, 59, 59, tzinfo=timezone.utc),
            datetime(2026, 9, 21, 7, 0, 1, tzinfo=timezone.utc),
        ):
            with self.subTest(instant=instant), self.assertRaisesRegex(
                ValueError, "SUBMISSION_CHALLENGE_NOT_CURRENT"
            ):
                submission_link.verify_challenge(
                    self.challenge, self.challenge_signature, self.release,
                    self.venue_key.public_key(), self.manuscript_digest,
                    self.handle, now_utc=instant,
                )

    def test_public_mode_does_not_accept_confidential_opening(self):
        public_challenge = copy.deepcopy(self.challenge)
        public_challenge["disclosure_mode"] = "public"
        confidential_opening = submission_link.build_opening(
            public_challenge, self.release, 1
        )
        confidential_opening["disclosure_authorization"] = "editor-confidential-only"
        signature = cose.cose_sign1(canonical(confidential_opening), self.author_keys[0])
        with self.assertRaisesRegex(ValueError, "DISCLOSURE_AUTHORIZATION_MISMATCH"):
            submission_link.verify_opening(
                confidential_opening, signature, public_challenge, self.release,
                self.public_keys[self.author_ids[0]],
            )


if __name__ == "__main__":
    unittest.main()
