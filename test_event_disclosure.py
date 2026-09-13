import copy
import unittest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import cose
from event_disclosure import DEFAULT_POLICY, key_id_of, verify_event_disclosure
from pec_core import canonical, dialogue_proof, dialogue_root, digest


class TestEventDisclosure(unittest.TestCase):
    def setUp(self):
        self.keys = [Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()]
        self.key_ids = sorted(key_id_of(key.public_key()) for key in self.keys)
        self.private_by_id = {key_id_of(key.public_key()): key for key in self.keys}
        self.public_by_id = {kid: key.public_key() for kid, key in self.private_by_id.items()}
        self.turns = [
            {"bytes": value.encode(), "salt": bytes([index + 1]) * 32}
            for index, value in enumerate(["idea", "counterexample", "repair"])
        ]
        self.event = {
            "schema": "acsd-pec-event/v0.1",
            "sequence": 0,
            "event_id": "dialogue-01",
            "previous_event_digest": None,
            "kind": "dialogue_snapshot",
            "commitment": {
                "scheme": "merkle-dialogue-v1",
                "digest": dialogue_root(self.turns),
                "disclosure_class": "revealable",
            },
        }
        self.pec = {
            "schema": "acsd-pec/v0.3",
            "pec_id": "pec-test",
            "governance": {"required_pec_approval_key_ids": self.key_ids},
            "events": [self.event],
            "disclosure_policy": copy.deepcopy(DEFAULT_POLICY),
        }
        self.disclosure = {
            "schema": "acsd-event-disclosure/v1",
            "pec_digest": digest(self.pec),
            "event_id": "dialogue-01",
            "event_sequence": 0,
            "kind": "dialogue_snapshot",
            "disclosure_mode": "dialogue_window",
            "opened_material": [
                {
                    "index": i,
                    "bytes": self.turns[i]["bytes"].decode(),
                    "salt": self.turns[i]["salt"].hex(),
                    "path": dialogue_proof(self.turns, i),
                }
                for i in (1, 2)
            ],
        }

    def signatures(self, disclosure=None):
        body = canonical(disclosure or self.disclosure)
        return {
            kid: cose.cose_sign1(body, key)
            for kid, key in self.private_by_id.items()
        }

    def test_atomic_valid_disclosure(self):
        result = verify_event_disclosure(
            self.disclosure, self.pec, self.public_by_id, self.signatures()
        )
        self.assertEqual(result["outcome"], "COMMITTED_EVIDENCE_MATCH")
        self.assertEqual(result["authorized_by"], self.key_ids)

    def test_opening_and_signatures_cannot_be_checked_separately(self):
        altered = copy.deepcopy(self.disclosure)
        altered["opened_material"][0]["bytes"] = "invented"
        with self.assertRaisesRegex(ValueError, "DISCLOSURE_BINDING_MISMATCH"):
            verify_event_disclosure(
                altered, self.pec, self.public_by_id, self.signatures(altered)
            )
        missing = dict(self.signatures())
        missing.pop(self.key_ids[0])
        with self.assertRaisesRegex(ValueError, "DISCLOSURE_APPROVAL_MISSING"):
            verify_event_disclosure(
                self.disclosure, self.pec, self.public_by_id, missing
            )

    def test_policy_and_cross_pec_replay_are_rejected(self):
        changed_policy = copy.deepcopy(self.pec)
        changed_policy["disclosure_policy"]["event_kinds"]["dialogue_snapshot"][
            "authorization"
        ] = "one-author"
        replay = copy.deepcopy(self.disclosure)
        replay["pec_digest"] = digest(changed_policy)
        with self.assertRaisesRegex(ValueError, "DISCLOSURE_POLICY_INVALID"):
            verify_event_disclosure(
                replay, changed_policy, self.public_by_id, self.signatures(replay)
            )
        other = copy.deepcopy(self.pec)
        other["pec_id"] = "pec-other"
        with self.assertRaisesRegex(ValueError, "DISCLOSURE_BINDING_MISMATCH"):
            verify_event_disclosure(
                self.disclosure, other, self.public_by_id, self.signatures()
            )

    def test_wrong_slot_key_is_rejected_even_with_valid_cose(self):
        impostor = Ed25519PrivateKey.generate()
        public = dict(self.public_by_id)
        public[self.key_ids[0]] = impostor.public_key()
        signatures = self.signatures()
        signatures[self.key_ids[0]] = cose.cose_sign1(
            canonical(self.disclosure), impostor
        )
        with self.assertRaisesRegex(ValueError, "PUBLIC_KEY_ID_MISMATCH"):
            verify_event_disclosure(
                self.disclosure, self.pec, public, signatures
            )


if __name__ == "__main__":
    unittest.main()
