import pathlib
import tempfile
import unittest

import approval_set
from pec_core import digest


class TestApprovalSet(unittest.TestCase):
    def _fixture(self, directory):
        root = pathlib.Path(directory)
        alice = "a" * 64
        bob = "b" * 64
        old = "c" * 64
        (root / "approvals").mkdir()
        (root / "lineage" / "authorizations").mkdir(parents=True)
        (root / "approvals" / f"{alice}.cose").write_bytes(b"alice signature")
        (root / "approvals" / f"{bob}.cose").write_bytes(b"bob signature")
        (root / "lineage" / "authorizations" / f"{old}.cose").write_bytes(
            b"old authority signature"
        )
        target = {"schema": "target", "release_digest": "a" * 64}
        obj = approval_set.build(root, target, [alice, bob], [old])
        return root, target, obj, alice, bob, old

    def test_round_trip_closes_exact_signature_bytes(self):
        with tempfile.TemporaryDirectory() as d:
            root, target, obj, alice, bob, old = self._fixture(d)
            result = approval_set.verify(obj, root, target, [alice, bob], [old])
            self.assertEqual(result["approval_set_digest"], digest(obj))

    def test_pure_builder_matches_filesystem_adapter(self):
        with tempfile.TemporaryDirectory() as d:
            root, target, obj, alice, bob, old = self._fixture(d)
            pure = approval_set.build_from_signatures(
                target,
                {
                    alice: (root / "approvals" / f"{alice}.cose").read_bytes(),
                    bob: (root / "approvals" / f"{bob}.cose").read_bytes(),
                },
                {
                    old: (root / "lineage" / "authorizations" / f"{old}.cose").read_bytes()
                },
            )
            self.assertEqual(pure, obj)

    def test_signature_added_after_timestamp_changes_set_digest(self):
        with tempfile.TemporaryDirectory() as d:
            root, target, obj, alice, bob, old = self._fixture(d)
            stamped_digest = digest(obj)
            (root / "approvals" / f"{bob}.cose").write_bytes(b"replacement signature")
            with self.assertRaisesRegex(
                ValueError, "APPROVAL_SET_AUTHOR_SIGNATURE_MISMATCH"
            ):
                approval_set.verify(obj, root, target, [alice, bob], [old])
            self.assertNotEqual(
                stamped_digest,
                digest(approval_set.build(root, target, [alice, bob], [old])),
            )

    def test_target_or_membership_substitution_is_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            root, target, obj, alice, bob, old = self._fixture(d)
            with self.assertRaisesRegex(ValueError, "APPROVAL_SET_TARGET_MISMATCH"):
                approval_set.verify(
                    obj, root, {**target, "release_digest": "b" * 64},
                    [alice, bob], [old]
                )
            with self.assertRaisesRegex(
                ValueError, "APPROVAL_SET_AUTHOR_FILE_SET_MISMATCH"
            ):
                approval_set.verify(obj, root, target, [alice], [old])

    def test_unlisted_signature_file_is_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            root, target, obj, alice, bob, old = self._fixture(d)
            (root / "approvals" / f"{'d' * 64}.cose").write_bytes(b"extra")
            with self.assertRaisesRegex(
                ValueError, "APPROVAL_SET_AUTHOR_FILE_SET_MISMATCH"
            ):
                approval_set.verify(obj, root, target, [alice, bob], [old])

    def test_path_like_key_id_is_rejected_before_file_access(self):
        with tempfile.TemporaryDirectory() as d:
            root = pathlib.Path(d)
            (root / "approvals").mkdir()
            (root / "lineage" / "authorizations").mkdir(parents=True)
            with self.assertRaisesRegex(ValueError, "APPROVAL_SET_KEY_ID_INVALID"):
                approval_set.build(root, {"schema": "target"}, ["../outside"], [])


if __name__ == "__main__":
    unittest.main()
