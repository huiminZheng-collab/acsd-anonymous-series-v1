import pathlib
import tempfile
import unittest

import approval_set
from pec_core import digest


class TestApprovalSet(unittest.TestCase):
    def _fixture(self, directory):
        root = pathlib.Path(directory)
        (root / "approvals").mkdir()
        (root / "lineage" / "authorizations").mkdir(parents=True)
        (root / "approvals" / "alice.cose").write_bytes(b"alice signature")
        (root / "approvals" / "bob.cose").write_bytes(b"bob signature")
        (root / "lineage" / "authorizations" / "old.cose").write_bytes(
            b"old authority signature"
        )
        target = {"schema": "target", "release_digest": "a" * 64}
        obj = approval_set.build(root, target, ["alice", "bob"], ["old"])
        return root, target, obj

    def test_round_trip_closes_exact_signature_bytes(self):
        with tempfile.TemporaryDirectory() as d:
            root, target, obj = self._fixture(d)
            result = approval_set.verify(obj, root, target, ["alice", "bob"], ["old"])
            self.assertEqual(result["approval_set_digest"], digest(obj))

    def test_signature_added_after_timestamp_changes_set_digest(self):
        with tempfile.TemporaryDirectory() as d:
            root, target, obj = self._fixture(d)
            stamped_digest = digest(obj)
            (root / "approvals" / "bob.cose").write_bytes(b"replacement signature")
            with self.assertRaisesRegex(
                ValueError, "APPROVAL_SET_AUTHOR_SIGNATURE_MISMATCH"
            ):
                approval_set.verify(obj, root, target, ["alice", "bob"], ["old"])
            self.assertNotEqual(
                stamped_digest,
                digest(approval_set.build(root, target, ["alice", "bob"], ["old"])),
            )

    def test_target_or_membership_substitution_is_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            root, target, obj = self._fixture(d)
            with self.assertRaisesRegex(ValueError, "APPROVAL_SET_TARGET_MISMATCH"):
                approval_set.verify(
                    obj, root, {**target, "release_digest": "b" * 64},
                    ["alice", "bob"], ["old"]
                )
            with self.assertRaisesRegex(
                ValueError, "APPROVAL_SET_AUTHOR_FILE_SET_MISMATCH"
            ):
                approval_set.verify(obj, root, target, ["alice"], ["old"])

    def test_unlisted_signature_file_is_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            root, target, obj = self._fixture(d)
            (root / "approvals" / "mallory.cose").write_bytes(b"extra")
            with self.assertRaisesRegex(
                ValueError, "APPROVAL_SET_AUTHOR_FILE_SET_MISMATCH"
            ):
                approval_set.verify(obj, root, target, ["alice", "bob"], ["old"])


if __name__ == "__main__":
    unittest.main()
