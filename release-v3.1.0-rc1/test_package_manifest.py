import hashlib
import os
import pathlib
import tempfile
import unittest
import unicodedata

from package_manifest import (
    MANIFEST_NAME,
    build_manifest_text,
    payload_path,
    validate_relative_name,
    verify_manifest,
    write_manifest,
)


class TestPackageManifest(unittest.TestCase):
    def test_round_trip_includes_nested_manifest_as_payload(self):
        with tempfile.TemporaryDirectory() as d:
            root = pathlib.Path(d)
            (root / "paper").mkdir()
            (root / "paper" / "paper.txt").write_text("paper", encoding="utf-8")
            (root / "nested").mkdir()
            (root / "nested" / MANIFEST_NAME).write_text("nested evidence", encoding="utf-8")
            (root / MANIFEST_NAME).write_text(build_manifest_text(root), encoding="ascii")
            self.assertEqual(verify_manifest(root), 2)
            manifest = (root / MANIFEST_NAME).read_text(encoding="ascii")
            self.assertIn("nested/MANIFEST.sha256", manifest)

    def test_writer_uses_lf_bytes(self):
        with tempfile.TemporaryDirectory() as d:
            root = pathlib.Path(d)
            (root / "item").write_bytes(b"item")
            manifest_path = write_manifest(root)
            self.assertNotIn(b"\r", manifest_path.read_bytes())
            self.assertEqual(verify_manifest(root), 1)

    def test_noncanonical_and_escaping_names_are_rejected(self):
        invalid = [
            "", "../x", "a/../b", "./a", "a/./b", "/abs", "a//b",
            "a/", r"a\b", "C:/x", "a/file:stream", MANIFEST_NAME,
            "line\nbreak", "tab\tname", "trailing.", "trailing ", "CON",
            "aux.txt", "has?.txt", unicodedata.normalize("NFD", "café.txt"),
        ]
        for name in invalid:
            with self.subTest(name=name):
                with self.assertRaisesRegex(ValueError, "MANIFEST_PATH_INVALID"):
                    validate_relative_name(name)

    def test_set_and_digest_mismatches_are_distinct(self):
        with tempfile.TemporaryDirectory() as d:
            root = pathlib.Path(d)
            item = root / "item"
            item.write_bytes(b"one")
            (root / MANIFEST_NAME).write_text(build_manifest_text(root), encoding="ascii")
            item.write_bytes(b"two")
            with self.assertRaisesRegex(ValueError, "MANIFEST_HASH_MISMATCH:item"):
                verify_manifest(root)
            item.write_bytes(b"one")
            (root / "extra").write_bytes(b"extra")
            with self.assertRaisesRegex(ValueError, "MANIFEST_SET_MISMATCH"):
                verify_manifest(root)

    def test_duplicate_manifest_path_is_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            root = pathlib.Path(d)
            digest = hashlib.sha256(b"x").hexdigest()
            (root / "x").write_bytes(b"x")
            (root / MANIFEST_NAME).write_text(
                f"{digest}  x\n{digest}  x\n", encoding="ascii"
            )
            with self.assertRaisesRegex(ValueError, "MANIFEST_PATH_INVALID"):
                verify_manifest(root)

    def test_casefold_collision_is_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            root = pathlib.Path(d)
            digest = hashlib.sha256(b"x").hexdigest()
            (root / "one").write_bytes(b"x")
            (root / MANIFEST_NAME).write_text(
                f"{digest}  Name.txt\n{digest}  name.txt\n", encoding="ascii"
            )
            with self.assertRaisesRegex(ValueError, "MANIFEST_PATH_COLLISION"):
                verify_manifest(root)

    @unittest.skipUnless(hasattr(os, "symlink"), "symlinks unavailable")
    def test_symlink_is_rejected_before_read(self):
        with tempfile.TemporaryDirectory() as d, tempfile.TemporaryDirectory() as outside:
            root = pathlib.Path(d)
            target = pathlib.Path(outside) / "secret"
            target.write_text("secret", encoding="utf-8")
            link = root / "link"
            try:
                os.symlink(target, link)
            except OSError as exc:
                self.skipTest(f"symlink creation not permitted: {exc}")
            with self.assertRaisesRegex(ValueError, "PACKAGE_SYMLINK_REJECTED"):
                build_manifest_text(root)
            with self.assertRaisesRegex(ValueError, "PACKAGE_SYMLINK_REJECTED"):
                payload_path(root, "link")


if __name__ == "__main__":
    unittest.main()
