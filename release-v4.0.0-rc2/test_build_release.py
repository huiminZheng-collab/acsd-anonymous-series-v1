import pathlib
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

import build_release
from package_manifest import write_manifest


class TestBuildRelease(unittest.TestCase):
    def test_output_inside_recursive_source_is_rejected(self):
        for source, _ in build_release.DIRS:
            with self.assertRaisesRegex(ValueError, "OUTPUT_INSIDE_RECURSIVE_SOURCE"):
                build_release._reject_recursive_output(
                    build_release.ROOT / source / "nested-output"
                )

    def test_check_requires_valid_manifest_before_comparison(self):
        with tempfile.TemporaryDirectory() as temporary:
            candidate = pathlib.Path(temporary) / "candidate"
            candidate.mkdir()
            (candidate / "payload.txt").write_text("not manifested", encoding="utf-8")
            with mock.patch("sys.argv", ["build_release.py", "--check", str(candidate)]):
                with self.assertRaises(FileNotFoundError):
                    build_release.main()

    def test_tree_comparison_distinguishes_regular_file_and_symlink(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            left = root / "left"
            right = root / "right"
            left.mkdir()
            right.mkdir()
            (left / "target.txt").write_text("same", encoding="utf-8")
            (right / "target.txt").write_text("same", encoding="utf-8")
            (left / "entry.txt").write_text("same", encoding="utf-8")
            try:
                (right / "entry.txt").symlink_to(right / "target.txt")
            except OSError:
                self.skipTest("symlink creation is unavailable")
            self.assertFalse(build_release._same_tree(left, right))

    def test_standalone_verifier_does_not_pollute_its_artifact(self):
        with tempfile.TemporaryDirectory() as temporary:
            candidate = pathlib.Path(temporary) / "candidate"
            candidate.mkdir()
            for name in ("verify_release.py", "package_manifest.py"):
                (candidate / name).write_bytes((build_release.ROOT / name).read_bytes())
            (candidate / "payload.txt").write_text("manifested\n", encoding="utf-8")
            write_manifest(candidate)

            for _ in range(2):
                result = subprocess.run(
                    [sys.executable, "verify_release.py", "."],
                    cwd=candidate,
                    capture_output=True,
                    text=True,
                )
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn("MANIFEST VALID", result.stdout)
                self.assertFalse((candidate / "__pycache__").exists())


if __name__ == "__main__":
    unittest.main()
