import contextlib
import io
import json
import pathlib
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

import acsd
from key_material import PrivateKeyPassphraseRequired, load_private_key


ROOT = pathlib.Path(__file__).resolve().parent
ACSD = ROOT / "acsd.py"
PASSPHRASE = "correct horse battery staple"


def invoke_interactive(argv, answers):
    """Run the public parser while supplying terminal-only secrets in memory."""
    stdin = mock.Mock()
    stdin.isatty.return_value = True
    output = io.StringIO()
    with mock.patch.object(acsd.sys, "stdin", stdin), mock.patch(
        "acsd.getpass.getpass", side_effect=answers
    ) as prompted, contextlib.redirect_stdout(output):
        code = acsd.main([*argv, "--json"])
    return code, json.loads(output.getvalue()), prompted.call_count


def encrypted_key(root, name="author"):
    code, payload, prompts = invoke_interactive(
        ["keygen", "--name", name, "--out-dir", str(root / "keys"), "--encrypt"],
        [PASSPHRASE, PASSPHRASE],
    )
    if code != 0:
        raise AssertionError(payload)
    if prompts != 2:
        raise AssertionError(f"expected confirmation prompts, got {prompts}")
    return payload["data"]


class TestEncryptedPrivateKeys(unittest.TestCase):
    def test_encrypted_keygen_and_one_command_release_prompt_once(self):
        with tempfile.TemporaryDirectory() as raw:
            root = pathlib.Path(raw)
            author = encrypted_key(root)
            private_key = pathlib.Path(author["private_key"])
            self.assertTrue(author["encrypted"])
            self.assertIn(b"BEGIN ENCRYPTED PRIVATE KEY", private_key.read_bytes())
            with self.assertRaises(PrivateKeyPassphraseRequired):
                load_private_key(private_key)

            paper = root / "paper.txt"
            paper.write_text("Encrypted local author key.\n", encoding="utf-8")
            release = root / "release"
            code, payload, prompts = invoke_interactive(
                [
                    "release", str(paper), "--key", str(private_key),
                    "--out", str(release),
                ],
                [PASSPHRASE],
            )
            self.assertEqual(code, 0, payload)
            self.assertEqual(prompts, 1)
            self.assertEqual(payload["message"], "finalized")

            verified = subprocess.run(
                [sys.executable, str(ACSD), "verify", str(release), "--json"],
                capture_output=True,
                text=True,
            )
            self.assertEqual(verified.returncode, 0, verified.stderr or verified.stdout)

    def test_wrong_passphrase_and_noninteractive_use_fail_closed(self):
        with tempfile.TemporaryDirectory() as raw:
            root = pathlib.Path(raw)
            author = encrypted_key(root)
            paper = root / "paper.txt"
            paper.write_text("Key passphrase failures.\n", encoding="utf-8")

            code, payload, prompts = invoke_interactive(
                [
                    "release", str(paper), "--key", author["private_key"],
                    "--out", str(root / "wrong"),
                ],
                ["incorrect passphrase"],
            )
            self.assertEqual(code, 2)
            self.assertEqual(prompts, 1)
            self.assertEqual(payload["message"], "PRIVATE_KEY_PASSPHRASE_INVALID")
            self.assertFalse((root / "wrong").exists())

            noninteractive = subprocess.run(
                [
                    sys.executable, str(ACSD), "release", str(paper),
                    "--key", author["private_key"], "--out", str(root / "batch"),
                    "--json",
                ],
                capture_output=True,
                text=True,
            )
            self.assertEqual(noninteractive.returncode, 2)
            self.assertEqual(
                json.loads(noninteractive.stdout)["message"],
                "PRIVATE_KEY_PASSPHRASE_REQUIRED",
            )
            self.assertFalse((root / "batch").exists())

    def test_keygen_requires_matching_nonempty_interactive_passphrase(self):
        with tempfile.TemporaryDirectory() as raw:
            root = pathlib.Path(raw)
            code, payload, prompts = invoke_interactive(
                ["keygen", "--name", "author", "--out-dir", str(root / "keys"), "--encrypt"],
                ["first passphrase", "second passphrase"],
            )
            self.assertEqual(code, 2)
            self.assertEqual(prompts, 2)
            self.assertEqual(
                payload["message"],
                "PRIVATE_KEY_PASSPHRASE_CONFIRMATION_MISMATCH",
            )
            self.assertFalse((root / "keys" / "author.key").exists())

            noninteractive = subprocess.run(
                [
                    sys.executable, str(ACSD), "keygen", "--name", "batch",
                    "--out-dir", str(root / "batch-keys"), "--encrypt", "--json",
                ],
                capture_output=True,
                text=True,
            )
            self.assertEqual(noninteractive.returncode, 2)
            self.assertEqual(
                json.loads(noninteractive.stdout)["message"],
                "PRIVATE_KEY_PASSPHRASE_REQUIRED",
            )
            self.assertFalse((root / "batch-keys" / "batch.key").exists())


if __name__ == "__main__":
    unittest.main()
