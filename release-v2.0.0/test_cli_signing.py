import json
import pathlib
import subprocess
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parent
ACSD = ROOT / "acsd.py"


def run(*args):
    return subprocess.run([sys.executable, str(ACSD), *args], capture_output=True, text=True)


class TestCLISigning(unittest.TestCase):
    def _setup(self, d):
        d = pathlib.Path(d)
        keys = d / "keys"
        alice = json.loads(run("keygen", "--name", "alice", "--out-dir", str(keys), "--json").stdout)["data"]
        bob = json.loads(run("keygen", "--name", "bob", "--out-dir", str(keys), "--json").stdout)["data"]
        team = {"schema": "acsd-team/v1", "authors": [
            {"key_id": alice["key_id"], "public_key": alice["public_key"], "role": "co-first", "corresponding": True},
            {"key_id": bob["key_id"], "public_key": bob["public_key"], "role": "co-first"},
        ]}
        team_path = d / "team.json"
        team_path.write_text(json.dumps(team), encoding="utf-8")
        paper = d / "paper.txt"
        paper.write_text("ACSD end-to-end manuscript.", encoding="utf-8")
        rel = d / "release-dir"
        self.assertEqual(run("init", str(paper), "--team", str(team_path), "--out", str(rel)).returncode, 0)
        return alice, bob, rel

    def test_full_flow(self):
        with tempfile.TemporaryDirectory() as d:
            alice, bob, rel = self._setup(d)
            self.assertEqual(run("approve", str(rel), "--key", alice["private_key"]).returncode, 0)
            r = run("verify", str(rel), "--json")
            self.assertEqual(r.returncode, 5)
            self.assertEqual(json.loads(r.stdout)["data"]["missing_approvals"], [bob["key_id"]])
            self.assertEqual(run("approve", str(rel), "--key", bob["private_key"]).returncode, 0)
            self.assertEqual(run("finalize", str(rel)).returncode, 0)
            r = run("verify", str(rel), "--json")
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertEqual(json.loads(r.stdout)["message"], "VALID")
            # tamper content -> TAMPERED
            p = next((rel / "paper").iterdir())
            p.write_bytes(p.read_bytes() + b"X")
            r = run("verify", str(rel), "--json")
            self.assertEqual(r.returncode, 1)
            self.assertEqual(json.loads(r.stdout)["data"]["error_code"], "CONTENT_DIGEST_MISMATCH")

    def test_unknown_key_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            alice, bob, rel = self._setup(d)
            keys = pathlib.Path(d) / "keys"
            mallory = json.loads(run("keygen", "--name", "mallory", "--out-dir", str(keys), "--json").stdout)["data"]
            r = run("approve", str(rel), "--key", mallory["private_key"], "--json")
            self.assertEqual(r.returncode, 1)
            self.assertEqual(json.loads(r.stdout)["message"], "UNKNOWN_AUTHOR_KEY")

    def test_finalize_incomplete(self):
        with tempfile.TemporaryDirectory() as d:
            alice, bob, rel = self._setup(d)
            run("approve", str(rel), "--key", alice["private_key"])
            r = run("finalize", str(rel), "--json")
            self.assertEqual(r.returncode, 5)
            self.assertEqual(json.loads(r.stdout)["data"]["missing_keys"], [bob["key_id"]])

    def test_duplicate_approval(self):
        with tempfile.TemporaryDirectory() as d:
            alice, bob, rel = self._setup(d)
            run("approve", str(rel), "--key", alice["private_key"])
            r = run("approve", str(rel), "--key", alice["private_key"], "--json")
            self.assertEqual(r.returncode, 3)
            self.assertEqual(json.loads(r.stdout)["message"], "DUPLICATE_APPROVAL")

    def test_timestamp_flow(self):
        with tempfile.TemporaryDirectory() as d:
            alice, bob, rel = self._setup(d)
            run("approve", str(rel), "--key", alice["private_key"])
            run("approve", str(rel), "--key", bob["private_key"])
            r = run("finalize", str(rel), "--tsa", "local", "--json")
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertEqual(json.loads(r.stdout)["data"]["state"], "finalized")
            r = run("verify", str(rel), "--json")
            self.assertEqual(r.returncode, 0, r.stderr)
            data = json.loads(r.stdout)["data"]
            self.assertIn("EXTERNALLY_NOT_AFTER", data["granted_outcomes"])
            self.assertIn("externally_not_after", data)

    def test_timestamp_failure_degrades(self):
        with tempfile.TemporaryDirectory() as d:
            alice, bob, rel = self._setup(d)
            run("approve", str(rel), "--key", alice["private_key"])
            run("approve", str(rel), "--key", bob["private_key"])
            # unreachable TSA without --allow-untimestamped -> exit 4
            r = run("finalize", str(rel), "--tsa", "http://127.0.0.1:1", "--json")
            self.assertEqual(r.returncode, 4, r.stderr)
            self.assertEqual(json.loads(r.stdout)["message"], "TSA_FAILED")
            # with --allow-untimestamped -> degrades to finalized-untimestamped
            r = run("finalize", str(rel), "--tsa", "http://127.0.0.1:1", "--allow-untimestamped", "--json")
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertEqual(json.loads(r.stdout)["data"]["state"], "finalized-untimestamped")
            r = run("verify", str(rel), "--json")
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertNotIn("EXTERNALLY_NOT_AFTER", json.loads(r.stdout)["data"]["granted_outcomes"])

    def test_forged_tsr_rejected_by_pinned_cert(self):
        import sys as _sys
        _sys.path.insert(0, str(ROOT))
        import tsa as tsa_mod
        from pec_core import digest
        with tempfile.TemporaryDirectory() as d:
            alice, bob, rel = self._setup(d)
            run("approve", str(rel), "--key", alice["private_key"])
            run("approve", str(rel), "--key", bob["private_key"])
            self.assertEqual(run("finalize", str(rel), "--tsa", "local").returncode, 0)
            # forge a response from a different TSA (different cert fingerprint)
            pec = json.loads((rel / "pec/pec.json").read_text(encoding="utf-8"))
            imprint = bytes.fromhex(digest(pec))
            fake = tsa_mod.LocalTSA()
            fake_tsr = fake.respond(tsa_mod.build_tsq(imprint, b"\x00" * 16))
            (rel / "receipts/response.tsr").write_bytes(fake_tsr)
            r = run("verify", str(rel), "--json")
            self.assertEqual(r.returncode, 1)
            self.assertIn("TSR_UNTRUSTED_SIGNER", json.loads(r.stdout)["data"]["error_code"])


if __name__ == "__main__":
    unittest.main()
