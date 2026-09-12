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


def make_team(tmp, authors):
    team = {"schema": "acsd-team/v1", "authors": authors}
    p = tmp / "team.json"
    p.write_text(json.dumps(team), encoding="utf-8")
    return str(p)


class TestCLI(unittest.TestCase):
    def test_init_verify_inspect(self):
        with tempfile.TemporaryDirectory() as d:
            d = pathlib.Path(d)
            paper = d / "paper.txt"
            paper.write_text("ACSD test manuscript.", encoding="utf-8")
            team = make_team(d, [
                {"key_id": "alice", "role": "co-first", "corresponding": True},
                {"key_id": "bob", "role": "co-first"},
            ])
            rel = d / "release-dir"
            r = run("init", str(paper), "--team", team, "--out", str(rel), "--json")
            self.assertEqual(r.returncode, 0, r.stderr)
            out = json.loads(r.stdout)
            self.assertEqual(out["data"]["state"], "awaiting-approvals")
            # verify -> INCOMPLETE (exit 5), with outcomes + non-claims
            r = run("verify", str(rel), "--json")
            self.assertEqual(r.returncode, 5, r.stderr)
            out = json.loads(r.stdout)
            self.assertEqual(out["data"]["missing_approvals"], ["alice", "bob"])
            self.assertIn("natural_person_authorship", out["data"]["non_claims"])
            self.assertEqual(out["data"]["granted_outcomes"], ["KEY_ASSENT", "GOVERNANCE_ASSENT"])
            # inspect -> exit 0
            r = run("inspect", str(rel))
            self.assertEqual(r.returncode, 0, r.stderr)

    def test_tamper_detected(self):
        with tempfile.TemporaryDirectory() as d:
            d = pathlib.Path(d)
            paper = d / "paper.txt"
            paper.write_text("ACSD test manuscript.", encoding="utf-8")
            team = make_team(d, [{"key_id": "alice"}])
            rel = d / "release-dir"
            self.assertEqual(run("init", str(paper), "--team", team, "--out", str(rel)).returncode, 0)
            p = next((rel / "paper").iterdir())
            p.write_bytes(p.read_bytes() + b"X")
            r = run("verify", str(rel), "--json")
            self.assertEqual(r.returncode, 1, r.stderr)
            self.assertEqual(json.loads(r.stdout)["data"]["error_code"], "CONTENT_DIGEST_MISMATCH")

    def test_output_exists_conflict(self):
        with tempfile.TemporaryDirectory() as d:
            d = pathlib.Path(d)
            paper = d / "paper.txt"
            paper.write_text("ACSD test manuscript.", encoding="utf-8")
            team = make_team(d, [{"key_id": "alice"}])
            rel = d / "release-dir"
            rel.mkdir()
            (rel / "junk").write_text("x", encoding="utf-8")
            r = run("init", str(paper), "--team", team, "--out", str(rel), "--json")
            self.assertEqual(r.returncode, 3, r.stderr)


if __name__ == "__main__":
    unittest.main()
