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


def make_team(tmp, names):
    """Generate real keys and return (team_path, key_ids, private_keys)."""
    keys = tmp / "keys"
    authors, key_ids, privs = [], [], []
    for i, name in enumerate(names, 1):
        kd = json.loads(run("keygen", "--name", name, "--out-dir", str(keys), "--json").stdout)["data"]
        authors.append({"key_id": kd["key_id"], "public_key": kd["public_key"],
                        "role": "co-first", "corresponding": i == 1})
        key_ids.append(kd["key_id"])
        privs.append(kd["private_key"])
    team = {"schema": "acsd-team/v1", "authors": authors}
    p = tmp / "team.json"
    p.write_text(json.dumps(team), encoding="utf-8")
    return str(p), key_ids, privs


class TestCLI(unittest.TestCase):
    def test_version_comes_from_package_version_source(self):
        result = run("--version")
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout.strip(), "acsd 3.2.0rc1")

    def test_init_verify_inspect(self):
        with tempfile.TemporaryDirectory() as d:
            d = pathlib.Path(d)
            paper = d / "paper.txt"
            paper.write_text("ACSD test manuscript.", encoding="utf-8")
            team, key_ids, _ = make_team(d, ["alice", "bob"])
            rel = d / "release-dir"
            r = run("init", str(paper), "--team", team, "--out", str(rel), "--json")
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertEqual(json.loads(r.stdout)["data"]["state"], "awaiting-approvals")
            r = run("verify", str(rel), "--json")
            self.assertEqual(r.returncode, 5, r.stderr)
            out = json.loads(r.stdout)
            self.assertEqual(out["data"]["missing_approvals"], sorted(key_ids))
            self.assertIn("natural_person_authorship", out["data"]["non_claims"])
            # Policy permission is not evidence: before unanimous signatures,
            # no outcome has been established.
            self.assertEqual(out["data"]["granted_outcomes"], [])
            self.assertEqual(run("inspect", str(rel)).returncode, 0)

    def test_tamper_detected(self):
        with tempfile.TemporaryDirectory() as d:
            d = pathlib.Path(d)
            paper = d / "paper.txt"
            paper.write_text("ACSD test manuscript.", encoding="utf-8")
            team, _, _ = make_team(d, ["alice"])
            rel = d / "release-dir"
            self.assertEqual(run("init", str(paper), "--team", team, "--out", str(rel)).returncode, 0)
            p = next((rel / "paper").iterdir())
            p.write_bytes(p.read_bytes() + b"X")
            r = run("verify", str(rel), "--json")
            self.assertEqual(r.returncode, 1)
            self.assertEqual(json.loads(r.stdout)["data"]["error_code"], "CONTENT_DIGEST_MISMATCH")

    def test_output_exists_conflict(self):
        with tempfile.TemporaryDirectory() as d:
            d = pathlib.Path(d)
            paper = d / "paper.txt"
            paper.write_text("ACSD test manuscript.", encoding="utf-8")
            team, _, _ = make_team(d, ["alice"])
            rel = d / "release-dir"
            rel.mkdir()
            (rel / "junk").write_text("x", encoding="utf-8")
            r = run("init", str(paper), "--team", team, "--out", str(rel), "--json")
            self.assertEqual(r.returncode, 3)

    def test_malformed_release_has_stable_json_error(self):
        from pec_core import canonical
        with tempfile.TemporaryDirectory() as d:
            d = pathlib.Path(d)
            paper = d / "paper.txt"
            paper.write_text("ACSD test manuscript.", encoding="utf-8")
            team, _, _ = make_team(d, ["alice"])
            rel = d / "release-dir"
            self.assertEqual(run("init", str(paper), "--team", team, "--out", str(rel)).returncode, 0)
            release_path = rel / "release/release.json"
            release = json.loads(release_path.read_text(encoding="utf-8"))
            del release["authors"]
            release_path.write_bytes(canonical(release) + b"\n")
            result = run("verify", str(rel), "--json")
            self.assertEqual(result.returncode, 1)
            self.assertEqual(json.loads(result.stdout)["message"], "MALFORMED_INPUT")

    def test_path_like_key_id_is_rejected_before_path_construction(self):
        from pec_core import canonical
        with tempfile.TemporaryDirectory() as d:
            d = pathlib.Path(d)
            paper = d / "paper.txt"
            paper.write_text("ACSD test manuscript.", encoding="utf-8")
            team, _, _ = make_team(d, ["alice"])
            rel = d / "release-dir"
            self.assertEqual(run("init", str(paper), "--team", team, "--out", str(rel)).returncode, 0)
            release_path = rel / "release/release.json"
            release = json.loads(release_path.read_text(encoding="utf-8"))
            release["authors"][0]["key_id"] = "../outside"
            release_path.write_bytes(canonical(release) + b"\n")
            result = run("verify", str(rel), "--json")
            self.assertEqual(result.returncode, 1)
            self.assertEqual(json.loads(result.stdout)["message"], "KEY_ID_INVALID")

    def test_governance_byline_must_match_release_order(self):
        from pec_core import canonical, digest
        with tempfile.TemporaryDirectory() as d:
            d = pathlib.Path(d)
            paper = d / "paper.txt"
            paper.write_text("ACSD test manuscript.", encoding="utf-8")
            team, _, _ = make_team(d, ["alice", "bob"])
            rel = d / "release-dir"
            self.assertEqual(run("init", str(paper), "--team", team, "--out", str(rel)).returncode, 0)
            governance_path = rel / "governance/statement.json"
            pec_path = rel / "pec/pec.json"
            governance = json.loads(governance_path.read_text(encoding="utf-8"))
            governance["byline"].reverse()
            pec = json.loads(pec_path.read_text(encoding="utf-8"))
            pec["governance"]["statement_digest"] = digest(governance)
            governance_path.write_bytes(canonical(governance) + b"\n")
            pec_path.write_bytes(canonical(pec) + b"\n")
            result = run("verify", str(rel), "--json")
            self.assertEqual(result.returncode, 1)
            self.assertEqual(
                json.loads(result.stdout)["data"]["error_code"],
                "GOVERNANCE_BYLINE_MISMATCH",
            )


if __name__ == "__main__":
    unittest.main()
