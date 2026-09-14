import json
import pathlib
import subprocess
import sys
import tempfile
import unittest

from test_cli import make_team


ROOT = pathlib.Path(__file__).resolve().parent
ACSD = ROOT / "acsd.py"
NODE_VERIFIER = ROOT / "design/verify_approval.cjs"


def run_acsd(*args):
    return subprocess.run([sys.executable, str(ACSD), *args], capture_output=True, text=True)


class TestNodeApprovalInterop(unittest.TestCase):
    def test_python_approval_verified_by_independent_node_path(self):
        with tempfile.TemporaryDirectory() as d:
            d = pathlib.Path(d)
            paper = d / "paper.txt"
            paper.write_text("Cross-implementation approval.", encoding="utf-8")
            team, key_ids, private_keys = make_team(d, ["alice"])
            release = d / "release-dir"
            self.assertEqual(run_acsd("init", str(paper), "--team", team, "--out", str(release)).returncode, 0)
            self.assertEqual(run_acsd("approve", str(release), "--key", private_keys[0]).returncode, 0)
            approval = release / f"approvals/{key_ids[0]}.cose"
            result = subprocess.run([
                "node", str(NODE_VERIFIER),
                str(release / "approval/target.json"), str(approval),
                str(release / f"public-keys/{key_ids[0]}.pub"), key_ids[0],
            ], capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertTrue(json.loads(result.stdout)["valid"])

            damaged = bytearray(approval.read_bytes())
            damaged[-1] ^= 1
            approval.write_bytes(damaged)
            result = subprocess.run([
                "node", str(NODE_VERIFIER),
                str(release / "approval/target.json"), str(approval),
                str(release / f"public-keys/{key_ids[0]}.pub"), key_ids[0],
            ], capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)


if __name__ == "__main__":
    unittest.main()
