import json
import pathlib
import subprocess
import sys
import tempfile
import unittest

import approval_delegation


ROOT = pathlib.Path(__file__).resolve().parent
ACSD = ROOT / "acsd.py"


def run(*args):
    return subprocess.run(
        [sys.executable, str(ACSD), *args], capture_output=True, text=True
    )


def keygen(root, name):
    result = run("keygen", "--name", name, "--out-dir", str(root), "--json")
    if result.returncode != 0:
        raise AssertionError(result.stdout)
    return json.loads(result.stdout)["data"]


class TestApprovalDelegation(unittest.TestCase):
    def _initialized(self, root):
        keys = root / "keys"
        alice = keygen(keys, "alice")
        bob = keygen(keys, "bob")
        delegate = keygen(keys, "coordinator-agent")
        team = {
            "schema": "acsd-team/v1",
            "authors": [
                {"key_id": alice["key_id"], "public_key": alice["public_key"],
                 "role": "first", "corresponding": True},
                {"key_id": bob["key_id"], "public_key": bob["public_key"],
                 "role": "co-author", "corresponding": False},
            ],
        }
        team_path = root / "team.json"
        team_path.write_text(json.dumps(team), encoding="utf-8")
        paper = root / "paper.txt"
        paper.write_text("Exact delegated approval test.\n", encoding="utf-8")
        release = root / "release"
        result = run(
            "init", str(paper), "--team", str(team_path), "--out", str(release),
            "--allow-delegated-approval",
        )
        self.assertEqual(result.returncode, 0, result.stdout)
        return alice, bob, delegate, release

    def test_mixed_direct_and_exact_delegated_approval(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            alice, bob, delegate, release = self._initialized(root)
            self.assertEqual(
                run("approve", str(release), "--key", alice["private_key"]).returncode,
                0,
            )
            delegated = run(
                "delegate-approval", str(release),
                "--author-key", bob["private_key"],
                "--delegate-public-key", str(root / "keys/coordinator-agent.pub"),
            )
            self.assertEqual(delegated.returncode, 0, delegated.stdout)
            approved = run(
                "approve-as", str(release), "--key", delegate["private_key"],
                "--for-author", bob["key_id"],
            )
            self.assertEqual(approved.returncode, 0, approved.stdout)
            self.assertEqual(run("finalize", str(release)).returncode, 0)
            verified = run("verify", str(release), "--json")
            self.assertEqual(verified.returncode, 0, verified.stdout)
            data = json.loads(verified.stdout)["data"]
            self.assertEqual(data["approval_modes"][alice["key_id"]]["mode"], "direct")
            self.assertEqual(data["approval_modes"][bob["key_id"]]["mode"], "delegated")
            self.assertIn("AUTHORIZED_TARGET_APPROVAL", data["granted_outcomes"])
            self.assertNotIn("KEY_ASSENT", data["granted_outcomes"])
            approval_set = json.loads(
                (release / "approval/approval-set.json").read_text(encoding="utf-8")
            )
            self.assertEqual(approval_set["schema"], "acsd-approval-set/v2")

    def test_wrong_delegate_cannot_exercise_authorization(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            _, bob, delegate, release = self._initialized(root)
            attacker = keygen(root / "keys", "attacker")
            self.assertEqual(run(
                "delegate-approval", str(release),
                "--author-key", bob["private_key"],
                "--delegate-public-key", str(root / "keys/coordinator-agent.pub"),
            ).returncode, 0)
            result = run(
                "approve-as", str(release), "--key", attacker["private_key"],
                "--for-author", bob["key_id"], "--json",
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(json.loads(result.stdout)["message"], "DELEGATION_DELEGATE_MISMATCH")

    def test_author_facing_command_can_create_exact_delegation(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            _, bob, delegate, release = self._initialized(root)
            result = run(
                "author-approve", str(release), "--key", bob["private_key"],
                "--delegate-public-key", str(root / "keys/coordinator-agent.pub"),
                "--yes", "--json",
            )
            self.assertEqual(result.returncode, 0, result.stdout)
            data = json.loads(result.stdout)["data"]
            self.assertEqual(data["action"], "delegate-exact-target")
            self.assertEqual(data["author_slot"], 2)
            self.assertEqual(data["delegate_key_id"], delegate["key_id"])
            self.assertTrue((release / f"delegations/{bob['key_id']}.cose").is_file())

    def test_delegation_is_bound_to_one_exact_target(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            _, bob, delegate, release = self._initialized(root)
            self.assertEqual(run(
                "delegate-approval", str(release),
                "--author-key", bob["private_key"],
                "--delegate-public-key", str(root / "keys/coordinator-agent.pub"),
            ).returncode, 0)
            delegation = json.loads(
                (release / f"delegations/{bob['key_id']}.json").read_text(encoding="utf-8")
            )
            target = json.loads(
                (release / "approval/target.json").read_text(encoding="utf-8")
            )
            target["release_digest"] = "f" * 64
            with self.assertRaisesRegex(ValueError, "DELEGATION_TARGET_MISMATCH"):
                approval_delegation.validate(
                    delegation, target, author_key_id=bob["key_id"],
                    delegate_key_id=delegate["key_id"],
                )

    def test_delegation_blocks_later_direct_approval_ambiguity(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            _, bob, _, release = self._initialized(root)
            self.assertEqual(run(
                "delegate-approval", str(release),
                "--author-key", bob["private_key"],
                "--delegate-public-key", str(root / "keys/coordinator-agent.pub"),
            ).returncode, 0)
            result = run("approve", str(release), "--key", bob["private_key"], "--json")
            self.assertEqual(result.returncode, 3)
            self.assertEqual(json.loads(result.stdout)["message"], "DUPLICATE_APPROVAL")

    def test_delegate_cannot_replace_predecessor_authority_on_successor(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            alice, bob, delegate, parent = self._initialized(root)
            self.assertEqual(run(
                "approve", str(parent), "--key", alice["private_key"]
            ).returncode, 0)
            self.assertEqual(run(
                "approve", str(parent), "--key", bob["private_key"]
            ).returncode, 0)
            self.assertEqual(run("finalize", str(parent)).returncode, 0)

            paper = root / "paper-v2.txt"
            paper.write_text("Exact delegated successor approval test.\n", encoding="utf-8")
            child = root / "release-v2"
            initialized = run(
                "init", str(paper), "--team", str(root / "team.json"),
                "--parent", str(parent), "--out", str(child),
                "--allow-delegated-approval",
            )
            self.assertEqual(initialized.returncode, 0, initialized.stdout)
            self.assertEqual(run(
                "approve", str(child), "--key", alice["private_key"]
            ).returncode, 0)
            self.assertEqual(run(
                "delegate-approval", str(child),
                "--author-key", bob["private_key"],
                "--delegate-public-key", str(root / "keys/coordinator-agent.pub"),
            ).returncode, 0)
            self.assertEqual(run(
                "approve-as", str(child), "--key", delegate["private_key"],
                "--for-author", bob["key_id"],
            ).returncode, 0)
            incomplete = run("finalize", str(child), "--json")
            self.assertEqual(incomplete.returncode, 5)
            self.assertEqual(
                json.loads(incomplete.stdout)["message"],
                "LINEAGE_AUTHORIZATION_INCOMPLETE",
            )
            self.assertEqual(run(
                "authorize", str(child), "--key", alice["private_key"]
            ).returncode, 0)
            self.assertEqual(run(
                "authorize", str(child), "--key", bob["private_key"]
            ).returncode, 0)
            self.assertEqual(run("finalize", str(child)).returncode, 0)
            verified = run("verify", str(child), "--json")
            self.assertEqual(verified.returncode, 0, verified.stdout)
            data = json.loads(verified.stdout)["data"]
            self.assertEqual(
                data["lineage_authorization_method"], "predecessor-explicit"
            )


if __name__ == "__main__":
    unittest.main()
