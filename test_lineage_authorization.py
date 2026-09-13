import json
import pathlib
import shutil
import subprocess
import sys
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parent
ACSD = ROOT / "acsd.py"


def run(*args):
    return subprocess.run([sys.executable, str(ACSD), *args], capture_output=True, text=True)


def keygen(root, name):
    result = run("keygen", "--name", name, "--out-dir", str(root / "keys"), "--json")
    if result.returncode != 0:
        raise AssertionError(result.stderr or result.stdout)
    return json.loads(result.stdout)["data"]


def team_file(root, name, keys):
    team = {
        "schema": "acsd-team/v1",
        "authors": [
            {
                "key_id": key["key_id"],
                "public_key": key["public_key"],
                "role": "sole" if len(keys) == 1 else "co-first",
                "corresponding": index == 0,
            }
            for index, key in enumerate(keys)
        ],
    }
    path = root / name
    path.write_text(json.dumps(team), encoding="utf-8")
    return path


def make_parent(root, keys, threshold=None):
    paper = root / "parent.txt"
    paper.write_text("Accepted parent manuscript.", encoding="utf-8")
    out = root / "parent-release"
    args = ["release", str(paper), "--out", str(out)]
    for key in keys:
        args.extend(["--key", key["private_key"]])
    if threshold is not None:
        args.extend(["--lineage-threshold", str(threshold)])
    result = run(*args, "--json")
    if result.returncode != 0:
        raise AssertionError(result.stderr or result.stdout)
    return out


class TestLineageAuthorization(unittest.TestCase):
    def test_same_authority_n_plus_one_is_authorized_by_child_approvals(self):
        with tempfile.TemporaryDirectory() as raw:
            root = pathlib.Path(raw)
            alice = keygen(root, "alice")
            parent = make_parent(root, [alice])
            paper = root / "v2.txt"
            paper.write_text("Legitimate second version.", encoding="utf-8")
            child = root / "child"
            result = run(
                "revise", str(parent), str(paper), "--key", alice["private_key"],
                "--out", str(child), "--json",
            )
            self.assertEqual(result.returncode, 0, result.stderr or result.stdout)
            data = json.loads(result.stdout)["data"]
            self.assertEqual(data["version"], 2)
            verified = run("verify", str(child), "--json")
            self.assertEqual(verified.returncode, 0, verified.stderr or verified.stdout)
            self.assertEqual(
                json.loads(verified.stdout)["data"]["lineage_status"],
                "AUTHORIZED_CONTINUATION",
            )
            parent_release_id = json.loads(
                (child / "release" / "release.json").read_text(encoding="utf-8")
            )["parent_release_id"]
            pinned = run(
                "verify", str(child), "--expected-parent-release-id", parent_release_id, "--json",
            )
            self.assertEqual(pinned.returncode, 0, pinned.stderr or pinned.stdout)
            self.assertEqual(json.loads(pinned.stdout)["data"]["lineage_anchor_status"], "PIN_MATCHED")
            wrong_pin = run(
                "verify", str(child), "--expected-parent-release-id", "urn:sha256:" + "0" * 64, "--json",
            )
            self.assertEqual(wrong_pin.returncode, 1)
            self.assertEqual(json.loads(wrong_pin.stdout)["data"]["error_code"], "PARENT_PIN_MISMATCH")

    def test_attacker_n_plus_one_is_valid_object_but_unauthorized_successor(self):
        with tempfile.TemporaryDirectory() as raw:
            root = pathlib.Path(raw)
            alice = keygen(root, "alice")
            mallory = keygen(root, "mallory")
            parent = make_parent(root, [alice])
            paper = root / "fake-v2.txt"
            paper.write_text("Attacker-controlled apparent next version.", encoding="utf-8")
            child = root / "fake-child"
            team = team_file(root, "mallory-team.json", [mallory])
            self.assertEqual(run(
                "init", str(paper), "--team", str(team), "--parent", str(parent),
                "--out", str(child),
            ).returncode, 0)
            self.assertEqual(run(
                "approve", str(child), "--key", mallory["private_key"],
            ).returncode, 0)

            verified = run("verify", str(child), "--json")
            self.assertEqual(verified.returncode, 1)
            report = json.loads(verified.stdout)
            self.assertEqual(report["message"], "VALID_OBJECT_BUT_UNAUTHORIZED_SUCCESSOR")
            self.assertEqual(report["data"]["lineage_status"], "UNAUTHORIZED_SUCCESSOR")
            finalized = run("finalize", str(child), "--json")
            self.assertEqual(finalized.returncode, 5)
            self.assertEqual(json.loads(finalized.stdout)["message"], "LINEAGE_AUTHORIZATION_INCOMPLETE")

    def test_authorized_team_change_requires_old_and_new_control(self):
        with tempfile.TemporaryDirectory() as raw:
            root = pathlib.Path(raw)
            alice = keygen(root, "alice")
            bob = keygen(root, "bob")
            parent = make_parent(root, [alice])
            paper = root / "rotated.txt"
            paper.write_text("Authorized successor under Bob's key.", encoding="utf-8")
            child = root / "rotated-child"
            result = run(
                "revise", str(parent), str(paper),
                "--key", bob["private_key"],
                "--parent-key", alice["private_key"],
                "--out", str(child), "--json",
            )
            self.assertEqual(result.returncode, 0, result.stderr or result.stdout)
            verified = run("verify", str(child), "--json")
            self.assertEqual(verified.returncode, 0, verified.stderr or verified.stdout)
            self.assertEqual(
                json.loads(verified.stdout)["data"]["lineage_status"],
                "AUTHORIZED_TRANSITION",
            )
            node = shutil.which("node")
            if node is None:
                self.skipTest("Node.js unavailable for independent COSE check")
            independent = subprocess.run(
                [
                    node,
                    str(ROOT / "design" / "verify_approval.cjs"),
                    str(child / "lineage" / "transition.json"),
                    str(child / "lineage" / "authorizations" / f"{alice['key_id']}.cose"),
                    str(child / "lineage" / "parent-public-keys" / f"{alice['key_id']}.pub"),
                    alice["key_id"],
                ],
                capture_output=True,
                text=True,
            )
            self.assertEqual(independent.returncode, 0, independent.stderr or independent.stdout)
            self.assertTrue(json.loads(independent.stdout)["valid"])

    def test_old_threshold_cannot_be_silently_lowered(self):
        with tempfile.TemporaryDirectory() as raw:
            root = pathlib.Path(raw)
            alice = keygen(root, "alice")
            bob = keygen(root, "bob")
            parent = make_parent(root, [alice, bob], threshold=2)
            paper = root / "v2.txt"
            paper.write_text("The child cannot silently lower the old threshold.", encoding="utf-8")
            child = root / "child"
            result = run(
                "revise", str(parent), str(paper),
                "--key", alice["private_key"], "--key", bob["private_key"],
                "--lineage-threshold", "1",
                "--out", str(child), "--json",
            )
            self.assertEqual(result.returncode, 5)
            self.assertEqual(json.loads(result.stdout)["message"], "LINEAGE_AUTHORIZATION_INCOMPLETE")

            authorized = root / "authorized-child"
            result = run(
                "revise", str(parent), str(paper),
                "--key", alice["private_key"], "--key", bob["private_key"],
                "--parent-key", alice["private_key"], "--parent-key", bob["private_key"],
                "--lineage-threshold", "1",
                "--out", str(authorized), "--json",
            )
            self.assertEqual(result.returncode, 0, result.stderr or result.stdout)
            verified = run("verify", str(authorized), "--json")
            self.assertEqual(verified.returncode, 0, verified.stderr or verified.stdout)
            self.assertEqual(
                json.loads(verified.stdout)["data"]["lineage_status"],
                "AUTHORIZED_TRANSITION",
            )

    def test_parent_threshold_one_allows_one_old_author_to_rotate(self):
        with tempfile.TemporaryDirectory() as raw:
            root = pathlib.Path(raw)
            alice = keygen(root, "alice")
            bob = keygen(root, "bob")
            carol = keygen(root, "carol")
            parent = make_parent(root, [alice, bob], threshold=1)
            paper = root / "v2.txt"
            paper.write_text("Parent explicitly chose a one-of-two continuation threshold.", encoding="utf-8")
            child = root / "child"
            result = run(
                "revise", str(parent), str(paper),
                "--key", carol["private_key"],
                "--parent-key", bob["private_key"],
                "--out", str(child), "--json",
            )
            self.assertEqual(result.returncode, 0, result.stderr or result.stdout)

    def test_transition_authorization_cannot_be_replayed_for_other_content(self):
        with tempfile.TemporaryDirectory() as raw:
            root = pathlib.Path(raw)
            alice = keygen(root, "alice")
            bob = keygen(root, "bob")
            parent = make_parent(root, [alice])
            team = team_file(root, "bob-team.json", [bob])
            children = []
            for suffix in ("one", "two"):
                paper = root / f"{suffix}.txt"
                paper.write_text(f"Candidate {suffix}.", encoding="utf-8")
                child = root / f"child-{suffix}"
                self.assertEqual(run(
                    "init", str(paper), "--team", str(team), "--parent", str(parent),
                    "--out", str(child),
                ).returncode, 0)
                self.assertEqual(run(
                    "approve", str(child), "--key", bob["private_key"],
                ).returncode, 0)
                children.append(child)
            self.assertEqual(run(
                "authorize", str(children[0]), "--key", alice["private_key"],
            ).returncode, 0)
            source = children[0] / f"lineage/authorizations/{alice['key_id']}.cose"
            target = children[1] / f"lineage/authorizations/{alice['key_id']}.cose"
            shutil.copyfile(source, target)
            verified = run("verify", str(children[1]), "--json")
            self.assertEqual(verified.returncode, 1)
            self.assertEqual(json.loads(verified.stdout)["data"]["error_code"], "COSE_PAYLOAD_MISMATCH")

    def test_authorized_branch_starts_at_version_one(self):
        with tempfile.TemporaryDirectory() as raw:
            root = pathlib.Path(raw)
            alice = keygen(root, "alice")
            parent = make_parent(root, [alice])
            paper = root / "companion.txt"
            paper.write_text("Authorized companion branch.", encoding="utf-8")
            child = root / "companion"
            result = run(
                "revise", str(parent), str(paper), "--key", alice["private_key"],
                "--line", "companion", "--out", str(child), "--json",
            )
            self.assertEqual(result.returncode, 0, result.stderr or result.stdout)
            data = json.loads(result.stdout)["data"]
            self.assertEqual(data["line"], "companion")
            self.assertEqual(data["version"], 1)

    def test_two_authorized_same_slot_successors_are_reported_not_ranked(self):
        with tempfile.TemporaryDirectory() as raw:
            root = pathlib.Path(raw)
            alice = keygen(root, "alice")
            parent = make_parent(root, [alice])
            successors = []
            for suffix in ("left", "right"):
                paper = root / f"{suffix}.txt"
                paper.write_text(f"Authorized but conflicting {suffix} successor.", encoding="utf-8")
                child = root / f"child-{suffix}"
                result = run(
                    "revise", str(parent), str(paper), "--key", alice["private_key"],
                    "--out", str(child),
                )
                self.assertEqual(result.returncode, 0, result.stderr or result.stdout)
                successors.append(child)
            compared = run(
                "compare-successors", str(successors[0]), str(successors[1]), "--json",
            )
            self.assertEqual(compared.returncode, 0, compared.stderr or compared.stdout)
            report = json.loads(compared.stdout)
            self.assertEqual(report["message"], "LINEAGE_EQUIVOCATION_DETECTED")
            self.assertTrue(report["data"]["conflict"])
            self.assertIsNone(report["data"]["winner"])


if __name__ == "__main__":
    unittest.main()
