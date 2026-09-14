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
    return subprocess.run(
        [sys.executable, str(ACSD), *args],
        capture_output=True,
        text=True,
    )


def keygen(root, name):
    result = run("keygen", "--name", name, "--out-dir", str(root / "keys"), "--json")
    if result.returncode != 0:
        raise AssertionError(result.stderr or result.stdout)
    data = json.loads(result.stdout)["data"]
    data["public_key_path"] = str(root / "keys" / f"{name}.pub")
    return data


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


def make_parent(root, online_keys, recovery_keys=None, recovery_threshold=None):
    root.mkdir(parents=True, exist_ok=True)
    paper = root / "parent.txt"
    paper.write_text("Parent with an optional precommitted recovery authority.", encoding="utf-8")
    out = root / "parent-release"
    args = ["release", str(paper), "--out", str(out)]
    for key in online_keys:
        args.extend(["--key", key["private_key"]])
    for key in recovery_keys or []:
        args.extend(["--recovery-public-key", key["public_key_path"]])
    if recovery_threshold is not None:
        args.extend(["--recovery-threshold", str(recovery_threshold)])
    result = run(*args, "--json")
    if result.returncode != 0:
        raise AssertionError(result.stderr or result.stdout)
    return out


def make_child_draft(root, parent, author, name, text):
    paper = root / f"{name}.txt"
    paper.write_text(text, encoding="utf-8")
    team = team_file(root, f"{name}-team.json", [author])
    child = root / name
    initialized = run(
        "init",
        str(paper),
        "--team",
        str(team),
        "--parent",
        str(parent),
        "--out",
        str(child),
        "--json",
    )
    if initialized.returncode != 0:
        raise AssertionError(initialized.stderr or initialized.stdout)
    approved = run("approve", str(child), "--key", author["private_key"], "--json")
    if approved.returncode != 0:
        raise AssertionError(approved.stderr or approved.stdout)
    return child


class TestPrecommittedRecovery(unittest.TestCase):
    def test_recovery_authority_must_be_disjoint_from_online_authority(self):
        with tempfile.TemporaryDirectory() as raw:
            root = pathlib.Path(raw)
            alice = keygen(root, "alice")
            paper = root / "paper.txt"
            paper.write_text("Disjoint authority check.", encoding="utf-8")
            result = run(
                "release",
                str(paper),
                "--key",
                alice["private_key"],
                "--recovery-public-key",
                alice["public_key_path"],
                "--out",
                str(root / "release"),
                "--json",
            )
            self.assertEqual(result.returncode, 1)
            self.assertEqual(
                json.loads(result.stdout)["message"],
                "RECOVERY_AUTHORITY_NOT_DISJOINT",
            )

    def test_two_of_two_recovery_authorizes_exact_rotated_child(self):
        with tempfile.TemporaryDirectory() as raw:
            root = pathlib.Path(raw)
            alice = keygen(root, "alice")
            bob = keygen(root, "bob")
            guardian_one = keygen(root, "guardian-one")
            guardian_two = keygen(root, "guardian-two")
            parent = make_parent(
                root,
                [alice],
                [guardian_one, guardian_two],
                recovery_threshold=2,
            )
            paper = root / "recovered.txt"
            paper.write_text("Exact successor after loss of the online key.", encoding="utf-8")
            child = root / "recovered-child"
            result = run(
                "revise",
                str(parent),
                str(paper),
                "--key",
                bob["private_key"],
                "--recovery-key",
                guardian_one["private_key"],
                "--recovery-key",
                guardian_two["private_key"],
                "--out",
                str(child),
                "--json",
            )
            self.assertEqual(result.returncode, 0, result.stderr or result.stdout)
            verified = run("verify", str(child), "--json")
            self.assertEqual(verified.returncode, 0, verified.stderr or verified.stdout)
            data = json.loads(verified.stdout)["data"]
            self.assertEqual(data["lineage_status"], "RECOVERY_AUTHORIZED_TRANSITION")
            self.assertEqual(data["lineage_authorization_method"], "recovery")
            self.assertIn("AUTHORIZED_SUCCESSOR", data["granted_outcomes"])
            release = json.loads((child / "release/release.json").read_text(encoding="utf-8"))
            self.assertEqual(release["lineage_authority"]["schema"], "acsd-lineage-authority/v2")
            approval_set = json.loads(
                (child / "approval/approval-set.json").read_text(encoding="utf-8")
            )
            self.assertEqual(len(approval_set["lineage_authorizations"]), 2)

    def test_recovery_threshold_is_enforced(self):
        with tempfile.TemporaryDirectory() as raw:
            root = pathlib.Path(raw)
            alice = keygen(root, "alice")
            bob = keygen(root, "bob")
            guardian_one = keygen(root, "guardian-one")
            guardian_two = keygen(root, "guardian-two")
            parent = make_parent(root, [alice], [guardian_one, guardian_two], 2)
            paper = root / "child.txt"
            paper.write_text("One guardian is insufficient.", encoding="utf-8")
            result = run(
                "revise",
                str(parent),
                str(paper),
                "--key",
                bob["private_key"],
                "--recovery-key",
                guardian_one["private_key"],
                "--out",
                str(root / "child"),
                "--json",
            )
            self.assertEqual(result.returncode, 5)
            report = json.loads(result.stdout)
            self.assertEqual(report["message"], "LINEAGE_AUTHORIZATION_INCOMPLETE")
            self.assertEqual(report["data"]["authorization_method"], "recovery")
            self.assertEqual(report["data"]["required_threshold"], 2)

    def test_uncommitted_or_unknown_recovery_key_is_rejected(self):
        with tempfile.TemporaryDirectory() as raw:
            root = pathlib.Path(raw)
            alice = keygen(root, "alice")
            bob = keygen(root, "bob")
            guardian = keygen(root, "guardian")
            mallory = keygen(root, "mallory")
            parent = make_parent(root, [alice], [guardian], 1)
            draft = make_child_draft(root, parent, bob, "unknown", "Unknown guardian.")
            unknown = run(
                "recover", str(draft), "--key", mallory["private_key"], "--json"
            )
            self.assertEqual(unknown.returncode, 1)
            self.assertEqual(json.loads(unknown.stdout)["message"], "UNKNOWN_RECOVERY_AUTHORITY_KEY")

            no_recovery_parent = make_parent(root / "plain", [alice])
            plain_draft = make_child_draft(
                root / "plain", no_recovery_parent, bob, "plain-child", "No precommit."
            )
            absent = run(
                "recover", str(plain_draft), "--key", guardian["private_key"], "--json"
            )
            self.assertEqual(absent.returncode, 1)
            self.assertEqual(json.loads(absent.stdout)["message"], "RECOVERY_AUTHORITY_NOT_PRECOMMITTED")

    def test_recovery_signature_cannot_be_replayed_to_other_child(self):
        with tempfile.TemporaryDirectory() as raw:
            root = pathlib.Path(raw)
            alice = keygen(root, "alice")
            bob = keygen(root, "bob")
            guardian = keygen(root, "guardian")
            parent = make_parent(root, [alice], [guardian], 1)
            first = make_child_draft(root, parent, bob, "first", "First exact child.")
            second = make_child_draft(root, parent, bob, "second", "Different exact child.")
            authorized = run(
                "recover", str(first), "--key", guardian["private_key"], "--json"
            )
            self.assertEqual(authorized.returncode, 0, authorized.stderr or authorized.stdout)
            signature = first / f"lineage/recovery-authorizations/{guardian['key_id']}.cose"
            shutil.copyfile(
                signature,
                second / f"lineage/recovery-authorizations/{guardian['key_id']}.cose",
            )
            verified = run("verify", str(second), "--json")
            self.assertEqual(verified.returncode, 1)
            self.assertEqual(json.loads(verified.stdout)["data"]["error_code"], "COSE_PAYLOAD_MISMATCH")

    def test_ordinary_and_recovery_authorizations_cannot_be_mixed(self):
        with tempfile.TemporaryDirectory() as raw:
            root = pathlib.Path(raw)
            alice = keygen(root, "alice")
            bob = keygen(root, "bob")
            guardian = keygen(root, "guardian")
            parent = make_parent(root, [alice], [guardian], 1)
            child = make_child_draft(root, parent, bob, "child", "Ambiguous method test.")
            ordinary = run(
                "authorize", str(child), "--key", alice["private_key"], "--json"
            )
            self.assertEqual(ordinary.returncode, 0, ordinary.stderr or ordinary.stdout)
            mixed = run(
                "recover", str(child), "--key", guardian["private_key"], "--json"
            )
            self.assertEqual(mixed.returncode, 3)
            self.assertEqual(json.loads(mixed.stdout)["message"], "LINEAGE_AUTHORIZATION_METHOD_AMBIGUOUS")

    def test_recovery_is_not_used_for_unchanged_authority(self):
        with tempfile.TemporaryDirectory() as raw:
            root = pathlib.Path(raw)
            alice = keygen(root, "alice")
            guardian = keygen(root, "guardian")
            parent = make_parent(root, [alice], [guardian], 1)
            paper = root / "child.txt"
            paper.write_text("Ordinary continuation.", encoding="utf-8")
            result = run(
                "revise",
                str(parent),
                str(paper),
                "--key",
                alice["private_key"],
                "--recovery-key",
                guardian["private_key"],
                "--out",
                str(root / "child"),
                "--json",
            )
            self.assertEqual(result.returncode, 3)
            self.assertEqual(
                json.loads(result.stdout)["message"],
                "RECOVERY_REQUIRES_ONLINE_AUTHORITY_CHANGE",
            )

    def test_recovery_cannot_authorize_only_guardian_rotation(self):
        with tempfile.TemporaryDirectory() as raw:
            root = pathlib.Path(raw)
            alice = keygen(root, "alice")
            guardian_one = keygen(root, "guardian-one")
            guardian_two = keygen(root, "guardian-two")
            parent = make_parent(root, [alice], [guardian_one], 1)
            paper = root / "child.txt"
            paper.write_text("Guardian-only rotation.", encoding="utf-8")
            result = run(
                "revise",
                str(parent),
                str(paper),
                "--key",
                alice["private_key"],
                "--recovery-key",
                guardian_one["private_key"],
                "--recovery-public-key",
                guardian_two["public_key_path"],
                "--out",
                str(root / "child"),
                "--json",
            )
            self.assertEqual(result.returncode, 3)
            self.assertEqual(
                json.loads(result.stdout)["message"],
                "RECOVERY_REQUIRES_ONLINE_AUTHORITY_CHANGE",
            )

    def test_online_predecessor_can_rotate_guardians_without_online_rotation(self):
        with tempfile.TemporaryDirectory() as raw:
            root = pathlib.Path(raw)
            alice = keygen(root, "alice")
            guardian_one = keygen(root, "guardian-one")
            guardian_two = keygen(root, "guardian-two")
            parent = make_parent(root, [alice], [guardian_one], 1)
            paper = root / "child.txt"
            paper.write_text("Ordinary guardian rotation.", encoding="utf-8")
            child = root / "child"
            result = run(
                "revise",
                str(parent),
                str(paper),
                "--key",
                alice["private_key"],
                "--parent-key",
                alice["private_key"],
                "--recovery-public-key",
                guardian_two["public_key_path"],
                "--out",
                str(child),
                "--json",
            )
            self.assertEqual(result.returncode, 0, result.stderr or result.stdout)
            verified = run("verify", str(child), "--json")
            self.assertEqual(verified.returncode, 0, verified.stderr or verified.stdout)
            data = json.loads(verified.stdout)["data"]
            self.assertEqual(data["lineage_status"], "AUTHORIZED_TRANSITION")
            self.assertEqual(data["lineage_authorization_method"], "predecessor")
            release = json.loads(
                (child / "release/release.json").read_text(encoding="utf-8")
            )
            self.assertEqual(
                release["lineage_authority"]["recovery"]["key_ids"],
                [guardian_two["key_id"]],
            )

    def test_competing_online_and_recovery_children_remain_an_unranked_fork(self):
        with tempfile.TemporaryDirectory() as raw:
            root = pathlib.Path(raw)
            alice = keygen(root, "alice")
            bob = keygen(root, "bob")
            carol = keygen(root, "carol")
            guardian = keygen(root, "guardian")
            parent = make_parent(root, [alice], [guardian], 1)

            online_paper = root / "online.txt"
            online_paper.write_text("Child authorized by the online predecessor.", encoding="utf-8")
            online = root / "online-child"
            online_result = run(
                "revise", str(parent), str(online_paper),
                "--key", bob["private_key"],
                "--parent-key", alice["private_key"],
                "--out", str(online), "--json",
            )
            self.assertEqual(online_result.returncode, 0, online_result.stderr or online_result.stdout)

            recovery_paper = root / "recovery.txt"
            recovery_paper.write_text("Competing child authorized by recovery.", encoding="utf-8")
            recovered = root / "recovery-child"
            recovery_result = run(
                "revise", str(parent), str(recovery_paper),
                "--key", carol["private_key"],
                "--recovery-key", guardian["private_key"],
                "--out", str(recovered), "--json",
            )
            self.assertEqual(recovery_result.returncode, 0, recovery_result.stderr or recovery_result.stdout)

            compared = run("compare-successors", str(online), str(recovered), "--json")
            self.assertEqual(compared.returncode, 0, compared.stderr or compared.stdout)
            report = json.loads(compared.stdout)
            self.assertEqual(report["message"], "LINEAGE_EQUIVOCATION_DETECTED")
            self.assertTrue(report["data"]["conflict"])
            self.assertIsNone(report["data"]["winner"])


if __name__ == "__main__":
    unittest.main()
