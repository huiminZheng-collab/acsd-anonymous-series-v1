import json
import pathlib
import subprocess
import sys
import tempfile
import unittest

import approval_exchange
from package_manifest import build_manifest_text


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


class TestApprovalExchange(unittest.TestCase):
    def _candidate(self, root, *, delegated=False):
        keys = root / "keys"
        alice = keygen(keys, "alice")
        bob = keygen(keys, "bob")
        paper = root / "paper.txt"
        paper.write_text("Portable exact approval request.\n", encoding="utf-8")
        release = root / "release"
        args = [
            "init", str(paper),
            "--public-key", str(keys / "alice.pub"),
            "--public-key", str(keys / "bob.pub"),
            "--out", str(release),
        ]
        if delegated:
            args.append("--allow-delegated-approval")
        result = run(*args)
        self.assertEqual(result.returncode, 0, result.stdout)
        return alice, bob, release

    def test_pure_exchange_objects_reject_mode_confusion(self):
        request = approval_exchange.build_request(
            "a" * 64, "urn:uuid:test", "b" * 64, "c" * 64
        )
        response = approval_exchange.build_response(request, "direct", "a" * 64)
        self.assertEqual(approval_exchange.validate_response(response), response)
        response["signer_key_id"] = "d" * 64
        with self.assertRaisesRegex(
            ValueError, "APPROVAL_RESPONSE_DIRECT_SIGNER_MISMATCH"
        ):
            approval_exchange.validate_response(response)

    def test_remote_direct_approval_round_trip_and_replay_rejection(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            alice, bob, release = self._candidate(root)
            request = root / "alice-request"
            response = root / "alice-response"
            # A stray private file in the mutable workspace is not part of the
            # allowlisted author-review snapshot.
            (release / "accidental.key").write_bytes(
                pathlib.Path(alice["private_key"]).read_bytes()
            )
            exported = run(
                "export-approval-request", str(release),
                "--for-author", alice["key_id"], "--out", str(request), "--json",
            )
            self.assertEqual(exported.returncode, 0, exported.stdout)
            self.assertFalse(any(request.rglob("*.key")))
            responded = run(
                "respond-approval-request", str(request),
                "--key", alice["private_key"], "--out", str(response),
                "--yes", "--json",
            )
            self.assertEqual(responded.returncode, 0, responded.stdout)
            self.assertEqual(
                {path.name for path in response.iterdir()},
                {"response.json", "approval.cose", "MANIFEST.sha256"},
            )
            imported = run(
                "import-approval-response", str(release), str(response), "--json"
            )
            self.assertEqual(imported.returncode, 0, imported.stdout)
            data = json.loads(imported.stdout)["data"]
            self.assertEqual(data["mode"], "direct")
            self.assertEqual(data["remaining"], [bob["key_id"]])
            replay = run(
                "import-approval-response", str(release), str(response), "--json"
            )
            self.assertEqual(replay.returncode, 3, replay.stdout)
            self.assertEqual(
                json.loads(replay.stdout)["message"],
                "AUTHOR_ACTION_ALREADY_RECORDED",
            )

    def test_tampered_request_and_wrong_author_fail_before_response(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            alice, bob, release = self._candidate(root)
            request = root / "alice-request"
            self.assertEqual(run(
                "export-approval-request", str(release),
                "--for-author", alice["key_id"], "--out", str(request),
            ).returncode, 0)
            wrong_out = root / "wrong-response"
            wrong = run(
                "respond-approval-request", str(request),
                "--key", bob["private_key"], "--out", str(wrong_out),
                "--yes", "--json",
            )
            self.assertNotEqual(wrong.returncode, 0)
            self.assertFalse(wrong_out.exists())
            paper = next((request / "candidate/paper").iterdir())
            paper.write_bytes(paper.read_bytes() + b"tamper")
            tampered_out = root / "tampered-response"
            tampered = run(
                "respond-approval-request", str(request),
                "--key", alice["private_key"], "--out", str(tampered_out),
                "--yes", "--json",
            )
            self.assertEqual(tampered.returncode, 1)
            self.assertTrue(
                json.loads(tampered.stdout)["message"].startswith(
                    "MANIFEST_HASH_MISMATCH:"
                )
            )
            self.assertFalse(tampered_out.exists())
            (request / "MANIFEST.sha256").write_bytes(
                build_manifest_text(request).encode("ascii")
            )
            coherently_repacked = run(
                "respond-approval-request", str(request),
                "--key", alice["private_key"], "--out", str(tampered_out),
                "--yes", "--json",
            )
            self.assertEqual(coherently_repacked.returncode, 1)
            self.assertEqual(
                json.loads(coherently_repacked.stdout)["message"],
                "APPROVAL_REQUEST_CANDIDATE_INVALID",
            )
            self.assertFalse(tampered_out.exists())

    def test_repacked_response_still_requires_valid_exact_signature(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            alice, _, release = self._candidate(root)
            request = root / "request"
            response = root / "response"
            self.assertEqual(run(
                "export-approval-request", str(release),
                "--for-author", alice["key_id"], "--out", str(request),
            ).returncode, 0)
            self.assertEqual(run(
                "respond-approval-request", str(request),
                "--key", alice["private_key"], "--out", str(response),
                "--yes",
            ).returncode, 0)
            approval = response / "approval.cose"
            raw = bytearray(approval.read_bytes())
            raw[-1] ^= 1
            approval.write_bytes(bytes(raw))
            (response / "MANIFEST.sha256").write_bytes(
                build_manifest_text(response).encode("ascii")
            )
            imported = run(
                "import-approval-response", str(release), str(response), "--json"
            )
            self.assertNotEqual(imported.returncode, 0)
            self.assertFalse(
                (release / f"approvals/{alice['key_id']}.cose").exists()
            )

    def test_remote_exact_delegation_round_trip(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            alice, bob, release = self._candidate(root, delegated=True)
            delegate = keygen(root / "keys", "coordinator-agent")
            request = root / "bob-request"
            response = root / "bob-response"
            self.assertEqual(run(
                "export-approval-request", str(release),
                "--for-author", bob["key_id"], "--out", str(request),
            ).returncode, 0)
            responded = run(
                "respond-approval-request", str(request),
                "--key", bob["private_key"], "--out", str(response),
                "--delegate-public-key", str(root / "keys/coordinator-agent.pub"),
                "--yes", "--json",
            )
            self.assertEqual(responded.returncode, 0, responded.stdout)
            self.assertEqual(run(
                "import-approval-response", str(release), str(response)
            ).returncode, 0)
            self.assertEqual(run(
                "approve", str(release), "--key", alice["private_key"]
            ).returncode, 0)
            self.assertEqual(run(
                "approve-as", str(release), "--key", delegate["private_key"],
                "--for-author", bob["key_id"],
            ).returncode, 0)
            self.assertEqual(run("finalize", str(release)).returncode, 0)
            verified = run("verify", str(release), "--json")
            self.assertEqual(verified.returncode, 0, verified.stdout)
            modes = json.loads(verified.stdout)["data"]["approval_modes"]
            self.assertEqual(modes[bob["key_id"]]["mode"], "delegated")

    def _batch_responses(self, root, release, authors, name):
        requests = root / f"{name}-requests"
        responses = root / f"{name}-responses"
        responses.mkdir()
        exported = run(
            "export-approval-requests", str(release), "--out", str(requests),
            "--json",
        )
        self.assertEqual(exported.returncode, 0, exported.stdout)
        request_entries = json.loads(exported.stdout)["data"]["requests"]
        by_key = {author["key_id"]: author for author in authors}
        for entry in request_entries:
            response = responses / entry["path"]
            result = run(
                "respond-approval-request", str(requests / entry["path"]),
                "--key", by_key[entry["author_key_id"]]["private_key"],
                "--out", str(response), "--yes", "--json",
            )
            self.assertEqual(result.returncode, 0, result.stdout)
        return responses

    def test_batch_import_is_all_or_nothing(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            alice, bob, release = self._candidate(root)
            responses = self._batch_responses(
                root, release, [alice, bob], "bad-batch"
            )
            bob_response = next(
                child for child in responses.iterdir()
                if bob["key_id"] in child.name
            )
            approval = bob_response / "approval.cose"
            damaged = bytearray(approval.read_bytes())
            damaged[-1] ^= 1
            approval.write_bytes(bytes(damaged))
            (bob_response / "MANIFEST.sha256").write_bytes(
                build_manifest_text(bob_response).encode("ascii")
            )
            result = run(
                "import-approval-responses", str(release),
                "--from-dir", str(responses), "--json",
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertTrue(json.loads(result.stdout)["data"]["original_unchanged"])
            self.assertEqual(
                list((release / "approvals").glob("*.cose")), []
            )

            good_responses = self._batch_responses(
                root, release, [alice, bob], "good-batch"
            )
            imported = run(
                "import-approval-responses", str(release),
                "--from-dir", str(good_responses), "--json",
            )
            self.assertEqual(imported.returncode, 0, imported.stdout)
            data = json.loads(imported.stdout)["data"]
            self.assertEqual(data["remaining"], [])
            self.assertEqual(len(data["imported"]), 2)

    def test_coordinator_finalize_requires_explicit_time_policy(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            alice, bob, release = self._candidate(root)
            responses = self._batch_responses(
                root, release, [alice, bob], "finish"
            )
            refused = run(
                "coordinator-finalize", str(release),
                "--responses-dir", str(responses), "--json",
            )
            self.assertEqual(refused.returncode, 2, refused.stdout)
            self.assertEqual(
                json.loads(refused.stdout)["message"],
                "TSA_OR_EXPLICIT_UNTIMESTAMPED_REQUIRED",
            )
            self.assertEqual(
                json.loads((release / "state.json").read_text(encoding="utf-8"))["state"],
                "awaiting-approvals",
            )
            finished = run(
                "coordinator-finalize", str(release),
                "--responses-dir", str(responses), "--allow-untimestamped", "--json",
            )
            self.assertEqual(finished.returncode, 0, finished.stdout)
            data = json.loads(finished.stdout)["data"]
            self.assertEqual(data["time_policy"], "explicit-untimestamped")
            self.assertEqual(len(data["imported"]), 2)
            verified = run("verify", str(release), "--json")
            self.assertEqual(verified.returncode, 0, verified.stdout)

    def test_approve_delegations_discovers_all_matching_slots_atomically(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            alice, bob, release = self._candidate(root, delegated=True)
            delegate = keygen(root / "keys", "agent")
            requests = root / "requests"
            responses = root / "responses"
            responses.mkdir()
            exported = run(
                "export-approval-requests", str(release), "--out", str(requests),
                "--json",
            )
            entries = json.loads(exported.stdout)["data"]["requests"]
            by_key = {alice["key_id"]: alice, bob["key_id"]: bob}
            for entry in entries:
                result = run(
                    "respond-approval-request", str(requests / entry["path"]),
                    "--key", by_key[entry["author_key_id"]]["private_key"],
                    "--delegate-public-key", str(root / "keys/agent.pub"),
                    "--out", str(responses / entry["path"]), "--yes", "--json",
                )
                self.assertEqual(result.returncode, 0, result.stdout)
            imported = run(
                "import-approval-responses", str(release),
                "--from-dir", str(responses), "--json",
            )
            self.assertEqual(imported.returncode, 0, imported.stdout)
            exercised = run(
                "approve-delegations", str(release),
                "--key", delegate["private_key"], "--json",
            )
            self.assertEqual(
                exercised.returncode, 0, exercised.stdout + exercised.stderr
            )
            self.assertEqual(json.loads(exercised.stdout)["data"]["count"], 2)
            inspected = run("inspect", str(release), "--json")
            self.assertEqual(
                json.loads(inspected.stdout)["data"]["missing_approvals"], []
            )

    def test_coordinator_finalize_imports_and_exercises_delegation_in_one_transaction(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            alice, bob, release = self._candidate(root, delegated=True)
            delegate = keygen(root / "keys", "coordinator-agent")
            requests = root / "requests"
            responses = root / "responses"
            responses.mkdir()
            exported = run(
                "export-approval-requests", str(release), "--out", str(requests),
                "--json",
            )
            entries = json.loads(exported.stdout)["data"]["requests"]
            by_key = {alice["key_id"]: alice, bob["key_id"]: bob}
            for entry in entries:
                args = [
                    "respond-approval-request", str(requests / entry["path"]),
                    "--key", by_key[entry["author_key_id"]]["private_key"],
                    "--out", str(responses / entry["path"]), "--yes", "--json",
                ]
                if entry["author_key_id"] == bob["key_id"]:
                    args.extend([
                        "--delegate-public-key", str(root / "keys/coordinator-agent.pub")
                    ])
                response = run(*args)
                self.assertEqual(response.returncode, 0, response.stdout)
            finalized = run(
                "coordinator-finalize", str(release),
                "--responses-dir", str(responses),
                "--delegate-key", delegate["private_key"],
                "--allow-untimestamped", "--json",
            )
            self.assertEqual(
                finalized.returncode, 0, finalized.stdout + finalized.stderr
            )
            data = json.loads(finalized.stdout)["data"]
            self.assertEqual(len(data["imported"]), 2)
            self.assertEqual(len(data["delegated_approvals_exercised"]), 1)
            self.assertEqual(run("verify", str(release)).returncode, 0)

    def test_wrong_delegate_key_does_not_mutate_live_candidate(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            alice, _, release = self._candidate(root, delegated=True)
            delegate = keygen(root / "keys", "agent")
            wrong = keygen(root / "keys", "wrong-agent")
            request = root / "request"
            response = root / "response"
            self.assertEqual(run(
                "export-approval-request", str(release),
                "--for-author", alice["key_id"], "--out", str(request),
            ).returncode, 0)
            self.assertEqual(run(
                "respond-approval-request", str(request),
                "--key", alice["private_key"],
                "--delegate-public-key", str(root / "keys/agent.pub"),
                "--out", str(response), "--yes",
            ).returncode, 0)
            self.assertEqual(run(
                "import-approval-response", str(release), str(response)
            ).returncode, 0)
            failed = run(
                "approve-delegations", str(release),
                "--key", wrong["private_key"], "--json",
            )
            self.assertNotEqual(failed.returncode, 0)
            self.assertFalse(any((release / "delegated-approvals").glob("*.cose")))
            self.assertTrue((release / f"delegations/{alice['key_id']}.json").is_file())
            self.assertNotEqual(delegate["key_id"], wrong["key_id"])


if __name__ == "__main__":
    unittest.main()
