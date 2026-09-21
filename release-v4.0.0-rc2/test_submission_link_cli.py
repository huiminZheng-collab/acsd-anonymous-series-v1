import json
import pathlib
import subprocess
import sys
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parent
ACSD = ROOT / "acsd.py"


def run(*args):
    return subprocess.run(
        [sys.executable, str(ACSD), *args],
        capture_output=True, text=True, encoding="utf-8", errors="replace",
    )


class TestSubmissionLinkCLI(unittest.TestCase):
    def test_exact_multiauthor_submission_link_flow(self):
        with tempfile.TemporaryDirectory() as raw:
            tmp = pathlib.Path(raw)
            keys = tmp / "keys"
            alice = json.loads(run(
                "keygen", "--name", "alice", "--out-dir", str(keys), "--json"
            ).stdout)["data"]
            bob = json.loads(run(
                "keygen", "--name", "bob", "--out-dir", str(keys), "--json"
            ).stdout)["data"]
            venue = json.loads(run(
                "keygen", "--name", "venue", "--out-dir", str(keys), "--json"
            ).stdout)["data"]
            team = {
                "schema": "acsd-team/v1",
                "authors": [
                    {"key_id": alice["key_id"], "public_key": alice["public_key"], "role": "first", "corresponding": True},
                    {"key_id": bob["key_id"], "public_key": bob["public_key"], "role": "second"},
                ],
            }
            team_path = tmp / "team.json"
            team_path.write_text(json.dumps(team), encoding="utf-8")
            anonymous = tmp / "anonymous.txt"
            anonymous.write_text("anonymous release", encoding="utf-8")
            release = tmp / "release"
            self.assertEqual(run(
                "init", str(anonymous), "--team", str(team_path), "--out", str(release)
            ).returncode, 0)
            self.assertEqual(run("approve", str(release), "--key", alice["private_key"]).returncode, 0)
            self.assertEqual(run("approve", str(release), "--key", bob["private_key"]).returncode, 0)
            self.assertEqual(run("finalize", str(release)).returncode, 0)

            submitted = tmp / "named.txt"
            submitted.write_text("named submission bytes", encoding="utf-8")
            challenge_dir = tmp / "challenge"
            created = run(
                "create-submission-challenge", str(release), str(submitted),
                "--venue-key", venue["private_key"],
                "--venue-domain", "journal.example",
                "--submission-handle", "SUB-42", "--round", "1",
                "--expires-at", "2099-01-01T00:00:00+00:00",
                "--byline", "1:Alice Example:https://orcid.org/0000-0000-0000-0001",
                "--byline", "2:Bob Example", "--out", str(challenge_dir), "--json",
            )
            self.assertEqual(created.returncode, 0, created.stdout + created.stderr)
            challenge_data = json.loads(created.stdout)["data"]
            openings = []
            for key in (alice, bob):
                out = tmp / ("opening-" + key["key_id"][:8])
                response = run(
                    "respond-submission-challenge", str(release), str(submitted),
                    "--challenge", challenge_data["challenge"],
                    "--venue-signature", challenge_data["signature"],
                    "--venue-public-key", str(keys / "venue.pub"),
                    "--submission-handle", "SUB-42", "--key", key["private_key"],
                    "--out", str(out), "--json",
                )
                self.assertEqual(response.returncode, 0, response.stdout + response.stderr)
                openings.append(json.loads(response.stdout)["data"])

            verified = run(
                "verify-submission-link", str(release), str(submitted),
                "--challenge", challenge_data["challenge"],
                "--venue-signature", challenge_data["signature"],
                "--venue-public-key", str(keys / "venue.pub"),
                "--submission-handle", "SUB-42",
                "--opening", openings[0]["opening"], "--opening", openings[1]["opening"],
                "--signature", openings[0]["signature"], "--signature", openings[1]["signature"],
                "--require-full-byline", "--json",
            )
            self.assertEqual(verified.returncode, 0, verified.stdout + verified.stderr)
            result = json.loads(verified.stdout)["data"]
            self.assertEqual(result["claim"], "SUBMISSION_LINEAGE_LINKED")
            self.assertEqual(result["status"], "FULL_BYLINE_SUBMISSION_LINEAGE_LINKED")

            swapped = tmp / "swapped.txt"
            swapped.write_text("different submitted bytes", encoding="utf-8")
            rejected = run(
                "verify-submission-link", str(release), str(swapped),
                "--challenge", challenge_data["challenge"],
                "--venue-signature", challenge_data["signature"],
                "--venue-public-key", str(keys / "venue.pub"),
                "--submission-handle", "SUB-42",
                "--opening", openings[0]["opening"], "--signature", openings[0]["signature"],
                "--json",
            )
            self.assertEqual(rejected.returncode, 1, rejected.stdout + rejected.stderr)
            self.assertEqual(
                json.loads(rejected.stdout)["message"], "SUBMITTED_MANUSCRIPT_MISMATCH"
            )


if __name__ == "__main__":
    unittest.main()
