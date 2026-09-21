import json
import pathlib
import subprocess
import sys
import tempfile
import unittest

import linkability_audit


ROOT = pathlib.Path(__file__).resolve().parent
ACSD = ROOT / "acsd.py"


def model_release(work_id, key_id, version=1, line="main"):
    return {
        "schema": "acsd-v3-paper-release/v1",
        "work_id": work_id,
        "slot": {"work_id": work_id, "line": line, "version": version},
        "content": {"path": "paper/example.txt", "sha256": "f" * 64},
        "authors": [{"slot": 1, "key_id": key_id}],
    }


def run(*args):
    return subprocess.run(
        [sys.executable, str(ACSD), *map(str, args), "--json"],
        cwd=ROOT,
        capture_output=True,
        text=True,
    )


class TestLinkabilityAudit(unittest.TestCase):
    def test_cross_work_reuse_is_reported(self):
        key = "a" * 64
        result = linkability_audit.audit_releases([
            model_release("urn:uuid:00000000-0000-4000-8000-000000000001", key),
            model_release("urn:uuid:00000000-0000-4000-8000-000000000002", key),
        ])
        self.assertEqual(result["status"], "CROSS_WORK_KEY_REUSE_DETECTED")
        self.assertEqual(len(result["cross_work_reuse_groups"]), 1)
        self.assertEqual(result["same_work_reuse_groups"], [])
        self.assertIn("natural_person_identity_verified", result["non_claims"])

    def test_same_work_reuse_is_not_a_cross_work_warning(self):
        key = "b" * 64
        work = "urn:uuid:00000000-0000-4000-8000-000000000003"
        result = linkability_audit.audit_releases([
            model_release(work, key, version=1),
            model_release(work, key, version=2),
        ])
        self.assertEqual(result["status"], "NO_CROSS_WORK_KEY_REUSE")
        self.assertEqual(result["cross_work_reuse_groups"], [])
        self.assertEqual(len(result["same_work_reuse_groups"]), 1)

    def test_independent_keys_have_no_equality_group(self):
        result = linkability_audit.audit_releases([
            model_release("urn:uuid:00000000-0000-4000-8000-000000000004", "c" * 64),
            model_release("urn:uuid:00000000-0000-4000-8000-000000000005", "d" * 64),
        ])
        self.assertEqual(result["status"], "NO_CROSS_WORK_KEY_REUSE")
        self.assertEqual(result["cross_work_reuse_groups"], [])
        self.assertEqual(result["same_work_reuse_groups"], [])

    def test_duplicate_release_input_is_rejected(self):
        release = model_release(
            "urn:uuid:00000000-0000-4000-8000-000000000006", "e" * 64
        )
        with self.assertRaisesRegex(ValueError, "DUPLICATE_RELEASE_INPUT"):
            linkability_audit.audit_releases([release, release])

    def test_cli_audits_only_verified_releases_and_can_fail_closed(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            keys = root / "keys"
            reused = json.loads(run(
                "keygen", "--name", "reused", "--out-dir", keys
            ).stdout)["data"]
            independent = json.loads(run(
                "keygen", "--name", "independent", "--out-dir", keys
            ).stdout)["data"]

            releases = []
            for name, private_key in (
                ("a", reused["private_key"]),
                ("b", reused["private_key"]),
                ("c", independent["private_key"]),
            ):
                manuscript = root / f"{name}.txt"
                manuscript.write_text(f"paper {name}\n", encoding="utf-8")
                release = root / f"release-{name}"
                created = run(
                    "release", manuscript, "--key", private_key,
                    "--out", release,
                )
                self.assertEqual(created.returncode, 0, created.stderr)
                releases.append(release)

            audit = run("audit-key-reuse", releases[0], releases[1])
            self.assertEqual(audit.returncode, 0, audit.stderr)
            payload = json.loads(audit.stdout)
            self.assertEqual(payload["message"], "CROSS_WORK_KEY_REUSE_DETECTED")
            self.assertEqual(len(payload["data"]["cross_work_reuse_groups"]), 1)

            strict = run(
                "audit-key-reuse", releases[0], releases[1],
                "--fail-on-cross-work",
            )
            self.assertEqual(strict.returncode, 1, strict.stderr)
            self.assertEqual(
                json.loads(strict.stdout)["message"],
                "CROSS_WORK_KEY_REUSE_DETECTED",
            )

            independent_audit = run(
                "audit-key-reuse", releases[0], releases[2]
            )
            self.assertEqual(independent_audit.returncode, 0, independent_audit.stderr)
            self.assertEqual(
                json.loads(independent_audit.stdout)["message"],
                "NO_CROSS_WORK_KEY_REUSE",
            )

            release_c = json.loads(
                (releases[2] / "release" / "release.json").read_text(
                    encoding="utf-8"
                )
            )
            content_c = releases[2] / release_c["content"]["path"]
            content_c.write_bytes(content_c.read_bytes() + b"tampered")
            rejected = run("audit-key-reuse", releases[0], releases[2])
            self.assertEqual(rejected.returncode, 1, rejected.stderr)
            rejected_payload = json.loads(rejected.stdout)
            self.assertEqual(rejected_payload["message"], "RELEASE_NOT_ACCEPTED")
            self.assertEqual(rejected_payload["data"]["release_index"], 2)


if __name__ == "__main__":
    unittest.main()
