import json
import pathlib
import subprocess
import sys
import tempfile
import unittest

import appraisal_transcript
import claim_derivation

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
            verified = json.loads(r.stdout)
            self.assertEqual(verified["message"], "VALID")
            self.assertEqual(
                verified["data"]["granted_outcomes"],
                ["KEY_ASSENT", "GOVERNANCE_ASSENT"],
            )
            self.assertNotIn("appraisal_transcript", verified["data"])
            r = run(
                "verify", str(rel), "--emit-appraisal-transcript", "--json"
            )
            self.assertEqual(r.returncode, 0, r.stderr)
            transcript_data = json.loads(r.stdout)["data"]
            transcript = transcript_data["appraisal_transcript"]
            self.assertEqual(transcript["schema"], appraisal_transcript.SCHEMA)
            self.assertEqual(
                list(claim_derivation.wire_outcomes(
                    appraisal_transcript.derive(transcript)
                )),
                transcript_data["granted_outcomes"],
            )
            # tamper content -> TAMPERED
            p = next((rel / "paper").iterdir())
            p.write_bytes(p.read_bytes() + b"X")
            r = run("verify", str(rel), "--json")
            self.assertEqual(r.returncode, 1)
            self.assertTrue(
                json.loads(r.stdout)["data"]["error_code"].startswith("MANIFEST_HASH_MISMATCH:paper/")
            )

    def test_unknown_key_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            alice, bob, rel = self._setup(d)
            keys = pathlib.Path(d) / "keys"
            mallory = json.loads(run("keygen", "--name", "mallory", "--out-dir", str(keys), "--json").stdout)["data"]
            r = run("approve", str(rel), "--key", mallory["private_key"], "--json")
            self.assertEqual(r.returncode, 1)
            self.assertEqual(json.loads(r.stdout)["message"], "UNKNOWN_AUTHOR_KEY")

    def test_public_key_substitution_is_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            alice, bob, rel = self._setup(d)
            keys = pathlib.Path(d) / "keys"
            mallory = json.loads(run("keygen", "--name", "mallory", "--out-dir", str(keys), "--json").stdout)["data"]
            # Keep Alice's declared key id and path, but replace the bytes.
            (rel / f"public-keys/{alice['key_id']}.pub").write_text(
                mallory["public_key"], encoding="ascii"
            )
            r = run("verify", str(rel), "--json")
            self.assertEqual(r.returncode, 1)
            self.assertEqual(json.loads(r.stdout)["data"]["error_code"], "PUBLIC_KEY_ID_MISMATCH")

    def test_coherent_claim_object_replacement_cannot_reuse_approvals(self):
        from acsd import build_approval_target, write_canonical
        from pec_core import digest
        with tempfile.TemporaryDirectory() as d:
            alice, bob, rel = self._setup(d)
            run("approve", str(rel), "--key", alice["private_key"])
            run("approve", str(rel), "--key", bob["private_key"])

            release = json.loads((rel / "release/release.json").read_text(encoding="utf-8"))
            governance_path = rel / "governance/statement.json"
            pec_path = rel / "pec/pec.json"
            target_path = rel / "approval/target.json"
            governance = json.loads(governance_path.read_text(encoding="utf-8"))
            pec = json.loads(pec_path.read_text(encoding="utf-8"))
            governance["editorial_note"] = "attacker replacement"
            pec["governance"]["statement_digest"] = digest(governance)
            write_canonical(governance_path, governance)
            write_canonical(pec_path, pec)

            # Old target detects the coherent governance+PEC replacement.
            r = run("verify", str(rel), "--json")
            self.assertEqual(r.returncode, 1)
            self.assertEqual(
                json.loads(r.stdout)["data"]["error_code"],
                "APPROVAL_TARGET_BINDING_MISMATCH",
            )

            # Recomputing the unsigned target still cannot reuse old approvals.
            write_canonical(target_path, build_approval_target(release, governance, pec))
            r = run("verify", str(rel), "--json")
            self.assertEqual(r.returncode, 1)
            self.assertEqual(
                json.loads(r.stdout)["data"]["error_code"],
                "COSE_PAYLOAD_MISMATCH",
            )

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

    def test_private_key_inside_release_is_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            alice, bob, rel = self._setup(d)
            copied_key = rel / "leaked.key"
            copied_key.write_bytes(pathlib.Path(alice["private_key"]).read_bytes())
            r = run("approve", str(rel), "--key", str(copied_key), "--json")
            self.assertEqual(r.returncode, 2)
            self.assertEqual(json.loads(r.stdout)["message"], "PRIVATE_KEY_INSIDE_RELEASE")

    def test_private_key_directory_is_reported_as_usage_error(self):
        with tempfile.TemporaryDirectory() as d:
            alice, bob, rel = self._setup(d)
            key_directory = pathlib.Path(alice["private_key"]).parent
            r = run("approve", str(rel), "--key", str(key_directory), "--json")
            self.assertEqual(r.returncode, 2)
            self.assertEqual(json.loads(r.stdout)["message"], "PRIVATE_KEY_INVALID")

            paper = pathlib.Path(d) / "another-paper.txt"
            paper.write_text("Invalid key input.", encoding="utf-8")
            r = run(
                "release", str(paper), "--key", str(key_directory),
                "--out", str(pathlib.Path(d) / "another-release"), "--json",
            )
            self.assertEqual(r.returncode, 2)
            self.assertEqual(json.loads(r.stdout)["message"], "PRIVATE_KEY_INVALID")

    def test_one_command_multi_author_release(self):
        with tempfile.TemporaryDirectory() as d:
            d = pathlib.Path(d)
            keys = d / "keys"
            alice = json.loads(run("keygen", "--name", "alice", "--out-dir", str(keys), "--json").stdout)["data"]
            bob = json.loads(run("keygen", "--name", "bob", "--out-dir", str(keys), "--json").stdout)["data"]
            paper = d / "paper.txt"
            paper.write_text("One-command ACSD release.", encoding="utf-8")
            rel = d / "release-dir"
            r = run(
                "release", str(paper), "--out", str(rel),
                "--key", alice["private_key"], "--key", bob["private_key"],
                "--json",
            )
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertEqual(json.loads(r.stdout)["data"]["author_key_ids"], [alice["key_id"], bob["key_id"]])
            verified = run("verify", str(rel), "--json")
            self.assertEqual(verified.returncode, 0, verified.stderr)
            self.assertEqual(
                json.loads(verified.stdout)["data"]["granted_outcomes"],
                ["KEY_ASSENT", "GOVERNANCE_ASSENT"],
            )

    def test_finalize_is_not_an_in_place_rewrite(self):
        with tempfile.TemporaryDirectory() as d:
            alice, bob, rel = self._setup(d)
            run("approve", str(rel), "--key", alice["private_key"])
            run("approve", str(rel), "--key", bob["private_key"])
            self.assertEqual(run("finalize", str(rel)).returncode, 0)
            r = run("finalize", str(rel), "--json")
            self.assertEqual(r.returncode, 3)
            self.assertEqual(json.loads(r.stdout)["message"], "STATE_CONFLICT")

    def test_selective_identity_disclosure_is_external_and_verifiable(self):
        with tempfile.TemporaryDirectory() as d:
            alice, bob, rel = self._setup(d)
            run("approve", str(rel), "--key", alice["private_key"])
            run("approve", str(rel), "--key", bob["private_key"])
            self.assertEqual(run("finalize", str(rel)).returncode, 0)
            manifest_before = (rel / "MANIFEST.sha256").read_bytes()
            sidecars = pathlib.Path(d) / "identity-sidecars"
            r = run(
                "disclose-identity", str(rel),
                "--key", alice["private_key"],
                "--display-name", "Alice Example",
                "--persistent-identifier", "https://orcid.org/0000-0000-0000-0001",
                "--publication-ref", "doi:10.0000/example",
                "--out", str(sidecars), "--json",
            )
            self.assertEqual(r.returncode, 0, r.stderr)
            created = json.loads(r.stdout)["data"]
            self.assertEqual((rel / "MANIFEST.sha256").read_bytes(), manifest_before)
            r = run(
                "verify-identity", str(rel),
                "--disclosure", created["disclosure"],
                "--signature", created["signature"], "--json",
            )
            self.assertEqual(r.returncode, 0, r.stderr)
            verified = json.loads(r.stdout)["data"]
            self.assertEqual(
                verified["status"], "SLOT_KEY_ASSENT_TO_IDENTITY_ASSERTION"
            )
            self.assertIn("natural_person_identity_verified", verified["non_claims"])

            inside = rel / "identity-sidecars"
            r = run(
                "disclose-identity", str(rel),
                "--key", alice["private_key"],
                "--display-name", "Alice Example", "--out", str(inside), "--json",
            )
            self.assertEqual(r.returncode, 2)
            self.assertEqual(json.loads(r.stdout)["message"], "DISCLOSURE_OUTPUT_INSIDE_RELEASE")

    def test_partial_and_full_identity_sets_have_distinct_cli_results(self):
        with tempfile.TemporaryDirectory() as d:
            alice, bob, rel = self._setup(d)
            run("approve", str(rel), "--key", alice["private_key"])
            run("approve", str(rel), "--key", bob["private_key"])
            self.assertEqual(run("finalize", str(rel)).returncode, 0)
            sidecars = pathlib.Path(d) / "identity-set"
            created = []
            for key, name in ((alice, "Alice Example"), (bob, "Bob Example")):
                result = run(
                    "disclose-identity", str(rel),
                    "--key", key["private_key"],
                    "--display-name", name,
                    "--publication-ref", "doi:10.0000/example",
                    "--out", str(sidecars), "--json",
                )
                self.assertEqual(result.returncode, 0, result.stderr)
                created.append(json.loads(result.stdout)["data"])

            partial = run(
                "verify-identity-set", str(rel),
                "--disclosure", created[0]["disclosure"],
                "--signature", created[0]["signature"], "--json",
            )
            self.assertEqual(partial.returncode, 0, partial.stderr)
            self.assertEqual(
                json.loads(partial.stdout)["message"],
                "PARTIAL_BYLINE_KEY_ASSENT",
            )
            required = run(
                "verify-identity-set", str(rel),
                "--disclosure", created[0]["disclosure"],
                "--signature", created[0]["signature"],
                "--require-full-byline", "--json",
            )
            self.assertEqual(required.returncode, 5, required.stderr)

            full = run(
                "verify-identity-set", str(rel),
                "--disclosure", created[0]["disclosure"],
                "--disclosure", created[1]["disclosure"],
                "--signature", created[0]["signature"],
                "--signature", created[1]["signature"],
                "--require-full-byline", "--json",
            )
            self.assertEqual(full.returncode, 0, full.stderr)
            full_data = json.loads(full.stdout)["data"]
            self.assertEqual(full_data["status"], "FULL_BYLINE_KEY_ASSENT")
            self.assertEqual(full_data["disclosed_slots"], [1, 2])
            self.assertEqual(
                full_data["shared_publication_ref"], "doi:10.0000/example"
            )
            self.assertIn("natural_person_identity_verified", full_data["non_claims"])

            duplicate = run(
                "verify-identity-set", str(rel),
                "--disclosure", created[0]["disclosure"],
                "--disclosure", created[0]["disclosure"],
                "--signature", created[0]["signature"],
                "--signature", created[0]["signature"], "--json",
            )
            self.assertEqual(duplicate.returncode, 1, duplicate.stderr)
            self.assertEqual(
                json.loads(duplicate.stdout)["message"],
                "VERIFIED_IDENTITY_SLOT_EQUIVOCATION",
            )

            mismatch = run(
                "verify-identity-set", str(rel),
                "--disclosure", created[0]["disclosure"],
                "--disclosure", created[1]["disclosure"],
                "--signature", created[0]["signature"], "--json",
            )
            self.assertEqual(mismatch.returncode, 2, mismatch.stderr)
            self.assertEqual(
                json.loads(mismatch.stdout)["message"],
                "IDENTITY_SIDECAR_COUNT_MISMATCH",
            )

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
            self.assertNotIn("EXTERNALLY_NOT_AFTER", data["granted_outcomes"])
            self.assertEqual(data["timestamp_status"], "PRESENT_UNVERIFIED_NO_EXTERNAL_TRUST")

            r = run("verify", str(rel), "--allow-local-test-tsa", "--json")
            self.assertEqual(r.returncode, 0, r.stderr)
            data = json.loads(r.stdout)["data"]
            self.assertEqual(data["timestamp_status"], "LOCAL_TEST_VERIFIED")
            self.assertIn("timestamp_gen_time", data)
            self.assertNotIn("EXTERNALLY_NOT_AFTER", data["granted_outcomes"])

            r = run("verify", str(rel), "--require-external-time", "--json")
            self.assertEqual(r.returncode, 5)
            self.assertEqual(json.loads(r.stdout)["message"], "EXTERNAL_TIME_UNVERIFIED")

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
            self.assertNotIn("externally_not_after", json.loads(r.stdout)["data"])

    def test_forged_tsr_rejected_by_pinned_cert(self):
        import sys as _sys
        _sys.path.insert(0, str(ROOT))
        import tsa as tsa_mod
        from acsd import manifest_entries
        with tempfile.TemporaryDirectory() as d:
            alice, bob, rel = self._setup(d)
            run("approve", str(rel), "--key", alice["private_key"])
            run("approve", str(rel), "--key", bob["private_key"])
            self.assertEqual(run("finalize", str(rel), "--tsa", "local").returncode, 0)
            trusted_cert = pathlib.Path(d) / "trusted-tsa.der"
            trusted_cert.write_bytes((rel / "receipts/tsa-cert.der").read_bytes())
            inside = run(
                "verify", str(rel),
                "--tsa-trust-cert", str(rel / "receipts/tsa-cert.der"),
                "--json",
            )
            self.assertEqual(inside.returncode, 2)
            self.assertEqual(
                json.loads(inside.stdout)["message"], "TSA_TRUST_MUST_BE_EXTERNAL"
            )
            # forge a response from a different TSA (different cert fingerprint)
            fake = tsa_mod.LocalTSA()
            fake_tsr = fake.respond((rel / "receipts/request.tsq").read_bytes())
            (rel / "receipts/response.tsr").write_bytes(fake_tsr)
            # Recompute the unsigned transport manifest to ensure the rejection
            # comes from the external signer pin, not only package checksums.
            (rel / "MANIFEST.sha256").write_text(manifest_entries(rel), encoding="ascii")
            r = run(
                "verify", str(rel),
                "--tsa-trust-cert", str(trusted_cert),
                "--json",
            )
            self.assertEqual(r.returncode, 1)
            self.assertIn(
                json.loads(r.stdout)["data"]["error_code"],
                {"TSR_EMBEDDED_CERT_MISMATCH", "TSR_SIGNATURE_INVALID"},
            )

    def test_tampered_policy_and_events_rejected(self):
        from pec_core import canonical
        with tempfile.TemporaryDirectory() as d:
            alice, bob, rel = self._setup(d)
            run("approve", str(rel), "--key", alice["private_key"])
            run("approve", str(rel), "--key", bob["private_key"])
            pec_path = rel / "pec/pec.json"
            # tamper 1: change policy after both authors approved the original
            # target.  The modified PEC is no longer covered by that target.
            pec = json.loads(pec_path.read_text(encoding="utf-8"))
            pec["claim_policy"]["permitted_outcomes"].append("NATURAL_PERSON_AUTHORSHIP")
            pec_path.write_bytes(canonical(pec) + b"\n")
            r = run("verify", str(rel), "--json")
            self.assertEqual(r.returncode, 1)
            self.assertEqual(json.loads(r.stdout)["data"]["error_code"], "CLAIM_POLICY_UNKNOWN_OUTCOME")
            # tamper 2: break the event chain
            pec["claim_policy"]["permitted_outcomes"].remove("NATURAL_PERSON_AUTHORSHIP")
            pec["events"] = [{"sequence": 5, "event_id": "x", "previous_event_digest": None, "kind": "note"}]
            pec_path.write_bytes(canonical(pec) + b"\n")
            r = run("verify", str(rel), "--json")
            self.assertEqual(r.returncode, 1)
            self.assertEqual(json.loads(r.stdout)["data"]["error_code"], "EVENT_CHAIN_BROKEN")


if __name__ == "__main__":
    unittest.main()
