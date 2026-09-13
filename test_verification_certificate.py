import copy
import hashlib
import json
import pathlib
import shutil
import subprocess
import sys
import tempfile
import unittest

import claim_derivation
import verification_transcript


ROOT = pathlib.Path(__file__).resolve().parent
PYTHON_ADAPTER = ROOT / "design/verification_certificate.py"
NODE_ADAPTER = ROOT / "design/verification_certificate.cjs"
CHECKED_CERTIFICATE = ROOT / "design/verification_certificate_demo.json"
CHECKED_CERTIFICATE_V2 = ROOT / "design/verification_certificate_demo_v2.json"


def run_python(bundle):
    return subprocess.run(
        [sys.executable, str(PYTHON_ADAPTER), str(bundle)],
        cwd=ROOT, capture_output=True,
    )


def run_node(bundle):
    return subprocess.run(
        ["node", str(NODE_ADAPTER), str(bundle)],
        cwd=ROOT, capture_output=True,
    )


def run_python_v2(bundle):
    return subprocess.run(
        [sys.executable, str(PYTHON_ADAPTER), str(bundle), "--include-identity"],
        cwd=ROOT, capture_output=True,
    )


def run_node_v2(bundle):
    return subprocess.run(
        ["node", str(NODE_ADAPTER), str(bundle), "--include-identity"],
        cwd=ROOT, capture_output=True,
    )


class TestVerificationCertificate(unittest.TestCase):
    def checked(self):
        raw = CHECKED_CERTIFICATE.read_bytes()
        return json.loads(raw), hashlib.sha256(raw).hexdigest()

    def checked_v2(self):
        raw = CHECKED_CERTIFICATE_V2.read_bytes()
        return json.loads(raw), hashlib.sha256(raw).hexdigest()

    def test_python_and_node_emit_identical_fact_certificate(self):
        python = run_python(ROOT / "demo")
        node = run_node(ROOT / "demo")
        self.assertEqual(python.returncode, 0, python.stderr.decode(errors="replace"))
        self.assertEqual(node.returncode, 0, node.stderr.decode(errors="replace"))
        self.assertEqual(python.stdout, node.stdout)
        self.assertEqual(python.stdout, CHECKED_CERTIFICATE.read_bytes())

        certificate = json.loads(python.stdout)
        self.assertEqual(certificate["schema"], "acsd-verification-certificate/v1")
        self.assertEqual(len(certificate["signature_facts"]), 4)
        self.assertEqual(len(certificate["merkle_facts"]), 1)
        forbidden = {"accepted", "claim", "claims", "granted", "outcome", "status", "valid", "verdict"}

        def keys(value):
            if isinstance(value, dict):
                for key, child in value.items():
                    yield key
                    yield from keys(child)
            elif isinstance(value, list):
                for child in value:
                    yield from keys(child)

        self.assertTrue(forbidden.isdisjoint(keys(certificate)))

    def test_identity_v2_adapters_and_scoped_derivation_agree(self):
        python = run_python_v2(ROOT / "demo")
        node = run_node_v2(ROOT / "demo")
        self.assertEqual(python.returncode, 0, python.stderr.decode(errors="replace"))
        self.assertEqual(node.returncode, 0, node.stderr.decode(errors="replace"))
        self.assertEqual(python.stdout, node.stdout)
        self.assertEqual(python.stdout, CHECKED_CERTIFICATE_V2.read_bytes())
        certificate, certificate_digest = self.checked_v2()
        self.assertEqual(
            claim_derivation.wire_outcomes(
                verification_transcript.derive(certificate, certificate_digest)
            ),
            (
                "KEY_ASSENT", "GOVERNANCE_ASSENT", "COMMITTED_EVIDENCE_MATCH",
                "SLOT_KEY_ASSENT_TO_IDENTITY_ASSERTION",
            ),
        )

    def test_identity_slot_substitution_removes_only_identity_claim(self):
        certificate, certificate_digest = self.checked_v2()
        certificate["identity_assertions"][0]["author_slot"] = 2
        self.assertEqual(
            claim_derivation.wire_outcomes(
                verification_transcript.derive(certificate, certificate_digest)
            ),
            ("KEY_ASSENT", "GOVERNANCE_ASSENT", "COMMITTED_EVIDENCE_MATCH"),
        )

    def test_identity_cose_input_substitution_removes_only_identity_claim(self):
        certificate, certificate_digest = self.checked_v2()
        item = next(entry for entry in certificate["inputs"]
                    if entry["role"] == "identity-disclosure-cose")
        item["sha256"] = "0" * 64
        self.assertEqual(
            claim_derivation.wire_outcomes(
                verification_transcript.derive(certificate, certificate_digest)
            ),
            ("KEY_ASSENT", "GOVERNANCE_ASSENT", "COMMITTED_EVIDENCE_MATCH"),
        )

    def test_corrupt_signature_produces_no_certificate_in_either_adapter(self):
        with tempfile.TemporaryDirectory() as directory:
            bundle = pathlib.Path(directory) / "demo"
            shutil.copytree(ROOT / "demo", bundle)
            signature = next((bundle / "disclosure-approvals").glob("*.cose"))
            raw = bytearray(signature.read_bytes())
            raw[-1] ^= 1
            signature.write_bytes(raw)
            python = run_python(bundle)
            node = run_node(bundle)
            self.assertNotEqual(python.returncode, 0)
            self.assertNotEqual(node.returncode, 0)
            self.assertEqual(python.stdout, b"")
            self.assertEqual(node.stdout, b"")

    def test_missing_required_signature_produces_no_partial_certificate(self):
        with tempfile.TemporaryDirectory() as directory:
            bundle = pathlib.Path(directory) / "demo"
            shutil.copytree(ROOT / "demo", bundle)
            next((bundle / "release-approvals").glob("*.cose")).unlink()
            python = run_python(bundle)
            node = run_node(bundle)
            self.assertNotEqual(python.returncode, 0)
            self.assertNotEqual(node.returncode, 0)
            self.assertEqual(python.stdout, b"")
            self.assertEqual(node.stdout, b"")

    def test_structural_checker_derives_only_closed_fact_groups(self):
        certificate, certificate_digest = self.checked()
        derivations = verification_transcript.derive(certificate, certificate_digest)
        self.assertEqual(
            claim_derivation.wire_outcomes(derivations),
            ("KEY_ASSENT", "GOVERNANCE_ASSENT", "COMMITTED_EVIDENCE_MATCH"),
        )

    def test_deleting_one_signature_removes_only_its_dependent_claims(self):
        certificate, certificate_digest = self.checked()
        missing_approval = copy.deepcopy(certificate)
        del missing_approval["signature_facts"][0]
        self.assertEqual(
            claim_derivation.wire_outcomes(
                verification_transcript.derive(missing_approval, certificate_digest)
            ),
            ("COMMITTED_EVIDENCE_MATCH",),
        )

        missing_event = copy.deepcopy(certificate)
        event_index = next(
            index for index, item in enumerate(missing_event["signature_facts"])
            if item["purpose"] == "event-disclosure"
        )
        del missing_event["signature_facts"][event_index]
        self.assertEqual(
            claim_derivation.wire_outcomes(
                verification_transcript.derive(missing_event, certificate_digest)
            ),
            ("KEY_ASSENT", "GOVERNANCE_ASSENT"),
        )

    def test_merkle_scope_substitution_removes_event_claim(self):
        certificate, certificate_digest = self.checked()
        certificate["merkle_facts"][0]["last_index"] += 1
        self.assertEqual(
            claim_derivation.wire_outcomes(
                verification_transcript.derive(certificate, certificate_digest)
            ),
            ("KEY_ASSENT", "GOVERNANCE_ASSENT"),
        )

    def test_extra_merkle_fact_is_not_silently_ignored(self):
        certificate, certificate_digest = self.checked()
        certificate["merkle_facts"].append(copy.deepcopy(certificate["merkle_facts"][0]))
        self.assertEqual(
            claim_derivation.wire_outcomes(
                verification_transcript.derive(certificate, certificate_digest)
            ),
            ("KEY_ASSENT", "GOVERNANCE_ASSENT"),
        )

    def test_cose_input_substitution_removes_only_dependent_claims(self):
        certificate, certificate_digest = self.checked()
        item = next(entry for entry in certificate["inputs"]
                    if entry["role"] == "author-approval-cose")
        item["sha256"] = "0" * 64
        self.assertEqual(
            claim_derivation.wire_outcomes(
                verification_transcript.derive(certificate, certificate_digest)
            ),
            ("COMMITTED_EVIDENCE_MATCH",),
        )

    def test_empty_required_key_set_is_rejected(self):
        certificate, certificate_digest = self.checked()
        certificate["approval_target"]["required_key_ids"] = []
        with self.assertRaisesRegex(ValueError, "TRANSCRIPT_APPROVAL_KEYS"):
            verification_transcript.derive(certificate, certificate_digest)

    def test_unsafe_json_integer_is_rejected(self):
        certificate, certificate_digest = self.checked()
        certificate["event_disclosure"]["event_sequence"] = 9_007_199_254_740_992
        with self.assertRaisesRegex(ValueError, "TRANSCRIPT_EVENT_SEQUENCE"):
            verification_transcript.derive(certificate, certificate_digest)

    def test_unimplemented_extension_is_rejected(self):
        certificate, certificate_digest = self.checked()
        certificate["identity_assertions"] = [{}]
        with self.assertRaisesRegex(ValueError, "TRANSCRIPT_UNSUPPORTED_EXTENSION"):
            verification_transcript.derive(certificate, certificate_digest)


if __name__ == "__main__":
    unittest.main()
