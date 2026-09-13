import pathlib
import shutil
import tempfile
import unittest

import time_evidence


ROOT = pathlib.Path(__file__).resolve().parent
FIXTURE = ROOT / "design" / "rfc3161-approval-set-fixture"
FINGERPRINT = "32e841a95cc1164101ffde41298ef2fc75c1c4372ef095e88a6bbd47dfb191fc"


class TestTimeEvidence(unittest.TestCase):
    def test_real_fixture_verifies_offline_with_explicit_pin(self):
        result = time_evidence.verify(
            ROOT / "demo", FIXTURE, FINGERPRINT, external_authority=True
        )
        self.assertEqual(result["subject_kind"], "approval-set")
        self.assertEqual(result["authority_class"], "external")
        self.assertEqual(result["not_after_utc"], "2026-09-13T11:37:22+00:00")

    def test_wrong_trust_pin_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "TIME_TRUST_PIN_MISMATCH"):
            time_evidence.verify(
                ROOT / "demo", FIXTURE, "0" * 64, external_authority=True
            )

    def test_response_mutation_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            copied = pathlib.Path(directory) / "fixture"
            shutil.copytree(FIXTURE, copied)
            response = copied / "response.tsr"
            raw = bytearray(response.read_bytes())
            raw[-1] ^= 1
            response.write_bytes(raw)
            with self.assertRaisesRegex(ValueError, "TIME_REPORT_INPUT_DIGEST"):
                time_evidence.verify(
                    ROOT / "demo", copied, FINGERPRINT, external_authority=True
                )


if __name__ == "__main__":
    unittest.main()
