import hashlib
import secrets
import unittest
from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

import tsa


class TestTSASecurity(unittest.TestCase):
    def setUp(self):
        self.imprint = hashlib.sha256(b"approved ACSD target").digest()
        self.nonce = secrets.token_bytes(16)
        self.tsq = tsa.build_tsq(self.imprint, self.nonce)
        self.authority = tsa.LocalTSA()
        self.tsr = self.authority.respond(self.tsq)
        self.cert_der = self.authority.cert.public_bytes(serialization.Encoding.DER)

    def test_request_and_response_nonce_are_bound(self):
        request = tsa.parse_tsq(self.tsq)
        self.assertEqual(request["imprint"], self.imprint)
        self.assertEqual(request["nonce"], int.from_bytes(self.nonce, "big"))
        info = tsa.verify_tsr(
            self.tsr, self.imprint, trusted_cert_der=self.cert_der,
            expected_nonce=request["nonce"],
        )
        self.assertEqual(info["nonce"], request["nonce"])
        self.assertEqual(info["trust_model"], "exact-signer-pin")

    def test_wrong_nonce_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "TSR_NONCE_MISMATCH"):
            tsa.verify_tsr(
                self.tsr, self.imprint, trusted_cert_der=self.cert_der,
                expected_nonce=int.from_bytes(self.nonce, "big") + 1,
            )

    def test_package_certificate_is_not_implicitly_trusted(self):
        with self.assertRaisesRegex(ValueError, "TSR_UNTRUSTED_SIGNER"):
            tsa.verify_tsr(self.tsr, self.imprint)

    def test_wrong_exact_signer_pin_is_rejected(self):
        other = tsa.LocalTSA()
        other_der = other.cert.public_bytes(serialization.Encoding.DER)
        with self.assertRaisesRegex(ValueError, "TSR_EMBEDDED_CERT_MISMATCH"):
            tsa.verify_tsr(
                self.tsr, self.imprint, trusted_cert_der=other_der,
                expected_nonce=int.from_bytes(self.nonce, "big"),
            )

    def _authority_with_eku(self, eku, critical):
        authority = tsa.LocalTSA()
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, "ACSD adverse TSA")
        ])
        builder = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(authority._key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.now(timezone.utc) - timedelta(minutes=1))
            .not_valid_after(datetime.now(timezone.utc) + timedelta(days=1))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        )
        if eku is not None:
            builder = builder.add_extension(x509.ExtendedKeyUsage(eku), critical=critical)
        authority.cert = builder.sign(authority._key, hashes.SHA256())
        return authority

    def test_timestamping_eku_must_be_present_critical_and_exclusive(self):
        cases = [
            (None, False, "TSR_TIMESTAMPING_EKU_MISSING"),
            ([ExtendedKeyUsageOID.TIME_STAMPING], False, "TSR_TIMESTAMPING_EKU_INVALID"),
            ([ExtendedKeyUsageOID.TIME_STAMPING, ExtendedKeyUsageOID.CODE_SIGNING], True,
             "TSR_TIMESTAMPING_EKU_INVALID"),
        ]
        for eku, critical, code in cases:
            with self.subTest(code=code):
                authority = self._authority_with_eku(eku, critical)
                response = authority.respond(self.tsq)
                cert_der = authority.cert.public_bytes(serialization.Encoding.DER)
                with self.assertRaisesRegex(ValueError, code):
                    tsa.verify_tsr(
                        response, self.imprint, trusted_cert_der=cert_der,
                        expected_nonce=int.from_bytes(self.nonce, "big"),
                    )

    def test_non_tstinfo_econtent_is_rejected_before_signature_use(self):
        wrong_oid = "1.2.840.113549.1.9.16.1.5"
        response = self.tsr.replace(tsa._oid(tsa.OID_TSTINFO), tsa._oid(wrong_oid), 1)
        with self.assertRaisesRegex(ValueError, "TSR_ECONTENT_TYPE"):
            tsa.verify_tsr(
                response, self.imprint, trusted_cert_der=self.cert_der,
                expected_nonce=int.from_bytes(self.nonce, "big"),
            )

    def test_signature_algorithm_identifier_must_match_key_and_digest(self):
        old = tsa._oid("1.2.840.113549.1.1.11")
        new = tsa._oid("1.2.840.113549.1.1.13")
        offset = self.tsr.rfind(old)  # SignerInfo, after the embedded certificate
        self.assertGreaterEqual(offset, 0)
        response = self.tsr[:offset] + new + self.tsr[offset + len(old):]
        with self.assertRaisesRegex(ValueError, "TSR_SIGNATURE_ALGORITHM_MISMATCH"):
            tsa.verify_tsr(
                response, self.imprint, trusted_cert_der=self.cert_der,
                expected_nonce=int.from_bytes(self.nonce, "big"),
            )


if __name__ == "__main__":
    unittest.main()
