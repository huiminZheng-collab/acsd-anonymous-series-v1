import unittest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import cose


class TestStrictCose(unittest.TestCase):
    def setUp(self):
        self.key = Ed25519PrivateKey.generate()
        self.payload = b"approval-target"
        self.signed = cose.cose_sign1(self.payload, self.key)

    def test_standard_eddsa_and_round_trip(self):
        self.assertEqual(cose.ALG_EDDSA, -8)
        self.assertEqual(self.signed[:2], b"\xd2\x84")
        self.assertEqual(
            cose.cose_verify(self.signed, self.key.public_key(), self.payload),
            self.payload,
        )

    def test_bare_array_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "COSE_SIGN1_TAG_REQUIRED"):
            cose.cose_verify(self.signed[1:], self.key.public_key(), self.payload)

    def test_wrong_algorithm_is_rejected(self):
        protected = cose.cbor_map([(cose.cbor_int(1), cose.cbor_int(-35))])
        signature = self.key.sign(cose.sig_structure(protected, self.payload))
        message = b"\xd2" + cose.cbor_array([
            cose.cbor_bstr(protected), cose.cbor_map([]),
            cose.cbor_bstr(self.payload), cose.cbor_bstr(signature),
        ])
        with self.assertRaisesRegex(ValueError, "COSE_ALG_NOT_EDDSA"):
            cose.cose_verify(message, self.key.public_key(), self.payload)

    def test_duplicate_and_nonminimal_protected_keys_are_rejected(self):
        cases = [
            b"\xa2\x01\x27\x01\x27",  # duplicate alg label
            b"\xa1\x18\x01\x27",      # label 1 in a non-minimal encoding
        ]
        for protected in cases:
            with self.subTest(protected=protected.hex()):
                signature = self.key.sign(cose.sig_structure(protected, self.payload))
                message = b"\xd2" + cose.cbor_array([
                    cose.cbor_bstr(protected), cose.cbor_map([]),
                    cose.cbor_bstr(self.payload), cose.cbor_bstr(signature),
                ])
                with self.assertRaises(ValueError):
                    cose.cose_verify(message, self.key.public_key(), self.payload)

    def test_unprotected_headers_and_bad_signature_length_are_rejected(self):
        protected = cose.cbor_map([(cose.cbor_int(1), cose.cbor_int(-8))])
        bad_unprotected = b"\xd2" + cose.cbor_array([
            cose.cbor_bstr(protected),
            cose.cbor_map([(cose.cbor_int(4), cose.cbor_bstr(b"kid"))]),
            cose.cbor_bstr(self.payload), cose.cbor_bstr(b"x" * 64),
        ])
        with self.assertRaisesRegex(ValueError, "COSE_UNPROTECTED_HEADER_FORBIDDEN"):
            cose.cose_verify(bad_unprotected, self.key.public_key(), self.payload)

        bad_length = b"\xd2" + cose.cbor_array([
            cose.cbor_bstr(protected), cose.cbor_map([]),
            cose.cbor_bstr(self.payload), cose.cbor_bstr(b"x" * 63),
        ])
        with self.assertRaisesRegex(ValueError, "COSE_SIGNATURE_LENGTH"):
            cose.cose_verify(bad_length, self.key.public_key(), self.payload)

    def test_truncation_is_reported_as_profile_error(self):
        for cut in (1, 2, 3, len(self.signed) - 1):
            with self.subTest(cut=cut), self.assertRaises(ValueError):
                cose.cose_verify(self.signed[:cut], self.key.public_key(), self.payload)


if __name__ == "__main__":
    unittest.main()
