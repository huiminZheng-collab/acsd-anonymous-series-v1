import hashlib
import os
import secrets
import socket
import unittest
import urllib.request

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization

import tsa


def _network_ok():
    try:
        socket.create_connection(("freetsa.org", 443), timeout=5)
        return True
    except Exception:
        return False


def _should_skip():
    return (not _network_ok()) or os.environ.get("ACSD_SKIP_NETWORK") == "1"


@unittest.skipUnless(not _should_skip(), "freetsa.org unreachable or ACSD_SKIP_NETWORK set")
class TestTSAInterop(unittest.TestCase):
    def test_freetsa_ecdsa_p384(self):
        """End-to-end against the real freeTSA.org service (ECDSA P-384,
        SHA-512, no embedded certificate)."""
        imprint = hashlib.sha256(b"acsd interop").digest()
        tsq = tsa.build_tsq(imprint, secrets.token_bytes(16))
        req = urllib.request.Request(
            "https://freetsa.org/tsr", data=tsq,
            headers={"Content-Type": "application/timestamp-query", "User-Agent": "acsd/1.0"},
        )
        with urllib.request.urlopen(req, timeout=30) as resp:
            tsr = resp.read()
        with urllib.request.urlopen("https://freetsa.org/files/tsa.crt", timeout=30) as resp:
            cert_pem = resp.read()
        cert = x509.load_pem_x509_certificate(cert_pem)
        cert_der = cert.public_bytes(serialization.Encoding.DER)
        fp = cert.fingerprint(hashes.SHA256()).hex()
        info = tsa.verify_tsr(tsr, imprint, trusted_cert_der=cert_der, trusted_fingerprint=fp)
        self.assertIsNotNone(info["genTime"])
        self.assertIsNotNone(info["imprint"])
        self.assertEqual(info["imprint"], imprint)


if __name__ == "__main__":
    unittest.main()
