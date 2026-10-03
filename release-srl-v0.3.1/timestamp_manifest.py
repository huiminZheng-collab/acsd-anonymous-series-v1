"""Acquire and verify RFC 3161 evidence for RELEASE-MANIFEST.sha256.

This is an explicit network operation. It writes only to a new, empty
``timestamp`` directory and verifies the response against the downloaded TSA
signer certificate, exact manifest imprint, and request nonce before success.
"""

from __future__ import annotations

import hashlib
import json
import pathlib
import secrets
import urllib.request

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization

import tsa


ROOT = pathlib.Path(__file__).resolve().parent
MANIFEST = ROOT / "RELEASE-MANIFEST.sha256"
OUTPUT = ROOT / "timestamp"
TSA_URL = "https://freetsa.org/tsr"
CERT_URL = "https://freetsa.org/files/tsa.crt"


def file_sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def main() -> int:
    if not MANIFEST.is_file():
        raise SystemExit("RELEASE-MANIFEST.sha256 is missing")
    if OUTPUT.exists() and any(OUTPUT.iterdir()):
        raise SystemExit("timestamp directory is not empty; refusing overwrite")
    OUTPUT.mkdir(exist_ok=True)

    manifest_bytes = MANIFEST.read_bytes()
    subject_digest = hashlib.sha256(manifest_bytes).digest()
    nonce = secrets.token_bytes(16)
    request_bytes = tsa.build_tsq(subject_digest, nonce)

    request = urllib.request.Request(
        TSA_URL,
        data=request_bytes,
        headers={
            "Content-Type": "application/timestamp-query",
            "User-Agent": "acsd-srl-release/0.3.1",
        },
    )
    with urllib.request.urlopen(request, timeout=30) as response:
        response_bytes = response.read()
    with urllib.request.urlopen(CERT_URL, timeout=30) as response:
        cert_pem = response.read()

    certificate = x509.load_pem_x509_certificate(cert_pem)
    cert_der = certificate.public_bytes(serialization.Encoding.DER)
    fingerprint = certificate.fingerprint(hashes.SHA256()).hex()
    info = tsa.verify_tsr(
        response_bytes,
        subject_digest,
        trusted_cert_der=cert_der,
        trusted_fingerprint=fingerprint,
        expected_nonce=int.from_bytes(nonce, "big"),
    )

    report = {
        "schema": "acsd-srl-release-rfc3161/v1",
        "subject": "RELEASE-MANIFEST.sha256",
        "subject_sha256": subject_digest.hex(),
        "request_sha256": file_sha256(request_bytes),
        "response_sha256": file_sha256(response_bytes),
        "tsa_certificate_sha256": file_sha256(cert_der),
        "tsa_certificate_fingerprint_sha256": fingerprint,
        "nonce_hex": nonce.hex(),
        "tsa_url": TSA_URL,
        "tsa_certificate_url": CERT_URL,
        "generation_time_utc": info["genTime"].isoformat(),
        "policy_oid": info["policy_oid"],
        "serial_hex": format(info["serial"], "x"),
        "trust_model": "exact-signer-certificate-pin",
        "verification": "OK",
        "non_claims": [
            "does not prove authorship",
            "does not prove novelty or correctness",
            "does not prove peer review, acceptance, or academic priority",
        ],
    }

    (OUTPUT / "request.tsq").write_bytes(request_bytes)
    (OUTPUT / "response.tsr").write_bytes(response_bytes)
    (OUTPUT / "tsa-cert.der").write_bytes(cert_der)
    (OUTPUT / "report.json").write_text(
        json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
