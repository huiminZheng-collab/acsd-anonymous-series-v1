"""Acquire one real RFC 3161 fixture for an exact ACSD approval set.

This is an explicit network operation and is never run by CI or demo
generation. The resulting files are verified before being written.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import secrets
import sys
import urllib.request

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization

ROOT = pathlib.Path(__file__).resolve().parent
PROJECT = ROOT.parent
sys.path.insert(0, str(PROJECT))

import tsa  # noqa: E402
from canonical_json import canonical, digest  # noqa: E402


def read_canonical(path: pathlib.Path):
    raw = path.read_bytes()
    payload = raw[:-1] if raw.endswith(b"\n") else raw
    value = json.loads(payload.decode("utf-8"))
    if canonical(value) != payload:
        raise ValueError("FIXTURE_SUBJECT_NONCANONICAL")
    return value


def sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def acquire(bundle: pathlib.Path, output: pathlib.Path, tsa_url: str, cert_url: str):
    if output.exists() and any(output.iterdir()):
        raise ValueError("FIXTURE_OUTPUT_NOT_EMPTY")
    output.mkdir(parents=True, exist_ok=True)

    approval_set = read_canonical(bundle / "approval" / "approval-set.json")
    subject_digest = digest(approval_set)
    nonce = secrets.token_bytes(16)
    request_bytes = tsa.build_tsq(bytes.fromhex(subject_digest), nonce)
    request = urllib.request.Request(
        tsa_url,
        data=request_bytes,
        headers={
            "Content-Type": "application/timestamp-query",
            "User-Agent": "acsd-research-fixture/1.0",
        },
    )
    with urllib.request.urlopen(request, timeout=30) as response:
        response_bytes = response.read()
    with urllib.request.urlopen(cert_url, timeout=30) as response:
        cert_pem = response.read()

    certificate = x509.load_pem_x509_certificate(cert_pem)
    cert_der = certificate.public_bytes(serialization.Encoding.DER)
    fingerprint = certificate.fingerprint(hashes.SHA256()).hex()
    info = tsa.verify_tsr(
        response_bytes,
        bytes.fromhex(subject_digest),
        trusted_cert_der=cert_der,
        trusted_fingerprint=fingerprint,
        expected_nonce=int.from_bytes(nonce, "big"),
    )
    report = {
        "schema": "acsd-rfc3161-fixture/v1",
        "subject": "approval/approval-set.json",
        "subject_digest": subject_digest,
        "request_sha256": sha256(request_bytes),
        "response_sha256": sha256(response_bytes),
        "tsa_cert_sha256": sha256(cert_der),
        "nonce": nonce.hex(),
        "tsa_url": tsa_url,
        "tsa_cert_fingerprint": fingerprint,
        "not_after_utc": info["genTime"].isoformat(),
        "policy_oid": info["policy_oid"],
        "serial_hex": format(info["serial"], "x"),
        "trust_model": "exact-signer-pin",
        "capability": "rfc3161-exact-approval-set-imprint",
    }
    (output / "request.tsq").write_bytes(request_bytes)
    (output / "response.tsr").write_bytes(response_bytes)
    (output / "tsa-cert.der").write_bytes(cert_der)
    (output / "report.json").write_bytes(canonical(report) + b"\n")
    return report


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("bundle", type=pathlib.Path)
    parser.add_argument("output", type=pathlib.Path)
    parser.add_argument("--tsa-url", default="https://freetsa.org/tsr")
    parser.add_argument("--cert-url", default="https://freetsa.org/files/tsa.crt")
    args = parser.parse_args()
    report = acquire(args.bundle, args.output, args.tsa_url, args.cert_url)
    print(json.dumps(report, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
