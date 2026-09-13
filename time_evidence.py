"""Exact RFC 3161 approval-set evidence adapter.

The adapter verifies receipt cryptography and binding, but authority
independence is an explicit verifier policy input rather than a package fact.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import pathlib

from cryptography import x509
from cryptography.hazmat.primitives import hashes

import approval_set
import tsa
from pec_core import HEX, canonical, digest, require


SCHEMA = "acsd-rfc3161-appraisal/v1"
REPORT_SCHEMA = "acsd-rfc3161-fixture/v1"


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _read_canonical(path: pathlib.Path):
    raw = path.read_bytes()
    payload = raw[:-1] if raw.endswith(b"\n") else raw
    try:
        value = json.loads(payload.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError("TIME_EVIDENCE_JSON_INVALID") from exc
    require(canonical(value) == payload, "TIME_EVIDENCE_JSON_NONCANONICAL")
    return value, raw


def verify(
    bundle: pathlib.Path,
    fixture: pathlib.Path,
    trusted_fingerprint: str,
    *,
    external_authority: bool,
):
    bundle = pathlib.Path(bundle)
    fixture = pathlib.Path(fixture)
    require(
        isinstance(trusted_fingerprint, str) and HEX.fullmatch(trusted_fingerprint),
        "TIME_TRUSTED_FINGERPRINT_INVALID",
    )
    target, _ = _read_canonical(bundle / "approval-target.json")
    pec, _ = _read_canonical(bundle / "pec.json")
    approval_set_obj, approval_set_raw = _read_canonical(
        bundle / "approval" / "approval-set.json"
    )
    required = pec["governance"]["required_pec_approval_key_ids"]
    author_signatures = {
        key_id: (bundle / "release-approvals" / f"{key_id}.cose").read_bytes()
        for key_id in required
    }
    verified_set = approval_set.verify_from_signatures(
        approval_set_obj, target, author_signatures, {}
    )
    subject_digest = verified_set["approval_set_digest"]

    report, report_raw = _read_canonical(fixture / "report.json")
    request_raw = (fixture / "request.tsq").read_bytes()
    response_raw = (fixture / "response.tsr").read_bytes()
    cert_raw = (fixture / "tsa-cert.der").read_bytes()
    expected_report_fields = {
        "schema", "subject", "subject_digest", "request_sha256",
        "response_sha256", "tsa_cert_sha256", "nonce", "tsa_url",
        "tsa_cert_fingerprint", "not_after_utc", "trust_model", "capability",
        "policy_oid", "serial_hex",
    }
    require(set(report) == expected_report_fields, "TIME_REPORT_FIELDS")
    require(report["schema"] == REPORT_SCHEMA, "TIME_REPORT_SCHEMA")
    require(
        report["subject"] == "approval/approval-set.json"
        and report["subject_digest"] == subject_digest,
        "TIME_REPORT_SUBJECT",
    )
    require(
        report["request_sha256"] == _sha256(request_raw)
        and report["response_sha256"] == _sha256(response_raw)
        and report["tsa_cert_sha256"] == _sha256(cert_raw),
        "TIME_REPORT_INPUT_DIGEST",
    )
    require(
        report["trust_model"] == "exact-signer-pin"
        and report["capability"] == "rfc3161-exact-approval-set-imprint",
        "TIME_REPORT_CAPABILITY",
    )
    certificate = x509.load_der_x509_certificate(cert_raw)
    fingerprint = certificate.fingerprint(hashes.SHA256()).hex()
    require(fingerprint == trusted_fingerprint, "TIME_TRUST_PIN_MISMATCH")
    require(report["tsa_cert_fingerprint"] == fingerprint, "TIME_REPORT_SIGNER")
    request_info = tsa.parse_tsq(request_raw)
    require(request_info["imprint"] == bytes.fromhex(subject_digest),
            "TIME_REQUEST_IMPRINT")
    require(
        request_info["nonce"] == int(report["nonce"], 16),
        "TIME_REQUEST_NONCE",
    )
    info = tsa.verify_tsr(
        response_raw,
        bytes.fromhex(subject_digest),
        trusted_cert_der=cert_raw,
        trusted_fingerprint=trusted_fingerprint,
        expected_nonce=request_info["nonce"],
    )
    not_after = info["genTime"].isoformat()
    require(report["not_after_utc"] == not_after, "TIME_REPORT_INSTANT")
    return {
        "schema": SCHEMA,
        "subject_kind": "approval-set",
        "subject_digest": subject_digest,
        "not_after_utc": not_after,
        "request_digest": _sha256(request_raw),
        "response_digest": _sha256(response_raw),
        "certificate_digest": _sha256(cert_raw),
        "report_digest": _sha256(report_raw),
        "approval_set_input_digest": _sha256(approval_set_raw),
        "nonce": report["nonce"],
        "signer_fingerprint": fingerprint,
        "trust_model": "exact-signer-pin",
        "authority_class": "external" if external_authority else "local-test",
        "policy_oid": report["policy_oid"],
        "serial_hex": report["serial_hex"],
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("bundle", type=pathlib.Path)
    parser.add_argument("fixture", type=pathlib.Path)
    parser.add_argument("--trusted-fingerprint", required=True)
    parser.add_argument("--external-authority", action="store_true")
    args = parser.parse_args()
    result = verify(
        args.bundle,
        args.fixture,
        args.trusted_fingerprint,
        external_authority=args.external_authority,
    )
    print(canonical(result).decode("utf-8"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
