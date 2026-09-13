"""Experimental Python adapter for ACSD verification certificates v1/v2.

The certificate records exact facts established from a demo bundle. It carries
no final verdict or application claim; the typed appraisal kernel is the only
component that may derive those claims.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import sys
from typing import Optional

ROOT = pathlib.Path(__file__).resolve().parent
PROJECT = ROOT.parent
sys.path.insert(0, str(PROJECT))

from cryptography.hazmat.primitives import serialization  # noqa: E402

import cose  # noqa: E402
import approval_set  # noqa: E402
import identity_disclosure  # noqa: E402
import time_evidence  # noqa: E402
from key_identity import key_id_of  # noqa: E402
from pec_core import canonical, digest, require, verify_dialogue_window  # noqa: E402


SCHEMA_V1 = "acsd-verification-certificate/v1"
SCHEMA_V2 = "acsd-verification-certificate/v2"
SCHEMA_V3 = "acsd-verification-certificate/v3"


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _read_canonical(root: pathlib.Path, relative: str):
    raw = (root / relative).read_bytes()
    payload = raw[:-1] if raw.endswith(b"\n") else raw
    try:
        value = json.loads(payload.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError("TRANSCRIPT_JSON_INVALID:" + relative) from exc
    require(canonical(value) == payload, "TRANSCRIPT_JSON_NONCANONICAL:" + relative)
    return value, raw


def build(
    root: pathlib.Path,
    *,
    include_identity: bool = False,
    time_fixture: Optional[pathlib.Path] = None,
    trusted_tsa_fingerprint: Optional[str] = None,
    external_authority: bool = False,
) -> dict:
    root = pathlib.Path(root)
    include_time = time_fixture is not None
    include_identity = include_identity or include_time
    target, target_raw = _read_canonical(root, "approval-target.json")
    pec, pec_raw = _read_canonical(root, "pec.json")
    disclosure, disclosure_raw = _read_canonical(root, "dialogue-disclosure.json")
    release = None
    identity = None
    identity_raw = None
    if include_identity:
        release, release_raw = _read_canonical(root, "release.json")
        identity, identity_raw = _read_canonical(root, "identity/slot-1.json")

    required = pec.get("governance", {}).get("required_pec_approval_key_ids")
    require(isinstance(required, list) and required == sorted(set(required)),
            "TRANSCRIPT_REQUIRED_KEYS")
    require(target.get("required_key_ids") == required, "TRANSCRIPT_KEY_SET_MISMATCH")
    require(target.get("pec_digest") == digest(pec), "TRANSCRIPT_PEC_BINDING")
    require(disclosure.get("pec_digest") == digest(pec), "TRANSCRIPT_DISCLOSURE_PEC")
    require("COMMITTED_EVIDENCE_MATCH" in
            pec.get("claim_policy", {}).get("permitted_outcomes", []),
            "TRANSCRIPT_EVENT_POLICY")

    events = [event for event in pec.get("events", [])
              if event.get("event_id") == disclosure.get("event_id")]
    require(len(events) == 1, "TRANSCRIPT_EVENT_LOOKUP")
    event = events[0]
    require(event.get("sequence") == disclosure.get("event_sequence"),
            "TRANSCRIPT_EVENT_SEQUENCE")
    require(event.get("kind") == disclosure.get("kind"), "TRANSCRIPT_EVENT_KIND")
    commitment = event.get("commitment", {})
    require(commitment.get("scheme") == "merkle-dialogue-v1",
            "TRANSCRIPT_COMMITMENT_SCHEME")
    require(disclosure.get("disclosure_mode") == "dialogue_window",
            "TRANSCRIPT_DISCLOSURE_MODE")

    opened = disclosure.get("opened_material")
    require(isinstance(opened, list) and opened, "TRANSCRIPT_OPENING")
    window = []
    for item in opened:
        try:
            window.append({
                "index": item["index"],
                "bytes": item["bytes"].encode("utf-8"),
                "salt": bytes.fromhex(item["salt"]),
                "path": item["path"],
            })
        except (AttributeError, KeyError, TypeError, ValueError) as exc:
            raise ValueError("TRANSCRIPT_OPENING") from exc
    verify_dialogue_window(commitment.get("digest"), window)

    inputs = [
        {"role": "approval-target", "path": "approval-target.json",
         "sha256": _sha256(target_raw)},
        {"role": "pec", "path": "pec.json", "sha256": _sha256(pec_raw)},
        {"role": "event-disclosure", "path": "dialogue-disclosure.json",
         "sha256": _sha256(disclosure_raw)},
    ]
    signature_facts = []
    for purpose, payload, directory in (
        ("author-approval", canonical(target), "release-approvals"),
        ("event-disclosure", canonical(disclosure), "disclosure-approvals"),
    ):
        for key_id in required:
            public_relative = f"public-keys/{key_id}.pub"
            cose_relative = f"{directory}/{key_id}.cose"
            public_raw = (root / public_relative).read_bytes()
            cose_raw = (root / cose_relative).read_bytes()
            public_key = serialization.load_pem_public_key(public_raw)
            require(key_id_of(public_key) == key_id, "PUBLIC_KEY_ID_MISMATCH")
            cose.cose_verify(cose_raw, public_key, expected_payload=payload)
            inputs.extend([
                {"role": "public-key", "path": public_relative,
                 "sha256": _sha256(public_raw)},
                {"role": purpose + "-cose", "path": cose_relative,
                 "sha256": _sha256(cose_raw)},
            ])
            signature_facts.append({
                "purpose": purpose,
                "key_id": key_id,
                "payload_digest": _sha256(payload),
                "cose_digest": _sha256(cose_raw),
            })

    identity_assertions = []
    if include_identity:
        key_id = identity["author_key_id"]
        public_relative = f"public-keys/{key_id}.pub"
        cose_relative = "identity/slot-1.cose"
        public_raw = (root / public_relative).read_bytes()
        cose_raw = (root / cose_relative).read_bytes()
        public_key = serialization.load_pem_public_key(public_raw)
        identity_disclosure.verify(identity, cose_raw, release, public_key)
        inputs.extend([
            {"role": "release", "path": "release.json", "sha256": _sha256(release_raw)},
            {"role": "identity-disclosure", "path": "identity/slot-1.json",
             "sha256": _sha256(identity_raw)},
            {"role": "identity-disclosure-cose", "path": cose_relative,
             "sha256": _sha256(cose_raw)},
        ])
        signature_facts.append({
            "purpose": "identity-disclosure",
            "key_id": key_id,
            "payload_digest": digest(identity),
            "cose_digest": _sha256(cose_raw),
        })
        identity_assertions.append({
            "body_digest": digest(identity),
            "release_digest": digest(release),
            "author_slot": identity["author_slot"],
            "author_key_id": key_id,
            "assertion_digest": digest(identity["identity_assertion"]),
            "cose_digest": _sha256(cose_raw),
        })

    approval_set_fact = None
    timestamp_facts = []
    trusted_inputs = []
    if include_time:
        require(trusted_tsa_fingerprint is not None, "TIME_TRUST_PIN_REQUIRED")
        approval_set_obj, approval_set_raw = _read_canonical(
            root, "approval/approval-set.json"
        )
        approval_set.verify_from_signatures(
            approval_set_obj,
            target,
            {
                key_id: (root / "release-approvals" / f"{key_id}.cose").read_bytes()
                for key_id in required
            },
            {},
        )
        appraisal = time_evidence.verify(
            root,
            pathlib.Path(time_fixture),
            trusted_tsa_fingerprint,
            external_authority=external_authority,
        )
        fixture = pathlib.Path(time_fixture)
        time_files = [
            ("time-request", "time-fixture/request.tsq", fixture / "request.tsq"),
            ("time-response", "time-fixture/response.tsr", fixture / "response.tsr"),
            ("tsa-certificate", "time-fixture/tsa-cert.der", fixture / "tsa-cert.der"),
            ("time-report", "time-fixture/report.json", fixture / "report.json"),
        ]
        inputs.append({
            "role": "approval-set",
            "path": "approval/approval-set.json",
            "sha256": _sha256(approval_set_raw),
        })
        inputs.extend({
            "role": role, "path": logical, "sha256": _sha256(path.read_bytes())
        } for role, logical, path in time_files)
        approval_set_fact = {
            "body_digest": digest(approval_set_obj),
            "approval_target_digest": approval_set_obj["approval_target_digest"],
            "author_approvals": approval_set_obj["author_approvals"],
            "lineage_authorizations": approval_set_obj["lineage_authorizations"],
        }
        timestamp_facts = [appraisal]
        trusted_inputs = [{
            "kind": "tsa-exact-signer-pin",
            "signer_fingerprint": appraisal["signer_fingerprint"],
            "certificate_digest": appraisal["certificate_digest"],
            "authority_class": appraisal["authority_class"],
        }]

    # Public keys appear for both signature purposes. Inputs are a set of exact
    # byte objects, while signature_facts retain both uses.
    inputs = sorted(
        {item["path"]: item for item in inputs}.values(),
        key=lambda item: (item["path"], item["role"]),
    )
    signature_facts.sort(key=lambda item: (item["purpose"], item["key_id"]))
    result = {
        "schema": SCHEMA_V3 if include_time else (
            SCHEMA_V2 if include_identity else SCHEMA_V1
        ),
        "inputs": inputs,
        "approval_target": {
            "target_digest": digest(target),
            "pec_digest": digest(pec),
            "required_key_ids": required,
        },
        "policy": {
            "pec_digest": digest(pec),
            "permitted_outcomes": pec["claim_policy"]["permitted_outcomes"],
        },
        "event_disclosure": {
            "body_digest": digest(disclosure),
            "pec_digest": digest(pec),
            "event_id": event["event_id"],
            "event_sequence": event["sequence"],
            "commitment_digest": commitment["digest"],
            "first_index": window[0]["index"],
            "last_index": window[-1]["index"],
            "required_key_ids": required,
        },
        "signature_facts": signature_facts,
        "merkle_facts": [{
            "body_digest": digest(disclosure),
            "commitment_digest": commitment["digest"],
            "first_index": window[0]["index"],
            "last_index": window[-1]["index"],
            "opened_leaf_count": len(window),
        }],
        "identity_assertions": identity_assertions,
        "timestamp_facts": timestamp_facts,
        "trusted_inputs": trusted_inputs,
    }
    if include_identity:
        result["release_context"] = {
            "release_digest": digest(release),
            "author_slots": [
                {"slot": author["slot"], "key_id": author["key_id"]}
                for author in release["authors"]
            ],
        }
    if include_time:
        result["approval_set"] = approval_set_fact
    return result


def encoded(root: pathlib.Path, **options) -> bytes:
    return canonical(build(root, **options))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("bundle")
    parser.add_argument("--output")
    parser.add_argument("--include-identity", action="store_true")
    parser.add_argument("--time-fixture", type=pathlib.Path)
    parser.add_argument("--trusted-tsa-fingerprint")
    parser.add_argument("--external-authority", action="store_true")
    args = parser.parse_args()
    output = encoded(
        pathlib.Path(args.bundle),
        include_identity=args.include_identity,
        time_fixture=args.time_fixture,
        trusted_tsa_fingerprint=args.trusted_tsa_fingerprint,
        external_authority=args.external_authority,
    ) + b"\n"
    if args.output:
        pathlib.Path(args.output).write_bytes(output)
    else:
        sys.stdout.buffer.write(output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
