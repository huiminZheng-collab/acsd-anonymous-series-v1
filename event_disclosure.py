"""Atomic verification for policy-scoped ACSD event disclosures."""

from __future__ import annotations

import hashlib
from typing import Mapping

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

import cose
from pec_core import canonical, digest, require, verify_dialogue_window


DISCLOSURE_SCHEMA = "acsd-event-disclosure/v1"
POLICY_SCHEMA = "acsd-disclosure-policy/v1"
DEFAULT_POLICY = {
    "schema": POLICY_SCHEMA,
    "event_kinds": {
        "dialogue_snapshot": {
            "modes": ["dialogue_window"],
            "authorization": "all-release-authors",
        }
    },
}


def key_id_of(public_key: Ed25519PublicKey) -> str:
    der = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return hashlib.sha256(der).hexdigest()


def validate_policy(policy) -> None:
    require(policy == DEFAULT_POLICY, "DISCLOSURE_POLICY_INVALID")


def _event_for(disclosure, pec):
    matches = [
        event for event in pec.get("events", [])
        if event.get("event_id") == disclosure.get("event_id")
    ]
    require(len(matches) == 1, "DISCLOSURE_EVENT_NOT_FOUND")
    event = matches[0]
    require(disclosure.get("pec_digest") == digest(pec), "DISCLOSURE_BINDING_MISMATCH")
    require(disclosure.get("event_sequence") == event.get("sequence"), "DISCLOSURE_BINDING_MISMATCH")
    require(disclosure.get("kind") == event.get("kind"), "DISCLOSURE_BINDING_MISMATCH")
    return event


def verify_event_disclosure(
    disclosure,
    pec,
    public_keys: Mapping[str, Ed25519PublicKey],
    signatures: Mapping[str, bytes],
):
    """Verify policy, opening, and every required signature as one decision.

    The disclosure body contains no self-authorizing signer list.  Its signer
    set is derived from the already-approved PEC governance binding.
    """
    require(disclosure.get("schema") == DISCLOSURE_SCHEMA, "DISCLOSURE_SCHEMA")
    policy = pec.get("disclosure_policy")
    validate_policy(policy)
    event = _event_for(disclosure, pec)
    rule = policy["event_kinds"].get(event.get("kind"))
    require(rule is not None, "DISCLOSURE_KIND_NOT_PERMITTED")
    mode = disclosure.get("disclosure_mode")
    require(mode in rule["modes"], "DISCLOSURE_MODE_NOT_PERMITTED")
    require(rule["authorization"] == "all-release-authors", "DISCLOSURE_POLICY_INVALID")

    commitment = event.get("commitment", {})
    require(commitment.get("disclosure_class") == "revealable", "EVENT_NOT_REVEALABLE")
    require(
        commitment.get("scheme") == "merkle-dialogue-v1" and mode == "dialogue_window",
        "COMMITMENT_SCHEME_MISMATCH",
    )
    opened = disclosure.get("opened_material")
    require(isinstance(opened, list), "DISCLOSURE_OPENING_INVALID")
    try:
        window = [
            {
                "index": item["index"],
                "bytes": item["bytes"].encode("utf-8"),
                "salt": bytes.fromhex(item["salt"]),
                "path": item["path"],
            }
            for item in opened
        ]
    except (AttributeError, KeyError, TypeError, ValueError) as exc:
        raise ValueError("DISCLOSURE_OPENING_INVALID") from exc
    verify_dialogue_window(commitment.get("digest"), window)

    required = sorted(pec["governance"]["required_pec_approval_key_ids"])
    require(sorted(public_keys) == required, "DISCLOSURE_PUBLIC_KEY_SET_MISMATCH")
    require(sorted(signatures) == required, "DISCLOSURE_APPROVAL_MISSING")
    body = canonical(disclosure)
    for key_id in required:
        public_key = public_keys[key_id]
        require(key_id_of(public_key) == key_id, "PUBLIC_KEY_ID_MISMATCH")
        try:
            cose.cose_verify(signatures[key_id], public_key, expected_payload=body)
        except ValueError:
            raise
        except Exception as exc:
            raise ValueError("DISCLOSURE_SIGNATURE_INVALID") from exc
    return {
        "status": "VALID",
        "outcome": "COMMITTED_EVIDENCE_MATCH",
        "event_id": event["event_id"],
        "authorized_by": required,
    }
