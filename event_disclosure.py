"""Atomic verification for policy-scoped ACSD event disclosures."""

from __future__ import annotations

import hashlib
from typing import Mapping

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

import cose
import claim_derivation as claim_core
from bundle_validation import (
    DEFAULT_DISCLOSURE_POLICY as DEFAULT_POLICY,
    new_disclosure_policy,
)
from canonical_json import HEX, canonical, digest, require
from key_identity import key_id_of
from pec_core import verify_dialogue_window


DISCLOSURE_SCHEMA = "acsd-event-disclosure/v1"
POLICY_SCHEMA = "acsd-disclosure-policy/v1"


def validate_policy(policy) -> None:
    require(policy == new_disclosure_policy(), "DISCLOSURE_POLICY_INVALID")


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
    *,
    accepted_pec_digest: str,
):
    """Verify policy, opening, and every required signature as one decision.

    The disclosure body contains no self-authorizing signer list.  Its signer
    set is derived from the already-approved PEC governance binding.
    """
    require(disclosure.get("schema") == DISCLOSURE_SCHEMA, "DISCLOSURE_SCHEMA")
    require(
        set(disclosure) == {
            "schema", "pec_digest", "event_id", "event_sequence", "kind",
            "disclosure_mode", "opened_material",
        },
        "DISCLOSURE_FIELDS",
    )
    require(
        isinstance(accepted_pec_digest, str)
        and HEX.fullmatch(accepted_pec_digest)
        and accepted_pec_digest == digest(pec),
        "PEC_NOT_ACCEPTED",
    )
    require(
        "COMMITTED_EVIDENCE_MATCH"
        in pec.get("claim_policy", {}).get("permitted_outcomes", []),
        "CLAIM_NOT_AUTHORIZED",
    )
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
    require(
        isinstance(commitment.get("digest"), str)
        and HEX.fullmatch(commitment["digest"]),
        "DIALOGUE_ROOT",
    )
    opened = disclosure.get("opened_material")
    require(isinstance(opened, list), "DISCLOSURE_OPENING_INVALID")
    try:
        window = []
        for item in opened:
            require(
                isinstance(item, dict)
                and set(item) == {"index", "bytes", "salt", "path"},
                "DISCLOSURE_OPENING_INVALID",
            )
            require(
                isinstance(item["index"], int)
                and not isinstance(item["index"], bool)
                and item["index"] >= 0
                and isinstance(item["bytes"], str)
                and isinstance(item["salt"], str),
                "DISCLOSURE_OPENING_INVALID",
            )
            salt = bytes.fromhex(item["salt"])
            require(len(salt) == 32, "DISCLOSURE_SALT_INVALID")
            window.append({
                "index": item["index"],
                "bytes": item["bytes"].encode("utf-8"),
                "salt": salt,
                "path": item["path"],
            })
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
    subject = claim_core.EventSubject(
        accepted_pec_digest,
        event["event_id"],
        event["sequence"],
        commitment["digest"],
        window[0]["index"],
        window[-1]["index"],
    )
    certificate_digest = digest({
        "body_digest": digest(disclosure),
        "signature_digests": [
            {"key_id": key_id, "sha256": hashlib.sha256(signatures[key_id]).hexdigest()}
            for key_id in required
        ],
    })
    derivations = claim_core.derive(
        [claim_core.AppraisedEvidence(
            claim_core.EvidenceKind.EVENT_DISCLOSURE,
            subject,
            certificate_digest,
        )],
        claim_core.permitted_claims(
            pec.get("claim_policy", {}).get("permitted_outcomes", [])
        ),
    )
    outcomes = claim_core.wire_outcomes(derivations)
    require(outcomes == ("COMMITTED_EVIDENCE_MATCH",), "CLAIM_NOT_DERIVED")
    return {
        "status": "VALID",
        "outcome": outcomes[0],
        "pec_digest": accepted_pec_digest,
        "event_id": event["event_id"],
        "event_sequence": event["sequence"],
        "commitment_digest": commitment["digest"],
        "window": {"first_index": window[0]["index"], "last_index": window[-1]["index"]},
        "authorized_by": required,
    }
