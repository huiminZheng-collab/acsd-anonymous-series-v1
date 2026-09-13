"""Per-author-slot selective identity disclosure for an exact ACSD release."""

from __future__ import annotations

import hashlib
from typing import Iterable, Mapping, Tuple

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

import cose
import claim_derivation as claim_core
from pec_core import canonical, digest, require


SCHEMA = "acsd-identity-disclosure/v1"
PURPOSE = "publication-unblinding"


def key_id_of(public_key: Ed25519PublicKey) -> str:
    der = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return hashlib.sha256(der).hexdigest()


def _author_for_slot(release, slot: int):
    matches = [author for author in release.get("authors", []) if author.get("slot") == slot]
    require(len(matches) == 1, "IDENTITY_AUTHOR_SLOT_INVALID")
    return matches[0]


def build(
    release,
    slot: int,
    display_name: str,
    persistent_identifier=None,
    publication_ref=None,
):
    author = _author_for_slot(release, slot)
    require(isinstance(display_name, str) and bool(display_name.strip()), "IDENTITY_ASSERTION_INVALID")
    require(
        persistent_identifier is None or isinstance(persistent_identifier, str),
        "IDENTITY_ASSERTION_INVALID",
    )
    require(publication_ref is None or isinstance(publication_ref, str), "PUBLICATION_REF_INVALID")
    return {
        "schema": SCHEMA,
        "release_id": "urn:sha256:" + digest(release),
        "work_id": release["work_id"],
        "author_slot": slot,
        "author_key_id": author["key_id"],
        "identity_assertion": {
            "display_name": display_name,
            "persistent_identifier": persistent_identifier,
        },
        "purpose": PURPOSE,
        "publication_ref": publication_ref,
    }


def verify(body, signature: bytes, release, public_key: Ed25519PublicKey):
    require(body.get("schema") == SCHEMA, "IDENTITY_DISCLOSURE_SCHEMA")
    expected_fields = {
        "schema", "release_id", "work_id", "author_slot", "author_key_id",
        "identity_assertion", "purpose", "publication_ref",
    }
    require(set(body) == expected_fields, "IDENTITY_DISCLOSURE_FIELDS")
    slot = body.get("author_slot")
    require(isinstance(slot, int) and not isinstance(slot, bool), "IDENTITY_AUTHOR_SLOT_INVALID")
    author = _author_for_slot(release, slot)
    require(body.get("release_id") == "urn:sha256:" + digest(release), "IDENTITY_RELEASE_MISMATCH")
    require(body.get("work_id") == release.get("work_id"), "IDENTITY_WORK_MISMATCH")
    require(body.get("author_key_id") == author.get("key_id"), "IDENTITY_SLOT_KEY_MISMATCH")
    require(key_id_of(public_key) == author.get("key_id"), "PUBLIC_KEY_ID_MISMATCH")
    assertion = body.get("identity_assertion")
    require(isinstance(assertion, dict) and set(assertion) == {
        "display_name", "persistent_identifier"
    }, "IDENTITY_ASSERTION_INVALID")
    require(
        isinstance(assertion.get("display_name"), str)
        and bool(assertion["display_name"].strip()),
        "IDENTITY_ASSERTION_INVALID",
    )
    require(
        assertion.get("persistent_identifier") is None
        or isinstance(assertion.get("persistent_identifier"), str),
        "IDENTITY_ASSERTION_INVALID",
    )
    require(body.get("purpose") == PURPOSE, "IDENTITY_PURPOSE_INVALID")
    require(
        body.get("publication_ref") is None
        or isinstance(body.get("publication_ref"), str),
        "PUBLICATION_REF_INVALID",
    )
    try:
        cose.cose_verify(signature, public_key, expected_payload=canonical(body))
    except ValueError:
        raise
    except Exception as exc:
        raise ValueError("IDENTITY_DISCLOSURE_SIGNATURE_INVALID") from exc
    subject = claim_core.IdentitySubject(
        digest(release),
        slot,
        author["key_id"],
        digest(assertion),
    )
    derivations = claim_core.derive(
        [claim_core.AppraisedEvidence(
            claim_core.EvidenceKind.SLOT_IDENTITY_ASSENT,
            subject,
            hashlib.sha256(signature).hexdigest(),
        )],
        [claim_core.ClaimKind.SLOT_KEY_ASSENT_TO_IDENTITY_ASSERTION],
    )
    outcomes = claim_core.wire_outcomes(derivations)
    require(
        outcomes == ("SLOT_KEY_ASSENT_TO_IDENTITY_ASSERTION",),
        "CLAIM_NOT_DERIVED",
    )
    return {
        "status": outcomes[0],
        "author_slot": slot,
        "author_key_id": author["key_id"],
        "identity_assertion": assertion,
        "non_claims": ["natural_person_identity_verified", "publication_acceptance_verified"],
    }


def verify_set(
    disclosures: Iterable[Tuple[dict, bytes]],
    release,
    public_keys: Mapping[str, Ed25519PublicKey],
):
    """Verify a set without treating partial unblinding as a full byline."""
    results = []
    seen_slots = set()
    publication_refs = []
    for body, signature in disclosures:
        slot = body.get("author_slot")
        key_id = body.get("author_key_id")
        require(key_id in public_keys, "IDENTITY_PUBLIC_KEY_MISSING")
        result = verify(body, signature, release, public_keys[key_id])
        require(slot not in seen_slots, "VERIFIED_IDENTITY_SLOT_EQUIVOCATION")
        seen_slots.add(slot)
        results.append(result)
        publication_refs.append(body.get("publication_ref"))
    required_slots = {author["slot"] for author in release.get("authors", [])}
    full = seen_slots == required_slots
    shared_publication_ref = None
    if publication_refs and publication_refs[0] is not None and len(set(publication_refs)) == 1:
        shared_publication_ref = publication_refs[0]
    return {
        "status": "FULL_BYLINE_KEY_ASSENT" if full else "PARTIAL_BYLINE_KEY_ASSENT",
        "full_byline": full,
        "disclosed_slots": sorted(seen_slots),
        "required_slots": sorted(required_slots),
        "shared_publication_ref": shared_publication_ref,
        "results": results,
        "non_claims": [
            "natural_person_identity_verified",
            "joint_team_statement",
            "publication_acceptance_verified",
        ],
    }
