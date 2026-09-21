"""Venue-authenticated, exact-context links from an ACSD release to a submission.

This is deliberately a thin profile.  It authenticates a venue challenge and
the assent of release author-slot keys to that exact challenge.  It does not
operate a submission service or authenticate civil identity.
"""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import re
import secrets
from typing import Iterable, Mapping, Optional, Tuple

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

import cose
from canonical_json import canonical, digest, require
from key_identity import key_id_of


CHALLENGE_SCHEMA = "acsd-submission-challenge/v1"
OPENING_SCHEMA = "acsd-submission-opening/v1"
HANDLE_COMMITMENT_SCHEMA = "acsd-submission-handle-commitment/v1"
PURPOSE = "submission-lineage-link"
DISCLOSURE_MODES = {"editor-confidential", "public"}
HEX64 = re.compile(r"^[0-9a-f]{64}$")
UTC_INSTANT = re.compile(
    r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\+00:00$"
)


def _utc(value: str, code: str) -> datetime:
    require(isinstance(value, str) and UTC_INSTANT.fullmatch(value), code)
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as exc:
        raise ValueError(code) from exc
    require(parsed.tzinfo == timezone.utc, code)
    return parsed


def _release_id(release) -> str:
    return "urn:sha256:" + digest(release)


def _author_for_slot(release, slot: int):
    matches = [author for author in release.get("authors", []) if author.get("slot") == slot]
    require(len(matches) == 1, "SUBMISSION_AUTHOR_SLOT_INVALID")
    return matches[0]


def handle_commitment(
    venue_domain: str, challenge_nonce: str, submission_handle: str
) -> str:
    require(isinstance(submission_handle, str) and bool(submission_handle), "SUBMISSION_HANDLE_INVALID")
    return digest({
        "schema": HANDLE_COMMITMENT_SCHEMA,
        "venue_domain": venue_domain,
        "challenge_nonce": challenge_nonce,
        "submission_handle": submission_handle,
    })


def _validate_byline(byline, release) -> None:
    require(isinstance(byline, list) and bool(byline), "SUBMISSION_BYLINE_INVALID")
    release_slots = {author["slot"] for author in release.get("authors", [])}
    seen_slots = set()
    for expected_position, item in enumerate(byline, 1):
        require(isinstance(item, dict) and set(item) == {
            "position", "author_slot", "display_name", "persistent_identifier"
        }, "SUBMISSION_BYLINE_INVALID")
        require(item.get("position") == expected_position, "SUBMISSION_BYLINE_ORDER_INVALID")
        slot = item.get("author_slot")
        require(
            isinstance(slot, int) and not isinstance(slot, bool) and slot in release_slots,
            "SUBMISSION_AUTHOR_SLOT_INVALID",
        )
        require(slot not in seen_slots, "SUBMISSION_BYLINE_DUPLICATE_SLOT")
        seen_slots.add(slot)
        require(
            isinstance(item.get("display_name"), str)
            and bool(item["display_name"].strip()),
            "SUBMISSION_IDENTITY_ASSERTION_INVALID",
        )
        require(
            item.get("persistent_identifier") is None
            or isinstance(item.get("persistent_identifier"), str),
            "SUBMISSION_IDENTITY_ASSERTION_INVALID",
        )


def build_challenge(
    release,
    submitted_manuscript_sha256: str,
    venue_domain: str,
    venue_key_id: str,
    submission_handle: str,
    review_round: int,
    issued_at_utc: str,
    expires_at_utc: str,
    disclosure_mode: str,
    ordered_byline,
    challenge_nonce: Optional[str] = None,
):
    require(
        isinstance(submitted_manuscript_sha256, str)
        and HEX64.fullmatch(submitted_manuscript_sha256),
        "SUBMITTED_MANUSCRIPT_DIGEST_INVALID",
    )
    require(
        isinstance(venue_domain, str)
        and bool(venue_domain)
        and venue_domain == venue_domain.strip().lower()
        and venue_domain.isascii()
        and not any(character.isspace() for character in venue_domain),
        "VENUE_DOMAIN_INVALID",
    )
    require(isinstance(venue_key_id, str) and HEX64.fullmatch(venue_key_id), "VENUE_KEY_ID_INVALID")
    require(
        isinstance(review_round, int) and not isinstance(review_round, bool) and review_round >= 1,
        "REVIEW_ROUND_INVALID",
    )
    issued = _utc(issued_at_utc, "CHALLENGE_ISSUED_AT_INVALID")
    expires = _utc(expires_at_utc, "CHALLENGE_EXPIRES_AT_INVALID")
    require(issued < expires, "CHALLENGE_INTERVAL_INVALID")
    require(disclosure_mode in DISCLOSURE_MODES, "DISCLOSURE_MODE_INVALID")
    _validate_byline(ordered_byline, release)
    nonce = challenge_nonce or secrets.token_hex(32)
    require(isinstance(nonce, str) and HEX64.fullmatch(nonce), "CHALLENGE_NONCE_INVALID")
    return {
        "schema": CHALLENGE_SCHEMA,
        "source_release_id": _release_id(release),
        "work_id": release["work_id"],
        "submitted_manuscript_sha256": submitted_manuscript_sha256,
        "venue": {"domain": venue_domain, "key_id": venue_key_id},
        "submission_handle_commitment": handle_commitment(
            venue_domain, nonce, submission_handle
        ),
        "review_round": review_round,
        "challenge_nonce": nonce,
        "issued_at_utc": issued_at_utc,
        "expires_at_utc": expires_at_utc,
        "disclosure_mode": disclosure_mode,
        "ordered_byline": ordered_byline,
        "purpose": PURPOSE,
    }


def verify_challenge(
    challenge,
    signature: bytes,
    release,
    venue_public_key: Ed25519PublicKey,
    submitted_manuscript_sha256: str,
    submission_handle: str,
    now_utc: Optional[datetime] = None,
):
    expected_fields = {
        "schema", "source_release_id", "work_id", "submitted_manuscript_sha256",
        "venue", "submission_handle_commitment", "review_round", "challenge_nonce",
        "issued_at_utc", "expires_at_utc", "disclosure_mode", "ordered_byline",
        "purpose",
    }
    require(challenge.get("schema") == CHALLENGE_SCHEMA, "SUBMISSION_CHALLENGE_SCHEMA")
    require(set(challenge) == expected_fields, "SUBMISSION_CHALLENGE_FIELDS")
    require(challenge.get("source_release_id") == _release_id(release), "SUBMISSION_RELEASE_MISMATCH")
    require(challenge.get("work_id") == release.get("work_id"), "SUBMISSION_WORK_MISMATCH")
    require(
        challenge.get("submitted_manuscript_sha256") == submitted_manuscript_sha256
        and isinstance(submitted_manuscript_sha256, str)
        and HEX64.fullmatch(submitted_manuscript_sha256),
        "SUBMITTED_MANUSCRIPT_MISMATCH",
    )
    venue = challenge.get("venue")
    require(isinstance(venue, dict) and set(venue) == {"domain", "key_id"}, "VENUE_INVALID")
    require(
        isinstance(venue.get("domain"), str)
        and venue["domain"] == venue["domain"].strip().lower()
        and venue["domain"].isascii()
        and bool(venue["domain"])
        and not any(character.isspace() for character in venue["domain"]),
        "VENUE_DOMAIN_INVALID",
    )
    require(venue.get("key_id") == key_id_of(venue_public_key), "VENUE_KEY_ID_MISMATCH")
    nonce = challenge.get("challenge_nonce")
    require(isinstance(nonce, str) and HEX64.fullmatch(nonce), "CHALLENGE_NONCE_INVALID")
    require(
        challenge.get("submission_handle_commitment")
        == handle_commitment(venue["domain"], nonce, submission_handle),
        "SUBMISSION_HANDLE_MISMATCH",
    )
    require(
        isinstance(challenge.get("review_round"), int)
        and not isinstance(challenge["review_round"], bool)
        and challenge["review_round"] >= 1,
        "REVIEW_ROUND_INVALID",
    )
    issued = _utc(challenge.get("issued_at_utc"), "CHALLENGE_ISSUED_AT_INVALID")
    expires = _utc(challenge.get("expires_at_utc"), "CHALLENGE_EXPIRES_AT_INVALID")
    require(issued < expires, "CHALLENGE_INTERVAL_INVALID")
    instant = now_utc or datetime.now(timezone.utc)
    require(instant.tzinfo is not None and instant.utcoffset() == timezone.utc.utcoffset(instant), "VERIFICATION_TIME_INVALID")
    require(issued <= instant <= expires, "SUBMISSION_CHALLENGE_NOT_CURRENT")
    require(challenge.get("disclosure_mode") in DISCLOSURE_MODES, "DISCLOSURE_MODE_INVALID")
    _validate_byline(challenge.get("ordered_byline"), release)
    require(challenge.get("purpose") == PURPOSE, "SUBMISSION_PURPOSE_INVALID")
    try:
        cose.cose_verify(signature, venue_public_key, expected_payload=canonical(challenge))
    except ValueError:
        raise
    except Exception as exc:
        raise ValueError("VENUE_CHALLENGE_SIGNATURE_INVALID") from exc
    return {
        "status": "AUTHENTICATED_SUBMISSION_CHALLENGE",
        "challenge_digest": digest(challenge),
        "venue_domain": venue["domain"],
        "review_round": challenge["review_round"],
        "disclosure_mode": challenge["disclosure_mode"],
    }


def build_opening(challenge, release, slot: int):
    author = _author_for_slot(release, slot)
    require(
        any(item.get("author_slot") == slot for item in challenge.get("ordered_byline", [])),
        "SUBMISSION_SLOT_NOT_REQUESTED",
    )
    return {
        "schema": OPENING_SCHEMA,
        "challenge_digest": digest(challenge),
        "source_release_id": _release_id(release),
        "author_slot": slot,
        "author_key_id": author["key_id"],
        "disclosure_authorization": (
            "editor-confidential-only"
            if challenge.get("disclosure_mode") == "editor-confidential"
            else "public-submission-link"
        ),
        "purpose": PURPOSE,
    }


def verify_opening(
    opening,
    signature: bytes,
    challenge,
    release,
    public_key: Ed25519PublicKey,
):
    require(opening.get("schema") == OPENING_SCHEMA, "SUBMISSION_OPENING_SCHEMA")
    require(set(opening) == {
        "schema", "challenge_digest", "source_release_id", "author_slot",
        "author_key_id", "disclosure_authorization", "purpose",
    }, "SUBMISSION_OPENING_FIELDS")
    require(opening.get("challenge_digest") == digest(challenge), "SUBMISSION_CHALLENGE_MISMATCH")
    require(opening.get("source_release_id") == _release_id(release), "SUBMISSION_RELEASE_MISMATCH")
    slot = opening.get("author_slot")
    require(isinstance(slot, int) and not isinstance(slot, bool), "SUBMISSION_AUTHOR_SLOT_INVALID")
    author = _author_for_slot(release, slot)
    require(opening.get("author_key_id") == author.get("key_id"), "SUBMISSION_SLOT_KEY_MISMATCH")
    require(key_id_of(public_key) == author.get("key_id"), "PUBLIC_KEY_ID_MISMATCH")
    require(
        any(item.get("author_slot") == slot for item in challenge.get("ordered_byline", [])),
        "SUBMISSION_SLOT_NOT_REQUESTED",
    )
    expected_authorization = (
        "editor-confidential-only"
        if challenge.get("disclosure_mode") == "editor-confidential"
        else "public-submission-link"
    )
    require(opening.get("disclosure_authorization") == expected_authorization, "DISCLOSURE_AUTHORIZATION_MISMATCH")
    require(opening.get("purpose") == PURPOSE, "SUBMISSION_PURPOSE_INVALID")
    try:
        cose.cose_verify(signature, public_key, expected_payload=canonical(opening))
    except ValueError:
        raise
    except Exception as exc:
        raise ValueError("SUBMISSION_OPENING_SIGNATURE_INVALID") from exc
    return {"author_slot": slot, "author_key_id": author["key_id"]}


def verify_set(
    challenge,
    challenge_signature: bytes,
    openings: Iterable[Tuple[dict, bytes]],
    release,
    venue_public_key: Ed25519PublicKey,
    author_public_keys: Mapping[str, Ed25519PublicKey],
    submitted_manuscript_sha256: str,
    submission_handle: str,
    now_utc: Optional[datetime] = None,
):
    challenge_result = verify_challenge(
        challenge, challenge_signature, release, venue_public_key,
        submitted_manuscript_sha256, submission_handle, now_utc=now_utc,
    )
    results = []
    seen_slots = set()
    signature_digests = []
    for opening, signature in openings:
        key_id = opening.get("author_key_id")
        require(key_id in author_public_keys, "SUBMISSION_PUBLIC_KEY_MISSING")
        result = verify_opening(
            opening, signature, challenge, release, author_public_keys[key_id]
        )
        require(result["author_slot"] not in seen_slots, "VERIFIED_SUBMISSION_SLOT_EQUIVOCATION")
        seen_slots.add(result["author_slot"])
        signature_digests.append(hashlib.sha256(signature).hexdigest())
        results.append(result)
    requested_slots = {item["author_slot"] for item in challenge["ordered_byline"]}
    release_slots = {author["slot"] for author in release.get("authors", [])}
    requested_complete = seen_slots == requested_slots
    full_byline = requested_complete and requested_slots == release_slots
    status = (
        "FULL_BYLINE_SUBMISSION_LINEAGE_LINKED"
        if full_byline
        else "REQUESTED_SUBMISSION_LINK_VERIFIED"
        if requested_complete
        else "PARTIAL_SUBMISSION_LINK_VERIFIED"
    )
    claim = (
        "SUBMISSION_LINEAGE_LINKED"
        if full_byline
        else "REQUESTED_SUBMISSION_SLOTS_LINKED"
        if requested_complete
        else "PARTIAL_SUBMISSION_SLOT_ASSENT"
    )
    certificate_digest = digest({
        "challenge_digest": challenge_result["challenge_digest"],
        "venue_signature_sha256": hashlib.sha256(challenge_signature).hexdigest(),
        "opening_signature_sha256": sorted(signature_digests),
    })
    return {
        "status": status,
        "claim": claim,
        "verification_certificate_digest": certificate_digest,
        "full_byline": full_byline,
        "requested_complete": requested_complete,
        "disclosed_slots": sorted(seen_slots),
        "requested_slots": sorted(requested_slots),
        "release_slots": sorted(release_slots),
        "challenge": challenge_result,
        "results": results,
        "non_claims": [
            "natural_person_identity_verified",
            "originality_verified",
            "publication_acceptance_verified",
            "submission_discoverability_guaranteed",
            "signers_uncompromised_at_response_time",
        ],
    }
