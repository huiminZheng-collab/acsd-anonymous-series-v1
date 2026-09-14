"""I/O-free construction and validation of ACSD protocol objects.

This layer owns the wire schemas and exact cross-object bindings.  It does not
read files, verify signatures, contact a timestamp authority, or grant claims
from unappraised bytes.
"""

import hashlib
import uuid

import claim_derivation as claim_core
from bundle_validation import (
    CURRENT_PEC_SCHEMA as PEC_SCHEMA,
    GLOBAL_NON_CLAIMS,
    GOVERNANCE_SCHEMA,
    new_disclosure_policy,
    validate_pec_bundle,
)
from canonical_json import digest, require
from key_identity import KEY_ID_RE, validate_key_id
from release_adapter import adapt_release


TEAM_SCHEMA = "acsd-team/v1"
RELEASE_SCHEMA = "acsd-v3-paper-release/v1"
LEGACY_RELEASE_SCHEMA = "acsd-v1.6.0-paper-release/v1"
APPROVAL_TARGET_SCHEMA = "acsd-approval-target/v2"
LEGACY_APPROVAL_TARGET_SCHEMA = "acsd-approval-target/v1"
LINEAGE_AUTHORITY_SCHEMA = "acsd-lineage-authority/v1"
RECOVERABLE_LINEAGE_AUTHORITY_SCHEMA = "acsd-lineage-authority/v2"
RECOVERY_AUTHORITY_SCHEMA = "acsd-recovery-authority/v1"
LINEAGE_TRANSITION_SCHEMA = "acsd-lineage-transition/v1"


def new_ai_use_declaration():
    """Return a fresh default declaration with no shared mutable lists."""
    return {
        "used": False,
        "purposes": [],
        "tools": [],
        "human_review_key_ids": [],
    }


# Compatibility value for callers that display the default. Builders below
# always call the factory so returned objects never share mutable list state.
DEFAULT_AI_USE = new_ai_use_declaration()


def lineage_authority_of(release):
    """Return and validate the authority controlling the next lineage edge."""
    author_keys = sorted(
        validate_key_id(author["key_id"])
        for author in release.get("authors", [])
    )
    require(
        author_keys and len(author_keys) == len(set(author_keys)),
        "LINEAGE_AUTHORITY_INVALID",
    )
    authority = release.get("lineage_authority")
    if authority is None:
        return {
            "schema": LINEAGE_AUTHORITY_SCHEMA,
            "key_ids": author_keys,
            "threshold": len(author_keys),
        }
    schema = authority.get("schema")
    require(
        schema in {LINEAGE_AUTHORITY_SCHEMA, RECOVERABLE_LINEAGE_AUTHORITY_SCHEMA},
        "LINEAGE_AUTHORITY_INVALID",
    )
    keys = authority.get("key_ids")
    threshold = authority.get("threshold")
    require(
        keys == sorted(keys or []) and len(keys) == len(set(keys or [])),
        "LINEAGE_AUTHORITY_INVALID",
    )
    require(
        all(isinstance(key, str) and KEY_ID_RE.fullmatch(key) for key in keys),
        "KEY_ID_INVALID",
    )
    require(keys == author_keys, "LINEAGE_AUTHORITY_KEY_SET_MISMATCH")
    require(
        isinstance(threshold, int) and not isinstance(threshold, bool),
        "LINEAGE_THRESHOLD_INVALID",
    )
    require(1 <= threshold <= len(keys), "LINEAGE_THRESHOLD_INVALID")
    if schema == LINEAGE_AUTHORITY_SCHEMA:
        require(
            set(authority) == {"schema", "key_ids", "threshold"},
            "LINEAGE_AUTHORITY_FIELDS",
        )
    else:
        require(
            set(authority) == {"schema", "key_ids", "threshold", "recovery"},
            "LINEAGE_AUTHORITY_FIELDS",
        )
        recovery = authority.get("recovery")
        require(isinstance(recovery, dict), "RECOVERY_AUTHORITY_INVALID")
        require(
            set(recovery) == {"schema", "key_ids", "threshold"}
            and recovery.get("schema") == RECOVERY_AUTHORITY_SCHEMA,
            "RECOVERY_AUTHORITY_INVALID",
        )
        recovery_keys = recovery.get("key_ids")
        recovery_threshold = recovery.get("threshold")
        require(
            isinstance(recovery_keys, list)
            and recovery_keys == sorted(recovery_keys)
            and len(recovery_keys) >= 1
            and len(recovery_keys) == len(set(recovery_keys))
            and all(
                isinstance(key, str) and KEY_ID_RE.fullmatch(key)
                for key in recovery_keys
            ),
            "RECOVERY_AUTHORITY_INVALID",
        )
        require(
            isinstance(recovery_threshold, int)
            and not isinstance(recovery_threshold, bool)
            and 1 <= recovery_threshold <= len(recovery_keys),
            "RECOVERY_THRESHOLD_INVALID",
        )
        require(
            set(keys).isdisjoint(recovery_keys),
            "RECOVERY_AUTHORITY_NOT_DISJOINT",
        )
    return authority


def recovery_authority_of(release):
    """Return the predecessor-bound optional recovery authority."""
    authority = lineage_authority_of(release)
    return authority.get("recovery")


def online_lineage_authority(authority):
    """Project the online key set and threshold from a validated authority."""
    return {
        "key_ids": authority["key_ids"],
        "threshold": authority["threshold"],
    }


def online_lineage_authority_of(release):
    """Project the online key set and threshold from a release."""
    return online_lineage_authority(lineage_authority_of(release))


def build_release(
    work_id,
    content_sha256,
    content_path,
    team,
    *,
    parent_release=None,
    line="main",
    lineage_threshold=None,
    recovery_authority=None,
):
    corresponding_key = next(
        (author["key_id"] for author in team["authors"] if author.get("corresponding")),
        team["authors"][0]["key_id"],
    )
    authors = []
    for index, author in enumerate(team["authors"], 1):
        authors.append({
            "slot": index,
            "key_id": author["key_id"],
            "role": author.get("role", "co-first"),
            "corresponding": author["key_id"] == corresponding_key,
            "contributions": list(author.get("contributions", [])),
            "issuer": author.get(
                "issuer",
                f"urn:acsd:pseudonym:{author['key_id'][:12]}",
            ),
            "kid_hex": author["key_id"][:16],
            "public_key_path": f"public-keys/{author['key_id']}.pub",
        })
    key_ids = sorted(author["key_id"] for author in team["authors"])
    threshold = len(key_ids) if lineage_threshold is None else lineage_threshold
    require(
        isinstance(threshold, int) and not isinstance(threshold, bool),
        "LINEAGE_THRESHOLD_INVALID",
    )
    require(1 <= threshold <= len(key_ids), "LINEAGE_THRESHOLD_INVALID")
    if parent_release is None:
        version = 1
        parent_release_id = None
    else:
        parent_slot = parent_release["slot"]
        version = parent_slot["version"] + 1 if line == parent_slot["line"] else 1
        parent_release_id = "urn:sha256:" + digest(parent_release)
    lineage_authority = {
        "schema": LINEAGE_AUTHORITY_SCHEMA,
        "key_ids": key_ids,
        "threshold": threshold,
    }
    if recovery_authority is not None:
        lineage_authority = {
            "schema": RECOVERABLE_LINEAGE_AUTHORITY_SCHEMA,
            "key_ids": key_ids,
            "threshold": threshold,
            "recovery": recovery_authority,
        }
    release = {
        "schema": RELEASE_SCHEMA,
        "work_id": work_id,
        "slot": {"line": line, "version": version, "work_id": work_id},
        "content": {"path": content_path, "sha256": content_sha256},
        "authors": authors,
        "lineage_authority": lineage_authority,
        "citation_witnesses": [],
        "reference_work_ids": [],
        "ai_use": new_ai_use_declaration(),
        "parent_release_id": parent_release_id,
        "issued_at": 0,
        "standalone_semantics": (
            "Every listed author key endorses this exact release payload; "
            "series membership is optional."
        ),
    }
    lineage_authority_of(release)
    return release


def build_governance(work_id, content_sha256, team):
    byline = [
        {
            "key_id": author["key_id"],
            "slot": index,
            "role": author.get("role", "co-first"),
        }
        for index, author in enumerate(team["authors"], 1)
    ]
    corresponding = next(
        (author["key_id"] for author in team["authors"] if author.get("corresponding")),
        team["authors"][0]["key_id"],
    )
    return {
        "schema": GOVERNANCE_SCHEMA,
        "work_id": work_id,
        "manuscript_sha256": content_sha256,
        "byline": byline,
        "corresponding_author": {"key_id": corresponding},
        "ai_use_declaration": new_ai_use_declaration(),
    }


def build_pec(
    work_id,
    adapted,
    gov_digest,
    content_sha256,
    ai_digest,
    key_ids,
    predecessor_pec=None,
):
    return {
        "schema": PEC_SCHEMA,
        "pec_id": "pec-" + uuid.uuid4().hex[:8],
        "subject": {
            "work_id": work_id,
            "release_digest": adapted["digest"],
            "version": f"v{adapted['version']}",
            "line": adapted["line"],
            "predecessor_pec_digest": (
                digest(predecessor_pec) if predecessor_pec is not None else None
            ),
            "series_package_digest": None,
        },
        "governance": {
            "statement_digest": gov_digest,
            "manuscript_sha256": content_sha256,
            "required_pec_approval_key_ids": sorted(key_ids),
            "ai_use_declaration_digest": ai_digest,
        },
        "events": [],
        "disclosure_policy": new_disclosure_policy(),
        "claim_policy": {
            "permitted_outcomes": [
                "KEY_ASSENT",
                "GOVERNANCE_ASSENT",
                "APPROVAL_SET_EXISTED_NOT_AFTER",
                "AUTHORIZED_SUCCESSOR",
            ],
            "global_non_claims": list(GLOBAL_NON_CLAIMS),
            "required_capabilities": {
                "APPROVAL_SET_EXISTED_NOT_AFTER": [
                    "rfc3161-exact-approval-set-imprint"
                ],
                "AUTHORIZED_SUCCESSOR": [
                    "predecessor-authority-exact-transition"
                ],
            },
        },
        "issuer_key_id": key_ids[0],
    }


def build_lineage_transition(parent_release, parent_pec, release, governance, pec):
    """Build the acyclic parent-to-child authorization body."""
    parent = adapt_release(parent_release)
    child = adapt_release(release)
    parent_authority = lineage_authority_of(parent_release)
    child_authority = lineage_authority_of(release)
    if parent["line"] != child["line"]:
        kind = "branch"
    elif parent_authority["key_ids"] != child_authority["key_ids"]:
        kind = "team-change"
    elif parent_authority["threshold"] != child_authority["threshold"]:
        kind = "threshold-change"
    elif parent_authority.get("recovery") != child_authority.get("recovery"):
        kind = "recovery-change"
    else:
        kind = "continuation"
    return {
        "schema": LINEAGE_TRANSITION_SCHEMA,
        "kind": kind,
        "work_id": child["work_id"],
        "parent": {
            "release_digest": parent["digest"],
            "pec_digest": digest(parent_pec),
            "line": parent["line"],
            "version": parent["version"],
            "authority": parent_authority,
        },
        "child": {
            "release_digest": child["digest"],
            "governance_digest": digest(governance),
            "pec_digest": digest(pec),
            "line": child["line"],
            "version": child["version"],
            "authority": child_authority,
        },
    }


def build_approval_target(release, governance, pec, lineage_transition=None):
    """Build the acyclic object jointly signed by every author key."""
    return {
        "schema": APPROVAL_TARGET_SCHEMA,
        "work_id": release["work_id"],
        "release_digest": digest(release),
        "governance_digest": digest(governance),
        "pec_digest": digest(pec),
        "required_key_ids": sorted(author["key_id"] for author in release["authors"]),
        "lineage_transition_digest": (
            digest(lineage_transition) if lineage_transition is not None else None
        ),
    }


def check_approval_target(
    target,
    release,
    governance,
    pec,
    adapted,
    lineage_transition=None,
):
    schema = target.get("schema")
    require(
        schema in {APPROVAL_TARGET_SCHEMA, LEGACY_APPROVAL_TARGET_SCHEMA},
        "APPROVAL_TARGET_SCHEMA",
    )
    require(
        schema != LEGACY_APPROVAL_TARGET_SCHEMA or lineage_transition is None,
        "APPROVAL_TARGET_SCHEMA",
    )
    require(
        target.get("work_id") == adapted["work_id"],
        "APPROVAL_TARGET_BINDING_MISMATCH",
    )
    require(
        target.get("release_digest") == adapted["digest"],
        "APPROVAL_TARGET_BINDING_MISMATCH",
    )
    require(
        target.get("governance_digest") == digest(governance),
        "APPROVAL_TARGET_BINDING_MISMATCH",
    )
    require(
        target.get("pec_digest") == digest(pec),
        "APPROVAL_TARGET_BINDING_MISMATCH",
    )
    require(
        target.get("required_key_ids") == sorted(adapted["author_key_ids"]),
        "APPROVAL_TARGET_BINDING_MISMATCH",
    )
    require(
        target.get("lineage_transition_digest") == (
            digest(lineage_transition) if lineage_transition is not None else None
        ),
        "APPROVAL_TARGET_BINDING_MISMATCH",
    )


def check_bindings(pec, adapted, governance, release=None):
    return validate_pec_bundle(
        pec,
        adapted,
        digest(governance),
        governance=governance,
        release=release,
        require_slot_bindings=True,
    )


def lineage_claim_subject(lineage):
    """Project one validated exact transition into the typed claim subject."""
    transition = lineage["transition"]
    parent = transition["parent"]
    child = transition["child"]

    def text_digest(value):
        return hashlib.sha256(value.encode("utf-8")).hexdigest()

    return claim_core.LineageSubject(
        text_digest(transition["work_id"]),
        parent["release_digest"],
        parent["pec_digest"],
        text_digest(parent["line"]),
        parent["version"],
        child["release_digest"],
        child["pec_digest"],
        text_digest(child["line"]),
        child["version"],
        digest(transition),
    )
