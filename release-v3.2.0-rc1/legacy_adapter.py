"""Explicit compatibility boundary for published ACSD v1 artifacts.

This module is intentionally outside the decision kernel.  It owns filesystem
access, the optional Node subprocess bridge, and the old metadata-only
disclosure check.  Successful results still need the normal ACSD appraisal
path before they can grant a current scoped claim.
"""

import hashlib
import json
import subprocess
from pathlib import Path

from canonical_json import digest, require
from release_adapter import adapt_release


def validate_v1_standalone_package(package, root, envelope_verifier=None):
    """Validate v1 file/digest bindings before verifying COSE envelopes."""
    require(
        package.get("schema") == "acsd-v1.6.0-standalone-paper-package/v1",
        "PACKAGE_SCHEMA",
    )
    base = Path(root)
    release_path = base / package["release_path"]
    release = json.loads(release_path.read_text(encoding="utf-8"))
    adapted = adapt_release(release)
    require(
        package["release_id"] == "urn:sha256:" + adapted["digest"],
        "PACKAGE_RELEASE_MISMATCH",
    )
    seen = set()
    for endorsement in package["endorsements"]:
        require(
            endorsement["author_key_id"] in adapted["author_key_ids"],
            "ENDORSEMENT_AUTHOR_MISMATCH",
        )
        require(
            endorsement["author_key_id"] not in seen,
            "ENDORSEMENT_DUPLICATE",
        )
        seen.add(endorsement["author_key_id"])
        raw = (base / endorsement["path"]).read_bytes()
        require(
            hashlib.sha256(raw).hexdigest() == endorsement["sha256"],
            "ENDORSEMENT_DIGEST_MISMATCH",
        )
        if envelope_verifier is not None:
            require(
                envelope_verifier(
                    raw,
                    endorsement["author_key_id"],
                    package["release_id"],
                ),
                "ENDORSEMENT_SIGNATURE_INVALID",
            )
    require(seen == set(adapted["author_key_ids"]), "ENDORSEMENT_SET_INCOMPLETE")
    return adapted


def verify_v1_package_with_node(package_path, verifier_script):
    """Delegate COSE verification to the pinned zero-dependency v1 verifier."""
    verifier_script = Path(verifier_script).resolve()
    package_path = Path(package_path).resolve()
    result = subprocess.run(
        [
            "node",
            str(verifier_script),
            str(package_path.relative_to(verifier_script.parent)),
        ],
        cwd=verifier_script.parent,
        capture_output=True,
        text=True,
        check=False,
    )
    require(result.returncode == 0, "ENDORSEMENT_SIGNATURE_INVALID")
    report = json.loads(result.stdout)
    require(
        report.get("release_valid") is True
        and report.get("forbidden_or_undeclared_reads") == 0,
        "ENDORSEMENT_SIGNATURE_INVALID",
    )
    return report


def verify_legacy_disclosure_metadata(
    disclosure,
    pec,
    event,
    required_approval_key_ids=None,
):
    """Check a legacy metadata-only fixture without granting a scoped claim."""
    require(disclosure["pec_digest"] == digest(pec), "DISCLOSURE_BINDING_MISMATCH")
    require(disclosure["event_id"] == event["event_id"], "DISCLOSURE_BINDING_MISMATCH")
    require(
        disclosure["event_sequence"] == event["sequence"],
        "DISCLOSURE_BINDING_MISMATCH",
    )
    require(disclosure["kind"] == event["kind"], "DISCLOSURE_BINDING_MISMATCH")
    approved = disclosure.get("approval_key_ids", [])
    require(len(approved) > 0, "DISCLOSURE_APPROVAL_MISSING")
    if required_approval_key_ids is not None:
        require(
            sorted(approved) == sorted(required_approval_key_ids),
            "DISCLOSURE_APPROVAL_MISSING",
        )
    return True
