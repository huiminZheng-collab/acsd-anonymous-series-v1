"""Compatibility facade plus dependency-free dialogue/sidecar primitives.

Current code should import canonical, bundle, release, and legacy adapters
directly.  Published imports remain available here for one compatibility
cycle; the ACSD envelope verifier remains the cryptographic boundary.
"""
import hashlib

from bundle_validation import (
    ALLOWED_OUTCOMES,
    REQUIRED_NON_CLAIMS,
    validate_pec_bundle,
)
from canonical_json import HEX, _check_json, canonical, digest, require
from release_adapter import adapt_release

def adapt_v1_release(release):
    """Compatibility name for :func:`release_adapter.adapt_release`."""
    return adapt_release(release)

def validate_v1_standalone_package(package, root, envelope_verifier=None):
    """Compatibility facade for the explicit v1 filesystem adapter."""
    from legacy_adapter import validate_v1_standalone_package as implementation

    return implementation(package, root, envelope_verifier)

def verify_v1_package_with_node(package_path, verifier_script):
    """Compatibility facade for the optional v1 Node adapter."""
    from legacy_adapter import verify_v1_package_with_node as implementation

    return implementation(package_path, verifier_script)

def validate_pec(pec, approvals, release, governance, predecessor_pec=None):
    require(HEX.fullmatch(pec["subject"]["release_digest"]), "RELEASE_DIGEST")
    return validate_pec_bundle(
        pec,
        release,
        governance["digest"],
        approvals=approvals,
        predecessor_pec=predecessor_pec,
        check_predecessor=True,
    )

def verify_legacy_disclosure_metadata(disclosure, pec, event, required_approval_key_ids=None):
    """Compatibility facade for the non-granting legacy metadata check."""
    from legacy_adapter import verify_legacy_disclosure_metadata as implementation

    return implementation(disclosure, pec, event, required_approval_key_ids)

def _leaf(index, turn, salt):
    raw = b"ACSD-PEC-DIALOGUE-LEAF-v1\0" + index.to_bytes(8, "big") + salt + turn
    return hashlib.sha256(raw).digest()

def dialogue_root(turns):
    """Return Merkle root and salted leaves for an ordered dialogue."""
    leaves = [_leaf(i, t["bytes"], t["salt"]) for i, t in enumerate(turns)]
    if not leaves: raise ValueError("DIALOGUE_EMPTY")
    level = leaves[:]
    while len(level) > 1:
        if len(level) % 2: level.append(level[-1])
        level = [hashlib.sha256(b"ACSD-PEC-DIALOGUE-NODE-v1\0" + level[i] + level[i+1]).digest() for i in range(0,len(level),2)]
    return level[0].hex()

def dialogue_proof(turns, index):
    """Generate a left/right sibling path for one dialogue leaf."""
    if not 0 <= index < len(turns): raise ValueError("DIALOGUE_INDEX")
    level = [_leaf(i, t["bytes"], t["salt"]) for i, t in enumerate(turns)]
    path = []; position = index
    while len(level) > 1:
        if len(level) % 2: level.append(level[-1])
        sibling = position ^ 1
        path.append([level[sibling].hex(), "R" if position % 2 == 0 else "L"])
        level = [hashlib.sha256(b"ACSD-PEC-DIALOGUE-NODE-v1\0" + level[i] + level[i+1]).digest() for i in range(0,len(level),2)]
        position //= 2
    return path

def verify_dialogue_window(root_hex, window):
    """Verify contiguous indexed leaves and their Merkle paths against root."""
    require(HEX.fullmatch(root_hex), "DIALOGUE_ROOT")
    require(window and all(window[i]["index"] + 1 == window[i+1]["index"] for i in range(len(window)-1)), "DISCLOSURE_WINDOW_INVALID")
    for item in window:
        require(
            isinstance(item.get("index"), int)
            and not isinstance(item.get("index"), bool)
            and item["index"] >= 0
            and isinstance(item.get("bytes"), bytes)
            and isinstance(item.get("salt"), bytes)
            and len(item["salt"]) == 32
            and isinstance(item.get("path"), list)
            and len(item["path"]) <= 256,
            "DISCLOSURE_OPENING_INVALID",
        )
        node = _leaf(item["index"], item["bytes"], item["salt"])
        index = item["index"]
        for step in item["path"]:
            require(
                isinstance(step, list) and len(step) == 2
                and isinstance(step[0], str) and HEX.fullmatch(step[0])
                and step[1] in {"L", "R"},
                "DISCLOSURE_OPENING_INVALID",
            )
            sibling, side = step
            sibling = bytes.fromhex(sibling)
            node = hashlib.sha256(b"ACSD-PEC-DIALOGUE-NODE-v1\0" + (node+sibling if side == "R" else sibling+node)).digest()
            index //= 2
        require(node.hex() == root_hex, "DISCLOSURE_BINDING_MISMATCH")
    return True

def verify_sidecar_subject(sidecar, pec, outcome, approval_target_digest):
    """Check sidecar scope and policy capability before cryptographic adapter use."""
    require(HEX.fullmatch(approval_target_digest), "RECEIPT_SUBJECT_MISMATCH")
    require(sidecar.get("subject_digest") == approval_target_digest, "RECEIPT_SUBJECT_MISMATCH")
    policy = pec["claim_policy"]
    require(outcome in ALLOWED_OUTCOMES, "CLAIM_NOT_AUTHORIZED")
    require(outcome in policy.get("permitted_outcomes", []), "CLAIM_NOT_AUTHORIZED")
    capability = sidecar.get("capability")
    required = policy.get("required_capabilities", {}).get(outcome, [])
    time_outcomes = {"EXTERNALLY_NOT_AFTER", "APPROVAL_SET_EXISTED_NOT_AFTER"}
    require(capability in required, "TIME_CAPABILITY_MISSING" if outcome in time_outcomes else "CLAIM_NOT_AUTHORIZED")
    return True
