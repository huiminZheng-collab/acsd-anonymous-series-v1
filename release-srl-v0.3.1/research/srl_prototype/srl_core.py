"""
SRL Core Module: Canonical JSON, Domain-Separated Merkle Trees, and Hardened Data Structures.
Part of the Sealed Research Lineage (SRL) Stage C Prototype.
Specification: docs/SPEC-SEALED-LINEAGE-PROFILE.md
"""

from __future__ import annotations

import dataclasses
import hashlib
import os
import sys
from typing import Any, Dict, List, Optional, Set, Tuple

# Use the repository's strict canonical_json implementation
ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

from canonical_json import canonical as acsd_canonical_json

from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.exceptions import InvalidSignature


# =============================================================================
# 1. Canonical Serialization & Cryptographic Hashes
# =============================================================================

def canonical_json_dumps(obj: Any) -> bytes:
    """
    Serializes an object using ACSD's strict canonical JSON profile.
    Rejects floats, lone surrogates, unsafe integers, and sorts keys strictly.
    """
    return acsd_canonical_json(obj)


def safe_canonical_json_dumps(obj: Any, context: str = "object") -> Tuple[Optional[bytes], Optional[str]]:
    """
    Safely serializes an object using strict RFC 8785 canonical JSON.
    Returns (canonical_bytes, error_message).
    Never raises an uncaught exception on floats, surrogates, or non-serializable objects.
    """
    try:
        data = acsd_canonical_json(obj)
        return data, None
    except RecursionError:
        # Gap 2: circular or deeply-nested objects trigger Python's recursion limit
        return None, f"REJECTED_NON_CANONICAL_JSON: {context} contains circular or excessively nested structure"
    except (ValueError, TypeError) as e:
        return None, f"REJECTED_NON_CANONICAL_JSON: {context} is not compliant with RFC 8785 ({str(e)})"


def sha256(data: bytes) -> bytes:
    """Computes raw SHA-256 digest bytes."""
    return hashlib.sha256(data).digest()


def sha256_hex(data: bytes) -> str:
    """Computes SHA-256 digest formatted with 'sha256:<hex>' prefix."""
    return f"sha256:{hashlib.sha256(data).hexdigest()}"


def safe_parse_sha256_hex(val: Any, field_name: str) -> Tuple[Optional[bytes], Optional[str]]:
    """
    Safely validates and parses a 'sha256:<64 hex chars>' string into bytes.
    Returns (raw_bytes, error_message).
    Never raises an exception on malformed inputs.
    """
    if not isinstance(val, str):
        return None, f"REJECTED_MALFORMED_FIELD: '{field_name}' must be a string"
    if not val.startswith("sha256:"):
        return None, f"REJECTED_MALFORMED_DIGEST: '{field_name}' must start with 'sha256:'"
    hex_str = val[7:]
    if len(hex_str) != 64:
        return None, f"REJECTED_INVALID_DIGEST_LENGTH: '{field_name}' must be 32 bytes (64 hex characters), got {len(hex_str)}"
    try:
        raw = bytes.fromhex(hex_str)
        return raw, None
    except ValueError:
        return None, f"REJECTED_MALFORMED_HEX: '{field_name}' contains invalid hex characters"


def safe_parse_hex(val: Any, field_name: str) -> Tuple[Optional[bytes], Optional[str]]:
    """
    Safely parses an arbitrary even-length hex string into bytes.
    Returns (raw_bytes, error_message).
    Never raises an exception on malformed inputs.
    """
    if not isinstance(val, str):
        return None, f"REJECTED_MALFORMED_FIELD: '{field_name}' must be a string"
    if len(val) % 2 != 0:
        return None, f"REJECTED_INVALID_HEX_LENGTH: '{field_name}' must have an even length"
    try:
        raw = bytes.fromhex(val)
        return raw, None
    except ValueError:
        return None, f"REJECTED_MALFORMED_HEX: '{field_name}' contains invalid hex characters"


def extract_normalized_ed25519_pubkey(
    obj: Dict[str, Any],
    context: str = "key"
) -> Tuple[Optional[str], Optional[str]]:
    """
    Extracts and normalizes an ed25519 public key from a dictionary containing
    either 'public_key', 'ed25519_public_key_hex', or both.
    Enforces that:
    1. If both are present, they MUST match (conflict yields REJECTED_ALIAS_CONFLICT).
    2. Exactly 32 bytes (64 hex characters), valid hex.
    Returns (normalized_key_string, error_message).
    """
    if not isinstance(obj, dict):
        return None, f"REJECTED_MALFORMED_OBJECT: {context} must be a dictionary"

    pk_canon = obj.get("public_key")
    pk_alias = obj.get("ed25519_public_key_hex")

    if pk_canon is not None and not isinstance(pk_canon, str):
        return None, f"REJECTED_MALFORMED_FIELD: {context}.public_key must be a string"
    if pk_alias is not None and not isinstance(pk_alias, str):
        return None, f"REJECTED_MALFORMED_FIELD: {context}.ed25519_public_key_hex must be a string"

    if pk_canon is not None and pk_alias is not None:
        # Normalize to lowercase before comparison to prevent case-mixed alias bypass (S1)
        norm_canon = pk_canon if pk_canon.startswith("ed25519:") else f"ed25519:{pk_canon}"
        norm_alias = pk_alias if pk_alias.startswith("ed25519:") else f"ed25519:{pk_alias}"
        if norm_canon.lower() != norm_alias.lower():
            return None, f"REJECTED_ALIAS_CONFLICT: CONFLICTING_ALIAS_VALUES: {context} contains conflicting public_key and ed25519_public_key_hex"

    raw_pk = pk_canon or pk_alias
    if not raw_pk:
        return None, f"REJECTED_MISSING_PUBLIC_KEY: {context} missing public key"

    # Always fold hex to canonical lowercase so set-based deduplication is case-insensitive (S1)
    norm = raw_pk if raw_pk.startswith("ed25519:") else f"ed25519:{raw_pk}"
    raw_hex = norm[8:].lower()
    norm = f"ed25519:{raw_hex}"
    if len(raw_hex) != 64:
        return None, f"REJECTED_INVALID_KEY_LENGTH: {context} ed25519 public key must be 32 bytes (64 hex characters), got {len(raw_hex)}"
    try:
        bytes.fromhex(raw_hex)
    except ValueError:
        return None, f"REJECTED_MALFORMED_HEX: {context} ed25519 public key contains non-hex characters"

    return norm, None


# =============================================================================
# 2. Domain Separation Prefixes
# =============================================================================

LEAF_DOMAIN = b"SRL:LEAF:v1\x00"
NODE_DOMAIN = b"SRL:NODE:v1\x00"
TARGET_DOMAIN = "SRL:APPROVAL_TARGET:v1"
OPENING_DOMAIN = "SRL:PARTIAL_OPENING:v1"
TRANSITION_DOMAIN = "SRL:LINEAGE_TRANSITION:v1"


# =============================================================================
# 3. Domain-Separated Malleability-Resistant Merkle Tree (RFC 6962 / CT Style)
# =============================================================================

def compute_leaf_hash(lineage_id: str, milestone_index: int, item_dict: Dict[str, Any]) -> bytes:
    """
    Computes domain-separated leaf hash binding lineage_id and milestone_index
    to prevent cross-lineage and cross-node replay / grafting.
    """
    leaf_payload = {
        "lineage_id": lineage_id,
        "milestone_index": milestone_index,
        "item": item_dict
    }
    return sha256(LEAF_DOMAIN + canonical_json_dumps(leaf_payload))


def safe_compute_leaf_hash(
    lineage_id: str,
    milestone_index: int,
    item_dict: Dict[str, Any]
) -> Tuple[Optional[bytes], Optional[str]]:
    """
    Safely computes domain-separated leaf hash.
    Returns (leaf_hash, error_message).
    Never raises exceptions on non-canonical dictionary items.
    """
    leaf_payload = {
        "lineage_id": lineage_id,
        "milestone_index": milestone_index,
        "item": item_dict
    }
    payload_bytes, err = safe_canonical_json_dumps(leaf_payload, "catalog_item")
    if err:
        return None, err
    return sha256(LEAF_DOMAIN + payload_bytes), None


def compute_node_hash(left: bytes, right: bytes) -> bytes:
    """Computes internal node hash with 0x01 node domain prefix."""
    return sha256(NODE_DOMAIN + left + right)


def build_merkle_tree(leaf_hashes: List[bytes]) -> Tuple[bytes, List[List[bytes]]]:
    """
    Builds a deterministic binary Merkle Tree over leaf_hashes.
    Returns (root_hash, tree_levels) where tree_levels[0] is leaves.
    Uses power-of-2 splitting (RFC 6962 style) to avoid duplicate-leaf malleability (CVE-2012-2459).
    """
    if not leaf_hashes:
        return sha256(b"SRL:EMPTY_TREE\x00"), []

    current_level = list(leaf_hashes)
    levels = [current_level]

    while len(current_level) > 1:
        next_level = []
        for i in range(0, len(current_level), 2):
            if i + 1 < len(current_level):
                next_level.append(compute_node_hash(current_level[i], current_level[i + 1]))
            else:
                next_level.append(current_level[i])
        current_level = next_level
        levels.append(current_level)

    return levels[-1][0], levels


def get_merkle_audit_path(levels: List[List[bytes]], leaf_index: int) -> List[Dict[str, str]]:
    """
    Generates an inclusion audit path for the leaf at leaf_index.
    Returns list of dicts: {"direction": "left"|"right", "hash": "sha256:..."}.
    """
    audit_path = []
    idx = leaf_index
    for level in levels[:-1]:
        if idx % 2 == 0:
            if idx + 1 < len(level):
                audit_path.append({"direction": "right", "hash": f"sha256:{level[idx + 1].hex()}"})
        else:
            audit_path.append({"direction": "left", "hash": f"sha256:{level[idx - 1].hex()}"})
        idx = idx // 2
    return audit_path


def verify_merkle_audit_path(
    leaf_hash: bytes,
    audit_path: Any,
    expected_root: bytes,
    leaf_index: Optional[int] = None,
    total_leaves: Optional[int] = None
) -> bool:
    """
    Verifies that leaf_hash leads to expected_root given audit_path.
    When leaf_index and total_leaves are provided, mathematically derives the legal
    direction at each tree level based on the tree shape, enforcing that:
    1. 0 <= leaf_index < total_leaves
    2. Sibling position (left or right) matches the binary tree division exactly
    3. Exactly the required number of audit path steps are consumed
    Never raises an exception on malformed audit_path inputs.
    """
    if not isinstance(audit_path, list) or not isinstance(leaf_hash, bytes) or not isinstance(expected_root, bytes):
        return False

    if leaf_index is not None and total_leaves is not None:
        if not isinstance(leaf_index, int) or not isinstance(total_leaves, int):
            return False
        if total_leaves < 1 or leaf_index < 0 or leaf_index >= total_leaves:
            return False

        current = leaf_hash
        idx = leaf_index
        width = total_leaves
        step_idx = 0

        while width > 1:
            if idx % 2 == 0:
                if idx + 1 < width:
                    if step_idx >= len(audit_path):
                        return False
                    step = audit_path[step_idx]
                    if not isinstance(step, dict):
                        return False
                    step_dir = step.get("direction")
                    if step_dir and step_dir != "right":
                        return False
                    sib_hex = step.get("hash")
                    if not isinstance(sib_hex, str) or not sib_hex.startswith("sha256:"):
                        return False
                    try:
                        sibling = bytes.fromhex(sib_hex[7:])
                    except ValueError:
                        return False
                    current = compute_node_hash(current, sibling)
                    step_idx += 1
                else:
                    # Isolated rightmost odd leaf promoted directly
                    pass
            else:
                # idx is odd: sibling MUST be on the left
                if step_idx >= len(audit_path):
                    return False
                step = audit_path[step_idx]
                if not isinstance(step, dict):
                    return False
                step_dir = step.get("direction")
                if step_dir and step_dir != "left":
                    return False
                sib_hex = step.get("hash")
                if not isinstance(sib_hex, str) or not sib_hex.startswith("sha256:"):
                    return False
                try:
                    sibling = bytes.fromhex(sib_hex[7:])
                except ValueError:
                    return False
                current = compute_node_hash(sibling, current)
                step_idx += 1

            idx = idx // 2
            width = (width + 1) // 2

        if step_idx != len(audit_path):
            return False
        return current == expected_root

    # Fallback if position not provided (caller provides explicit direction)
    current = leaf_hash
    for step in audit_path:
        if not isinstance(step, dict):
            return False
        direction = step.get("direction")
        sibling_hex = step.get("hash")
        if not isinstance(sibling_hex, str) or not sibling_hex.startswith("sha256:"):
            return False
        try:
            sibling = bytes.fromhex(sibling_hex[7:])
        except ValueError:
            return False

        if direction == "right":
            current = compute_node_hash(current, sibling)
        elif direction == "left":
            current = compute_node_hash(sibling, current)
        else:
            return False
    return current == expected_root


# =============================================================================
# 4. Core Data Structures & Models
# =============================================================================

@dataclasses.dataclass
class AuthorSlot:
    slot_id: str
    public_key: str  # "ed25519:<hex>"

    def __init__(
        self,
        slot_id: str,
        public_key: Optional[str] = None,
        ed25519_public_key_hex: Optional[str] = None
    ):
        self.slot_id = slot_id
        norm_pk, err = extract_normalized_ed25519_pubkey(
            {"public_key": public_key, "ed25519_public_key_hex": ed25519_public_key_hex},
            context=f"slot '{slot_id}'"
        )
        if err:
            raise ValueError(err)
        self.public_key = norm_pk

    @property
    def ed25519_public_key_hex(self) -> str:
        return self.public_key

    def to_dict(self) -> Dict[str, Any]:
        return {"slot_id": self.slot_id, "public_key": self.public_key}


@dataclasses.dataclass
class Governance:
    author_slots: List[AuthorSlot]
    threshold: int

    def validate(self) -> None:
        """Enforces non-zero threshold and author slot validity."""
        if not isinstance(self.threshold, int) or isinstance(self.threshold, bool) or self.threshold < 1:
            raise ValueError("INVALID_GOVERNANCE_THRESHOLD: threshold must be an integer >= 1")
        if not self.author_slots:
            raise ValueError("INVALID_GOVERNANCE_SLOTS: author_slots cannot be empty")
        if self.threshold > len(self.author_slots):
            raise ValueError("INVALID_GOVERNANCE_THRESHOLD: threshold cannot exceed number of author slots")

        slot_ids: Set[str] = set()
        pub_keys: Set[str] = set()
        for slot in self.author_slots:
            if not slot.slot_id or not isinstance(slot.slot_id, str):
                raise ValueError("INVALID_SLOT_ID")
            if slot.slot_id in slot_ids:
                raise ValueError(f"DUPLICATE_SLOT_ID: {slot.slot_id}")
            if not slot.public_key.startswith("ed25519:"):
                raise ValueError(f"INVALID_PUBLIC_KEY_FORMAT: {slot.public_key}")
            if slot.public_key in pub_keys:
                raise ValueError(f"DUPLICATE_PUBLIC_KEY: {slot.public_key}")
            slot_ids.add(slot.slot_id)
            pub_keys.add(slot.public_key)

    def to_dict(self) -> Dict[str, Any]:
        self.validate()
        return {
            "author_slots": [s.to_dict() for s in self.author_slots],
            "threshold": self.threshold
        }


def validate_governance_dict(gov: Dict[str, Any]) -> Tuple[bool, Optional[str]]:
    """Validates raw governance dictionary."""
    if not isinstance(gov, dict):
        return False, "INVALID_GOVERNANCE_TYPE"
    threshold = gov.get("threshold")
    author_slots = gov.get("author_slots")
    if not isinstance(threshold, int) or isinstance(threshold, bool) or threshold < 1:
        return False, "INVALID_GOVERNANCE_THRESHOLD: threshold must be an integer >= 1"
    if not isinstance(author_slots, list) or not author_slots:
        return False, "INVALID_GOVERNANCE_SLOTS: author_slots cannot be empty"
    if threshold > len(author_slots):
        return False, f"INVALID_GOVERNANCE_THRESHOLD: threshold {threshold} exceeds author slots {len(author_slots)}"

    seen_slots: Set[str] = set()
    seen_keys: Set[str] = set()
    for s in author_slots:
        if not isinstance(s, dict):
            return False, "INVALID_SLOT_FORMAT"
        sid = s.get("slot_id")
        if not sid or not isinstance(sid, str):
            return False, "INVALID_SLOT_ID"
        if sid in seen_slots:
            return False, f"DUPLICATE_SLOT_ID: {sid}"
        pk, err = extract_normalized_ed25519_pubkey(s, context=f"slot '{sid}'")
        if err:
            return False, err
        if pk in seen_keys:
            return False, f"DUPLICATE_PUBLIC_KEY_IN_GOVERNANCE: key '{pk}' reused across multiple slots"
        seen_slots.add(sid)
        seen_keys.add(pk)
    return True, None


@dataclasses.dataclass
class ClaimCatalogItem:
    """
    A single claim item. Note: raw un-salted material_digest is REMOVED.
    Only salt_commitment (SHA-256 over 256-bit random salt + material) is stored.
    This provides computational hiding and prevents dictionary guessing attacks.
    """
    claim_id: str
    statement_summary: str
    claim_status: str  # "CONDITIONALLY_PROVED", "UNCONDITIONALLY_PROVED", "CONJECTURED", "DISPROVED", "ABANDONED"
    assumptions: List[str]
    proof_obligations_open: List[str]
    salt_commitment: str  # "sha256:<hex>"

    def __init__(
        self,
        claim_id: str,
        statement_summary: str,
        claim_status: str,
        assumptions: List[str],
        proof_obligations_open: List[str],
        salt_commitment: Optional[str] = None,
        salted_commitment: Optional[str] = None,
    ):
        self.claim_id = claim_id
        self.statement_summary = statement_summary
        self.claim_status = claim_status
        self.assumptions = assumptions
        self.proof_obligations_open = proof_obligations_open
        if salt_commitment is not None and salted_commitment is not None:
            if salt_commitment != salted_commitment:
                raise ValueError("CONFLICTING_ALIAS_VALUES: conflicting salt_commitment and salted_commitment")
        commit = salt_commitment or salted_commitment
        if not commit:
            raise ValueError("salt_commitment is required")
        self.salt_commitment = commit

    @property
    def salted_commitment(self) -> str:
        return self.salt_commitment

    def to_dict(self) -> Dict[str, Any]:
        return {
            "claim_id": self.claim_id,
            "statement_summary": self.statement_summary,
            "claim_status": self.claim_status,
            "assumptions": sorted(self.assumptions),
            "proof_obligations_open": sorted(self.proof_obligations_open),
            "salt_commitment": self.salt_commitment
        }


@dataclasses.dataclass
class MilestonePayload:
    lineage_id: str
    milestone_index: int
    created_at: str
    predecessor_digest: Optional[str]
    governance: Governance
    claim_catalog: List[ClaimCatalogItem]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "lineage_id": self.lineage_id,
            "milestone_index": self.milestone_index,
            "created_at": self.created_at,
            "predecessor_digest": self.predecessor_digest,
            "governance": self.governance.to_dict(),
            "claim_catalog": [item.to_dict() for item in self.claim_catalog]
        }

    def compute_catalog_merkle_root(self) -> Tuple[bytes, List[List[bytes]]]:
        leaf_hashes = [
            compute_leaf_hash(self.lineage_id, self.milestone_index, item.to_dict())
            for item in self.claim_catalog
        ]
        return build_merkle_tree(leaf_hashes)


@dataclasses.dataclass
class ApprovalTarget:
    """
    Explicitly binds catalog_leaf_count into the signed and timestamped target.
    This prevents total_leaves malleability attacks where an attacker under-reports tree size.
    """
    domain: str
    lineage_id: str
    milestone_index: int
    catalog_leaf_count: int  # EXPLICITLY BOUND LEAF COUNT
    predecessor_digest: Optional[str]
    catalog_root: str
    encrypted_archive_digest: str
    governance_digest: str

    def validate(self) -> None:
        if self.domain != TARGET_DOMAIN:
            raise ValueError(f"INVALID_TARGET_DOMAIN: {self.domain}")
        if self.milestone_index < 1:
            raise ValueError("INVALID_MILESTONE_INDEX")
        if self.catalog_leaf_count < 1:
            raise ValueError("INVALID_CATALOG_LEAF_COUNT: catalog_leaf_count must be >= 1")
        if self.milestone_index > 1 and not self.predecessor_digest:
            raise ValueError("MISSING_PREDECESSOR_DIGEST: milestones > 1 must declare predecessor_digest")

    def to_dict(self) -> Dict[str, Any]:
        self.validate()
        return {
            "domain": self.domain,
            "lineage_id": self.lineage_id,
            "milestone_index": self.milestone_index,
            "catalog_leaf_count": self.catalog_leaf_count,
            "predecessor_digest": self.predecessor_digest,
            "catalog_root": self.catalog_root,
            "encrypted_archive_digest": self.encrypted_archive_digest,
            "governance_digest": self.governance_digest
        }

    def digest(self) -> str:
        return sha256_hex(canonical_json_dumps(self.to_dict()))


@dataclasses.dataclass
class LineageTransition:
    """
    Explicit authorization target for milestone succession.
    Signed by the PREDECESSOR's governance authority to prevent fresh-key n+1 takeovers.
    """
    domain: str
    lineage_id: str
    predecessor_target_digest: str
    successor_target_digest: str
    predecessor_milestone_index: int
    successor_milestone_index: int

    def __init__(
        self,
        domain: str = TRANSITION_DOMAIN,
        lineage_id: str = "",
        predecessor_target_digest: Optional[str] = None,
        successor_target_digest: Optional[str] = None,
        predecessor_milestone_index: Optional[int] = None,
        successor_milestone_index: Optional[int] = None,
        parent_target_digest: Optional[str] = None,
        child_target_digest: Optional[str] = None,
        parent_milestone_index: Optional[int] = None,
        child_milestone_index: Optional[int] = None,
    ):
        self.domain = domain
        self.lineage_id = lineage_id

        # Alias conflict validation
        if predecessor_target_digest is not None and parent_target_digest is not None:
            if predecessor_target_digest != parent_target_digest:
                raise ValueError("CONFLICTING_ALIAS_VALUES: conflicting predecessor_target_digest and parent_target_digest")
        if successor_target_digest is not None and child_target_digest is not None:
            if successor_target_digest != child_target_digest:
                raise ValueError("CONFLICTING_ALIAS_VALUES: conflicting successor_target_digest and child_target_digest")
        if predecessor_milestone_index is not None and parent_milestone_index is not None:
            if predecessor_milestone_index != parent_milestone_index:
                raise ValueError("CONFLICTING_ALIAS_VALUES: conflicting predecessor_milestone_index and parent_milestone_index")
        if successor_milestone_index is not None and child_milestone_index is not None:
            if successor_milestone_index != child_milestone_index:
                raise ValueError("CONFLICTING_ALIAS_VALUES: conflicting successor_milestone_index and child_milestone_index")

        self.predecessor_target_digest = predecessor_target_digest or parent_target_digest or ""
        self.successor_target_digest = successor_target_digest or child_target_digest or ""
        self.predecessor_milestone_index = (
            predecessor_milestone_index if predecessor_milestone_index is not None
            else (parent_milestone_index if parent_milestone_index is not None else 0)
        )
        self.successor_milestone_index = (
            successor_milestone_index if successor_milestone_index is not None
            else (child_milestone_index if child_milestone_index is not None else 0)
        )

    @property
    def parent_target_digest(self) -> str:
        return self.predecessor_target_digest

    @property
    def child_target_digest(self) -> str:
        return self.successor_target_digest

    @property
    def parent_milestone_index(self) -> int:
        return self.predecessor_milestone_index

    @property
    def child_milestone_index(self) -> int:
        return self.successor_milestone_index

    def validate(self) -> None:
        if self.domain != TRANSITION_DOMAIN:
            raise ValueError("INVALID_TRANSITION_DOMAIN")
        if self.successor_milestone_index != self.predecessor_milestone_index + 1:
            raise ValueError("INVALID_MILESTONE_SUCCESSION")

    def to_dict(self) -> Dict[str, Any]:
        self.validate()
        return {
            "domain": self.domain,
            "lineage_id": self.lineage_id,
            "predecessor_target_digest": self.predecessor_target_digest,
            "successor_target_digest": self.successor_target_digest,
            "predecessor_milestone_index": self.predecessor_milestone_index,
            "successor_milestone_index": self.successor_milestone_index
        }

    def digest(self) -> str:
        return sha256_hex(canonical_json_dumps(self.to_dict()))


# =============================================================================
# 5. Ed25519 Signing and Verification Helpers
# =============================================================================

def sign_data(
    data_dict: Dict[str, Any],
    private_key: ed25519.Ed25519PrivateKey,
    slot_id: str
) -> Dict[str, str]:
    """Signs an arbitrary canonical dictionary using Ed25519."""
    data_to_sign = canonical_json_dumps(data_dict)
    signature = private_key.sign(data_to_sign)
    pub_bytes = private_key.public_key().public_bytes_raw()
    return {
        "slot_id": slot_id,
        "public_key": f"ed25519:{pub_bytes.hex()}",
        "signature": f"ed25519_sig:{signature.hex()}"
    }


def verify_ed25519_signature(
    data_bytes: bytes,
    public_key_hex: str,
    signature_hex: str
) -> bool:
    """Verifies Ed25519 signature over canonical data_bytes."""
    if not public_key_hex.startswith("ed25519:") or not signature_hex.startswith("ed25519_sig:"):
        return False
    try:
        pub_bytes = bytes.fromhex(public_key_hex[8:])
        sig_bytes = bytes.fromhex(signature_hex[12:])
        pub_key = ed25519.Ed25519PublicKey.from_public_bytes(pub_bytes)
        pub_key.verify(sig_bytes, data_bytes)
        return True
    except (ValueError, InvalidSignature):
        return False
