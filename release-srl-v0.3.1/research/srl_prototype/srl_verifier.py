"""
SRL Pure Functional Verifier and Typed Appraisal Calculus.
Part of the Sealed Research Lineage (SRL) Stage C Prototype.
Specification: docs/SPEC-SEALED-LINEAGE-PROFILE.md
"""

from __future__ import annotations

import dataclasses
import datetime
import os
import sys
from typing import Any, Dict, List, Optional, Set, Tuple


ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

from srl_core import (
    canonical_json_dumps,
    safe_canonical_json_dumps,
    compute_leaf_hash,
    safe_compute_leaf_hash,
    sha256,
    sha256_hex,
    safe_parse_sha256_hex,
    safe_parse_hex,
    extract_normalized_ed25519_pubkey,
    validate_governance_dict,
    verify_ed25519_signature,
    verify_merkle_audit_path,
    TARGET_DOMAIN,
    OPENING_DOMAIN,
    TRANSITION_DOMAIN,
)
from tsa import verify_tsr


# =============================================================================
# Public API boundary — only these names are part of the documented interface.
# _appraise_internal is intentionally excluded: it accepts internal trust flags
# and is NOT safe to call from external code (Gap 3 / naming convention boundary).
# =============================================================================
__all__ = ["AppraisalResult", "appraise", "appraise_lineage_chain"]


# =============================================================================
# 1. Closed Appraisal Calculus Vocabulary & Result Model
# =============================================================================

@dataclasses.dataclass
class AppraisalResult:
    status: str  # "PASS", "REJECTED", "REFUSED"
    granted_predicates: List[str] = dataclasses.field(default_factory=list)
    rejection_reasons: List[str] = dataclasses.field(default_factory=list)
    refusal_reasons: List[str] = dataclasses.field(default_factory=list)
    opened_ratio: Optional[Tuple[int, int]] = None

    def is_valid(self) -> bool:
        return self.status == "PASS"


# Prohibited inference queries that the verifier categorically refuses to evaluate
PROHIBITED_QUERY_KEYWORDS = [
    "FIRST_PROVED_FINAL_CONJECTURE",
    "LATER_PROVER_PLAGIARIZED",
    "THIRD_PARTY_INFRINGEMENT",
    "OWNERSHIP_OF_FINAL_THEOREM",
    "NATURAL_PERSON_AUTHORSHIP"
]


MAX_PREDECESSOR_DEPTH = 32
MAX_OPENED_CLAIMS    = 65_536   # Gap 2: cap total claims per proof
MAX_REASON_LEN       = 512      # Gap 2: cap each rejection/refusal string

# =============================================================================
# 2. Pure Verification Engine
# =============================================================================

def _appraise_internal(
    proof: Dict[str, Any],
    trust_pins: Dict[str, Any],
    query: Optional[str] = None,
    predecessor_proof: Optional[Dict[str, Any]] = None,
    _predecessor_verified: bool = False,
    _depth: int = 0,
    _trusted_genesis_digest: Optional[str] = None,
) -> AppraisalResult:
    """
    Pure-functional appraisal of an SRL Opening Proof.
    Returns strictly typed AppraisalResult with allowlisted predicates.
    No mutation, no state, no unverified assertions.

    Parameters starting with '_' are INTERNAL ONLY (used by appraise_lineage_chain).
    External callers MUST NOT pass _predecessor_verified=True or _trusted_genesis_digest.
    Doing so bypasses predecessor quorum checks and genesis pinning — that is the S9 attack.
    Maintains complete input totality: never raises uncaught exceptions on malformed inputs.
    """

    if not isinstance(proof, dict):
        return AppraisalResult(
            status="REJECTED",
            rejection_reasons=["REJECTED_MALFORMED_PROOF: proof must be a dictionary"]
        )

    if not isinstance(trust_pins, dict):
        return AppraisalResult(
            status="REJECTED",
            rejection_reasons=["REJECTED_MALFORMED_TRUST_PINS: trust_pins must be a dictionary"]
        )

    # Guard against deep or cyclic predecessor recursion (REG-16)
    if _depth >= MAX_PREDECESSOR_DEPTH:
        return AppraisalResult(
            status="REJECTED",
            rejection_reasons=[
                f"REJECTED_MAX_PREDECESSOR_DEPTH_EXCEEDED: recursion depth {_depth} >= {MAX_PREDECESSOR_DEPTH}"
            ]
        )

    # -------------------------------------------------------------------------
    # Guard 0: Terminal Credit & Scholarly Adjudication Refusal
    # -------------------------------------------------------------------------
    if query is not None:
        if not isinstance(query, str):
            return AppraisalResult(
                status="REFUSED",
                refusal_reasons=["OUT_OF_SCOPE_QUERY: query must be a string"]
            )
        for keyword in PROHIBITED_QUERY_KEYWORDS:
            if keyword in query.upper():
                return AppraisalResult(
                    status="REFUSED",
                    refusal_reasons=[
                        "OUT_OF_SCOPE_QUERY",
                        f"TERMINAL_CREDIT_NON_EVALUABLE: The verifier categorically refuses to adjudicate '{keyword}'"
                    ]
                )

    rejections: List[str] = []
    granted: List[str] = []

    # -------------------------------------------------------------------------
    # Check 1: Envelope & Target Domain Separation
    # -------------------------------------------------------------------------
    if proof.get("domain") != OPENING_DOMAIN:
        rejections.append("REJECTED_DOMAIN_SEPARATOR_MISMATCH: proof domain is not SRL:PARTIAL_OPENING:v1")

    target = proof.get("target")
    if not isinstance(target, dict) or target.get("domain") != TARGET_DOMAIN:
        rejections.append("REJECTED_TARGET_DOMAIN_MISMATCH: target domain is not SRL:APPROVAL_TARGET:v1")
        return AppraisalResult(status="REJECTED", rejection_reasons=rejections)

    target_bytes, target_err = safe_canonical_json_dumps(target, "target")
    if target_err:
        rejections.append(target_err)
        return AppraisalResult(status="REJECTED", rejection_reasons=rejections)
    target_digest = sha256_hex(target_bytes)

    lineage_id = proof.get("lineage_id")
    milestone_index = proof.get("milestone_index")

    if not isinstance(lineage_id, str) or not lineage_id.strip():
        rejections.append("REJECTED_INVALID_LINEAGE_ID: lineage_id must be a non-empty string")
        return AppraisalResult(status="REJECTED", rejection_reasons=rejections)

    if not isinstance(milestone_index, int) or isinstance(milestone_index, bool) or milestone_index < 1:
        rejections.append("REJECTED_INVALID_MILESTONE_INDEX: milestone_index must be an integer >= 1")
        return AppraisalResult(status="REJECTED", rejection_reasons=rejections)

    if target.get("lineage_id") != lineage_id or target.get("milestone_index") != milestone_index:
        rejections.append("REJECTED_LINEAGE_TARGET_MISMATCH: proof and target lineage identifiers differ")

    # Milestone 1 MUST NOT declare predecessor_digest; milestones > 1 MUST declare it
    pred_digest = target.get("predecessor_digest")
    if milestone_index == 1:
        if pred_digest is not None:
            rejections.append("REJECTED_GENESIS_HAS_PREDECESSOR: milestone 1 must not declare predecessor_digest")
    else:
        if pred_digest is None:
            rejections.append("REJECTED_MISSING_PREDECESSOR_DIGEST: milestones > 1 must declare predecessor_digest")
        else:
            _, pred_dig_err = safe_parse_sha256_hex(pred_digest, "target.predecessor_digest")
            if pred_dig_err:
                rejections.append(pred_dig_err)

    # Validate target governance_digest format
    _, gov_dig_err = safe_parse_sha256_hex(target.get("governance_digest"), "target.governance_digest")
    if gov_dig_err:
        rejections.append(gov_dig_err)

    # Resolve predecessor proof if embedded
    if predecessor_proof is None:
        predecessor_proof = proof.get("predecessor_proof")

    if predecessor_proof is not None and not isinstance(predecessor_proof, dict):
        rejections.append("REJECTED_MALFORMED_PREDECESSOR_PROOF: predecessor_proof must be a dictionary")
        return AppraisalResult(status="REJECTED", rejection_reasons=rejections)

    # Ancestry depth limit check (prevents recursion / stack exhaustion / cycles)
    if not _predecessor_verified and predecessor_proof:
        curr = predecessor_proof
        curr_depth = 1
        seen_proof_ids = {id(curr)}
        while isinstance(curr, dict) and curr.get("predecessor_proof"):
            curr = curr.get("predecessor_proof")
            curr_depth += 1
            if id(curr) in seen_proof_ids or curr_depth > MAX_PREDECESSOR_DEPTH:
                rejections.append(
                    f"REJECTED_MAX_PREDECESSOR_DEPTH_EXCEEDED: predecessor ancestry depth {curr_depth} exceeds limit {MAX_PREDECESSOR_DEPTH}"
                )
                return AppraisalResult(status="REJECTED", rejection_reasons=rejections)
            seen_proof_ids.add(id(curr))

    # Lineage / Genesis pinning checks
    expected_lineage_id = trust_pins.get("expected_lineage_id")
    if expected_lineage_id and lineage_id != expected_lineage_id:
        rejections.append(f"REJECTED_LINEAGE_ID_MISMATCH: lineage '{lineage_id}' != expected '{expected_lineage_id}'")

    expected_genesis = trust_pins.get("expected_genesis_target_digest")
    if expected_genesis:
        _, gen_err = safe_parse_sha256_hex(expected_genesis, "trust_pins.expected_genesis_target_digest")
        if gen_err:
            rejections.append(gen_err)
        elif milestone_index == 1:
            if target_digest != expected_genesis:
                rejections.append("REJECTED_GENESIS_DIGEST_MISMATCH: M1 target does not match expected_genesis_target_digest")
        elif milestone_index > 1:
            if _predecessor_verified and predecessor_proof:
                # Use the internally-computed genesis digest (passed by appraise_lineage_chain).
                # Do NOT adopt self-reported genesis_target_digest from the proof dict — that is the S9 attack (R1).
                # _trusted_genesis_digest is ALWAYS provided by appraise_lineage_chain.
                # If it is None here, _predecessor_verified=True was called without the
                # internal genesis parameter — this indicates external misuse (S9).
                # The old traversal fallback only verified the bottom-most node hash and
                # NOT intermediate-layer signatures/governance — it was a decorative defence
                # that an attacker could bypass by embedding the real public M1 target
                # at the bottom of a forged chain with correct hashes (P1 attack, Round 3).
                if _trusted_genesis_digest is None:
                    rejections.append(
                        "REJECTED_INTERNAL_MISUSE: _predecessor_verified=True requires "
                        "_trusted_genesis_digest; use appraise() or appraise_lineage_chain()"
                    )
                elif _trusted_genesis_digest != expected_genesis:
                    rejections.append("REJECTED_GENESIS_DIGEST_MISMATCH: predecessor ancestry does not anchor to expected_genesis_target_digest")

            else:
                curr = predecessor_proof
                while isinstance(curr, dict):
                    inner_target = curr.get("target")
                    if not isinstance(inner_target, dict):
                        break
                    inner_mi = inner_target.get("milestone_index", 1)
                    if not isinstance(inner_mi, int) or inner_mi <= 1:
                        break
                    curr = curr.get("predecessor_proof")
                if isinstance(curr, dict) and not rejections:
                    genesis_target = curr.get("target")
                    if not isinstance(genesis_target, dict):
                        rejections.append("REJECTED_MALFORMED_PREDECESSOR_PROOF: genesis ancestor has non-dict target")
                    else:
                        gen_t_bytes, gen_t_err = safe_canonical_json_dumps(genesis_target, "genesis target")
                        if gen_t_err:
                            rejections.append(gen_t_err)
                        elif sha256_hex(gen_t_bytes) != expected_genesis:
                            rejections.append("REJECTED_GENESIS_DIGEST_MISMATCH: predecessor ancestry does not anchor to expected_genesis_target_digest")

    expected_pred_pin = trust_pins.get("expected_parent_target_digest")
    expected_pred_alias = trust_pins.get("expected_predecessor_target_digest")
    if expected_pred_pin is not None:
        _, pin_err = safe_parse_sha256_hex(expected_pred_pin, "trust_pins.expected_parent_target_digest")
        if pin_err:
            rejections.append(pin_err)
    if expected_pred_alias is not None:
        _, alias_err = safe_parse_sha256_hex(expected_pred_alias, "trust_pins.expected_predecessor_target_digest")
        if alias_err:
            rejections.append(alias_err)

    if expected_pred_pin is not None and expected_pred_alias is not None:
        if expected_pred_pin != expected_pred_alias:
            rejections.append("REJECTED_ALIAS_CONFLICT: conflicting expected_parent_target_digest and expected_predecessor_target_digest in trust_pins")
    pred_pin = expected_pred_pin or expected_pred_alias
    if pred_pin and target.get("predecessor_digest") != pred_pin:
        rejections.append("REJECTED_PREDECESSOR_PIN_MISMATCH: predecessor does not match expected_parent_target_digest")

    # -------------------------------------------------------------------------
    # Check 2: Governance Validation & Multi-Slot Quorum Integrity
    # -------------------------------------------------------------------------
    governance = proof.get("governance")
    if not isinstance(governance, dict):
        rejections.append("INVALID_GOVERNANCE: governance must be a dictionary")
        return AppraisalResult(status="REJECTED", rejection_reasons=rejections)

    gov_valid, gov_err = validate_governance_dict(governance)
    if not gov_valid:
        rejections.append(f"INVALID_GOVERNANCE: {gov_err}")
        return AppraisalResult(status="REJECTED", rejection_reasons=rejections)

    gov_bytes, gov_err = safe_canonical_json_dumps(governance, "governance")
    if gov_err:
        rejections.append(gov_err)
        return AppraisalResult(status="REJECTED", rejection_reasons=rejections)
    gov_digest = sha256_hex(gov_bytes)

    author_slots = governance.get("author_slots", [])
    threshold = governance.get("threshold", 1)

    # Check governance digest in target
    if target.get("governance_digest") != gov_digest:
        rejections.append("REJECTED_GOVERNANCE_DIGEST_MISMATCH")

    valid_slot_signatures: Set[str] = set()
    valid_key_signatures: Set[str] = set()

    # Safe extraction of slot public keys (handles alias-only governance without KeyError)
    slot_key_map: Dict[str, str] = {}
    for slot in author_slots:
        sid = slot.get("slot_id")
        norm_pk, err = extract_normalized_ed25519_pubkey(slot, context=f"governance slot '{sid}'")
        if err:
            rejections.append(err)
        else:
            slot_key_map[sid] = norm_pk

    raw_signatures = proof.get("signatures")
    if raw_signatures is None or not isinstance(raw_signatures, list):
        if raw_signatures is not None:
            rejections.append("REJECTED_MALFORMED_SIGNATURES: signatures must be a list")
        signatures = []
    else:
        signatures = raw_signatures

    for sig in signatures:
        if not isinstance(sig, dict):
            rejections.append("REJECTED_MALFORMED_SIGNATURE_OBJECT: signature entry must be a dictionary")
            continue
        slot_id = sig.get("slot_id")
        if not isinstance(slot_id, str):
            rejections.append("REJECTED_MALFORMED_SIGNATURE: slot_id must be a string")
            continue
        declared_pk, err = extract_normalized_ed25519_pubkey(sig, context=f"signature for slot '{slot_id}'")
        if err:
            rejections.append(err)
            continue
        sig_val = sig.get("signature")
        if not isinstance(sig_val, str):
            rejections.append(f"REJECTED_MALFORMED_SIGNATURE: signature for slot '{slot_id}' must be a string")
            continue

        if slot_id not in slot_key_map or slot_key_map[slot_id] != declared_pk:
            rejections.append(f"REJECTED_UNAUTHORIZED_SIGNER_KEY: slot '{slot_id}' key substitution detected")
            continue

        if verify_ed25519_signature(target_bytes, declared_pk, sig_val):
            valid_slot_signatures.add(slot_id)
            valid_key_signatures.add(declared_pk)
        else:
            rejections.append(f"REJECTED_INVALID_SIGNATURE: signature for slot '{slot_id}' failed verification")

    # Both slot count AND distinct key count must satisfy threshold
    if len(valid_slot_signatures) < threshold or len(valid_key_signatures) < threshold:
        rejections.append(
            f"QUORUM_NOT_MET: required {threshold} distinct slot/key signatures, got {len(valid_slot_signatures)} slots and {len(valid_key_signatures)} keys"
        )

    # -------------------------------------------------------------------------
    # Check 3: Predecessor Quorum & Authorization Integrity
    # -------------------------------------------------------------------------
    if isinstance(milestone_index, int) and not isinstance(milestone_index, bool) and milestone_index > 1:
        pred_digest = target.get("predecessor_digest")
        _, pred_dig_err = safe_parse_sha256_hex(pred_digest, "target.predecessor_digest")
        if pred_dig_err:
            rejections.append(pred_dig_err)
        elif not predecessor_proof:
            rejections.append("REJECTED_MISSING_PREDECESSOR_PROOF: transition requires predecessor proof")
        else:
            # 3a. Predecessor proof validation
            if _predecessor_verified:
                pred_target = predecessor_proof.get("target") if isinstance(predecessor_proof, dict) else {}
                pred_gov = predecessor_proof.get("governance") if isinstance(predecessor_proof, dict) else {}
                if not isinstance(pred_target, dict):
                    rejections.append("REJECTED_MALFORMED_PREDECESSOR_PROOF: predecessor target must be a dictionary")
                    pred_is_valid = False
                else:
                    pred_t_bytes, pred_t_err = safe_canonical_json_dumps(pred_target, "predecessor target")
                    if pred_t_err:
                        rejections.append(pred_t_err)
                        pred_is_valid = False
                    else:
                        # Always recompute — never trust self-reported target_digest (R1/S9)
                        pred_computed_digest = sha256_hex(pred_t_bytes)
                        pred_is_valid = True

            else:
                pred_res = _appraise_internal(
                    predecessor_proof,
                    trust_pins,
                    query=query,
                    predecessor_proof=predecessor_proof.get("predecessor_proof") if isinstance(predecessor_proof, dict) else None,
                    _predecessor_verified=False,
                    _depth=_depth + 1
                )
                pred_is_valid = pred_res.is_valid()
                if not pred_is_valid:
                    # Bounded error reason: do not embed full string representation of nested list
                    err_code = pred_res.rejection_reasons[0].split(":")[0] if pred_res.rejection_reasons else "UNKNOWN"
                    rejections.append(f"REJECTED_INVALID_PREDECESSOR_PROOF: predecessor at depth {_depth + 1} rejected ({err_code})")
                else:
                    pred_target = predecessor_proof.get("target") if isinstance(predecessor_proof, dict) else {}
                    pred_gov = predecessor_proof.get("governance") if isinstance(predecessor_proof, dict) else {}
                    pred_t_bytes, pred_t_err = safe_canonical_json_dumps(pred_target, "predecessor target")
                    if pred_t_err:
                        rejections.append(pred_t_err)
                        pred_is_valid = False
                    else:
                        pred_computed_digest = sha256_hex(pred_t_bytes)

            if pred_is_valid:
                if pred_digest != pred_computed_digest:
                    rejections.append("REJECTED_PREDECESSOR_DIGEST_MISMATCH: target.predecessor_digest does not match parent")
                else:
                    # 3b. Check predecessor governance digest matches predecessor target
                    pred_gov_valid, pred_gov_err = validate_governance_dict(pred_gov)
                    if not pred_gov_valid:
                        rejections.append(f"REJECTED_INVALID_PREDECESSOR_GOVERNANCE: {pred_gov_err}")
                    else:
                        pred_g_bytes, pred_g_err = safe_canonical_json_dumps(pred_gov, "predecessor governance")
                        if pred_g_err:
                            rejections.append(pred_g_err)
                        elif sha256_hex(pred_g_bytes) != (pred_target.get("governance_digest") if isinstance(pred_target, dict) else None):
                            rejections.append("REJECTED_PREDECESSOR_GOVERNANCE_DIGEST_MISMATCH: predecessor governance does not match predecessor target")
                        else:
                            # 3c. Predecessor authority MUST authorize this child target via LineageTransition
                            trans_auth = proof.get("predecessor_transition_auth")
                            if not trans_auth:
                                rejections.append("REJECTED_UNAUTHORIZED_PREDECESSOR: missing predecessor transition authorization")
                            elif not isinstance(trans_auth, dict):
                                rejections.append("REJECTED_MALFORMED_TRANSITION_AUTH: predecessor_transition_auth must be a dictionary")
                            else:
                                raw_trans_obj = trans_auth.get("transition")
                                if not isinstance(raw_trans_obj, dict):
                                    rejections.append("REJECTED_MALFORMED_TRANSITION_OBJECT: transition must be a dictionary")
                                else:
                                    trans_obj = raw_trans_obj

                                    # Validate alias conflicts in transition object (REG-15)
                                    has_trans_conflict = False
                                    if "predecessor_target_digest" in trans_obj and "parent_target_digest" in trans_obj:
                                        if trans_obj["predecessor_target_digest"] != trans_obj["parent_target_digest"]:
                                            rejections.append("REJECTED_ALIAS_CONFLICT: conflicting predecessor_target_digest and parent_target_digest")
                                            has_trans_conflict = True
                                    if "successor_target_digest" in trans_obj and "child_target_digest" in trans_obj:
                                        if trans_obj["successor_target_digest"] != trans_obj["child_target_digest"]:
                                            rejections.append("REJECTED_ALIAS_CONFLICT: conflicting successor_target_digest and child_target_digest")
                                            has_trans_conflict = True
                                    if "predecessor_milestone_index" in trans_obj and "parent_milestone_index" in trans_obj:
                                        if trans_obj["predecessor_milestone_index"] != trans_obj["parent_milestone_index"]:
                                            rejections.append("REJECTED_ALIAS_CONFLICT: conflicting predecessor_milestone_index and parent_milestone_index")
                                            has_trans_conflict = True
                                    if "successor_milestone_index" in trans_obj and "child_milestone_index" in trans_obj:
                                        if trans_obj["successor_milestone_index"] != trans_obj["child_milestone_index"]:
                                            rejections.append("REJECTED_ALIAS_CONFLICT: conflicting successor_milestone_index and child_milestone_index")
                                            has_trans_conflict = True

                                    if not has_trans_conflict:
                                        trans_pred_digest = trans_obj.get("predecessor_target_digest") or trans_obj.get("parent_target_digest")
                                        trans_succ_digest = trans_obj.get("successor_target_digest") or trans_obj.get("child_target_digest")
                                        trans_pred_idx = (
                                            trans_obj.get("predecessor_milestone_index")
                                            if "predecessor_milestone_index" in trans_obj
                                            else trans_obj.get("parent_milestone_index")
                                        )
                                        trans_succ_idx = (
                                            trans_obj.get("successor_milestone_index")
                                            if "successor_milestone_index" in trans_obj
                                            else trans_obj.get("child_milestone_index")
                                        )

                                        # S4: Also cross-check against the actual predecessor target milestone_index
                                        # (prevents sequence-skip: M1->M3 where transition declares pred_idx=2)
                                        actual_pred_mi = pred_target.get("milestone_index") if isinstance(pred_target, dict) else None
                                        # R2: trans_pred_idx must not be bool (True==1 would bypass the check)
                                        trans_pred_idx_is_bool = isinstance(trans_pred_idx, bool)
                                        trans_succ_idx_is_bool = isinstance(trans_succ_idx, bool)
                                        actual_pred_mi_is_bool = isinstance(actual_pred_mi, bool)

                                        if trans_obj.get("domain") != TRANSITION_DOMAIN or \
                                           trans_obj.get("lineage_id") != lineage_id or \
                                           trans_pred_digest != pred_digest or \
                                           trans_succ_digest != sha256_hex(target_bytes) or \
                                           trans_pred_idx_is_bool or trans_succ_idx_is_bool or \
                                           actual_pred_mi_is_bool or \
                                           trans_pred_idx != milestone_index - 1 or \
                                           trans_succ_idx != milestone_index or \
                                           (actual_pred_mi is not None and trans_pred_idx != actual_pred_mi):
                                            rejections.append("REJECTED_INVALID_TRANSITION_TARGET: transition object does not bind exact parent/child")

                                        else:
                                            trans_bytes, trans_err = safe_canonical_json_dumps(trans_obj, "transition object")
                                            if trans_err:
                                                rejections.append(trans_err)
                                            else:
                                                pred_threshold = pred_gov.get("threshold", 1)
                                                pred_slots: Dict[str, str] = {}
                                                for s in pred_gov.get("author_slots", []):
                                                    sid = s.get("slot_id")
                                                    spk, err = extract_normalized_ed25519_pubkey(s, context=f"predecessor slot '{sid}'")
                                                    if err:
                                                        rejections.append(err)
                                                    else:
                                                        pred_slots[sid] = spk

                                                valid_pred_signers: Set[str] = set()
                                                valid_pred_keys: Set[str] = set()
                                                raw_trans_sigs = trans_auth.get("signatures")
                                                if not isinstance(raw_trans_sigs, list):
                                                    trans_sigs = []
                                                    if raw_trans_sigs is not None:
                                                        rejections.append("REJECTED_MALFORMED_SIGNATURES: transition signatures must be a list")
                                                else:
                                                    trans_sigs = raw_trans_sigs

                                                for sig in trans_sigs:
                                                    if not isinstance(sig, dict):
                                                        rejections.append("REJECTED_MALFORMED_SIGNATURE_OBJECT: transition signature must be a dictionary")
                                                        continue
                                                    sid = sig.get("slot_id")
                                                    if not isinstance(sid, str):
                                                        rejections.append("REJECTED_MALFORMED_SIGNATURE: slot_id must be a string")
                                                        continue
                                                    spk, err = extract_normalized_ed25519_pubkey(sig, context=f"transition signature for slot '{sid}'")
                                                    if err:
                                                        rejections.append(err)
                                                        continue
                                                    sval = sig.get("signature")
                                                    if not isinstance(sval, str):
                                                        rejections.append(f"REJECTED_MALFORMED_SIGNATURE: transition signature for slot '{sid}' must be a string")
                                                        continue
                                                    if sid in pred_slots and pred_slots[sid] == spk:
                                                        if verify_ed25519_signature(trans_bytes, spk, sval):
                                                            valid_pred_signers.add(sid)
                                                            valid_pred_keys.add(spk)

                                                if len(valid_pred_signers) < pred_threshold or len(valid_pred_keys) < pred_threshold:
                                                    rejections.append(
                                                        f"PREDECESSOR_QUORUM_NOT_MET: required {pred_threshold} parent signatures, got {len(valid_pred_signers)} slots and {len(valid_pred_keys)} keys"
                                                    )
                                                else:
                                                    granted.append(f"AUTHORIZED_PREDECESSOR_TRANSITION({pred_digest} -> {milestone_index})")
                                    # S7: do NOT grant AUTHORIZED_PREDECESSOR_TRANSITION on alias-conflict path


    # -------------------------------------------------------------------------
    # Check 4: Cryptographic RFC 3161 Verification (with Nonce & Signer Pin)
    # -------------------------------------------------------------------------
    ts_token = proof.get("timestamp_token")
    if not isinstance(ts_token, dict):
        rejections.append("REJECTED_MISSING_TIMESTAMP_TOKEN")
        return AppraisalResult(status="REJECTED", rejection_reasons=rejections)

    tsa_pin = trust_pins.get("trusted_tsa_pin")
    imprint_scope = ts_token.get("imprint_scope", "target")
    if imprint_scope == "archive":
        arch_hex = target.get("encrypted_archive_digest", "")
        arch_bytes, arch_err = safe_parse_sha256_hex(arch_hex, "target.encrypted_archive_digest")
        if arch_err:
            rejections.append(arch_err)
            return AppraisalResult(status="REJECTED", rejection_reasons=rejections)
        expected_imprint = arch_bytes
    elif imprint_scope == "target":
        expected_imprint = sha256(target_bytes)
    else:
        rejections.append(f"REJECTED_UNKNOWN_IMPRINT_SCOPE: unknown imprint_scope '{imprint_scope}'")
        return AppraisalResult(status="REJECTED", rejection_reasons=rejections)

    tsr_hex = ts_token.get("tsr_der_hex")
    expected_nonce = ts_token.get("expected_nonce")

    if not tsr_hex:
        rejections.append("REJECTED_MISSING_RFC3161_DER: timestamp_token must supply tsr_der_hex")
    else:
        tsr_der, tsr_err = safe_parse_hex(tsr_hex, "timestamp_token.tsr_der_hex")
        if tsr_err:
            rejections.append(tsr_err)
        else:
            try:
                tsr_info = verify_tsr(
                    tsr=tsr_der,
                    expected_imprint=expected_imprint,
                    expected_nonce=expected_nonce,
                    trusted_fingerprint=tsa_pin,
                    allow_self_signed=False
                )
                attested_time = tsr_info["genTime"].isoformat()
                if imprint_scope == "target":
                    granted.append(f"APPROVAL_TARGET_EXISTED_NOT_AFTER({lineage_id}, M{milestone_index}, {attested_time})")
                elif imprint_scope == "archive":
                    granted.append(f"ARCHIVE_DIGEST_EXISTED_NOT_AFTER({arch_hex}, {attested_time})")
            except Exception as e:
                rejections.append(f"REJECTED_TIMESTAMP_VERIFICATION_FAILED: {str(e)}")

    # -------------------------------------------------------------------------
    # Check 5: Claim Catalog & Domain-Separated Merkle Openings
    # -------------------------------------------------------------------------
    catalog_root_hex = target.get("catalog_root", "")
    catalog_root_bytes, cat_err = safe_parse_sha256_hex(catalog_root_hex, "target.catalog_root")
    if cat_err:
        rejections.append(cat_err)
        return AppraisalResult(status="REJECTED", rejection_reasons=rejections)

    # Total committed leaves is BOUND TO THE SIGNED TARGET
    committed_leaf_count = target.get("catalog_leaf_count")
    if not isinstance(committed_leaf_count, int) or isinstance(committed_leaf_count, bool) or committed_leaf_count < 1:
        rejections.append("REJECTED_INVALID_TARGET_LEAF_COUNT")
        return AppraisalResult(status="REJECTED", rejection_reasons=rejections)

    MAX_CATALOG_LEAF_COUNT = 65536
    if committed_leaf_count > MAX_CATALOG_LEAF_COUNT:
        rejections.append(f"REJECTED_CATALOG_LEAF_COUNT_EXCEEDED: leaf count {committed_leaf_count} exceeds maximum {MAX_CATALOG_LEAF_COUNT}")
        return AppraisalResult(status="REJECTED", rejection_reasons=rejections)

    raw_opened_claims = proof.get("opened_claims")
    if raw_opened_claims is None:
        opened_claims = []
    elif not isinstance(raw_opened_claims, list):
        rejections.append("REJECTED_MALFORMED_OPENED_CLAIMS: opened_claims must be a list")
        opened_claims = []
    else:
        if len(raw_opened_claims) > MAX_OPENED_CLAIMS:
            rejections.append(
                f"REJECTED_TOO_MANY_OPENED_CLAIMS: opened_claims length "
                f"{len(raw_opened_claims)} exceeds limit {MAX_OPENED_CLAIMS}"
            )
            raw_opened_claims = []  # skip further processing
        opened_claims = raw_opened_claims

    seen_leaf_indices: Set[int] = set()
    seen_claim_ids: Set[str] = set()
    seen_leaf_hashes: Set[bytes] = set()

    for idx, claim in enumerate(opened_claims):
        if not isinstance(claim, dict):
            rejections.append("REJECTED_MALFORMED_CLAIM: claim item must be a dictionary")
            continue

        cat_item = claim.get("catalog_item")
        if not isinstance(cat_item, dict):
            rejections.append(f"REJECTED_MALFORMED_CATALOG_ITEM: claim at index {idx} has invalid catalog_item")
            continue

        claim_id = cat_item.get("claim_id")
        if not isinstance(claim_id, str) or not claim_id.strip():
            claim_id = f"INVALID_CLAIM_ID_{idx}"
            rejections.append(f"REJECTED_INVALID_CLAIM_ID: claim at index {idx} must have non-empty string claim_id")
            continue

        mat_content = claim.get("material_content")
        if not isinstance(mat_content, str):
            rejections.append(f"REJECTED_MALFORMED_MATERIAL_CONTENT: claim '{claim_id}' material_content must be a string")
            continue

        salt_hex = claim.get("salt")
        if not isinstance(salt_hex, str):
            rejections.append(f"REJECTED_MALFORMED_SALT: claim '{claim_id}' salt must be a string")
            continue

        merkle_proof = claim.get("merkle_proof")
        if not isinstance(merkle_proof, dict):
            rejections.append(f"REJECTED_MALFORMED_MERKLE_PROOF: claim '{claim_id}' merkle_proof must be a dictionary")
            continue

        leaf_index = merkle_proof.get("leaf_index")

        # 5a. Unique checks (leaf index and claim_id)
        if not isinstance(leaf_index, int) or isinstance(leaf_index, bool) or leaf_index < 0 or leaf_index >= committed_leaf_count:
            rejections.append(f"REJECTED_INVALID_LEAF_INDEX: claim '{claim_id}' leaf_index {leaf_index} out of bounds [0, {committed_leaf_count})")
            continue

        is_dup = False
        if leaf_index in seen_leaf_indices:
            rejections.append(f"REJECTED_DUPLICATE_OPENED_LEAF: leaf_index {leaf_index} opened more than once")
            is_dup = True

        if claim_id in seen_claim_ids:
            rejections.append(f"REJECTED_DUPLICATE_CLAIM_ID: claim_id '{claim_id}' opened more than once")
            is_dup = True

        if is_dup:
            continue

        # 5c. Salt entropy requirement (at least 32 bytes / 256 bits)
        if not salt_hex.startswith("hex:") or len(salt_hex[4:]) < 64:
            rejections.append(f"REJECTED_INSUFFICIENT_SALT_ENTROPY: claim '{claim_id}' salt must be at least 32 bytes hex")
            continue

        salt_bytes, salt_err = safe_parse_hex(salt_hex[4:], f"claim '{claim_id}' salt")
        if salt_err:
            rejections.append(salt_err)
            continue
        try:
            mat_bytes = mat_content.encode("utf-8")
        except (UnicodeEncodeError, UnicodeDecodeError) as ue:
            rejections.append(
                f"REJECTED_MALFORMED_MATERIAL_CONTENT: claim '{claim_id}' material_content contains"
                f" invalid Unicode (lone surrogate or encoding error): {ue}"
            )
            continue

        # 5d. Salted commitment check (Hiding: SHA-256(salt || material))
        # Supports both canonical salt_commitment and legacy alias salted_commitment
        if "salt_commitment" in cat_item and "salted_commitment" in cat_item:
            if cat_item["salt_commitment"] != cat_item["salted_commitment"]:
                rejections.append(
                    f"REJECTED_ALIAS_CONFLICT: claim '{claim_id}' has conflicting salt_commitment and salted_commitment"
                )
                continue

        expected_commit = cat_item.get("salt_commitment") or cat_item.get("salted_commitment")
        _, commit_err = safe_parse_sha256_hex(expected_commit, f"claim '{claim_id}' salt_commitment")
        if commit_err:
            rejections.append(commit_err)
            continue

        computed_commitment = sha256_hex(salt_bytes + mat_bytes)
        if computed_commitment != expected_commit:
            rejections.append(
                f"REJECTED_SALTED_COMMITMENT_MISMATCH: claim '{claim_id}' salt + material does not reproduce salt_commitment"
            )
            continue

        # 5e. Anti-Retroactive Strengthening: Premises & Status Consistency
        VALID_CLAIM_STATUSES = {
            "CONDITIONALLY_PROVED", "UNCONDITIONALLY_PROVED",
            "CONJECTURED", "DISPROVED", "ABANDONED"
        }
        status = cat_item.get("claim_status")
        if status not in VALID_CLAIM_STATUSES:
            rejections.append(
                f"REJECTED_INVALID_CLAIM_STATUS: claim '{claim_id}' has unrecognized claim_status '{status}'; "
                f"must be one of {sorted(VALID_CLAIM_STATUSES)}"
            )
            continue
        assumptions = cat_item.get("assumptions", [])
        # Gap 1: structural validation — must be a list of unique sorted strings
        if not isinstance(assumptions, list):
            rejections.append(
                f"REJECTED_MALFORMED_ASSUMPTIONS: claim '{claim_id}' assumptions must be a list, got {type(assumptions).__name__}"
            )
            continue
        if not all(isinstance(a, str) for a in assumptions):
            rejections.append(
                f"REJECTED_MALFORMED_ASSUMPTIONS: claim '{claim_id}' assumptions must contain only strings, got {assumptions!r}"
            )
            continue
        if len(assumptions) != len(set(assumptions)):
            rejections.append(
                f"REJECTED_MALFORMED_ASSUMPTIONS: claim '{claim_id}' assumptions must be unique, got duplicates in {assumptions}"
            )
            continue
        if assumptions != sorted(assumptions):
            rejections.append(
                f"REJECTED_MALFORMED_ASSUMPTIONS: claim '{claim_id}' assumptions must be in ascending order, got {assumptions}"
            )
            continue

        proof_obligations_open = cat_item.get("proof_obligations_open", [])
        # Gap 1: structural validation — must be a list of unique sorted strings
        if not isinstance(proof_obligations_open, list):
            rejections.append(
                f"REJECTED_MALFORMED_OBLIGATIONS: claim '{claim_id}' proof_obligations_open must be a list, got {type(proof_obligations_open).__name__}"
            )
            continue
        if not all(isinstance(o, str) for o in proof_obligations_open):
            rejections.append(
                f"REJECTED_MALFORMED_OBLIGATIONS: claim '{claim_id}' proof_obligations_open must contain only strings, got {proof_obligations_open!r}"
            )
            continue
        if len(proof_obligations_open) != len(set(proof_obligations_open)):
            rejections.append(
                f"REJECTED_MALFORMED_OBLIGATIONS: claim '{claim_id}' proof_obligations_open must be unique, got duplicates in {proof_obligations_open}"
            )
            continue
        if proof_obligations_open != sorted(proof_obligations_open):
            rejections.append(
                f"REJECTED_MALFORMED_OBLIGATIONS: claim '{claim_id}' proof_obligations_open must be in ascending order, got {proof_obligations_open}"
            )
            continue

        if status == "UNCONDITIONALLY_PROVED" and assumptions:
            rejections.append(
                f"REJECTED_ASSUMPTION_MUTATION: claim '{claim_id}' declared UNCONDITIONALLY_PROVED but retains assumptions {assumptions}"
            )
            continue



        # 5f. Domain-separated Merkle leaf and inclusion proof with mathematical position derivation
        leaf_hash, leaf_err = safe_compute_leaf_hash(lineage_id, milestone_index, cat_item)
        if leaf_err:
            rejections.append(leaf_err)
            continue

        if leaf_hash in seen_leaf_hashes:
            rejections.append(f"REJECTED_DUPLICATE_LEAF_HASH: identical leaf opened at multiple positions for claim '{claim_id}'")
            continue

        audit_path = merkle_proof.get("audit_path", [])
        if not verify_merkle_audit_path(
            leaf_hash, audit_path, catalog_root_bytes,
            leaf_index=leaf_index, total_leaves=committed_leaf_count
        ):
            rejections.append(
                f"REJECTED_DOMAIN_SEPARATOR_MISMATCH: Merkle inclusion path failed for claim '{claim_id}' at index {leaf_index}"
            )
            continue

        seen_leaf_indices.add(leaf_index)
        seen_claim_ids.add(claim_id)
        seen_leaf_hashes.add(leaf_hash)

        granted.append(
            f"EXACT_CLAIM_OPENING_VERIFIED(claim_id={claim_id}, status={status}, assumptions={assumptions})"
        )

    # -------------------------------------------------------------------------
    # Check 6: Scope Non-Amplification (Exact Index Set Coverage [0, ..., N-1])
    # -------------------------------------------------------------------------
    claimed_complete = proof.get("claim_complete_opening", False)
    is_exact_complete = (
        len(seen_leaf_indices) == committed_leaf_count
        and len(seen_claim_ids) == committed_leaf_count
        and len(seen_leaf_hashes) == committed_leaf_count
        and (committed_leaf_count == 0 or (min(seen_leaf_indices, default=-1) == 0 and max(seen_leaf_indices, default=-1) == committed_leaf_count - 1))
    )

    if is_exact_complete:
        granted.append(f"COMPLETE_CATALOG_OPENING(total={committed_leaf_count})")
    else:
        if claimed_complete:
            rejections.append(
                f"REJECTED_SCOPE_AMPLIFICATION: claimed complete opening but opened indices {sorted(seen_leaf_indices)} do not cover [0, {committed_leaf_count})"
            )
        else:
            granted.append(
                f"PARTIAL_CATALOG_OPENING(revealed={len(seen_leaf_indices)}, committed_total={committed_leaf_count})"
            )

    # -------------------------------------------------------------------------
    # Final Result Compilation
    # Gap 2: truncate individual reason strings to MAX_REASON_LEN to prevent
    # exponential diagnostic blowup in deeply nested chains.
    # -------------------------------------------------------------------------
    def _trunc(s: str) -> str:
        return s if len(s) <= MAX_REASON_LEN else s[:MAX_REASON_LEN] + "...[truncated]"

    if rejections:
        return AppraisalResult(
            status="REJECTED",
            rejection_reasons=[_trunc(r) for r in rejections],
            granted_predicates=[],
            opened_ratio=(len(seen_leaf_indices), committed_leaf_count)
        )

    return AppraisalResult(
        status="PASS",
        granted_predicates=[_trunc(g) for g in granted],
        opened_ratio=(len(seen_leaf_indices), committed_leaf_count)
    )



def appraise(
    proof: Dict[str, Any],
    trust_pins: Dict[str, Any],
    query: Optional[str] = None,
    predecessor_proof: Optional[Dict[str, Any]] = None,
) -> AppraisalResult:
    """
    Public API for SRL Opening Proof appraisal.
    Returns strictly typed AppraisalResult with allowlisted predicates.

    External callers: use ONLY this function — there is no trust flag, no
    predecessor_verified shortcut, and no depth parameter. Predecessor proofs
    are always re-appraised recursively up to MAX_PREDECESSOR_DEPTH.

    For verifying ordered milestone sequences use appraise_lineage_chain() instead.
    """
    return _appraise_internal(
        proof=proof,
        trust_pins=trust_pins,
        query=query,
        predecessor_proof=predecessor_proof,
        _predecessor_verified=False,   # hard-coded: external callers never skip verification
        _depth=0,
        _trusted_genesis_digest=None,  # hard-coded: external callers never inject trusted genesis
    )

def appraise_lineage_chain(
    chain: List[Dict[str, Any]],
    trust_pins: Dict[str, Any],
    query: Optional[str] = None
) -> List[AppraisalResult]:
    """
    Iteratively verifies an ordered lineage proof chain: [M1, M2, M3, ...].

    Gap 4 / monotonicity guarantee: this function enforces non-decreasing
    attested timestamps across the chain (each milestone must be >= the
    previous one).  The single-proof appraise() function does NOT enforce
    monotonicity — it has no notion of a 'previous' milestone.  If you
    need timestamp ordering guarantees, always use appraise_lineage_chain().
    Verifies each milestone in succession in O(1) stack space, checking cryptographic succession,
    governance transition, and timestamps without re-recursing through ancestors.
    Also enforces timestamp monotonicity (S5): each milestone's RFC 3161 attested time must be
    >= the previous milestone's attested time (not before). Equal timestamps are accepted
    because RFC 3161 genTime has 1-second resolution. Times are compared as timezone-aware
    datetime objects to correctly handle mixed TSA timezone formats.
    """

    if not isinstance(chain, list):
        return [
            AppraisalResult(
                status="REJECTED",
                rejection_reasons=["REJECTED_MALFORMED_CHAIN: chain must be a list"]
            )
        ]

    results: List[AppraisalResult] = []
    prev_cert: Optional[Dict[str, Any]] = None
    prev_attested_time: Optional[str] = None  # S5: track last genTime for monotonicity

    for idx, proof in enumerate(chain):
        if not isinstance(proof, dict):
            results.append(
                AppraisalResult(
                    status="REJECTED",
                    rejection_reasons=[f"REJECTED_MALFORMED_CHAIN_ITEM: item at index {idx} must be a dictionary"]
                )
            )
            break

        if prev_cert is not None:
            res = _appraise_internal(
                proof,
                trust_pins,
                query=query,
                predecessor_proof=prev_cert,
                _predecessor_verified=True,
                _depth=0,
                # Pass internally-computed genesis digest — prevents self-reported genesis bypass (R1/S9)
                _trusted_genesis_digest=prev_cert.get("genesis_target_digest"),
            )

        else:
            res = _appraise_internal(
                proof,
                trust_pins,
                query=query,
                predecessor_proof=None,
                _predecessor_verified=False,
                _depth=0
            )

        # S5: Enforce timestamp monotonicity across chain items
        if res.is_valid():
            curr_attested_time: Optional[str] = None
            for pred in res.granted_predicates:
                # Extract ISO time from APPROVAL_TARGET_EXISTED_NOT_AFTER(lid, Mn, <time>)
                if pred.startswith("APPROVAL_TARGET_EXISTED_NOT_AFTER("):
                    parts = pred[len("APPROVAL_TARGET_EXISTED_NOT_AFTER("):-1].split(", ")
                    if len(parts) >= 3:
                        curr_attested_time = parts[-1]
                    break

            if curr_attested_time is not None and prev_attested_time is not None:
                # R3: Parse to timezone-aware datetime before comparing.
                # String comparison breaks when TSA emits timezone-offset format (+08:00 vs Z):
                # "2026-01-01T10:00:00+08:00" < "2026-01-01T03:00:00Z" by string despite same UTC instant.
                try:
                    curr_dt = datetime.datetime.fromisoformat(curr_attested_time)
                    prev_dt = datetime.datetime.fromisoformat(prev_attested_time)
                    if curr_dt.tzinfo is not None and prev_dt.tzinfo is not None:
                        monotonic = curr_dt >= prev_dt
                    elif curr_dt.tzinfo is None and prev_dt.tzinfo is None:
                        monotonic = curr_dt >= prev_dt
                    else:
                        # Mixed aware/naive: conservative string fallback
                        monotonic = curr_attested_time >= prev_attested_time
                except (ValueError, TypeError):
                    # Unparseable format: conservative string fallback
                    monotonic = curr_attested_time >= prev_attested_time

                if not monotonic:
                    mono_err = (
                        f"REJECTED_NON_MONOTONIC_TIMESTAMP: chain item {idx} "
                        f"attested_time '{curr_attested_time}' is before "
                        f"predecessor attested_time '{prev_attested_time}'"
                    )
                    results.append(AppraisalResult(
                        status="REJECTED",
                        rejection_reasons=[mono_err]
                    ))
                    break

            if curr_attested_time is not None:
                prev_attested_time = curr_attested_time


        results.append(res)
        if not res.is_valid():
            break

        prev_target = proof.get("target") if isinstance(proof, dict) else {}
        prev_gov = proof.get("governance") if isinstance(proof, dict) else {}
        prev_t_bytes, _ = safe_canonical_json_dumps(prev_target, "chain target")
        curr_target_digest = sha256_hex(prev_t_bytes) if prev_t_bytes else ""
        if prev_cert is None:
            genesis_digest = curr_target_digest
        else:
            genesis_digest = prev_cert.get("genesis_target_digest", curr_target_digest)

        prev_cert = {
            "target": prev_target,
            "governance": prev_gov,
            "target_digest": curr_target_digest,
            "genesis_target_digest": genesis_digest,
        }

    return results

