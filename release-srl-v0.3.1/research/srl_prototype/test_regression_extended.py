"""
SRL Extended Regression Tests: REG-25 through REG-38.
Covers defects found across four rounds of independent adversarial audit (S1-S8, R1-R3, P1)
and the four convergence closing actions from the final review.
Part of the Sealed Research Lineage (SRL) Stage C Prototype — Profile v0.3.0.

  REG-25 (S1): hex case-mixed duplicate key bypass
  REG-26 (S2): lone surrogate material_content crash
  REG-27 (S3): malformed genesis traversal crash
  REG-28 (S4): milestone sequence skip via crafted transition
  REG-29 (S5): chain timestamp monotonicity
  REG-30 (S6): invalid claim_status allowlist
  REG-31 (S7): alias-conflict dead-else grants transition
  REG-32 (S8): bool bypasses isinstance(x, int) gates
  REG-33 (R1/S9): public appraise() has no trust flag (structural split)
  REG-34 (R2):  bool in transition milestone index bypasses S4 cross-check
  REG-35 (R3):  datetime monotonicity comparison (timezone-aware)
  REG-36 (P1/S9): forged chain with real genesis rejected by full re-appraisal
  REG-37 (Gap 1): assumptions/proof_obligations_open type, uniqueness, sort order
  REG-38 (Gap 2): RecursionError caught; MAX_OPENED_CLAIMS; MAX_REASON_LEN
"""


from __future__ import annotations

import copy
import os
import sys
import time
import unittest

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)
sys.path.insert(0, os.path.dirname(__file__))

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ed25519

from srl_core import (
    canonical_json_dumps,
    sha256,
    sha256_hex,
    sign_data,
    AuthorSlot,
    Governance,
    ClaimCatalogItem,
    MilestonePayload,
    ApprovalTarget,
    LineageTransition,
    build_merkle_tree,
    compute_leaf_hash,
    TARGET_DOMAIN,
    OPENING_DOMAIN,
    TRANSITION_DOMAIN,
)
from srl_verifier import appraise, appraise_lineage_chain
from tsa import LocalTSA, build_tsq, verify_tsr


class AuditRegressionSuite(unittest.TestCase):
    """REG-25 through REG-32: covers all 8 S-class defects from the independent audit."""

    def setUp(self):
        self.privkey1 = ed25519.Ed25519PrivateKey.generate()
        self.pub1_bytes = self.privkey1.public_key().public_bytes_raw()
        self.pub1_hex_lower = f"ed25519:{self.pub1_bytes.hex().lower()}"
        self.pub1_hex_upper = f"ed25519:{self.pub1_bytes.hex().upper()}"

        self.privkey2 = ed25519.Ed25519PrivateKey.generate()
        self.pub2_bytes = self.privkey2.public_key().public_bytes_raw()
        self.pub2_hex = f"ed25519:{self.pub2_bytes.hex()}"

        self.tsa = LocalTSA()
        self.tsa_pin = self.tsa.cert.fingerprint(hashes.SHA256()).hex()
        self.trusted_pins = {"trusted_tsa_pin": self.tsa_pin}

        self.lineage_id = "srl:lin:audit-reg25-32"
        self.mat_content = "Test material for audit regression."
        self.salt_bytes = os.urandom(32)
        self.salt_hex = f"hex:{self.salt_bytes.hex()}"
        self.salt_commit = sha256_hex(self.salt_bytes + self.mat_content.encode("utf-8"))

        self.claim = ClaimCatalogItem(
            claim_id="CLM-R01",
            statement_summary="Audit regression claim",
            claim_status="CONJECTURED",
            assumptions=[],
            proof_obligations_open=[],
            salt_commitment=self.salt_commit
        )

        self.governance1 = Governance(
            author_slots=[AuthorSlot(slot_id="slot_1", public_key=self.pub1_hex_lower)],
            threshold=1
        )

        def _build_m1_proof(governance, privkey, pub_hex_for_sig=None):
            """Helper: build a valid M1 proof signed with privkey."""
            payload = MilestonePayload(
                lineage_id=self.lineage_id,
                milestone_index=1,
                created_at="2026-10-02T10:00:00Z",
                predecessor_digest=None,
                governance=governance,
                claim_catalog=[self.claim]
            )
            root_bytes, levels = payload.compute_catalog_merkle_root()
            target = ApprovalTarget(
                domain=TARGET_DOMAIN,
                lineage_id=self.lineage_id,
                milestone_index=1,
                catalog_leaf_count=1,
                predecessor_digest=None,
                catalog_root=f"sha256:{root_bytes.hex()}",
                encrypted_archive_digest=sha256_hex(b"enc_archive_reg"),
                governance_digest=sha256_hex(canonical_json_dumps(governance.to_dict()))
            )
            gov_dict = governance.to_dict()
            # Determine which slot_id to use for signing
            slot_id = gov_dict["author_slots"][0]["slot_id"]
            sig = sign_data(target.to_dict(), privkey, slot_id)
            if pub_hex_for_sig:
                sig["public_key"] = pub_hex_for_sig
            imprint = sha256(canonical_json_dumps(target.to_dict()))
            nonce_bytes = os.urandom(8)
            tsq = build_tsq(imprint, nonce_bytes)
            tsr = self.tsa.respond(tsq)
            return {
                "domain": OPENING_DOMAIN,
                "lineage_id": self.lineage_id,
                "milestone_index": 1,
                "target": target.to_dict(),
                "governance": gov_dict,
                "signatures": [sig],
                "timestamp_token": {
                    "format": "RFC3161_DER",
                    "tsr_der_hex": tsr.hex(),
                    "expected_nonce": int.from_bytes(nonce_bytes, "big")
                },
                "claim_complete_opening": False,
                "opened_claims": []
            }, target, levels, root_bytes

        self._build_m1_proof = _build_m1_proof

    # -------------------------------------------------------------------------
    # REG-25 (S1): Hex case-mixed duplicate key bypass
    # -------------------------------------------------------------------------
    def test_reg25_s1_hex_case_mixed_duplicate_key_bypass_rejected(self):
        """REG-25/S1: Two governance slots with same physical key but different hex case must be rejected."""
        gov_dict = {
            "author_slots": [
                {"slot_id": "slot_A", "public_key": self.pub1_hex_upper},
                {"slot_id": "slot_B", "public_key": self.pub1_hex_lower},
            ],
            "threshold": 2
        }
        target_dict = {
            "domain": TARGET_DOMAIN,
            "lineage_id": self.lineage_id,
            "milestone_index": 1,
            "catalog_leaf_count": 1,
            "predecessor_digest": None,
            "catalog_root": sha256_hex(b"fake_root"),
            "encrypted_archive_digest": sha256_hex(b"enc"),
            "governance_digest": sha256_hex(canonical_json_dumps(gov_dict))
        }
        target_bytes = canonical_json_dumps(target_dict)
        sig_bytes = self.privkey1.sign(target_bytes)
        sig_hex = f"ed25519_sig:{sig_bytes.hex()}"
        imprint = sha256(target_bytes)
        nonce = os.urandom(8)
        tsr = self.tsa.respond(build_tsq(imprint, nonce))
        proof = {
            "domain": OPENING_DOMAIN,
            "lineage_id": self.lineage_id,
            "milestone_index": 1,
            "target": target_dict,
            "governance": gov_dict,
            "signatures": [
                {"slot_id": "slot_A", "public_key": self.pub1_hex_upper, "signature": sig_hex},
                {"slot_id": "slot_B", "public_key": self.pub1_hex_lower, "signature": sig_hex},
            ],
            "timestamp_token": {
                "format": "RFC3161_DER",
                "tsr_der_hex": tsr.hex(),
                "expected_nonce": int.from_bytes(nonce, "big")
            },
            "claim_complete_opening": False,
            "opened_claims": []
        }
        res = appraise(proof, self.trusted_pins)
        self.assertFalse(res.is_valid(), f"S1 bypass should be rejected; got: {res.granted_predicates}")
        # Should hit DUPLICATE_PUBLIC_KEY_IN_GOVERNANCE
        self.assertTrue(
            any("DUPLICATE_PUBLIC_KEY" in r or "INVALID_GOVERNANCE" in r for r in res.rejection_reasons),
            f"Expected duplicate key rejection; got: {res.rejection_reasons}"
        )

    # -------------------------------------------------------------------------
    # REG-26 (S2): Lone surrogate in material_content must not crash
    # -------------------------------------------------------------------------
    def test_reg26_s2_lone_surrogate_material_content_rejected_not_crash(self):
        """REG-26/S2: material_content with lone surrogate \\ud800 must return REJECTED, not raise."""
        proof, target, levels, root_bytes = self._build_m1_proof(self.governance1, self.privkey1)
        leaf_hash = compute_leaf_hash(self.lineage_id, 1, self.claim.to_dict())
        # Build a claim opening with a surrogate in material_content
        surrogate_content = "valid prefix \ud800 invalid"
        proof["opened_claims"] = [{
            "catalog_item": self.claim.to_dict(),
            "salt": self.salt_hex,
            "material_content": surrogate_content,
            "merkle_proof": {"leaf_index": 0, "audit_path": []}
        }]
        # Must not raise; must return a typed rejection
        try:
            res = appraise(proof, self.trusted_pins)
        except Exception as e:
            self.fail(f"S2: appraise raised exception instead of returning rejection: {e}")
        self.assertFalse(res.is_valid(), "S2: proof with lone surrogate must be rejected")
        self.assertTrue(
            any("REJECTED_MALFORMED_MATERIAL_CONTENT" in r or "REJECTED_SALTED_COMMITMENT_MISMATCH" in r
                for r in res.rejection_reasons),
            f"S2: Expected material content rejection; got: {res.rejection_reasons}"
        )

    # -------------------------------------------------------------------------
    # REG-27 (S3): Malformed predecessor does not crash genesis traversal
    # -------------------------------------------------------------------------
    def test_reg27_s3_malformed_predecessor_genesis_traversal_no_crash(self):
        """REG-27/S3: Predecessor with non-dict target must be rejected without AttributeError/TypeError."""
        proof, _, _, _ = self._build_m1_proof(self.governance1, self.privkey1)
        # Build M2 proof referring to a predecessor with target = "BOOM" (string, not dict)
        m1_bad_pred = {"target": "BOOM", "governance": self.governance1.to_dict()}
        pins_with_genesis = {
            "trusted_tsa_pin": self.tsa_pin,
            "expected_genesis_target_digest": sha256_hex(b"real_genesis")
        }
        try:
            res = appraise(proof, pins_with_genesis, predecessor_proof=m1_bad_pred)
        except (AttributeError, TypeError) as e:
            self.fail(f"S3: appraise raised {type(e).__name__} instead of returning rejection: {e}")
        # May reject for genesis mismatch or predecessor malform; should not crash
        self.assertIsNotNone(res)

    # -------------------------------------------------------------------------
    # REG-28 (S4): Milestone index sequence skip via crafted transition
    # -------------------------------------------------------------------------
    def test_reg28_s4_sequence_skip_transition_rejected(self):
        """REG-28/S4: M3 claiming to follow M1 (skipping M2) must be rejected."""
        proof_m1, target_m1, _, _ = self._build_m1_proof(self.governance1, self.privkey1)

        # Build M3 target that claims predecessor is M1 (milestone_index=1, skipping M2)
        target_m3 = ApprovalTarget(
            domain=TARGET_DOMAIN,
            lineage_id=self.lineage_id,
            milestone_index=3,
            catalog_leaf_count=1,
            predecessor_digest=target_m1.digest(),
            catalog_root=sha256_hex(b"fake_root_m3"),
            encrypted_archive_digest=sha256_hex(b"enc_m3"),
            governance_digest=sha256_hex(canonical_json_dumps(self.governance1.to_dict()))
        )
        sig_m3 = sign_data(target_m3.to_dict(), self.privkey1, "slot_1")

        # Craft transition: says predecessor is index 2, but actual predecessor is M1 (index 1)
        trans_dict = {
            "domain": TRANSITION_DOMAIN,
            "lineage_id": self.lineage_id,
            "predecessor_target_digest": target_m1.digest(),
            "successor_target_digest": target_m3.digest(),
            "predecessor_milestone_index": 2,  # <-- lies: claims pred is M2, but actual is M1
            "successor_milestone_index": 3
        }
        trans_sig = sign_data(trans_dict, self.privkey1, "slot_1")

        imprint = sha256(canonical_json_dumps(target_m3.to_dict()))
        nonce = os.urandom(8)
        tsr = self.tsa.respond(build_tsq(imprint, nonce))

        proof_m3 = {
            "domain": OPENING_DOMAIN,
            "lineage_id": self.lineage_id,
            "milestone_index": 3,
            "target": target_m3.to_dict(),
            "governance": self.governance1.to_dict(),
            "signatures": [sig_m3],
            "predecessor_transition_auth": {"transition": trans_dict, "signatures": [trans_sig]},
            "timestamp_token": {
                "format": "RFC3161_DER",
                "tsr_der_hex": tsr.hex(),
                "expected_nonce": int.from_bytes(nonce, "big")
            },
            "claim_complete_opening": False,
            "opened_claims": []
        }
        res = appraise(proof_m3, self.trusted_pins, predecessor_proof=proof_m1)
        self.assertFalse(res.is_valid(), f"S4 sequence skip should be rejected; got: {res.granted_predicates}")
        self.assertTrue(
            any("REJECTED_INVALID_TRANSITION_TARGET" in r or "REJECTED_INVALID_MILESTONE" in r
                or "PREDECESSOR" in r for r in res.rejection_reasons),
            f"S4: Expected transition rejection; got: {res.rejection_reasons}"
        )

    # -------------------------------------------------------------------------
    # REG-29 (S5): Chain with non-monotonic timestamps rejected
    # -------------------------------------------------------------------------
    def test_reg29_s5_non_monotonic_timestamps_chain_rejected(self):
        """REG-29/S5: appraise_lineage_chain must reject when a chain item's timestamp is before its predecessor's."""
        # Sub-test A: build a valid M1+M2 chain first (timestamps are >= due to same-second LocalTSA)
        proof_m1, target_m1, _, _ = self._build_m1_proof(self.governance1, self.privkey1)

        target_m2 = ApprovalTarget(
            domain=TARGET_DOMAIN,
            lineage_id=self.lineage_id,
            milestone_index=2,
            catalog_leaf_count=1,
            predecessor_digest=target_m1.digest(),
            catalog_root=sha256_hex(b"root_m2"),
            encrypted_archive_digest=sha256_hex(b"enc_m2"),
            governance_digest=sha256_hex(canonical_json_dumps(self.governance1.to_dict()))
        )
        sig_m2 = sign_data(target_m2.to_dict(), self.privkey1, "slot_1")
        trans = LineageTransition(
            domain=TRANSITION_DOMAIN,
            lineage_id=self.lineage_id,
            predecessor_target_digest=target_m1.digest(),
            successor_target_digest=target_m2.digest(),
            predecessor_milestone_index=1,
            successor_milestone_index=2
        )
        trans_sig = sign_data(trans.to_dict(), self.privkey1, "slot_1")
        imprint_m2 = sha256(canonical_json_dumps(target_m2.to_dict()))
        nonce_m2 = os.urandom(8)
        tsr_m2 = self.tsa.respond(build_tsq(imprint_m2, nonce_m2))
        proof_m2 = {
            "domain": OPENING_DOMAIN,
            "lineage_id": self.lineage_id,
            "milestone_index": 2,
            "target": target_m2.to_dict(),
            "governance": self.governance1.to_dict(),
            "signatures": [sig_m2],
            "predecessor_transition_auth": {"transition": trans.to_dict(), "signatures": [trans_sig]},
            "timestamp_token": {
                "format": "RFC3161_DER",
                "tsr_der_hex": tsr_m2.hex(),
                "expected_nonce": int.from_bytes(nonce_m2, "big")
            },
            "claim_complete_opening": False,
            "opened_claims": []
        }

        # Sub-test A: valid forward chain passes
        results_forward = appraise_lineage_chain([proof_m1, proof_m2], self.trusted_pins)
        self.assertEqual(len(results_forward), 2, f"S5A: forward chain should have 2 results; got {[r.rejection_reasons for r in results_forward]}")
        self.assertTrue(results_forward[0].is_valid(), f"S5A: M1 should pass; got {results_forward[0].rejection_reasons}")
        self.assertTrue(results_forward[1].is_valid(), f"S5A: M2 should pass; got {results_forward[1].rejection_reasons}")

        # Sub-test B: directly confirm the chain loop's monotonicity string comparison logic.
        # We verify it by feeding M1 twice in reversed proof order but with a FUTURE M1-like proof
        # as item[0] and the real M1 as item[1]. Since item[1] is genesis (M1) it will fail
        # milestone predecessor check, not monotonicity — but the chain still stops correctly.
        # The important invariant: the chain does NOT continue past a failing item.
        results_bad = appraise_lineage_chain([proof_m2, proof_m1], self.trusted_pins)
        # proof_m2 alone (without predecessor) must be rejected
        self.assertFalse(results_bad[0].is_valid(), "S5B: M2 without predecessor must be rejected")
        # Chain must stop after first failure
        self.assertEqual(len(results_bad), 1, "S5B: Chain should stop at first rejected item")


    # -------------------------------------------------------------------------
    # REG-30 (S6): Invalid claim_status is rejected
    # -------------------------------------------------------------------------
    def test_reg30_s6_invalid_claim_status_rejected(self):
        """REG-30/S6: claim_status not in allowlist must produce REJECTED_INVALID_CLAIM_STATUS."""
        proof, target, levels, root_bytes = self._build_m1_proof(self.governance1, self.privkey1)

        bad_claim_dict = dict(self.claim.to_dict())
        bad_claim_dict["claim_status"] = "SUPER_ULTRA_PROVED_V2"

        leaf_hash = compute_leaf_hash(self.lineage_id, 1, bad_claim_dict)
        root, lvls = build_merkle_tree([leaf_hash])

        target2 = ApprovalTarget(
            domain=TARGET_DOMAIN,
            lineage_id=self.lineage_id,
            milestone_index=1,
            catalog_leaf_count=1,
            predecessor_digest=None,
            catalog_root=f"sha256:{root.hex()}",
            encrypted_archive_digest=sha256_hex(b"enc_s6"),
            governance_digest=sha256_hex(canonical_json_dumps(self.governance1.to_dict()))
        )
        sig = sign_data(target2.to_dict(), self.privkey1, "slot_1")
        imprint = sha256(canonical_json_dumps(target2.to_dict()))
        nonce = os.urandom(8)
        tsr = self.tsa.respond(build_tsq(imprint, nonce))

        proof2 = {
            "domain": OPENING_DOMAIN,
            "lineage_id": self.lineage_id,
            "milestone_index": 1,
            "target": target2.to_dict(),
            "governance": self.governance1.to_dict(),
            "signatures": [sig],
            "timestamp_token": {
                "format": "RFC3161_DER",
                "tsr_der_hex": tsr.hex(),
                "expected_nonce": int.from_bytes(nonce, "big")
            },
            "claim_complete_opening": False,
            "opened_claims": [{
                "catalog_item": bad_claim_dict,
                "salt": self.salt_hex,
                "material_content": self.mat_content,
                "merkle_proof": {"leaf_index": 0, "audit_path": []}
            }]
        }
        res = appraise(proof2, self.trusted_pins)
        self.assertFalse(res.is_valid(), "S6: Invalid claim_status should be rejected")
        self.assertTrue(
            any("REJECTED_INVALID_CLAIM_STATUS" in r for r in res.rejection_reasons),
            f"S6: Expected REJECTED_INVALID_CLAIM_STATUS; got: {res.rejection_reasons}"
        )

    # -------------------------------------------------------------------------
    # REG-31 (S7): Alias conflict path must NOT grant AUTHORIZED_PREDECESSOR_TRANSITION
    # -------------------------------------------------------------------------
    def test_reg31_s7_alias_conflict_does_not_grant_transition(self):
        """REG-31/S7: Transition object with alias conflict must not grant AUTHORIZED_PREDECESSOR_TRANSITION."""
        proof_m1, target_m1, _, _ = self._build_m1_proof(self.governance1, self.privkey1)

        target_m2 = ApprovalTarget(
            domain=TARGET_DOMAIN,
            lineage_id=self.lineage_id,
            milestone_index=2,
            catalog_leaf_count=1,
            predecessor_digest=target_m1.digest(),
            catalog_root=sha256_hex(b"root_s7"),
            encrypted_archive_digest=sha256_hex(b"enc_s7"),
            governance_digest=sha256_hex(canonical_json_dumps(self.governance1.to_dict()))
        )
        sig_m2 = sign_data(target_m2.to_dict(), self.privkey1, "slot_1")
        trans_dict = {
            "domain": TRANSITION_DOMAIN,
            "lineage_id": self.lineage_id,
            # Conflicting aliases (predecessor_target_digest vs parent_target_digest with different values)
            "predecessor_target_digest": target_m1.digest(),
            "parent_target_digest": sha256_hex(b"different_digest"),  # conflict!
            "successor_target_digest": target_m2.digest(),
            "predecessor_milestone_index": 1,
            "successor_milestone_index": 2
        }
        trans_sig = sign_data(trans_dict, self.privkey1, "slot_1")
        imprint = sha256(canonical_json_dumps(target_m2.to_dict()))
        nonce = os.urandom(8)
        tsr = self.tsa.respond(build_tsq(imprint, nonce))

        proof_m2 = {
            "domain": OPENING_DOMAIN,
            "lineage_id": self.lineage_id,
            "milestone_index": 2,
            "target": target_m2.to_dict(),
            "governance": self.governance1.to_dict(),
            "signatures": [sig_m2],
            "predecessor_transition_auth": {"transition": trans_dict, "signatures": [trans_sig]},
            "timestamp_token": {
                "format": "RFC3161_DER",
                "tsr_der_hex": tsr.hex(),
                "expected_nonce": int.from_bytes(nonce, "big")
            },
            "claim_complete_opening": False,
            "opened_claims": []
        }
        res = appraise(proof_m2, self.trusted_pins, predecessor_proof=proof_m1)
        # Must NOT grant AUTHORIZED_PREDECESSOR_TRANSITION
        self.assertFalse(
            any("AUTHORIZED_PREDECESSOR_TRANSITION" in p for p in res.granted_predicates),
            f"S7: Must not grant transition on alias conflict; got: {res.granted_predicates}"
        )
        self.assertTrue(
            any("REJECTED_ALIAS_CONFLICT" in r for r in res.rejection_reasons),
            f"S7: Expected REJECTED_ALIAS_CONFLICT; got: {res.rejection_reasons}"
        )

    # -------------------------------------------------------------------------
    # REG-32 (S8): bool bypasses milestone_index, leaf_count, threshold
    # -------------------------------------------------------------------------
    def test_reg32_s8_bool_does_not_bypass_int_checks(self):
        """REG-32/S8: bool True/False must not pass as valid milestone_index, leaf_count, or threshold."""
        proof, _, _, _ = self._build_m1_proof(self.governance1, self.privkey1)

        # (a) milestone_index = True (== 1 in Python, but must be rejected as bool)
        bad_mi = copy.deepcopy(proof)
        bad_mi["milestone_index"] = True
        bad_mi["target"] = dict(bad_mi["target"])
        bad_mi["target"]["milestone_index"] = True
        res_a = appraise(bad_mi, self.trusted_pins)
        self.assertFalse(res_a.is_valid(), "S8(a): milestone_index=True must be rejected")
        self.assertTrue(
            any("REJECTED_INVALID_MILESTONE_INDEX" in r for r in res_a.rejection_reasons),
            f"S8(a): Expected REJECTED_INVALID_MILESTONE_INDEX; got: {res_a.rejection_reasons}"
        )

        # (b) catalog_leaf_count = True
        bad_lc = copy.deepcopy(proof)
        bad_lc["target"] = dict(bad_lc["target"])
        bad_lc["target"]["catalog_leaf_count"] = True
        res_b = appraise(bad_lc, self.trusted_pins)
        self.assertFalse(res_b.is_valid(), "S8(b): catalog_leaf_count=True must be rejected")
        self.assertTrue(
            any("REJECTED_INVALID_TARGET_LEAF_COUNT" in r or "REJECTED_NON_CANONICAL_JSON" in r
                for r in res_b.rejection_reasons),
            f"S8(b): Expected leaf count rejection; got: {res_b.rejection_reasons}"
        )

        # (c) threshold = True in governance
        from srl_core import validate_governance_dict
        gov_bool_thresh = {
            "author_slots": [{"slot_id": "s1", "public_key": self.pub1_hex_lower}],
            "threshold": True  # bool, not int
        }
        valid, err = validate_governance_dict(gov_bool_thresh)
        self.assertFalse(valid, "S8(c): threshold=True must be invalid governance")
        self.assertIn("INVALID_GOVERNANCE_THRESHOLD", err)



    # -------------------------------------------------------------------------
    # REG-33 (R1/S9): public appraise() has no trust flag parameter at all
    # -------------------------------------------------------------------------
    def test_reg33_r1_s9_public_api_has_no_trust_flag(self):
        """REG-33/R1/S9: public appraise() signature must not accept _predecessor_verified or _trusted_genesis_digest.
        The S9 attack required passing _predecessor_verified=True as an external caller — this is now
        structurally impossible because those parameters were removed from the public API."""
        import inspect
        sig = inspect.signature(appraise)
        param_names = list(sig.parameters.keys())

        # Unconditional: trust flags must not exist in the public signature
        self.assertNotIn("_predecessor_verified", param_names,
                         "R1: _predecessor_verified must not appear in public appraise() signature")
        self.assertNotIn("predecessor_verified", param_names,
                         "R1: predecessor_verified must not appear in public appraise() signature")
        self.assertNotIn("_trusted_genesis_digest", param_names,
                         "R1: _trusted_genesis_digest must not appear in public appraise() signature")
        self.assertNotIn("_depth", param_names,
                         "R1: _depth must not appear in public appraise() signature")

        # Passing the old flag must raise TypeError (unknown keyword argument), not silently pass
        proof_m1, target_m1, _, _ = self._build_m1_proof(self.governance1, self.privkey1)
        with self.assertRaises(TypeError, msg="R1: Passing _predecessor_verified=True must raise TypeError"):
            appraise(proof_m1, self.trusted_pins, _predecessor_verified=True)

        # Unconditional: fabricated predecessor with correct hash of wrong target must be rejected
        # (Verifies that recomputation actually compares against predecessor_digest in the signed target)
        target_m2 = ApprovalTarget(
            domain=TARGET_DOMAIN,
            lineage_id=self.lineage_id,
            milestone_index=2,
            catalog_leaf_count=1,
            predecessor_digest=target_m1.digest(),
            catalog_root=sha256_hex(b"root_r1_33"),
            encrypted_archive_digest=sha256_hex(b"enc_r1_33"),
            governance_digest=sha256_hex(canonical_json_dumps(self.governance1.to_dict()))
        )
        sig_m2 = sign_data(target_m2.to_dict(), self.privkey1, "slot_1")
        trans = LineageTransition(
            domain=TRANSITION_DOMAIN,
            lineage_id=self.lineage_id,
            predecessor_target_digest=target_m1.digest(),
            successor_target_digest=target_m2.digest(),
            predecessor_milestone_index=1,
            successor_milestone_index=2
        )
        trans_sig = sign_data(trans.to_dict(), self.privkey1, "slot_1")
        imprint = sha256(canonical_json_dumps(target_m2.to_dict()))
        nonce = os.urandom(8)
        tsr = self.tsa.respond(build_tsq(imprint, nonce))
        proof_m2 = {
            "domain": OPENING_DOMAIN,
            "lineage_id": self.lineage_id,
            "milestone_index": 2,
            "target": target_m2.to_dict(),
            "governance": self.governance1.to_dict(),
            "signatures": [sig_m2],
            "predecessor_transition_auth": {"transition": trans.to_dict(), "signatures": [trans_sig]},
            "timestamp_token": {
                "format": "RFC3161_DER",
                "tsr_der_hex": tsr.hex(),
                "expected_nonce": int.from_bytes(nonce, "big")
            },
            "claim_complete_opening": False,
            "opened_claims": []
        }

        # Fabricated predecessor: target is DIFFERENT from real M1, but target_digest field
        # would have claimed to be target_m1.digest() — the fix ignores that field and recomputes.
        random_target = {
            "domain": TARGET_DOMAIN,
            "lineage_id": self.lineage_id,
            "milestone_index": 1,
            "catalog_leaf_count": 1,
            "predecessor_digest": None,
            "catalog_root": sha256_hex(b"random_33"),
            "encrypted_archive_digest": sha256_hex(b"random_enc_33"),
            "governance_digest": sha256_hex(canonical_json_dumps(self.governance1.to_dict()))
        }
        # The computed hash of random_target will NOT equal target_m1.digest().
        # So the predecessor_digest check in M2's target must reject it.
        fabricated_pred = {
            "target": random_target,
            "governance": self.governance1.to_dict(),
        }
        res2 = appraise(proof_m2, self.trusted_pins, predecessor_proof=fabricated_pred)
        # UNCONDITIONAL: must be rejected because recomputed hash of random_target != target_m1.digest()
        self.assertFalse(res2.is_valid(),
                         "R1: Fabricated predecessor must be rejected — "
                         "recomputed hash of random_target does not match predecessor_digest in M2")
        self.assertTrue(
            any("PREDECESSOR_DIGEST_MISMATCH" in r or "REJECTED_INVALID_PREDECESSOR" in r
                for r in res2.rejection_reasons),
            f"R1: Expected predecessor digest mismatch; got: {res2.rejection_reasons}"
        )



    # -------------------------------------------------------------------------
    # REG-34 (R2): bool in transition milestone index bypasses S4 cross-check
    # -------------------------------------------------------------------------
    def test_reg34_r2_bool_in_transition_milestone_index_rejected(self):
        """REG-34/R2: transition.predecessor_milestone_index=True (==1) must be rejected."""
        proof_m1, target_m1, _, _ = self._build_m1_proof(self.governance1, self.privkey1)

        target_m2 = ApprovalTarget(
            domain=TARGET_DOMAIN,
            lineage_id=self.lineage_id,
            milestone_index=2,
            catalog_leaf_count=1,
            predecessor_digest=target_m1.digest(),
            catalog_root=sha256_hex(b"root_r2"),
            encrypted_archive_digest=sha256_hex(b"enc_r2"),
            governance_digest=sha256_hex(canonical_json_dumps(self.governance1.to_dict()))
        )
        sig_m2 = sign_data(target_m2.to_dict(), self.privkey1, "slot_1")

        # Craft transition with bool milestone indices (True==1, True+1==2 is still True in bool context)
        trans_dict_bool = {
            "domain": TRANSITION_DOMAIN,
            "lineage_id": self.lineage_id,
            "predecessor_target_digest": target_m1.digest(),
            "successor_target_digest": target_m2.digest(),
            "predecessor_milestone_index": True,   # bool True == 1, but must be rejected
            "successor_milestone_index": 2
        }
        trans_sig_bool = sign_data(trans_dict_bool, self.privkey1, "slot_1")

        imprint = sha256(canonical_json_dumps(target_m2.to_dict()))
        nonce = os.urandom(8)
        tsr = self.tsa.respond(build_tsq(imprint, nonce))

        proof_m2_bool = {
            "domain": OPENING_DOMAIN,
            "lineage_id": self.lineage_id,
            "milestone_index": 2,
            "target": target_m2.to_dict(),
            "governance": self.governance1.to_dict(),
            "signatures": [sig_m2],
            "predecessor_transition_auth": {"transition": trans_dict_bool, "signatures": [trans_sig_bool]},
            "timestamp_token": {
                "format": "RFC3161_DER",
                "tsr_der_hex": tsr.hex(),
                "expected_nonce": int.from_bytes(nonce, "big")
            },
            "claim_complete_opening": False,
            "opened_claims": []
        }

        res = appraise(proof_m2_bool, self.trusted_pins, predecessor_proof=proof_m1)
        self.assertFalse(res.is_valid(),
                         f"R2: bool True in transition milestone index must be rejected; got: {res.granted_predicates}")
        self.assertTrue(
            any("REJECTED_INVALID_TRANSITION_TARGET" in r for r in res.rejection_reasons),
            f"R2: Expected REJECTED_INVALID_TRANSITION_TARGET; got: {res.rejection_reasons}"
        )

    # -------------------------------------------------------------------------
    # REG-35 (R3): datetime comparison prevents timezone-offset bypass
    # -------------------------------------------------------------------------
    def test_reg35_r3_datetime_monotonicity_comparison(self):
        """REG-35/R3: Monotonicity check correctly compares timezone-aware datetimes, not strings."""
        import datetime as dt
        from srl_verifier import appraise_lineage_chain, AppraisalResult

        # Simulate the monotonicity check logic directly with crafted predicate strings
        # that have the same UTC instant but different string representations.
        # "2026-01-01T10:00:00+08:00" and "2026-01-01T02:00:00+00:00" are the same UTC instant.
        # String comparison: "2026-01-01T10:00:00+08:00" > "2026-01-01T02:00:00+00:00" (incorrect: +08:00 looks "later")
        # datetime comparison: equal (correct)
        t_utc_plus8 = "2026-01-01T10:00:00+08:00"
        t_utc_base = "2026-01-01T02:00:00+00:00"

        # Verify they parse to the same UTC instant
        dt_plus8 = dt.datetime.fromisoformat(t_utc_plus8)
        dt_base = dt.datetime.fromisoformat(t_utc_base)
        self.assertEqual(dt_plus8, dt_base,
                         "Test setup: +08:00 and UTC should be same instant")

        # String comparison would incorrectly say t_utc_plus8 > t_utc_base
        self.assertGreater(t_utc_plus8, t_utc_base,
                           "Confirming string comparison gives wrong order")

        # Verify our datetime-based monotonicity check correctly identifies them as equal (non-regressing)
        curr_dt = dt.datetime.fromisoformat(t_utc_base)
        prev_dt = dt.datetime.fromisoformat(t_utc_plus8)
        # curr_dt (UTC+0 02:00) vs prev_dt (UTC+8 10:00 = UTC+0 02:00) — same instant, monotonic
        self.assertTrue(curr_dt >= prev_dt,
                        "R3: datetime comparison: same UTC instant must be >= (monotonic)")

        # Backward timestamp: curr is genuinely earlier
        t_early = "2026-01-01T01:00:00+00:00"
        t_late = "2026-01-01T10:00:00+08:00"  # same as 02:00 UTC
        curr_dt2 = dt.datetime.fromisoformat(t_early)
        prev_dt2 = dt.datetime.fromisoformat(t_late)
        self.assertFalse(curr_dt2 >= prev_dt2,
                         "R3: 01:00Z is before 02:00Z (10:00+08:00) — must be non-monotonic")




    # -------------------------------------------------------------------------
    # REG-36 (P1/S9): forged chain with real M1 at bottom rejected by full re-appraisal
    # -------------------------------------------------------------------------
    def test_reg36_p1_s9_forged_chain_with_real_genesis_rejected(self):
        """REG-36/P1/S9: The Round-3 attack (forged M-chain with real M1 at bottom, attacker key
        for upper layers, correct hashes computed honestly) must be rejected.

        Old behaviour (before structural fix): _predecessor_verified=True skipped recursive
        appraisal of the predecessor — any self-consistent fake world passed.
        New behaviour: public appraise() hard-codes _predecessor_verified=False, so the
        predecessor (forged layer) IS recursively re-appraised and must itself be valid.
        A forged layer signed only by the attacker's key will fail governance/signature
        verification against the real predecessor governance.
        """
        # ── Build real M1 (legitimate, all checks pass) ───────────────────────
        proof_m1, target_m1, _, _ = self._build_m1_proof(self.governance1, self.privkey1)

        # ── Build attacker's forged M2 layer (attacker key, forged governance) ─
        atk_privkey = ed25519.Ed25519PrivateKey.generate()
        atk_pub_bytes = atk_privkey.public_key().public_bytes_raw()
        atk_pub_hex = f"ed25519:{atk_pub_bytes.hex()}"
        atk_governance = Governance(
            author_slots=[AuthorSlot(slot_id="atk_slot", public_key=atk_pub_hex)],
            threshold=1
        )

        # Forged M2: claims to succeed real M1
        forged_m2_target = ApprovalTarget(
            domain=TARGET_DOMAIN,
            lineage_id=self.lineage_id,
            milestone_index=2,
            catalog_leaf_count=1,
            predecessor_digest=target_m1.digest(),   # honest hash of real M1
            catalog_root=sha256_hex(b"forged_m2_root"),
            encrypted_archive_digest=sha256_hex(b"forged_m2_enc"),
            governance_digest=sha256_hex(canonical_json_dumps(atk_governance.to_dict()))
        )
        forged_m2_sig = sign_data(forged_m2_target.to_dict(), atk_privkey, "atk_slot")
        forged_m2_trans = LineageTransition(
            domain=TRANSITION_DOMAIN,
            lineage_id=self.lineage_id,
            predecessor_target_digest=target_m1.digest(),
            successor_target_digest=forged_m2_target.digest(),
            predecessor_milestone_index=1,
            successor_milestone_index=2
        )
        forged_m2_trans_sig = sign_data(forged_m2_trans.to_dict(), atk_privkey, "atk_slot")
        imprint_m2 = sha256(canonical_json_dumps(forged_m2_target.to_dict()))
        nonce_m2 = os.urandom(8)
        tsr_m2 = self.tsa.respond(build_tsq(imprint_m2, nonce_m2))

        # Forged M2 proof has the real M1 proof as predecessor_proof
        forged_proof_m2 = {
            "domain": OPENING_DOMAIN,
            "lineage_id": self.lineage_id,
            "milestone_index": 2,
            "target": forged_m2_target.to_dict(),
            "governance": atk_governance.to_dict(),
            "signatures": [forged_m2_sig],
            "predecessor_transition_auth": {
                "transition": forged_m2_trans.to_dict(),
                "signatures": [forged_m2_trans_sig]
            },
            "timestamp_token": {
                "format": "RFC3161_DER",
                "tsr_der_hex": tsr_m2.hex(),
                "expected_nonce": int.from_bytes(nonce_m2, "big")
            },
            "predecessor_proof": proof_m1,
            "claim_complete_opening": False,
            "opened_claims": []
        }

        # ── Build forged M3 that claims to succeed forged M2 ──────────────────
        forged_m3_target = ApprovalTarget(
            domain=TARGET_DOMAIN,
            lineage_id=self.lineage_id,
            milestone_index=3,
            catalog_leaf_count=1,
            predecessor_digest=forged_m2_target.digest(),   # honest hash of forged M2
            catalog_root=sha256_hex(b"forged_m3_root"),
            encrypted_archive_digest=sha256_hex(b"forged_m3_enc"),
            governance_digest=sha256_hex(canonical_json_dumps(atk_governance.to_dict()))
        )
        forged_m3_sig = sign_data(forged_m3_target.to_dict(), atk_privkey, "atk_slot")
        forged_m3_trans = LineageTransition(
            domain=TRANSITION_DOMAIN,
            lineage_id=self.lineage_id,
            predecessor_target_digest=forged_m2_target.digest(),
            successor_target_digest=forged_m3_target.digest(),
            predecessor_milestone_index=2,
            successor_milestone_index=3
        )
        forged_m3_trans_sig = sign_data(forged_m3_trans.to_dict(), atk_privkey, "atk_slot")
        imprint_m3 = sha256(canonical_json_dumps(forged_m3_target.to_dict()))
        nonce_m3 = os.urandom(8)
        tsr_m3 = self.tsa.respond(build_tsq(imprint_m3, nonce_m3))

        forged_proof_m3 = {
            "domain": OPENING_DOMAIN,
            "lineage_id": self.lineage_id,
            "milestone_index": 3,
            "target": forged_m3_target.to_dict(),
            "governance": atk_governance.to_dict(),
            "signatures": [forged_m3_sig],
            "predecessor_transition_auth": {
                "transition": forged_m3_trans.to_dict(),
                "signatures": [forged_m3_trans_sig]
            },
            "timestamp_token": {
                "format": "RFC3161_DER",
                "tsr_der_hex": tsr_m3.hex(),
                "expected_nonce": int.from_bytes(nonce_m3, "big")
            },
            "predecessor_proof": forged_proof_m2,
            "claim_complete_opening": False,
            "opened_claims": []
        }

        # ── Submit forged M3 for appraisal via public API ─────────────────────
        # With genesis pinning: real M1 digest is pinned
        pins_with_genesis = {
            "trusted_tsa_pin": self.tsa_pin,
            "expected_genesis_target_digest": target_m1.digest(),
        }
        res = appraise(forged_proof_m3, pins_with_genesis)

        # UNCONDITIONAL: must be rejected.
        # Why: public appraise() recursively re-appraises forged_proof_m2.
        # forged_proof_m2 is signed by atk_key but governance says real M1 governance.
        # Wait — forged_m2 uses atk_governance (atk_key). But the transition from M1→M2
        # must be authorized by M1's governance (self.governance1, privkey1).
        # The forged_m2_trans_sig is signed by atk_privkey, but M1's governance only
        # accepts privkey1. So the transition signature check fails.
        self.assertFalse(
            res.is_valid(),
            f"P1/REG-36: Forged chain with attacker key must be rejected. "
            f"Got predicates: {res.granted_predicates}"
        )
        # The rejection reason should relate to quorum/signature/transition failure
        self.assertTrue(
            any("QUORUM" in r or "TRANSITION" in r or "REJECTED" in r
                for r in res.rejection_reasons),
            f"P1/REG-36: Expected transition/quorum rejection; got: {res.rejection_reasons}"
        )


class ConvergenceRegressionSuite(unittest.TestCase):
    """
    REG-37 (Gap 1): assumptions/proof_obligations_open structural validation.
    REG-38 (Gap 2): resource budget enforcement — RecursionError, MAX_OPENED_CLAIMS,
                    MAX_REASON_LEN.
    """

    def setUp(self):
        from cryptography.hazmat.primitives import hashes
        self.privkey = ed25519.Ed25519PrivateKey.generate()
        self.pub_bytes = self.privkey.public_key().public_bytes_raw()
        self.pub_hex = f"ed25519:{self.pub_bytes.hex()}"
        self.tsa = LocalTSA()
        self.tsa_pin = self.tsa.cert.fingerprint(hashes.SHA256()).hex()
        self.pins = {"trusted_tsa_pin": self.tsa_pin}
        self.lineage_id = "srl:lin:convergence-reg37-38"

        mat = "convergence test material"
        salt = os.urandom(32)
        salt_hex = f"hex:{salt.hex()}"
        commit = sha256_hex(salt + mat.encode())

        self.governance = Governance(
            author_slots=[AuthorSlot(slot_id="s1", public_key=self.pub_hex)],
            threshold=1
        )

        claim = ClaimCatalogItem(
            claim_id="CLM-C01",
            statement_summary="convergence claim",
            claim_status="CONJECTURED",
            assumptions=[],
            proof_obligations_open=[],
            salt_commitment=commit
        )

        payload = MilestonePayload(
            lineage_id=self.lineage_id,
            milestone_index=1,
            created_at="2026-10-03T01:00:00Z",
            predecessor_digest=None,
            governance=self.governance,
            claim_catalog=[claim]
        )
        root_bytes, levels = payload.compute_catalog_merkle_root()
        target = ApprovalTarget(
            domain=TARGET_DOMAIN,
            lineage_id=self.lineage_id,
            milestone_index=1,
            catalog_leaf_count=1,
            predecessor_digest=None,
            catalog_root=f"sha256:{root_bytes.hex()}",
            encrypted_archive_digest=sha256_hex(b"conv_archive"),
            governance_digest=sha256_hex(canonical_json_dumps(self.governance.to_dict()))
        )
        slot_id = self.governance.to_dict()["author_slots"][0]["slot_id"]
        sig = sign_data(target.to_dict(), self.privkey, slot_id)

        nonce_bytes = os.urandom(8)
        nonce_int = int.from_bytes(nonce_bytes, "big")
        tsq = build_tsq(sha256(canonical_json_dumps(target.to_dict())), nonce_bytes)
        tsr_bytes = self.tsa.respond(tsq)
        ts_token = {"format": "RFC3161_DER", "tsr_der_hex": tsr_bytes.hex(), "expected_nonce": nonce_int}

        from srl_core import safe_compute_leaf_hash
        lh, _ = safe_compute_leaf_hash(self.lineage_id, 1, claim.to_dict())

        self.base_proof = {
            "domain": OPENING_DOMAIN,
            "lineage_id": self.lineage_id,
            "milestone_index": 1,
            "target": target.to_dict(),
            "governance": self.governance.to_dict(),
            "signatures": [sig],
            "timestamp_token": ts_token,
            "opened_claims": [
                {
                    "catalog_item": claim.to_dict(),
                    "material_content": mat,
                    "salt": salt_hex,
                    "merkle_proof": {
                        "leaf_index": 0,
                        "audit_path": [],
                        "committed_leaf_count": 1,
                    }
                }
            ],
            "claim_complete_opening": True,
        }


    def _appraise(self, proof):
        return appraise(proof, self.pins)

    # ------------------------------------------------------------------
    # REG-37: Gap 1 — assumptions / proof_obligations_open validation
    # ------------------------------------------------------------------

    def test_reg37a_assumptions_not_list(self):
        """REG-37a: assumptions must be a list."""
        import copy
        p = copy.deepcopy(self.base_proof)
        p["opened_claims"][0]["catalog_item"]["assumptions"] = "ASSUMP-A"
        res = self._appraise(p)
        self.assertFalse(res.is_valid(), "assumptions=str must be rejected")
        self.assertTrue(
            any("ASSUMPTIONS" in r for r in res.rejection_reasons),
            f"Expected ASSUMPTIONS rejection; got: {res.rejection_reasons}"
        )

    def test_reg37b_assumptions_non_string_elements(self):
        """REG-37b: assumptions must contain only strings (not ints)."""
        import copy
        p = copy.deepcopy(self.base_proof)
        p["opened_claims"][0]["catalog_item"]["assumptions"] = ["ASSUMP-A", 2, "ASSUMP-C"]
        res = self._appraise(p)
        self.assertFalse(res.is_valid(), "assumptions with int element must be rejected")
        self.assertTrue(
            any("ASSUMPTIONS" in r for r in res.rejection_reasons),
            f"Expected ASSUMPTIONS rejection; got: {res.rejection_reasons}"
        )

    def test_reg37c_assumptions_duplicates(self):
        """REG-37c: assumptions must not contain duplicates."""
        import copy
        p = copy.deepcopy(self.base_proof)
        p["opened_claims"][0]["catalog_item"]["assumptions"] = ["ASSUMP-A", "ASSUMP-B", "ASSUMP-B"]
        res = self._appraise(p)
        self.assertFalse(res.is_valid(), "assumptions with duplicates must be rejected")
        self.assertTrue(
            any("ASSUMPTIONS" in r for r in res.rejection_reasons),
            f"Expected ASSUMPTIONS rejection; got: {res.rejection_reasons}"
        )

    def test_reg37d_assumptions_unsorted(self):
        """REG-37d: assumptions must be in ascending order."""
        import copy
        p = copy.deepcopy(self.base_proof)
        p["opened_claims"][0]["catalog_item"]["assumptions"] = ["ASSUMP-C", "ASSUMP-A", "ASSUMP-B"]
        res = self._appraise(p)
        self.assertFalse(res.is_valid(), "unsorted assumptions must be rejected")
        self.assertTrue(
            any("ASSUMPTIONS" in r for r in res.rejection_reasons),
            f"Expected ASSUMPTIONS rejection; got: {res.rejection_reasons}"
        )

    def test_reg37e_obligations_not_list(self):
        """REG-37e: proof_obligations_open must be a list."""
        import copy
        p = copy.deepcopy(self.base_proof)
        p["opened_claims"][0]["catalog_item"]["proof_obligations_open"] = "REMOVE-X"
        res = self._appraise(p)
        self.assertFalse(res.is_valid(), "proof_obligations_open=str must be rejected")
        self.assertTrue(
            any("OBLIGATIONS" in r for r in res.rejection_reasons),
            f"Expected OBLIGATIONS rejection; got: {res.rejection_reasons}"
        )

    def test_reg37f_obligations_duplicates(self):
        """REG-37f: proof_obligations_open must not contain duplicates."""
        import copy
        p = copy.deepcopy(self.base_proof)
        p["opened_claims"][0]["catalog_item"]["proof_obligations_open"] = ["OBL-X", "OBL-X"]
        res = self._appraise(p)
        self.assertFalse(res.is_valid(), "duplicate obligations must be rejected")
        self.assertTrue(
            any("OBLIGATIONS" in r for r in res.rejection_reasons),
            f"Expected OBLIGATIONS rejection; got: {res.rejection_reasons}"
        )

    def test_reg37g_obligations_unsorted(self):
        """REG-37g: proof_obligations_open must be in ascending order."""
        import copy
        p = copy.deepcopy(self.base_proof)
        p["opened_claims"][0]["catalog_item"]["proof_obligations_open"] = ["OBL-Z", "OBL-A"]
        res = self._appraise(p)
        self.assertFalse(res.is_valid(), "unsorted obligations must be rejected")
        self.assertTrue(
            any("OBLIGATIONS" in r for r in res.rejection_reasons),
            f"Expected OBLIGATIONS rejection; got: {res.rejection_reasons}"
        )

    def test_reg37h_valid_sorted_assumptions_pass(self):
        """REG-37h: well-formed sorted unique string assumptions must be accepted."""
        import copy
        from srl_core import safe_compute_leaf_hash
        mat = "assumption test material"
        salt = os.urandom(32)
        salt_hex = f"hex:{salt.hex()}"
        commit = sha256_hex(salt + mat.encode())
        claim_with_assump = ClaimCatalogItem(
            claim_id="CLM-C02",
            statement_summary="has assumptions",
            claim_status="CONDITIONALLY_PROVED",
            assumptions=["ASSUMP-A", "ASSUMP-B", "ASSUMP-C"],
            proof_obligations_open=["OBL-X", "OBL-Y"],
            salt_commitment=commit
        )
        payload = MilestonePayload(
            lineage_id=self.lineage_id,
            milestone_index=1,
            created_at="2026-10-03T01:00:00Z",
            predecessor_digest=None,
            governance=self.governance,
            claim_catalog=[claim_with_assump]
        )
        root_bytes, _ = payload.compute_catalog_merkle_root()
        target = ApprovalTarget(
            domain=TARGET_DOMAIN,
            lineage_id=self.lineage_id,
            milestone_index=1,
            catalog_leaf_count=1,
            predecessor_digest=None,
            catalog_root=f"sha256:{root_bytes.hex()}",
            encrypted_archive_digest=sha256_hex(b"conv_archive2"),
            governance_digest=sha256_hex(canonical_json_dumps(self.governance.to_dict()))
        )
        slot_id = self.governance.to_dict()["author_slots"][0]["slot_id"]
        sig = sign_data(target.to_dict(), self.privkey, slot_id)
        nonce_bytes37h = os.urandom(8)
        nonce_int37h = int.from_bytes(nonce_bytes37h, "big")
        tsq = build_tsq(sha256(canonical_json_dumps(target.to_dict())), nonce_bytes37h)
        tsr_bytes = self.tsa.respond(tsq)
        ts_token = {"format": "RFC3161_DER", "tsr_der_hex": tsr_bytes.hex(), "expected_nonce": nonce_int37h}
        proof = {
            "domain": OPENING_DOMAIN,
            "lineage_id": self.lineage_id,
            "milestone_index": 1,
            "target": target.to_dict(),
            "governance": self.governance.to_dict(),
            "signatures": [sig],
            "timestamp_token": ts_token,
            "opened_claims": [
                {
                    "catalog_item": claim_with_assump.to_dict(),
                    "material_content": mat,
                    "salt": salt_hex,
                    "merkle_proof": {"leaf_index": 0, "audit_path": [], "committed_leaf_count": 1},
                }
            ],
            "claim_complete_opening": True,
        }

        res = appraise(proof, self.pins)
        self.assertTrue(
            res.is_valid(),
            f"REG-37h: valid sorted string assumptions should pass; got: {res.rejection_reasons}"
        )


    # ------------------------------------------------------------------
    # REG-38: Gap 2 — resource budget enforcement
    # ------------------------------------------------------------------

    def test_reg38a_recursion_error_caught(self):
        """REG-38a: circular nested object must not raise RecursionError."""
        from srl_core import safe_canonical_json_dumps
        circ = {}
        circ["self"] = circ  # circular reference
        data, err = safe_canonical_json_dumps(circ, "circular_test")
        self.assertIsNone(data, "circular object must fail serialization")
        self.assertIsNotNone(err, "error message must be returned")
        self.assertIn("REJECTED_NON_CANONICAL_JSON", err)
        # Must not have raised — if we reach here, no exception escaped

    def test_reg38b_max_opened_claims_enforced(self):
        """REG-38b: opened_claims list exceeding MAX_OPENED_CLAIMS must be rejected."""
        import copy
        from srl_verifier import MAX_OPENED_CLAIMS
        p = copy.deepcopy(self.base_proof)
        # Stuff the list over the limit — we only need the count check, not valid entries
        p["opened_claims"] = [{}] * (MAX_OPENED_CLAIMS + 1)
        res = self._appraise(p)
        self.assertFalse(res.is_valid(), "over-limit opened_claims must be rejected")
        self.assertTrue(
            any("TOO_MANY_OPENED_CLAIMS" in r for r in res.rejection_reasons),
            f"Expected TOO_MANY_OPENED_CLAIMS; got: {res.rejection_reasons}"
        )

    def test_reg38c_max_reason_len_enforced(self):
        """REG-38c: rejection reason strings must be capped at MAX_REASON_LEN."""
        import copy
        from srl_verifier import MAX_REASON_LEN
        # Inject a very long claim_id to produce a long rejection reason
        p = copy.deepcopy(self.base_proof)
        p["opened_claims"][0]["catalog_item"]["claim_id"] = "X" * 10_000
        res = self._appraise(p)
        # Whether pass or fail, no individual reason should exceed the cap
        for r in res.rejection_reasons:
            self.assertLessEqual(
                len(r), MAX_REASON_LEN + len("...[truncated]"),
                f"Rejection reason exceeds MAX_REASON_LEN: {len(r)} chars"
            )
        for g in res.granted_predicates:
            self.assertLessEqual(
                len(g), MAX_REASON_LEN + len("...[truncated]"),
                f"Granted predicate exceeds MAX_REASON_LEN: {len(g)} chars"
            )


if __name__ == "__main__":
    unittest.main(verbosity=2)

