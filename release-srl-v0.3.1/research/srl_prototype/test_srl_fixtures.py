"""
SRL Hardened Test Fixtures (FX-01 through FX-06 and Regressions REG-01 through REG-09).
Part of the Sealed Research Lineage (SRL) Stage C Prototype.
Specification: docs/SPEC-SEALED-LINEAGE-PROFILE.md
"""

from __future__ import annotations

import copy
import json
import os
import pathlib
import sys
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
    compute_leaf_hash,
    build_merkle_tree,
    TARGET_DOMAIN,
    OPENING_DOMAIN,
    TRANSITION_DOMAIN,
)
from srl_verifier import appraise, appraise_lineage_chain
from tsa import LocalTSA, build_tsq, verify_tsr


class SRLHardenedTestSuite(unittest.TestCase):
    """
    Comprehensive test suite covering FX-01~06 and REG-01~16:
    - REG-01: Fake 1900-01-01 timestamp without valid TSA signature
    - REG-02: Self-reported total_leaves under-reporting malleability
    - REG-03: Fresh-key n+1 takeover without predecessor transition quorum
    - REG-04: Zero threshold / zero author slot bypass
    - REG-05: Duplicate leaf opening cannot complete catalog
    - REG-06: Substituted predecessor governance rejected
    - REG-07: Duplicate-key multi-slot quorum rejected
    - REG-08: Predecessor proof must itself verify
    - REG-09: Timestamp nonce/query binding
    - REG-10: Mathematical Merkle leaf index position derivation
    - REG-11: Multi-milestone (M1->M2->M3) recursive and iterative appraisal
    - REG-12: Specification examples parse as implementation objects
    - REG-13: Expected genesis target digest pinning
    - REG-14: Archive timestamp cannot grant target/milestone existence
    - REG-15: Conflicting canonical and alias fields rejected
    - REG-16: Maximum predecessor depth recursion protection
    - Offline External DigiCert RFC 3161 fixture verification
    """

    def setUp(self):
        # 1. Genuine Author keypair
        self.lead_privkey = ed25519.Ed25519PrivateKey.generate()
        self.lead_pub_bytes = self.lead_privkey.public_key().public_bytes_raw()
        self.lead_pub_hex = f"ed25519:{self.lead_pub_bytes.hex()}"

        # 2. Attacker keypair
        self.attacker_privkey = ed25519.Ed25519PrivateKey.generate()
        self.attacker_pub_bytes = self.attacker_privkey.public_key().public_bytes_raw()
        self.attacker_pub_hex = f"ed25519:{self.attacker_pub_bytes.hex()}"

        self.governance = Governance(
            author_slots=[AuthorSlot(slot_id="slot_lead", public_key=self.lead_pub_hex)],
            threshold=1
        )

        # 3. Real RFC 3161 Local TSA (local test instance)
        self.tsa = LocalTSA()
        self.tsa_pin = self.tsa.cert.fingerprint(hashes.SHA256()).hex()
        self.trusted_pins = {"trusted_tsa_pin": self.tsa_pin}

        self.lineage_id = "srl:lin:riemann-gap-demo"

        # 4. Claim 1: Conditional Lemma L under Condition A (with 256-bit random salt)
        self.m1_mat1_content = "Lemma L holds under Condition A: For all compact manifolds..."
        self.m1_salt1_bytes = os.urandom(32)  # 256-bit salt
        self.m1_salt1_hex = f"hex:{self.m1_salt1_bytes.hex()}"
        self.m1_salt1_commit = sha256_hex(self.m1_salt1_bytes + self.m1_mat1_content.encode("utf-8"))

        self.m1_claim1 = ClaimCatalogItem(
            claim_id="CLM-001",
            statement_summary="Lemma L holds under Condition A",
            claim_status="CONDITIONALLY_PROVED",
            assumptions=["ASSUMP-A"],
            proof_obligations_open=["REMOVE-ASSUMP-A"],
            salted_commitment=self.m1_salt1_commit
        )

        # 5. Claim 2: Conjecture T (conjectured, dependent on CLM-001)
        self.m1_mat2_content = "Conjecture T entails from Lemma L plus Step S: Assuming CLM-001..."
        self.m1_salt2_bytes = os.urandom(32)
        self.m1_salt2_hex = f"hex:{self.m1_salt2_bytes.hex()}"
        self.m1_salt2_commit = sha256_hex(self.m1_salt2_bytes + self.m1_mat2_content.encode("utf-8"))

        self.m1_claim2 = ClaimCatalogItem(
            claim_id="CLM-002",
            statement_summary="Conjecture T entails from L and Step S",
            claim_status="CONJECTURED",
            assumptions=["CLM-001", "STEP-S"],
            proof_obligations_open=["COMPLETE-STEP-S"],
            salted_commitment=self.m1_salt2_commit
        )

        self.m1_payload = MilestonePayload(
            lineage_id=self.lineage_id,
            milestone_index=1,
            created_at="2026-10-02T12:00:00Z",
            predecessor_digest=None,
            governance=self.governance,
            claim_catalog=[self.m1_claim1, self.m1_claim2]
        )

        self.m1_root_bytes, self.m1_levels = self.m1_payload.compute_catalog_merkle_root()
        self.m1_target = ApprovalTarget(
            domain=TARGET_DOMAIN,
            lineage_id=self.lineage_id,
            milestone_index=1,
            catalog_leaf_count=2,  # Exactly 2 leaves
            predecessor_digest=None,
            catalog_root=f"sha256:{self.m1_root_bytes.hex()}",
            encrypted_archive_digest=sha256_hex(b"mock_encrypted_archive_m1"),
            governance_digest=sha256_hex(canonical_json_dumps(self.governance.to_dict()))
        )

        self.m1_sig = sign_data(self.m1_target.to_dict(), self.lead_privkey, "slot_lead")

        # Generate genuine RFC 3161 DER response with a bound nonce
        self.m1_nonce_bytes = os.urandom(8)
        self.m1_nonce_int = int.from_bytes(self.m1_nonce_bytes, "big")
        m1_imprint = sha256(canonical_json_dumps(self.m1_target.to_dict()))
        m1_tsq = build_tsq(m1_imprint, self.m1_nonce_bytes)
        self.m1_tsr_bytes = self.tsa.respond(m1_tsq)
        self.m1_ts_token = {
            "format": "RFC3161_DER",
            "tsr_der_hex": self.m1_tsr_bytes.hex(),
            "expected_nonce": self.m1_nonce_int
        }

        self.m1_proof_base = {
            "domain": OPENING_DOMAIN,
            "lineage_id": self.lineage_id,
            "milestone_index": 1,
            "target": self.m1_target.to_dict(),
            "governance": self.governance.to_dict(),
            "signatures": [self.m1_sig],
            "timestamp_token": self.m1_ts_token,
            "claim_complete_opening": False,
            "opened_claims": []
        }

        # Baseline Milestone 2 fixture
        self.m2_target = ApprovalTarget(
            domain=TARGET_DOMAIN,
            lineage_id=self.lineage_id,
            milestone_index=2,
            catalog_leaf_count=1,
            predecessor_digest=self.m1_target.digest(),
            catalog_root="sha256:0000000000000000000000000000000000000000000000000000000000000000",
            encrypted_archive_digest="sha256:0000000000000000000000000000000000000000000000000000000000000000",
            governance_digest=sha256_hex(canonical_json_dumps(self.governance.to_dict()))
        )
        self.m2_sig = sign_data(self.m2_target.to_dict(), self.lead_privkey, "slot_lead")
        self.m2_trans = LineageTransition(
            domain=TRANSITION_DOMAIN,
            lineage_id=self.lineage_id,
            predecessor_target_digest=self.m1_target.digest(),
            successor_target_digest=self.m2_target.digest(),
            predecessor_milestone_index=1,
            successor_milestone_index=2
        )
        self.m2_trans_sig = sign_data(self.m2_trans.to_dict(), self.lead_privkey, "slot_lead")
        m2_imprint = sha256(canonical_json_dumps(self.m2_target.to_dict()))
        m2_nonce_bytes = os.urandom(8)
        m2_tsq = build_tsq(m2_imprint, m2_nonce_bytes)
        self.m2_tsr_bytes = self.tsa.respond(m2_tsq)
        self.m2_proof_base = {
            "domain": OPENING_DOMAIN,
            "lineage_id": self.lineage_id,
            "milestone_index": 2,
            "target": self.m2_target.to_dict(),
            "governance": self.governance.to_dict(),
            "signatures": [self.m2_sig],
            "predecessor_transition_auth": {
                "transition": self.m2_trans.to_dict(),
                "signatures": [self.m2_trans_sig]
            },
            "timestamp_token": {
                "format": "RFC3161_DER",
                "tsr_der_hex": self.m2_tsr_bytes.hex(),
                "expected_nonce": int.from_bytes(m2_nonce_bytes, "big")
            },
            "predecessor_proof": self.m1_proof_base,
            "claim_complete_opening": False,
            "opened_claims": []
        }

    # -------------------------------------------------------------------------
    # FX-01: Happy Path (Partial M1 opening + Complete M2 opening)
    # -------------------------------------------------------------------------
    def test_fx01_happy_path(self):
        """FX-01: Partial M1 opening (1 of 2 claims) and complete M2 opening."""
        audit_path_0 = [{"direction": "right", "hash": f"sha256:{self.m1_levels[0][1].hex()}"}]

        m1_proof = {
            "domain": OPENING_DOMAIN,
            "lineage_id": self.lineage_id,
            "milestone_index": 1,
            "target": self.m1_target.to_dict(),
            "governance": self.governance.to_dict(),
            "signatures": [self.m1_sig],
            "timestamp_token": self.m1_ts_token,
            "claim_complete_opening": False,
            "opened_claims": [
                {
                    "catalog_item": self.m1_claim1.to_dict(),
                    "salt": self.m1_salt1_hex,
                    "material_content": self.m1_mat1_content,
                    "merkle_proof": {"leaf_index": 0, "audit_path": audit_path_0}
                }
            ]
        }

        result_m1 = appraise(m1_proof, self.trusted_pins)
        self.assertTrue(result_m1.is_valid(), f"M1 failed: {result_m1.rejection_reasons}")
        self.assertEqual(result_m1.opened_ratio, (1, 2))
        self.assertIn("PARTIAL_CATALOG_OPENING(revealed=1, committed_total=2)", result_m1.granted_predicates)

        # Build Milestone 2 (M2)
        m2_mat1_content = "Lemma L holds unconditionally: General proof without compactness assumption A..."
        m2_salt1_bytes = os.urandom(32)
        m2_salt1_hex = f"hex:{m2_salt1_bytes.hex()}"
        m2_salt1_commit = sha256_hex(m2_salt1_bytes + m2_mat1_content.encode("utf-8"))

        m2_claim1 = ClaimCatalogItem(
            claim_id="CLM-001",
            statement_summary="Lemma L holds unconditionally",
            claim_status="UNCONDITIONALLY_PROVED",
            assumptions=[],
            proof_obligations_open=[],
            salted_commitment=m2_salt1_commit
        )

        m2_payload = MilestonePayload(
            lineage_id=self.lineage_id,
            milestone_index=2,
            created_at="2026-10-15T12:00:00Z",
            predecessor_digest=self.m1_target.digest(),
            governance=self.governance,
            claim_catalog=[m2_claim1, self.m1_claim2]
        )

        m2_root_bytes, m2_levels = m2_payload.compute_catalog_merkle_root()
        m2_target = ApprovalTarget(
            domain=TARGET_DOMAIN,
            lineage_id=self.lineage_id,
            milestone_index=2,
            catalog_leaf_count=2,
            predecessor_digest=self.m1_target.digest(),
            catalog_root=f"sha256:{m2_root_bytes.hex()}",
            encrypted_archive_digest=sha256_hex(b"mock_encrypted_archive_m2"),
            governance_digest=sha256_hex(canonical_json_dumps(self.governance.to_dict()))
        )

        m2_sig = sign_data(m2_target.to_dict(), self.lead_privkey, "slot_lead")

        # Authorized transition from M1 -> M2 signed by M1 authority
        trans = LineageTransition(
            domain=TRANSITION_DOMAIN,
            lineage_id=self.lineage_id,
            parent_target_digest=self.m1_target.digest(),
            child_target_digest=m2_target.digest(),
            parent_milestone_index=1,
            child_milestone_index=2
        )
        trans_sig = sign_data(trans.to_dict(), self.lead_privkey, "slot_lead")

        # M2 Timestamp
        m2_imprint = sha256(canonical_json_dumps(m2_target.to_dict()))
        m2_nonce_bytes = os.urandom(8)
        m2_nonce_int = int.from_bytes(m2_nonce_bytes, "big")
        m2_tsq = build_tsq(m2_imprint, m2_nonce_bytes)
        m2_tsr_bytes = self.tsa.respond(m2_tsq)

        m2_audit_path_0 = [{"direction": "right", "hash": f"sha256:{m2_levels[0][1].hex()}"}]
        m2_audit_path_1 = [{"direction": "left", "hash": f"sha256:{m2_levels[0][0].hex()}"}]

        m2_proof = {
            "domain": OPENING_DOMAIN,
            "lineage_id": self.lineage_id,
            "milestone_index": 2,
            "target": m2_target.to_dict(),
            "governance": self.governance.to_dict(),
            "signatures": [m2_sig],
            "predecessor_transition_auth": {
                "transition": trans.to_dict(),
                "signatures": [trans_sig]
            },
            "timestamp_token": {
                "format": "RFC3161_DER",
                "tsr_der_hex": m2_tsr_bytes.hex(),
                "expected_nonce": m2_nonce_int
            },
            "claim_complete_opening": True,
            "opened_claims": [
                {
                    "catalog_item": m2_claim1.to_dict(),
                    "salt": m2_salt1_hex,
                    "material_content": m2_mat1_content,
                    "merkle_proof": {"leaf_index": 0, "audit_path": m2_audit_path_0}
                },
                {
                    "catalog_item": self.m1_claim2.to_dict(),
                    "salt": self.m1_salt2_hex,
                    "material_content": self.m1_mat2_content,
                    "merkle_proof": {"leaf_index": 1, "audit_path": m2_audit_path_1}
                }
            ]
        }

        result_m2 = appraise(m2_proof, self.trusted_pins, predecessor_proof=m1_proof)
        self.assertTrue(result_m2.is_valid(), f"M2 failed: {result_m2.rejection_reasons}")
        self.assertEqual(result_m2.opened_ratio, (2, 2))
        self.assertIn("COMPLETE_CATALOG_OPENING(total=2)", result_m2.granted_predicates)
        self.assertIn(f"AUTHORIZED_PREDECESSOR_TRANSITION({self.m1_target.digest()} -> 2)", result_m2.granted_predicates)

    # -------------------------------------------------------------------------
    # FX-02: Retroactive Strengthening Attack Rejection
    # -------------------------------------------------------------------------
    def test_fx02_retroactive_strengthening_attack(self):
        """FX-02: Attacker attempts to attach M2's unconditional material to M1's timestamp."""
        m2_unconditional_mat = "Lemma L holds unconditionally: General proof without compactness assumption A..."
        audit_path_0 = [{"direction": "right", "hash": f"sha256:{self.m1_levels[0][1].hex()}"}]

        m1_proof_spoofed = {
            "domain": OPENING_DOMAIN,
            "lineage_id": self.lineage_id,
            "milestone_index": 1,
            "target": self.m1_target.to_dict(),
            "governance": self.governance.to_dict(),
            "signatures": [self.m1_sig],
            "timestamp_token": self.m1_ts_token,
            "claim_complete_opening": False,
            "opened_claims": [
                {
                    "catalog_item": self.m1_claim1.to_dict(),
                    "salt": self.m1_salt1_hex,
                    "material_content": m2_unconditional_mat,  # SPOOFED
                    "merkle_proof": {"leaf_index": 0, "audit_path": audit_path_0}
                }
            ]
        }
        res_a = appraise(m1_proof_spoofed, self.trusted_pins)
        self.assertFalse(res_a.is_valid())
        self.assertTrue(any("REJECTED_SALTED_COMMITMENT_MISMATCH" in r for r in res_a.rejection_reasons))

    # -------------------------------------------------------------------------
    # FX-03: Scope Amplification Attack Rejection
    # -------------------------------------------------------------------------
    def test_fx03_scope_amplification_attack(self):
        """FX-03: Opening only 1 of 2 claims, but claiming complete opening."""
        audit_path_0 = [{"direction": "right", "hash": f"sha256:{self.m1_levels[0][1].hex()}"}]
        m1_proof_amplified = {
            "domain": OPENING_DOMAIN,
            "lineage_id": self.lineage_id,
            "milestone_index": 1,
            "target": self.m1_target.to_dict(),
            "governance": self.governance.to_dict(),
            "signatures": [self.m1_sig],
            "timestamp_token": self.m1_ts_token,
            "claim_complete_opening": True,  # FRAUDULENT
            "opened_claims": [
                {
                    "catalog_item": self.m1_claim1.to_dict(),
                    "salt": self.m1_salt1_hex,
                    "material_content": self.m1_mat1_content,
                    "merkle_proof": {"leaf_index": 0, "audit_path": audit_path_0}
                }
            ]
        }
        res = appraise(m1_proof_amplified, self.trusted_pins)
        self.assertFalse(res.is_valid())
        self.assertTrue(any("REJECTED_SCOPE_AMPLIFICATION" in r for r in res.rejection_reasons))

    # -------------------------------------------------------------------------
    # FX-04: Lineage Grafting Rejection
    # -------------------------------------------------------------------------
    def test_fx04_lineage_grafting_attack(self):
        """FX-04: Replaying valid M1 opening proof under a rival lineage ID."""
        audit_path_0 = [{"direction": "right", "hash": f"sha256:{self.m1_levels[0][1].hex()}"}]
        rival_lineage_id = "srl:lin:rival-plagiarist-project"

        grafted_proof = {
            "domain": OPENING_DOMAIN,
            "lineage_id": rival_lineage_id,  # GRAFTED
            "milestone_index": 1,
            "target": self.m1_target.to_dict(),
            "governance": self.governance.to_dict(),
            "signatures": [self.m1_sig],
            "timestamp_token": self.m1_ts_token,
            "claim_complete_opening": False,
            "opened_claims": [
                {
                    "catalog_item": self.m1_claim1.to_dict(),
                    "salt": self.m1_salt1_hex,
                    "material_content": self.m1_mat1_content,
                    "merkle_proof": {"leaf_index": 0, "audit_path": audit_path_0}
                }
            ]
        }
        res = appraise(grafted_proof, self.trusted_pins)
        self.assertFalse(res.is_valid())
        self.assertTrue(any("REJECTED_LINEAGE_TARGET_MISMATCH" in r for r in res.rejection_reasons))

    # -------------------------------------------------------------------------
    # FX-05: Unauthorized Predecessor Succession Attack Rejection
    # -------------------------------------------------------------------------
    def test_fx05_unauthorized_predecessor_attack(self):
        """FX-05: Attacker attempts fresh-key n+1 takeover without predecessor quorum."""
        attacker_gov = Governance(
            author_slots=[AuthorSlot(slot_id="slot_attacker", public_key=self.attacker_pub_hex)],
            threshold=1
        )
        m2_fake_target = ApprovalTarget(
            domain=TARGET_DOMAIN,
            lineage_id=self.lineage_id,
            milestone_index=2,
            catalog_leaf_count=2,
            predecessor_digest=self.m1_target.digest(),
            catalog_root=f"sha256:{self.m1_root_bytes.hex()}",
            encrypted_archive_digest=sha256_hex(b"attacker_archive"),
            governance_digest=sha256_hex(canonical_json_dumps(attacker_gov.to_dict()))
        )
        fake_sig = sign_data(m2_fake_target.to_dict(), self.attacker_privkey, "slot_attacker")

        m2_fake_proof = {
            "domain": OPENING_DOMAIN,
            "lineage_id": self.lineage_id,
            "milestone_index": 2,
            "target": m2_fake_target.to_dict(),
            "governance": attacker_gov.to_dict(),
            "signatures": [fake_sig],
            "timestamp_token": self.m1_ts_token,
            "claim_complete_opening": False,
            "opened_claims": []
        }

        # Parent proof requires self.lead_pub_hex
        m1_proof_base = {
            "domain": OPENING_DOMAIN,
            "lineage_id": self.lineage_id,
            "milestone_index": 1,
            "target": self.m1_target.to_dict(),
            "governance": self.governance.to_dict(),
            "signatures": [self.m1_sig],
            "timestamp_token": self.m1_ts_token,
            "claim_complete_opening": False,
            "opened_claims": []
        }

        res = appraise(m2_fake_proof, self.trusted_pins, predecessor_proof=m1_proof_base)
        self.assertFalse(res.is_valid())
        self.assertTrue(any("REJECTED_UNAUTHORIZED_PREDECESSOR" in r for r in res.rejection_reasons))

    # -------------------------------------------------------------------------
    # FX-06: Terminal Credit Query Categorical Refusal
    # -------------------------------------------------------------------------
    def test_fx06_terminal_credit_refusal(self):
        """FX-06: Verifier categorically refuses out-of-scope terminal credit evaluation queries."""
        audit_path_0 = [{"direction": "right", "hash": f"sha256:{self.m1_levels[0][1].hex()}"}]
        m1_proof = {
            "domain": OPENING_DOMAIN,
            "lineage_id": self.lineage_id,
            "milestone_index": 1,
            "target": self.m1_target.to_dict(),
            "governance": self.governance.to_dict(),
            "signatures": [self.m1_sig],
            "timestamp_token": self.m1_ts_token,
            "claim_complete_opening": False,
            "opened_claims": [
                {
                    "catalog_item": self.m1_claim1.to_dict(),
                    "salt": self.m1_salt1_hex,
                    "material_content": self.m1_mat1_content,
                    "merkle_proof": {"leaf_index": 0, "audit_path": audit_path_0}
                }
            ]
        }
        illicit_query = "Does M1 prove FIRST_PROVED_FINAL_CONJECTURE so later paper is LATER_PROVER_PLAGIARIZED?"
        res = appraise(m1_proof, self.trusted_pins, query=illicit_query)
        self.assertEqual(res.status, "REFUSED")
        self.assertFalse(res.is_valid())

    # =========================================================================
    # Critical Regressions (REG-01 to REG-09)
    # =========================================================================

    def test_reg01_forged_timestamp_1900_rejected(self):
        """REG-01: Fake 1900-01-01 timestamp without valid TSA signature MUST be rejected."""
        audit_path_0 = [{"direction": "right", "hash": f"sha256:{self.m1_levels[0][1].hex()}"}]
        fake_ts_token = {
            "format": "RFC3161_DER",
            "tsr_der_hex": "deadbeef19000101"
        }
        m1_proof_fake_ts = {
            "domain": OPENING_DOMAIN,
            "lineage_id": self.lineage_id,
            "milestone_index": 1,
            "target": self.m1_target.to_dict(),
            "governance": self.governance.to_dict(),
            "signatures": [self.m1_sig],
            "timestamp_token": fake_ts_token,
            "claim_complete_opening": False,
            "opened_claims": [
                {
                    "catalog_item": self.m1_claim1.to_dict(),
                    "salt": self.m1_salt1_hex,
                    "material_content": self.m1_mat1_content,
                    "merkle_proof": {"leaf_index": 0, "audit_path": audit_path_0}
                }
            ]
        }
        res = appraise(m1_proof_fake_ts, self.trusted_pins)
        self.assertFalse(res.is_valid())
        self.assertTrue(any("REJECTED_TIMESTAMP_VERIFICATION_FAILED" in r for r in res.rejection_reasons))

    def test_reg02_total_leaves_malleability_rejected(self):
        """REG-02: Under-reporting total_leaves in proof cannot override target catalog_leaf_count."""
        audit_path_0 = [{"direction": "right", "hash": f"sha256:{self.m1_levels[0][1].hex()}"}]
        m1_proof_tampered_leaves = {
            "domain": OPENING_DOMAIN,
            "lineage_id": self.lineage_id,
            "milestone_index": 1,
            "target": self.m1_target.to_dict(),
            "governance": self.governance.to_dict(),
            "signatures": [self.m1_sig],
            "timestamp_token": self.m1_ts_token,
            "claim_complete_opening": True,  # Attacker claims complete opening with only 1 leaf
            "opened_claims": [
                {
                    "catalog_item": self.m1_claim1.to_dict(),
                    "salt": self.m1_salt1_hex,
                    "material_content": self.m1_mat1_content,
                    "merkle_proof": {"leaf_index": 0, "audit_path": audit_path_0}
                }
            ]
        }
        res = appraise(m1_proof_tampered_leaves, self.trusted_pins)
        self.assertFalse(res.is_valid())
        self.assertTrue(any("REJECTED_SCOPE_AMPLIFICATION" in r for r in res.rejection_reasons))

    def test_reg03_fresh_key_takeover_with_forged_pred_rejected(self):
        """REG-03: Fresh-key n+1 successor signed by attacker must be rejected even with parent target."""
        attacker_gov = Governance(
            author_slots=[AuthorSlot(slot_id="slot_attacker", public_key=self.attacker_pub_hex)],
            threshold=1
        )
        m2_fake_target = ApprovalTarget(
            domain=TARGET_DOMAIN,
            lineage_id=self.lineage_id,
            milestone_index=2,
            catalog_leaf_count=2,
            predecessor_digest=self.m1_target.digest(),
            catalog_root=f"sha256:{self.m1_root_bytes.hex()}",
            encrypted_archive_digest=sha256_hex(b"attacker_archive"),
            governance_digest=sha256_hex(canonical_json_dumps(attacker_gov.to_dict()))
        )
        fake_sig = sign_data(m2_fake_target.to_dict(), self.attacker_privkey, "slot_attacker")
        fake_trans = LineageTransition(
            domain=TRANSITION_DOMAIN,
            lineage_id=self.lineage_id,
            parent_target_digest=self.m1_target.digest(),
            child_target_digest=m2_fake_target.digest(),
            parent_milestone_index=1,
            child_milestone_index=2
        )
        fake_trans_sig = sign_data(fake_trans.to_dict(), self.attacker_privkey, "slot_attacker")

        m2_takeover_proof = {
            "domain": OPENING_DOMAIN,
            "lineage_id": self.lineage_id,
            "milestone_index": 2,
            "target": m2_fake_target.to_dict(),
            "governance": attacker_gov.to_dict(),
            "signatures": [fake_sig],
            "predecessor_transition_auth": {
                "transition": fake_trans.to_dict(),
                "signatures": [fake_trans_sig]
            },
            "timestamp_token": self.m1_ts_token,
            "claim_complete_opening": False,
            "opened_claims": []
        }
        m1_proof_base = {
            "domain": OPENING_DOMAIN,
            "lineage_id": self.lineage_id,
            "milestone_index": 1,
            "target": self.m1_target.to_dict(),
            "governance": self.governance.to_dict(),
            "signatures": [self.m1_sig],
            "timestamp_token": self.m1_ts_token,
            "claim_complete_opening": False,
            "opened_claims": []
        }
        res = appraise(m2_takeover_proof, self.trusted_pins, predecessor_proof=m1_proof_base)
        self.assertFalse(res.is_valid())
        self.assertTrue(any("PREDECESSOR_QUORUM_NOT_MET" in r for r in res.rejection_reasons))

    def test_reg04_zero_threshold_rejected(self):
        """REG-04: threshold=0, zero authors, or zero signatures must be rejected."""
        audit_path_0 = [{"direction": "right", "hash": f"sha256:{self.m1_levels[0][1].hex()}"}]
        zero_gov = {"author_slots": [], "threshold": 0}
        m1_zero_proof = {
            "domain": OPENING_DOMAIN,
            "lineage_id": self.lineage_id,
            "milestone_index": 1,
            "target": self.m1_target.to_dict(),
            "governance": zero_gov,
            "signatures": [],
            "timestamp_token": self.m1_ts_token,
            "claim_complete_opening": False,
            "opened_claims": [
                {
                    "catalog_item": self.m1_claim1.to_dict(),
                    "salt": self.m1_salt1_hex,
                    "material_content": self.m1_mat1_content,
                    "merkle_proof": {"leaf_index": 0, "audit_path": audit_path_0}
                }
            ]
        }
        res = appraise(m1_zero_proof, self.trusted_pins)
        self.assertFalse(res.is_valid())
        self.assertTrue(any("INVALID_GOVERNANCE" in r for r in res.rejection_reasons))

    def test_reg05_duplicate_opening_cannot_complete_catalog(self):
        """REG-05: Submitting leaf 0 twice cannot yield complete opening."""
        audit_path_0 = [{"direction": "right", "hash": f"sha256:{self.m1_levels[0][1].hex()}"}]

        # Attacker opens leaf 0 twice and claims complete opening!
        m1_dup_proof = {
            "domain": OPENING_DOMAIN,
            "lineage_id": self.lineage_id,
            "milestone_index": 1,
            "target": self.m1_target.to_dict(),
            "governance": self.governance.to_dict(),
            "signatures": [self.m1_sig],
            "timestamp_token": self.m1_ts_token,
            "claim_complete_opening": True,
            "opened_claims": [
                {
                    "catalog_item": self.m1_claim1.to_dict(),
                    "salt": self.m1_salt1_hex,
                    "material_content": self.m1_mat1_content,
                    "merkle_proof": {"leaf_index": 0, "audit_path": audit_path_0}
                },
                {
                    "catalog_item": self.m1_claim1.to_dict(),  # DUPLICATE OPENING OF LEAF 0
                    "salt": self.m1_salt1_hex,
                    "material_content": self.m1_mat1_content,
                    "merkle_proof": {"leaf_index": 0, "audit_path": audit_path_0}
                }
            ]
        }
        res = appraise(m1_dup_proof, self.trusted_pins)
        self.assertFalse(res.is_valid())
        self.assertTrue(any("REJECTED_DUPLICATE_OPENED_LEAF" in r for r in res.rejection_reasons))

    def test_reg06_substituted_predecessor_governance_rejected(self):
        """REG-06: Predecessor proof with substituted governance must be rejected."""
        attacker_gov = Governance(
            author_slots=[AuthorSlot(slot_id="slot_attacker", public_key=self.attacker_pub_hex)],
            threshold=1
        )
        # Attacker takes genuine m1_target, but presents attacker_gov as m1's governance
        m1_tampered_proof = {
            "domain": OPENING_DOMAIN,
            "lineage_id": self.lineage_id,
            "milestone_index": 1,
            "target": self.m1_target.to_dict(),
            "governance": attacker_gov.to_dict(),  # TAMPERED GOVERNANCE
            "signatures": [sign_data(self.m1_target.to_dict(), self.attacker_privkey, "slot_attacker")],
            "timestamp_token": self.m1_ts_token,
            "claim_complete_opening": False,
            "opened_claims": []
        }

        # Child M2 attempts to transition from this tampered M1
        m2_target = ApprovalTarget(
            domain=TARGET_DOMAIN,
            lineage_id=self.lineage_id,
            milestone_index=2,
            catalog_leaf_count=2,
            predecessor_digest=self.m1_target.digest(),
            catalog_root=f"sha256:{self.m1_root_bytes.hex()}",
            encrypted_archive_digest=sha256_hex(b"archive"),
            governance_digest=sha256_hex(canonical_json_dumps(self.governance.to_dict()))
        )
        trans = LineageTransition(
            domain=TRANSITION_DOMAIN,
            lineage_id=self.lineage_id,
            parent_target_digest=self.m1_target.digest(),
            child_target_digest=m2_target.digest(),
            parent_milestone_index=1,
            child_milestone_index=2
        )
        trans_sig = sign_data(trans.to_dict(), self.attacker_privkey, "slot_attacker")

        m2_proof = {
            "domain": OPENING_DOMAIN,
            "lineage_id": self.lineage_id,
            "milestone_index": 2,
            "target": m2_target.to_dict(),
            "governance": self.governance.to_dict(),
            "signatures": [sign_data(m2_target.to_dict(), self.lead_privkey, "slot_lead")],
            "predecessor_transition_auth": {
                "transition": trans.to_dict(),
                "signatures": [trans_sig]
            },
            "timestamp_token": self.m1_ts_token,
            "claim_complete_opening": False,
            "opened_claims": []
        }

        res = appraise(m2_proof, self.trusted_pins, predecessor_proof=m1_tampered_proof)
        self.assertFalse(res.is_valid())
        self.assertTrue(
            any("REJECTED_INVALID_PREDECESSOR_PROOF" in r or "REJECTED_PREDECESSOR_GOVERNANCE_DIGEST_MISMATCH" in r
                for r in res.rejection_reasons)
        )

    def test_reg07_duplicate_key_multi_slot_quorum_rejected(self):
        """REG-07: Governance reusing one key across two slots must be rejected."""
        dup_key_gov = {
            "author_slots": [
                {"slot_id": "slot1", "public_key": self.lead_pub_hex},
                {"slot_id": "slot2", "public_key": self.lead_pub_hex}  # REUSED KEY
            ],
            "threshold": 2
        }

        target = ApprovalTarget(
            domain=TARGET_DOMAIN,
            lineage_id=self.lineage_id,
            milestone_index=1,
            catalog_leaf_count=2,
            predecessor_digest=None,
            catalog_root=f"sha256:{self.m1_root_bytes.hex()}",
            encrypted_archive_digest=sha256_hex(b"archive"),
            governance_digest=sha256_hex(canonical_json_dumps(dup_key_gov))
        )
        sig1 = sign_data(target.to_dict(), self.lead_privkey, "slot1")
        sig2 = sign_data(target.to_dict(), self.lead_privkey, "slot2")

        proof = {
            "domain": OPENING_DOMAIN,
            "lineage_id": self.lineage_id,
            "milestone_index": 1,
            "target": target.to_dict(),
            "governance": dup_key_gov,
            "signatures": [sig1, sig2],
            "timestamp_token": self.m1_ts_token,
            "claim_complete_opening": False,
            "opened_claims": []
        }

        res = appraise(proof, self.trusted_pins)
        self.assertFalse(res.is_valid())
        self.assertTrue(any("DUPLICATE_PUBLIC_KEY_IN_GOVERNANCE" in r for r in res.rejection_reasons))

    def test_reg08_predecessor_proof_must_itself_verify(self):
        """REG-08: Corrupted predecessor proof causes child verification to fail."""
        corrupted_m1_proof = {
            "domain": OPENING_DOMAIN,
            "lineage_id": self.lineage_id,
            "milestone_index": 1,
            "target": self.m1_target.to_dict(),
            "governance": self.governance.to_dict(),
            "signatures": [{"slot_id": "slot_lead", "public_key": self.lead_pub_hex, "signature": "ed25519_sig:" + "00"*64}],  # BAD SIG
            "timestamp_token": self.m1_ts_token,
            "claim_complete_opening": False,
            "opened_claims": []
        }

        m2_target = ApprovalTarget(
            domain=TARGET_DOMAIN,
            lineage_id=self.lineage_id,
            milestone_index=2,
            catalog_leaf_count=2,
            predecessor_digest=self.m1_target.digest(),
            catalog_root=f"sha256:{self.m1_root_bytes.hex()}",
            encrypted_archive_digest=sha256_hex(b"archive"),
            governance_digest=sha256_hex(canonical_json_dumps(self.governance.to_dict()))
        )
        trans = LineageTransition(
            domain=TRANSITION_DOMAIN,
            lineage_id=self.lineage_id,
            parent_target_digest=self.m1_target.digest(),
            child_target_digest=m2_target.digest(),
            parent_milestone_index=1,
            child_milestone_index=2
        )
        trans_sig = sign_data(trans.to_dict(), self.lead_privkey, "slot_lead")
        m2_proof = {
            "domain": OPENING_DOMAIN,
            "lineage_id": self.lineage_id,
            "milestone_index": 2,
            "target": m2_target.to_dict(),
            "governance": self.governance.to_dict(),
            "signatures": [sign_data(m2_target.to_dict(), self.lead_privkey, "slot_lead")],
            "predecessor_transition_auth": {
                "transition": trans.to_dict(),
                "signatures": [trans_sig]
            },
            "timestamp_token": self.m1_ts_token,
            "claim_complete_opening": False,
            "opened_claims": []
        }

        res = appraise(m2_proof, self.trusted_pins, predecessor_proof=corrupted_m1_proof)
        self.assertFalse(res.is_valid())
        self.assertTrue(any("REJECTED_INVALID_PREDECESSOR_PROOF" in r for r in res.rejection_reasons))

    def test_reg09_timestamp_nonce_query_binding(self):
        """REG-09: Timestamp verification enforces nonce equality when expected_nonce is provided."""
        # 1. Correct nonce passes
        valid_token = {
            "format": "RFC3161_DER",
            "tsr_der_hex": self.m1_tsr_bytes.hex(),
            "expected_nonce": self.m1_nonce_int
        }
        res_ok = appraise({
            "domain": OPENING_DOMAIN,
            "lineage_id": self.lineage_id,
            "milestone_index": 1,
            "target": self.m1_target.to_dict(),
            "governance": self.governance.to_dict(),
            "signatures": [self.m1_sig],
            "timestamp_token": valid_token,
            "claim_complete_opening": False,
            "opened_claims": []
        }, self.trusted_pins)
        self.assertTrue(res_ok.is_valid())

        # 2. Tampered nonce is rejected with TSR_NONCE_MISMATCH
        tampered_token = {
            "format": "RFC3161_DER",
            "tsr_der_hex": self.m1_tsr_bytes.hex(),
            "expected_nonce": self.m1_nonce_int + 1  # WRONG NONCE
        }
        res_bad = appraise({
            "domain": OPENING_DOMAIN,
            "lineage_id": self.lineage_id,
            "milestone_index": 1,
            "target": self.m1_target.to_dict(),
            "governance": self.governance.to_dict(),
            "signatures": [self.m1_sig],
            "timestamp_token": tampered_token,
            "claim_complete_opening": False,
            "opened_claims": []
        }, self.trusted_pins)
        self.assertFalse(res_bad.is_valid())
        self.assertTrue(any("TSR_NONCE_MISMATCH" in r for r in res_bad.rejection_reasons))

    # -------------------------------------------------------------------------
    # REG-10: Same Leaf Relabeled with Different Indices Rejected
    # -------------------------------------------------------------------------
    def test_reg10_same_leaf_relabeled_with_different_indices_rejected(self):
        """REG-10: Submitting same leaf twice with relabeled leaf_index must be rejected."""
        audit_path_0 = [{"direction": "right", "hash": f"sha256:{self.m1_levels[0][1].hex()}"}]

        # Attacker submits leaf 0 twice: once as leaf_index 0, once as leaf_index 1
        m1_relabeled_proof = {
            "domain": OPENING_DOMAIN,
            "lineage_id": self.lineage_id,
            "milestone_index": 1,
            "target": self.m1_target.to_dict(),
            "governance": self.governance.to_dict(),
            "signatures": [self.m1_sig],
            "timestamp_token": self.m1_ts_token,
            "claim_complete_opening": True,
            "opened_claims": [
                {
                    "catalog_item": self.m1_claim1.to_dict(),
                    "salt": self.m1_salt1_hex,
                    "material_content": self.m1_mat1_content,
                    "merkle_proof": {"leaf_index": 0, "audit_path": audit_path_0}
                },
                {
                    "catalog_item": self.m1_claim1.to_dict(),  # Relabeled with leaf_index 1
                    "salt": self.m1_salt1_hex,
                    "material_content": self.m1_mat1_content,
                    "merkle_proof": {"leaf_index": 1, "audit_path": audit_path_0}
                }
            ]
        }
        res = appraise(m1_relabeled_proof, self.trusted_pins)
        self.assertFalse(res.is_valid())
        self.assertTrue(
            any("REJECTED_DUPLICATE_CLAIM_ID" in r for r in res.rejection_reasons) or
            any("REJECTED_DUPLICATE_LEAF_HASH" in r for r in res.rejection_reasons) or
            any("REJECTED_DOMAIN_SEPARATOR_MISMATCH" in r for r in res.rejection_reasons)
        )

    # -------------------------------------------------------------------------
    # REG-11: Three-Milestone Lineage Chain Verification (M1 -> M2 -> M3)
    # -------------------------------------------------------------------------
    def test_reg11_three_milestone_chain_verifies(self):
        """REG-11: Three-milestone chain M1 -> M2 -> M3 verifies via nested proof and iterative chain."""
        # 1. Build M1 proof
        audit_path_0 = [{"direction": "right", "hash": f"sha256:{self.m1_levels[0][1].hex()}"}]
        m1_proof = {
            "domain": OPENING_DOMAIN,
            "lineage_id": self.lineage_id,
            "milestone_index": 1,
            "target": self.m1_target.to_dict(),
            "governance": self.governance.to_dict(),
            "signatures": [self.m1_sig],
            "timestamp_token": self.m1_ts_token,
            "claim_complete_opening": False,
            "opened_claims": [
                {
                    "catalog_item": self.m1_claim1.to_dict(),
                    "salt": self.m1_salt1_hex,
                    "material_content": self.m1_mat1_content,
                    "merkle_proof": {"leaf_index": 0, "audit_path": audit_path_0}
                }
            ]
        }

        # 2. Build M2 payload & proof
        m2_mat1 = "Lemma L holds unconditionally"
        m2_salt1 = os.urandom(32)
        m2_commit1 = sha256_hex(m2_salt1 + m2_mat1.encode("utf-8"))
        m2_claim1 = ClaimCatalogItem(
            claim_id="CLM-001",
            statement_summary="Lemma L holds unconditionally",
            claim_status="UNCONDITIONALLY_PROVED",
            assumptions=[],
            proof_obligations_open=[],
            salt_commitment=m2_commit1
        )
        m2_payload = MilestonePayload(
            lineage_id=self.lineage_id,
            milestone_index=2,
            created_at="2026-10-15T12:00:00Z",
            predecessor_digest=self.m1_target.digest(),
            governance=self.governance,
            claim_catalog=[m2_claim1, self.m1_claim2]
        )
        m2_root_bytes, m2_levels = m2_payload.compute_catalog_merkle_root()
        m2_target = ApprovalTarget(
            domain=TARGET_DOMAIN,
            lineage_id=self.lineage_id,
            milestone_index=2,
            catalog_leaf_count=2,
            predecessor_digest=self.m1_target.digest(),
            catalog_root=f"sha256:{m2_root_bytes.hex()}",
            encrypted_archive_digest=sha256_hex(b"archive_m2"),
            governance_digest=sha256_hex(canonical_json_dumps(self.governance.to_dict()))
        )
        m2_sig = sign_data(m2_target.to_dict(), self.lead_privkey, "slot_lead")
        trans_1_to_2 = LineageTransition(
            domain=TRANSITION_DOMAIN,
            lineage_id=self.lineage_id,
            predecessor_target_digest=self.m1_target.digest(),
            successor_target_digest=m2_target.digest(),
            predecessor_milestone_index=1,
            successor_milestone_index=2
        )
        trans_sig_1_to_2 = sign_data(trans_1_to_2.to_dict(), self.lead_privkey, "slot_lead")

        m2_nonce_bytes = os.urandom(8)
        m2_tsq = build_tsq(sha256(canonical_json_dumps(m2_target.to_dict())), m2_nonce_bytes)
        m2_tsr = self.tsa.respond(m2_tsq)
        m2_audit_path_0 = [{"direction": "right", "hash": f"sha256:{m2_levels[0][1].hex()}"}]

        m2_proof = {
            "domain": OPENING_DOMAIN,
            "lineage_id": self.lineage_id,
            "milestone_index": 2,
            "target": m2_target.to_dict(),
            "governance": self.governance.to_dict(),
            "signatures": [m2_sig],
            "predecessor_transition_auth": {
                "transition": trans_1_to_2.to_dict(),
                "signatures": [trans_sig_1_to_2]
            },
            "timestamp_token": {
                "format": "RFC3161_DER",
                "tsr_der_hex": m2_tsr.hex(),
                "expected_nonce": int.from_bytes(m2_nonce_bytes, "big")
            },
            "predecessor_proof": m1_proof,
            "claim_complete_opening": False,
            "opened_claims": [
                {
                    "catalog_item": m2_claim1.to_dict(),
                    "salt": f"hex:{m2_salt1.hex()}",
                    "material_content": m2_mat1,
                    "merkle_proof": {"leaf_index": 0, "audit_path": m2_audit_path_0}
                }
            ]
        }

        # 3. Build M3 payload & proof
        m3_mat1 = "Theorem T complete proof extending Lemma L"
        m3_salt1 = os.urandom(32)
        m3_commit1 = sha256_hex(m3_salt1 + m3_mat1.encode("utf-8"))
        m3_claim1 = ClaimCatalogItem(
            claim_id="CLM-002",
            statement_summary="Conjecture T is fully proven",
            claim_status="UNCONDITIONALLY_PROVED",
            assumptions=[],
            proof_obligations_open=[],
            salt_commitment=m3_commit1
        )
        m3_payload = MilestonePayload(
            lineage_id=self.lineage_id,
            milestone_index=3,
            created_at="2026-11-01T12:00:00Z",
            predecessor_digest=m2_target.digest(),
            governance=self.governance,
            claim_catalog=[m3_claim1]
        )
        m3_root_bytes, m3_levels = m3_payload.compute_catalog_merkle_root()
        m3_target = ApprovalTarget(
            domain=TARGET_DOMAIN,
            lineage_id=self.lineage_id,
            milestone_index=3,
            catalog_leaf_count=1,
            predecessor_digest=m2_target.digest(),
            catalog_root=f"sha256:{m3_root_bytes.hex()}",
            encrypted_archive_digest=sha256_hex(b"archive_m3"),
            governance_digest=sha256_hex(canonical_json_dumps(self.governance.to_dict()))
        )
        m3_sig = sign_data(m3_target.to_dict(), self.lead_privkey, "slot_lead")
        trans_2_to_3 = LineageTransition(
            domain=TRANSITION_DOMAIN,
            lineage_id=self.lineage_id,
            predecessor_target_digest=m2_target.digest(),
            successor_target_digest=m3_target.digest(),
            predecessor_milestone_index=2,
            successor_milestone_index=3
        )
        trans_sig_2_to_3 = sign_data(trans_2_to_3.to_dict(), self.lead_privkey, "slot_lead")

        m3_nonce_bytes = os.urandom(8)
        m3_tsq = build_tsq(sha256(canonical_json_dumps(m3_target.to_dict())), m3_nonce_bytes)
        m3_tsr = self.tsa.respond(m3_tsq)

        m3_proof = {
            "domain": OPENING_DOMAIN,
            "lineage_id": self.lineage_id,
            "milestone_index": 3,
            "target": m3_target.to_dict(),
            "governance": self.governance.to_dict(),
            "signatures": [m3_sig],
            "predecessor_transition_auth": {
                "transition": trans_2_to_3.to_dict(),
                "signatures": [trans_sig_2_to_3]
            },
            "timestamp_token": {
                "format": "RFC3161_DER",
                "tsr_der_hex": m3_tsr.hex(),
                "expected_nonce": int.from_bytes(m3_nonce_bytes, "big")
            },
            "predecessor_proof": m2_proof,
            "claim_complete_opening": True,
            "opened_claims": [
                {
                    "catalog_item": m3_claim1.to_dict(),
                    "salt": f"hex:{m3_salt1.hex()}",
                    "material_content": m3_mat1,
                    "merkle_proof": {"leaf_index": 0, "audit_path": []}
                }
            ]
        }

        # Verification Mode A: Recursive nested predecessor proof on M3
        res_m3_nested = appraise(m3_proof, self.trusted_pins)
        self.assertTrue(res_m3_nested.is_valid(), f"M3 nested failed: {res_m3_nested.rejection_reasons}")
        self.assertIn("COMPLETE_CATALOG_OPENING(total=1)", res_m3_nested.granted_predicates)

        # Verification Mode B: Sequential iterative chain appraisal
        chain_results = appraise_lineage_chain([m1_proof, m2_proof, m3_proof], self.trusted_pins)
        self.assertEqual(len(chain_results), 3)
        self.assertTrue(all(r.is_valid() for r in chain_results))

    # -------------------------------------------------------------------------
    # REG-12: Specification Examples Parse As Implementation Objects
    # -------------------------------------------------------------------------
    def test_reg12_specification_examples_parse_as_implementation_objects(self):
        """REG-12: Verifies that specification JSON snippets directly parse as valid implementation objects."""
        # 1. ClaimCatalogItem
        spec_claim = {
            "claim_id": "CLM-001",
            "statement_summary": "Lemma L holds under Compactness Condition A",
            "claim_status": "CONDITIONALLY_PROVED",
            "assumptions": ["ASSUMP-A-COMPACTNESS"],
            "proof_obligations_open": ["REMOVE-ASSUMP-A"],
            "salt_commitment": "sha256:e1b7a2bb00000000000000000000000000000000000000000000000000000000"
        }
        item = ClaimCatalogItem(**spec_claim)
        self.assertEqual(item.salt_commitment, spec_claim["salt_commitment"])
        self.assertEqual(item.to_dict()["salt_commitment"], spec_claim["salt_commitment"])

        # 2. AuthorSlot (both public_key and ed25519_public_key_hex supported)
        slot1 = AuthorSlot(slot_id="slot-01-lead", public_key="ed25519:4a5b6c0000000000000000000000000000000000000000000000000000000000")
        self.assertTrue(slot1.public_key.startswith("ed25519:"))
        slot2 = AuthorSlot(slot_id="slot-02", ed25519_public_key_hex="7d8e9f0000000000000000000000000000000000000000000000000000000000")
        self.assertEqual(slot2.public_key, "ed25519:7d8e9f0000000000000000000000000000000000000000000000000000000000")

        # 3. Governance
        gov = Governance(author_slots=[slot1, slot2], threshold=2)
        gov.validate()
        self.assertEqual(gov.threshold, 2)

        # 4. ApprovalTarget
        spec_target = {
            "domain": TARGET_DOMAIN,
            "lineage_id": "srl:lin:riemann-gap-demo",
            "milestone_index": 1,
            "catalog_leaf_count": 2,
            "predecessor_digest": None,
            "catalog_root": "sha256:5555555555555555555555555555555555555555555555555555555555555555",
            "encrypted_archive_digest": "sha256:6666666666666666666666666666666666666666666666666666666666666666",
            "governance_digest": "sha256:7777777777777777777777777777777777777777777777777777777777777777"
        }
        target = ApprovalTarget(**spec_target)
        target.validate()
        self.assertEqual(target.catalog_leaf_count, 2)

        # 5. LineageTransition
        spec_transition = {
            "domain": TRANSITION_DOMAIN,
            "lineage_id": "srl:lin:riemann-gap-demo",
            "predecessor_target_digest": "sha256:1111111111111111111111111111111111111111111111111111111111111111",
            "successor_target_digest": "sha256:2222222222222222222222222222222222222222222222222222222222222222",
            "predecessor_milestone_index": 1,
            "successor_milestone_index": 2
        }
        trans = LineageTransition(**spec_transition)
        trans.validate()
        self.assertEqual(trans.to_dict()["predecessor_target_digest"], spec_transition["predecessor_target_digest"])

    # -------------------------------------------------------------------------
    # REG-13: Expected Genesis / Lineage Pin Distinguishes Parallel Lineage
    # -------------------------------------------------------------------------
    def test_reg13_expected_genesis_parent_pin_distinguishes_parallel_lineage(self):
        """REG-13: Confirms pinning expected_genesis_target_digest rejects rogue parallel lineages."""
        # Lineage A is genuine self.m1_target
        # Lineage B is a parallel rogue branch claiming the same lineage_id
        privkey_b = ed25519.Ed25519PrivateKey.generate()
        pubkey_b_hex = f"ed25519:{privkey_b.public_key().public_bytes_raw().hex()}"
        gov_b = Governance(author_slots=[AuthorSlot(slot_id="slot_b", public_key=pubkey_b_hex)], threshold=1)
        
        target_b = ApprovalTarget(
            domain=TARGET_DOMAIN,
            lineage_id=self.lineage_id,  # Same lineage_id!
            milestone_index=1,
            catalog_leaf_count=1,
            predecessor_digest=None,
            catalog_root=sha256_hex(b"rogue_root"),
            encrypted_archive_digest=sha256_hex(b"rogue_archive"),
            governance_digest=sha256_hex(canonical_json_dumps(gov_b.to_dict()))
        )
        sig_b = sign_data(target_b.to_dict(), privkey_b, "slot_b")
        nonce_b = os.urandom(8)
        tsq_b = build_tsq(sha256(canonical_json_dumps(target_b.to_dict())), nonce_b)
        tsr_b = self.tsa.respond(tsq_b)

        proof_b = {
            "domain": OPENING_DOMAIN,
            "lineage_id": self.lineage_id,
            "milestone_index": 1,
            "target": target_b.to_dict(),
            "governance": gov_b.to_dict(),
            "signatures": [sig_b],
            "timestamp_token": {
                "format": "RFC3161_DER",
                "tsr_der_hex": tsr_b.hex(),
                "expected_nonce": int.from_bytes(nonce_b, "big")
            },
            "claim_complete_opening": True,
            "opened_claims": []
        }

        # Pinned verifier anchors to genuine Lineage A genesis target digest
        pinned_trust = {
            "trusted_tsa_pin": self.trusted_pins["trusted_tsa_pin"],
            "expected_genesis_target_digest": self.m1_target.digest()
        }

        # Rogue lineage B must be rejected because its genesis does not match
        res_b = appraise(proof_b, pinned_trust)
        self.assertFalse(res_b.is_valid())
        self.assertTrue(any("REJECTED_GENESIS_DIGEST_MISMATCH" in r for r in res_b.rejection_reasons))

    # -------------------------------------------------------------------------
    # REG-14: Archive Timestamp Cannot Grant Target/Milestone Existence
    # -------------------------------------------------------------------------
    def test_reg14_archive_timestamp_cannot_grant_target_existence(self):
        """REG-14: Archive timestamp only attests to encrypted_archive_digest, NEVER granting APPROVAL_TARGET_EXISTED_NOT_AFTER."""
        # 1. Genuine archive timestamp proof
        archive_bytes = b"real_encrypted_archive_payload_data_reg14"
        arch_digest_hex = sha256_hex(archive_bytes)
        arch_nonce = os.urandom(8)
        arch_tsq = build_tsq(bytes.fromhex(arch_digest_hex[7:]), arch_nonce)
        arch_tsr = self.tsa.respond(arch_tsq)

        salt_bytes = os.urandom(32)
        material_str = "Sound experimental data in archive"
        commit = sha256_hex(salt_bytes + material_str.encode("utf-8"))
        claim = ClaimCatalogItem(
            claim_id="CLM-001",
            statement_summary="Claim with archive timestamp",
            claim_status="UNCONDITIONALLY_PROVED",
            assumptions=[],
            proof_obligations_open=[],
            salt_commitment=commit
        )
        leaf_hash = compute_leaf_hash(self.lineage_id, 1, claim.to_dict())
        catalog_root, _ = build_merkle_tree([leaf_hash])

        target = ApprovalTarget(
            domain=TARGET_DOMAIN,
            lineage_id=self.lineage_id,
            milestone_index=1,
            catalog_leaf_count=1,
            predecessor_digest=None,
            catalog_root=f"sha256:{catalog_root.hex()}",
            encrypted_archive_digest=arch_digest_hex,
            governance_digest=sha256_hex(canonical_json_dumps(self.governance.to_dict()))
        )
        sig = sign_data(target.to_dict(), self.lead_privkey, "slot_lead")

        archive_ts_proof = {
            "domain": OPENING_DOMAIN,
            "lineage_id": self.lineage_id,
            "milestone_index": 1,
            "target": target.to_dict(),
            "governance": self.governance.to_dict(),
            "signatures": [sig],
            "timestamp_token": {
                "format": "RFC3161_DER",
                "tsr_der_hex": arch_tsr.hex(),
                "expected_nonce": int.from_bytes(arch_nonce, "big"),
                "imprint_scope": "archive"
            },
            "claim_complete_opening": True,
            "opened_claims": [
                {
                    "catalog_item": claim.to_dict(),
                    "salt": f"hex:{salt_bytes.hex()}",
                    "material_content": material_str,
                    "merkle_proof": {"leaf_index": 0, "audit_path": []}
                }
            ]
        }

        # Verifier MUST grant ARCHIVE_DIGEST_EXISTED_NOT_AFTER and MUST NOT grant APPROVAL_TARGET_EXISTED_NOT_AFTER
        res = appraise(archive_ts_proof, self.trusted_pins)
        self.assertTrue(res.is_valid(), f"Valid archive timestamp proof failed: {res.rejection_reasons}")
        self.assertTrue(any(p.startswith("ARCHIVE_DIGEST_EXISTED_NOT_AFTER") for p in res.granted_predicates))
        self.assertFalse(any(p.startswith("APPROVAL_TARGET_EXISTED_NOT_AFTER") for p in res.granted_predicates))
        self.assertFalse(any(p.startswith("SEALED_BYTES_EXISTED_NOT_AFTER") for p in res.granted_predicates))

        # Tampered attempt: Claim imprint_scope == "target" using the archive TSR
        tampered_proof = dict(archive_ts_proof)
        tampered_proof["timestamp_token"] = dict(archive_ts_proof["timestamp_token"])
        tampered_proof["timestamp_token"]["imprint_scope"] = "target"
        res_tampered = appraise(tampered_proof, self.trusted_pins)
        self.assertFalse(res_tampered.is_valid())
        self.assertTrue(any("REJECTED_TIMESTAMP_VERIFICATION_FAILED" in r for r in res_tampered.rejection_reasons))

    # -------------------------------------------------------------------------
    # REG-15: Conflicting Canonical and Alias Fields Rejected
    # -------------------------------------------------------------------------
    def test_reg15_conflicting_aliases_rejected(self):
        """REG-15: Conflicting canonical and compatibility alias fields must be strictly rejected rather than silently picked."""
        audit_path_0 = [{"direction": "right", "hash": f"sha256:{self.m1_levels[0][1].hex()}"}]

        # 1. ClaimCatalogItem constructor rejects conflicting salt_commitment vs salted_commitment
        with self.assertRaises(ValueError) as ctx1:
            ClaimCatalogItem(
                claim_id="CLM-001",
                statement_summary="Summary",
                claim_status="UNCONDITIONALLY_PROVED",
                assumptions=[],
                proof_obligations_open=[],
                salt_commitment="sha256:1111111111111111111111111111111111111111111111111111111111111111",
                salted_commitment="sha256:2222222222222222222222222222222222222222222222222222222222222222"
            )
        self.assertIn("CONFLICTING_ALIAS_VALUES", str(ctx1.exception))

        # 2. Verifier rejects raw proof catalog item with conflicting salt_commitment and salted_commitment
        conflicting_claim_item = self.m1_claim1.to_dict()
        conflicting_claim_item["salted_commitment"] = "sha256:0000000000000000000000000000000000000000000000000000000000000000"
        proof_with_conflicting_claim = {
            "domain": OPENING_DOMAIN,
            "lineage_id": self.lineage_id,
            "milestone_index": 1,
            "target": self.m1_target.to_dict(),
            "governance": self.governance.to_dict(),
            "signatures": [self.m1_sig],
            "timestamp_token": self.m1_ts_token,
            "claim_complete_opening": False,
            "opened_claims": [
                {
                    "catalog_item": conflicting_claim_item,
                    "salt": self.m1_salt1_hex,
                    "material_content": self.m1_mat1_content,
                    "merkle_proof": {"leaf_index": 0, "audit_path": audit_path_0}
                }
            ]
        }
        res_cat = appraise(proof_with_conflicting_claim, self.trusted_pins)
        self.assertFalse(res_cat.is_valid())
        self.assertTrue(any("REJECTED_ALIAS_CONFLICT" in r for r in res_cat.rejection_reasons))

        # 3. AuthorSlot constructor rejects conflicting public_key vs ed25519_public_key_hex
        with self.assertRaises(ValueError) as ctx2:
            AuthorSlot(
                slot_id="slot_lead",
                public_key="ed25519:aaaa000000000000000000000000000000000000000000000000000000000000",
                ed25519_public_key_hex="ed25519:bbbb000000000000000000000000000000000000000000000000000000000000"
            )
        self.assertIn("CONFLICTING_ALIAS_VALUES", str(ctx2.exception))

        # 4. Verifier rejects raw proof signature with conflicting public_key and ed25519_public_key_hex
        conflicting_sig = dict(self.m1_sig)
        conflicting_sig["ed25519_public_key_hex"] = "ed25519:ffff000000000000000000000000000000000000000000000000000000000000"
        proof_with_sig_conflict = {
            "domain": OPENING_DOMAIN,
            "lineage_id": self.lineage_id,
            "milestone_index": 1,
            "target": self.m1_target.to_dict(),
            "governance": self.governance.to_dict(),
            "signatures": [conflicting_sig],
            "timestamp_token": self.m1_ts_token,
            "claim_complete_opening": False,
            "opened_claims": []
        }
        res_sig = appraise(proof_with_sig_conflict, self.trusted_pins)
        self.assertFalse(res_sig.is_valid())
        self.assertTrue(any("REJECTED_ALIAS_CONFLICT" in r for r in res_sig.rejection_reasons))

        # 5. LineageTransition constructor rejects conflicting target digest aliases
        with self.assertRaises(ValueError) as ctx3:
            LineageTransition(
                domain=TRANSITION_DOMAIN,
                lineage_id=self.lineage_id,
                predecessor_target_digest="sha256:1111111111111111111111111111111111111111111111111111111111111111",
                parent_target_digest="sha256:2222222222222222222222222222222222222222222222222222222222222222"
            )
        self.assertIn("CONFLICTING_ALIAS_VALUES", str(ctx3.exception))

        # 6. Trust pins with conflicting expected_parent_target_digest and expected_predecessor_target_digest
        conflicting_trust = {
            "trusted_tsa_pin": self.tsa_pin,
            "expected_parent_target_digest": "sha256:1111111111111111111111111111111111111111111111111111111111111111",
            "expected_predecessor_target_digest": "sha256:2222222222222222222222222222222222222222222222222222222222222222"
        }
        res_pins = appraise(proof_with_conflicting_claim, conflicting_trust)
        self.assertFalse(res_pins.is_valid())
        self.assertTrue(any("REJECTED_ALIAS_CONFLICT" in r for r in res_pins.rejection_reasons))

    # -------------------------------------------------------------------------
    # REG-16: Maximum Predecessor Depth Rejection
    # -------------------------------------------------------------------------
    def test_reg16_max_predecessor_depth_exceeded_rejected(self):
        """REG-16: Predecessor proof chains exceeding MAX_PREDECESSOR_DEPTH (32) are safely rejected without RecursionError."""
        current_proof = {
            "domain": OPENING_DOMAIN,
            "lineage_id": self.lineage_id,
            "milestone_index": 1,
            "target": self.m1_target.to_dict(),
            "governance": self.governance.to_dict(),
            "signatures": [self.m1_sig],
            "timestamp_token": self.m1_ts_token,
            "claim_complete_opening": False,
            "opened_claims": []
        }

        # Build a 35-deep nested chain
        chain_list = [current_proof]
        for m in range(2, 36):
            dummy_target = {
                "domain": TARGET_DOMAIN,
                "lineage_id": self.lineage_id,
                "milestone_index": m,
                "catalog_leaf_count": 1,
                "predecessor_digest": sha256_hex(canonical_json_dumps(current_proof["target"])),
                "catalog_root": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
                "encrypted_archive_digest": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
                "governance_digest": sha256_hex(canonical_json_dumps(self.governance.to_dict()))
            }
            sig = sign_data(dummy_target, self.lead_privkey, "slot_lead")
            trans = LineageTransition(
                domain=TRANSITION_DOMAIN,
                lineage_id=self.lineage_id,
                predecessor_target_digest=dummy_target["predecessor_digest"],
                successor_target_digest=sha256_hex(canonical_json_dumps(dummy_target)),
                predecessor_milestone_index=m - 1,
                successor_milestone_index=m
            )
            trans_sig = sign_data(trans.to_dict(), self.lead_privkey, "slot_lead")

            ts_nonce = os.urandom(8)
            tsq = build_tsq(sha256(canonical_json_dumps(dummy_target)), ts_nonce)
            tsr = self.tsa.respond(tsq)

            current_proof = {
                "domain": OPENING_DOMAIN,
                "lineage_id": self.lineage_id,
                "milestone_index": m,
                "target": dummy_target,
                "governance": self.governance.to_dict(),
                "signatures": [sig],
                "predecessor_transition_auth": {
                    "transition": trans.to_dict(),
                    "signatures": [trans_sig]
                },
                "timestamp_token": {
                    "format": "RFC3161_DER",
                    "tsr_der_hex": tsr.hex(),
                    "expected_nonce": int.from_bytes(ts_nonce, "big")
                },
                "predecessor_proof": current_proof,
                "claim_complete_opening": False,
                "opened_claims": []
            }
            chain_list.append(current_proof)

        # 1. Deep recursive nested appraisal MUST be safely rejected due to depth limit
        res_deep = appraise(current_proof, self.trusted_pins)
        self.assertFalse(res_deep.is_valid())
        self.assertTrue(any("REJECTED_MAX_PREDECESSOR_DEPTH_EXCEEDED" in r for r in res_deep.rejection_reasons))

        # 2. Sequential iterative chain appraisal functions without recursive exhaustion
        # (Passes previous element in chain iteratively)
        chain_slice = chain_list[:5]  # verify first 5 milestones iteratively
        iter_results = appraise_lineage_chain(chain_slice, self.trusted_pins)
        self.assertEqual(len(iter_results), 5)
        self.assertTrue(all(r.is_valid() for r in iter_results))

    # -------------------------------------------------------------------------
    # End-to-End appraise() with Authentic DigiCert Production Fixture
    # -------------------------------------------------------------------------
    def test_full_appraise_with_real_digicert_fixture(self):
        """Verifies full appraise() execution using real DigiCert RFC 3161 evidence."""
        ts_dir = pathlib.Path(ROOT_DIR) / "release-v4.0.0-rc2.timestamp"
        tsr_path = ts_dir / "response.tsr"
        report_path = ts_dir / "report.json"

        if not tsr_path.exists() or not report_path.exists():
            self.skipTest("DigiCert timestamp fixture not found on disk")

        report = json.loads(report_path.read_text(encoding="utf-8"))
        tsr_der = tsr_path.read_bytes()
        tsa_pin = report["signer_certificate_sha256_fingerprint"]
        expected_nonce = int(report["nonce_hex"], 16)
        subject_sha256 = report["subject_sha256"]

        # Build 1 claim with valid salted commitment and Merkle leaf
        mat_content = "Reproducible research note timestamped by DigiCert"
        salt_bytes = os.urandom(32)
        commit = sha256_hex(salt_bytes + mat_content.encode("utf-8"))
        claim_item = ClaimCatalogItem(
            claim_id="CLM-001",
            statement_summary="Reproducible research note",
            claim_status="UNCONDITIONALLY_PROVED",
            assumptions=[],
            proof_obligations_open=[],
            salt_commitment=commit
        )
        leaf_hash = compute_leaf_hash("srl:lin:digicert-verified-study", 1, claim_item.to_dict())
        catalog_root, _ = build_merkle_tree([leaf_hash])

        # Build Milestone 1 whose archive digest binds the genuine DigiCert subject
        m1_digi_target = ApprovalTarget(
            domain=TARGET_DOMAIN,
            lineage_id="srl:lin:digicert-verified-study",
            milestone_index=1,
            catalog_leaf_count=1,
            predecessor_digest=None,
            catalog_root=f"sha256:{catalog_root.hex()}",
            encrypted_archive_digest=f"sha256:{subject_sha256}",
            governance_digest=sha256_hex(canonical_json_dumps(self.governance.to_dict()))
        )
        sig = sign_data(m1_digi_target.to_dict(), self.lead_privkey, "slot_lead")

        proof = {
            "domain": OPENING_DOMAIN,
            "lineage_id": "srl:lin:digicert-verified-study",
            "milestone_index": 1,
            "target": m1_digi_target.to_dict(),
            "governance": self.governance.to_dict(),
            "signatures": [sig],
            "timestamp_token": {
                "format": "RFC3161_DER",
                "tsr_der_hex": tsr_der.hex(),
                "expected_nonce": expected_nonce,
                "imprint_scope": "archive"
            },
            "claim_complete_opening": True,
            "opened_claims": [
                {
                    "catalog_item": claim_item.to_dict(),
                    "salt": f"hex:{salt_bytes.hex()}",
                    "material_content": mat_content,
                    "merkle_proof": {"leaf_index": 0, "audit_path": []}
                }
            ]
        }

        res = appraise(proof, {"trusted_tsa_pin": tsa_pin})
        self.assertTrue(res.is_valid(), f"DigiCert appraise failed: {res.rejection_reasons}")
        self.assertIn("COMPLETE_CATALOG_OPENING(total=1)", res.granted_predicates)
        self.assertTrue(any("2026-09-21T13:38:52" in p for p in res.granted_predicates))
        # Archive timestamp certifies archive digest existed, NOT that the newly minted target existed
        self.assertTrue(any(p.startswith("ARCHIVE_DIGEST_EXISTED_NOT_AFTER") for p in res.granted_predicates))
        self.assertFalse(any(p.startswith("APPROVAL_TARGET_EXISTED_NOT_AFTER") for p in res.granted_predicates))

    # -------------------------------------------------------------------------
    # Offline External RFC 3161 Fixture Verification (DigiCert Production Token)
    # -------------------------------------------------------------------------
    def test_offline_external_digicert_rfc3161_fixture(self):
        """Verifies that the verification engine works with real DigiCert RFC 3161 evidence."""
        ts_dir = pathlib.Path(ROOT_DIR) / "release-v4.0.0-rc2.timestamp"
        tsr_path = ts_dir / "response.tsr"
        report_path = ts_dir / "report.json"

        if not tsr_path.exists() or not report_path.exists():
            self.skipTest("DigiCert timestamp fixture not found on disk")

        report = json.loads(report_path.read_text(encoding="utf-8"))
        tsr_der = tsr_path.read_bytes()
        subject_imprint = bytes.fromhex(report["subject_sha256"])
        tsa_pin = report["signer_certificate_sha256_fingerprint"]
        expected_nonce = int(report["nonce_hex"], 16)

        # Call verify_tsr directly on real production DigiCert timestamp response
        info = verify_tsr(
            tsr=tsr_der,
            expected_imprint=subject_imprint,
            trusted_fingerprint=tsa_pin,
            expected_nonce=expected_nonce,
            allow_self_signed=False
        )
        self.assertIn(info["status"], (0, 1))
        self.assertEqual(info["signer_fingerprint"], tsa_pin.lower().replace(":", ""))
        self.assertEqual(info["genTime"].strftime("%Y-%m-%dT%H:%M:%SZ"), report["generation_time_utc"])

    # -------------------------------------------------------------------------
    # REG-17: Invalid Transition Target Rejection without Exception
    # -------------------------------------------------------------------------
    def test_reg17_invalid_transition_target_rejected_without_exception(self):
        """REG-17: Transition object with invalid domain or mismatched targets rejected safely without UnboundLocalError."""
        # 1. Modify transition domain
        m2_bad_domain = copy.deepcopy(self.m2_proof_base)
        m2_bad_domain["predecessor_transition_auth"]["transition"]["domain"] = "SRL:INVALID_DOMAIN:v1"
        res_domain = appraise(m2_bad_domain, self.trusted_pins, predecessor_proof=self.m1_proof_base)
        self.assertFalse(res_domain.is_valid())
        self.assertTrue(any("REJECTED_INVALID_TRANSITION_TARGET" in r for r in res_domain.rejection_reasons))

        # 2. Modify transition successor digest
        m2_bad_succ = copy.deepcopy(self.m2_proof_base)
        m2_bad_succ["predecessor_transition_auth"]["transition"]["successor_target_digest"] = "sha256:0000000000000000000000000000000000000000000000000000000000000000"
        res_succ = appraise(m2_bad_succ, self.trusted_pins, predecessor_proof=self.m1_proof_base)
        self.assertFalse(res_succ.is_valid())
        self.assertTrue(any("REJECTED_INVALID_TRANSITION_TARGET" in r for r in res_succ.rejection_reasons))

        # 3. Modify transition milestone indices
        m2_bad_idx = copy.deepcopy(self.m2_proof_base)
        m2_bad_idx["predecessor_transition_auth"]["transition"]["successor_milestone_index"] = 99
        res_idx = appraise(m2_bad_idx, self.trusted_pins, predecessor_proof=self.m1_proof_base)
        self.assertFalse(res_idx.is_valid())
        self.assertTrue(any("REJECTED_INVALID_TRANSITION_TARGET" in r for r in res_idx.rejection_reasons))

    # -------------------------------------------------------------------------
    # REG-18: Public Key Alias Normalization and Conflict Rejection
    # -------------------------------------------------------------------------
    def test_reg18_pubkey_alias_normalization_and_conflict_rejection(self):
        """REG-18: Alias-only governance works without KeyError; alias conflicts strictly rejected."""
        # 1. Alias-only governance (ed25519_public_key_hex without public_key)
        lead_pub_hex = self.lead_privkey.public_key().public_bytes_raw().hex()
        alias_only_gov = {
            "author_slots": [
                {"slot_id": "slot_lead", "ed25519_public_key_hex": f"ed25519:{lead_pub_hex}"}
            ],
            "threshold": 1
        }
        alias_target = ApprovalTarget(
            domain=TARGET_DOMAIN,
            lineage_id=self.lineage_id,
            milestone_index=1,
            catalog_leaf_count=1,
            predecessor_digest=None,
            catalog_root="sha256:0000000000000000000000000000000000000000000000000000000000000000",
            encrypted_archive_digest="sha256:0000000000000000000000000000000000000000000000000000000000000000",
            governance_digest=sha256_hex(canonical_json_dumps(alias_only_gov))
        )
        sig = sign_data(alias_target.to_dict(), self.lead_privkey, "slot_lead")
        ts_nonce = os.urandom(8)
        tsq = build_tsq(sha256(canonical_json_dumps(alias_target.to_dict())), ts_nonce)
        tsr = self.tsa.respond(tsq)

        proof_alias_only = {
            "domain": OPENING_DOMAIN,
            "lineage_id": self.lineage_id,
            "milestone_index": 1,
            "target": alias_target.to_dict(),
            "governance": alias_only_gov,
            "signatures": [sig],
            "timestamp_token": {
                "format": "RFC3161_DER",
                "tsr_der_hex": tsr.hex(),
                "expected_nonce": int.from_bytes(ts_nonce, "big")
            },
            "claim_complete_opening": False,
            "opened_claims": []
        }
        res_alias_only = appraise(proof_alias_only, self.trusted_pins)
        # Should not raise KeyError: 'public_key'
        self.assertTrue(res_alias_only.is_valid(), f"Alias-only governance failed: {res_alias_only.rejection_reasons}")

        # 2. Conflicting keys in transition signatures
        m2_trans_sig_conflict = copy.deepcopy(self.m2_proof_base)
        m2_trans_sig_conflict["predecessor_transition_auth"]["signatures"][0]["ed25519_public_key_hex"] = (
            "ed25519:ffff000000000000000000000000000000000000000000000000000000000000"
        )
        res_trans_conflict = appraise(m2_trans_sig_conflict, self.trusted_pins, predecessor_proof=self.m1_proof_base)
        self.assertFalse(res_trans_conflict.is_valid())
        self.assertTrue(any("REJECTED_ALIAS_CONFLICT" in r for r in res_trans_conflict.rejection_reasons))

    # -------------------------------------------------------------------------
    # REG-19: True Flat Iterative Chain & Bounded Diagnostics
    # -------------------------------------------------------------------------
    def test_reg19_true_flat_iterative_chain_and_bounded_errors(self):
        """REG-19: 35-milestone chain verified sequentially in O(1) stack; diagnostic strings bounded."""
        chain_list = []
        prev_target_dict = None

        for m in range(1, 36):
            target_dict = {
                "domain": TARGET_DOMAIN,
                "lineage_id": self.lineage_id,
                "milestone_index": m,
                "catalog_leaf_count": 1,
                "predecessor_digest": sha256_hex(canonical_json_dumps(prev_target_dict)) if prev_target_dict else None,
                "catalog_root": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
                "encrypted_archive_digest": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
                "governance_digest": sha256_hex(canonical_json_dumps(self.governance.to_dict()))
            }
            sig = sign_data(target_dict, self.lead_privkey, "slot_lead")
            ts_nonce = os.urandom(8)
            tsq = build_tsq(sha256(canonical_json_dumps(target_dict)), ts_nonce)
            tsr = self.tsa.respond(tsq)

            milestone_proof = {
                "domain": OPENING_DOMAIN,
                "lineage_id": self.lineage_id,
                "milestone_index": m,
                "target": target_dict,
                "governance": self.governance.to_dict(),
                "signatures": [sig],
                "timestamp_token": {
                    "format": "RFC3161_DER",
                    "tsr_der_hex": tsr.hex(),
                    "expected_nonce": int.from_bytes(ts_nonce, "big")
                },
                "claim_complete_opening": False,
                "opened_claims": []
            }

            if m > 1:
                trans = LineageTransition(
                    domain=TRANSITION_DOMAIN,
                    lineage_id=self.lineage_id,
                    predecessor_target_digest=target_dict["predecessor_digest"],
                    successor_target_digest=sha256_hex(canonical_json_dumps(target_dict)),
                    predecessor_milestone_index=m - 1,
                    successor_milestone_index=m
                )
                trans_sig = sign_data(trans.to_dict(), self.lead_privkey, "slot_lead")
                milestone_proof["predecessor_transition_auth"] = {
                    "transition": trans.to_dict(),
                    "signatures": [trans_sig]
                }

            chain_list.append(milestone_proof)
            prev_target_dict = target_dict

        # Verify all 35 milestones via appraise_lineage_chain in O(1) stack
        results = appraise_lineage_chain(chain_list, self.trusted_pins)
        self.assertEqual(len(results), 35)
        for i, res in enumerate(results):
            self.assertTrue(res.is_valid(), f"Milestone {i+1} failed: {res.rejection_reasons}")

        # Check bounded diagnostic string size when predecessor fails
        bad_pred = copy.deepcopy(self.m1_proof_base)
        bad_pred["signatures"][0]["signature"] = "ed25519_sig:" + "00" * 64
        res_pred_fail = appraise(self.m2_proof_base, self.trusted_pins, predecessor_proof=bad_pred)
        self.assertFalse(res_pred_fail.is_valid())
        self.assertLess(len(str(res_pred_fail.rejection_reasons)), 300)
        self.assertTrue(any("REJECTED_INVALID_PREDECESSOR_PROOF" in r for r in res_pred_fail.rejection_reasons))

    # -------------------------------------------------------------------------
    # REG-20: Total Input Parsing and Safe Hex/Digest Validation
    # -------------------------------------------------------------------------
    def test_reg20_malformed_hex_and_digests_converted_to_typed_rejections(self):
        """REG-20: Malformed hex in all target, proof, and token fields returns typed rejections without ValueError."""
        # 1. Malformed archive digest with imprint_scope=archive (64 non-hex characters)
        m1_bad_arch = copy.deepcopy(self.m1_proof_base)
        m1_bad_arch["timestamp_token"]["imprint_scope"] = "archive"
        m1_bad_arch["target"]["encrypted_archive_digest"] = "sha256:" + "g" * 64
        res1 = appraise(m1_bad_arch, self.trusted_pins)
        self.assertFalse(res1.is_valid())
        self.assertTrue(any("REJECTED_MALFORMED_HEX" in r for r in res1.rejection_reasons))

        # 2. Malformed catalog_root (short length)
        m1_bad_root = copy.deepcopy(self.m1_proof_base)
        m1_bad_root["target"]["catalog_root"] = "sha256:short"
        res2 = appraise(m1_bad_root, self.trusted_pins)
        self.assertFalse(res2.is_valid())
        self.assertTrue(any("REJECTED_INVALID_DIGEST_LENGTH" in r for r in res2.rejection_reasons))

        # 3. Malformed predecessor_digest for M2 (64 non-hex characters)
        m2_bad_pred = copy.deepcopy(self.m2_proof_base)
        m2_bad_pred["target"]["predecessor_digest"] = "sha256:" + "z" * 64
        res3 = appraise(m2_bad_pred, self.trusted_pins, predecessor_proof=self.m1_proof_base)
        self.assertFalse(res3.is_valid())
        self.assertTrue(any("REJECTED_MALFORMED_HEX" in r for r in res3.rejection_reasons))

        # 4. Malformed salt in opened claim
        m1_bad_salt = copy.deepcopy(self.m1_proof_base)
        m1_bad_salt["opened_claims"] = [
            {
                "catalog_item": self.m1_claim1.to_dict(),
                "salt": "hex:not_hex_chars_gggggggggggggggggggggggggggggggggggggggggggggggggg",
                "material_content": self.m1_mat1_content,
                "merkle_proof": {"leaf_index": 0, "audit_path": [{"direction": "right", "hash": f"sha256:{self.m1_levels[0][1].hex()}"}]}
            }
        ]
        res4 = appraise(m1_bad_salt, self.trusted_pins)
        self.assertFalse(res4.is_valid())
        self.assertTrue(any("REJECTED_MALFORMED_HEX" in r for r in res4.rejection_reasons))

        # 5. Malformed tsr_der_hex in timestamp token (10 non-hex chars, even length)
        m1_bad_tsr = copy.deepcopy(self.m1_proof_base)
        m1_bad_tsr["timestamp_token"]["tsr_der_hex"] = "deadbeefgg"
        res5 = appraise(m1_bad_tsr, self.trusted_pins)
        self.assertFalse(res5.is_valid())
        self.assertTrue(any("REJECTED_MALFORMED_HEX" in r for r in res5.rejection_reasons))

        # 6. Malformed public key in author slot (64 non-hex chars)
        m1_bad_pk = copy.deepcopy(self.m1_proof_base)
        m1_bad_pk["governance"]["author_slots"][0]["public_key"] = "ed25519:" + "g" * 64
        res6 = appraise(m1_bad_pk, self.trusted_pins)
        self.assertFalse(res6.is_valid())
        self.assertTrue(any("INVALID_GOVERNANCE" in r or "REJECTED_MALFORMED_HEX" in r for r in res6.rejection_reasons))

    # -------------------------------------------------------------------------
    # REG-21: Input Totality on Nulls and Malformed Collections
    # -------------------------------------------------------------------------
    def test_reg21_input_totality_nulls_and_malformed_collections(self):
        """REG-21: Null collections and non-dict inputs never raise uncaught exceptions."""
        # 1. Null signatures in proof
        m1_null_sigs = copy.deepcopy(self.m1_proof_base)
        m1_null_sigs["signatures"] = None
        res1 = appraise(m1_null_sigs, self.trusted_pins)
        self.assertFalse(res1.is_valid())
        self.assertTrue(any("QUORUM_NOT_MET" in r or "REJECTED_MALFORMED_SIGNATURES" in r for r in res1.rejection_reasons))

        # 2. Null opened_claims in proof
        m1_null_claims = copy.deepcopy(self.m1_proof_base)
        m1_null_claims["opened_claims"] = None
        res2 = appraise(m1_null_claims, self.trusted_pins)
        self.assertTrue(res2.is_valid())  # Valid 0-claim partial opening
        self.assertEqual(res2.opened_ratio, (0, 2))

        # 3. String signatures in proof
        m1_str_sigs = copy.deepcopy(self.m1_proof_base)
        m1_str_sigs["signatures"] = "invalid_not_a_list"
        res3 = appraise(m1_str_sigs, self.trusted_pins)
        self.assertFalse(res3.is_valid())
        self.assertTrue(any("REJECTED_MALFORMED_SIGNATURES" in r for r in res3.rejection_reasons))

        # 4. Null material_content in opened claim
        claim1_opening = {
            "catalog_item": self.m1_claim1.to_dict(),
            "salt": self.m1_salt1_hex,
            "material_content": self.m1_mat1_content,
            "merkle_proof": {
                "leaf_index": 0,
                "audit_path": [{"direction": "right", "hash": f"sha256:{self.m1_levels[0][1].hex()}"}]
            }
        }
        m1_null_mat = copy.deepcopy(self.m1_proof_base)
        m1_null_mat["opened_claims"] = [copy.deepcopy(claim1_opening)]
        m1_null_mat["opened_claims"][0]["material_content"] = None
        res4 = appraise(m1_null_mat, self.trusted_pins)
        self.assertFalse(res4.is_valid())
        self.assertTrue(any("REJECTED_MALFORMED_MATERIAL_CONTENT" in r for r in res4.rejection_reasons))

        # 5. Null audit_path in merkle proof
        m1_null_path = copy.deepcopy(self.m1_proof_base)
        m1_null_path["opened_claims"] = [copy.deepcopy(claim1_opening)]
        m1_null_path["opened_claims"][0]["merkle_proof"]["audit_path"] = None
        res5 = appraise(m1_null_path, self.trusted_pins)
        self.assertFalse(res5.is_valid())
        self.assertTrue(any("REJECTED_DOMAIN_SEPARATOR_MISMATCH" in r for r in res5.rejection_reasons))

        # 6. Malformed audit_path elements (None, int, string)
        m1_bad_steps = copy.deepcopy(self.m1_proof_base)
        m1_bad_steps["opened_claims"] = [copy.deepcopy(claim1_opening)]
        m1_bad_steps["opened_claims"][0]["merkle_proof"]["audit_path"] = [None, 42, "not_dict"]
        res6 = appraise(m1_bad_steps, self.trusted_pins)
        self.assertFalse(res6.is_valid())
        self.assertTrue(any("REJECTED_DOMAIN_SEPARATOR_MISMATCH" in r for r in res6.rejection_reasons))

        # 7. Non-dict proof and non-dict trust_pins
        res7a = appraise("not_dict", self.trusted_pins)
        self.assertFalse(res7a.is_valid())
        self.assertTrue(any("REJECTED_MALFORMED_PROOF" in r for r in res7a.rejection_reasons))

        res7b = appraise(self.m1_proof_base, "not_dict")
        self.assertFalse(res7b.is_valid())
        self.assertTrue(any("REJECTED_MALFORMED_TRUST_PINS" in r for r in res7b.rejection_reasons))

        # 8. Non-string query
        res8 = appraise(self.m1_proof_base, self.trusted_pins, query=12345)
        self.assertEqual(res8.status, "REFUSED")
        self.assertTrue(any("OUT_OF_SCOPE_QUERY" in r for r in res8.refusal_reasons))

        # 9. Non-list chain in appraise_lineage_chain
        res9 = appraise_lineage_chain("not_list", self.trusted_pins)
        self.assertEqual(len(res9), 1)
        self.assertFalse(res9[0].is_valid())
        self.assertTrue(any("REJECTED_MALFORMED_CHAIN" in r for r in res9[0].rejection_reasons))

        # 10. Chain containing non-dict items
        res10 = appraise_lineage_chain([None, 42], self.trusted_pins)
        self.assertEqual(len(res10), 1)
        self.assertFalse(res10[0].is_valid())
        self.assertTrue(any("REJECTED_MALFORMED_CHAIN_ITEM" in r for r in res10[0].rejection_reasons))

    # -------------------------------------------------------------------------
    # REG-22: Non-JCS Floats Converted to Typed Rejections
    # -------------------------------------------------------------------------
    def test_reg22_non_jcs_floats_converted_to_typed_rejections(self):
        """REG-22: Floats in target, governance, cat_item, or transition yield typed rejections without ValueError."""
        # 1. Float in target
        m1_float_target = copy.deepcopy(self.m1_proof_base)
        m1_float_target["target"]["invalid_float"] = 3.14159
        res1 = appraise(m1_float_target, self.trusted_pins)
        self.assertFalse(res1.is_valid())
        self.assertTrue(any("REJECTED_NON_CANONICAL_JSON" in r for r in res1.rejection_reasons))

        # 2. Float in governance
        m1_float_gov = copy.deepcopy(self.m1_proof_base)
        m1_float_gov["governance"]["float_param"] = 1.0
        res2 = appraise(m1_float_gov, self.trusted_pins)
        self.assertFalse(res2.is_valid())
        self.assertTrue(any("REJECTED_NON_CANONICAL_JSON" in r for r in res2.rejection_reasons))

        # 3. Float in opened catalog_item
        claim1_opening = {
            "catalog_item": self.m1_claim1.to_dict(),
            "salt": self.m1_salt1_hex,
            "material_content": self.m1_mat1_content,
            "merkle_proof": {
                "leaf_index": 0,
                "audit_path": [{"direction": "right", "hash": f"sha256:{self.m1_levels[0][1].hex()}"}]
            }
        }
        m1_float_claim = copy.deepcopy(self.m1_proof_base)
        m1_float_claim["opened_claims"] = [copy.deepcopy(claim1_opening)]
        m1_float_claim["opened_claims"][0]["catalog_item"]["weight"] = 0.5
        res3 = appraise(m1_float_claim, self.trusted_pins)
        self.assertFalse(res3.is_valid())
        self.assertTrue(any("REJECTED_NON_CANONICAL_JSON" in r for r in res3.rejection_reasons))

        # 4. Float in predecessor transition
        m2_float_trans = copy.deepcopy(self.m2_proof_base)
        m2_float_trans["predecessor_transition_auth"]["transition"]["ratio"] = 0.99
        res4 = appraise(m2_float_trans, self.trusted_pins, predecessor_proof=self.m1_proof_base)
        self.assertFalse(res4.is_valid())
        self.assertTrue(any("REJECTED_NON_CANONICAL_JSON" in r for r in res4.rejection_reasons))

    # -------------------------------------------------------------------------
    # REG-23: Milestone Index Bounds and Genesis Invariants
    # -------------------------------------------------------------------------
    def test_reg23_milestone_index_bounds_and_genesis_invariants(self):
        """REG-23: milestone_index must be int >= 1; M1 cannot declare predecessor; M>1 must declare predecessor."""
        # 1. String milestone_index ("1")
        m1_str_idx = copy.deepcopy(self.m1_proof_base)
        m1_str_idx["milestone_index"] = "1"
        res1 = appraise(m1_str_idx, self.trusted_pins)
        self.assertFalse(res1.is_valid())
        self.assertTrue(any("REJECTED_INVALID_MILESTONE_INDEX" in r for r in res1.rejection_reasons))

        # 2. milestone_index = 0
        m1_zero_idx = copy.deepcopy(self.m1_proof_base)
        m1_zero_idx["milestone_index"] = 0
        res2 = appraise(m1_zero_idx, self.trusted_pins)
        self.assertFalse(res2.is_valid())
        self.assertTrue(any("REJECTED_INVALID_MILESTONE_INDEX" in r for r in res2.rejection_reasons))

        # 3. Negative milestone_index
        m1_neg_idx = copy.deepcopy(self.m1_proof_base)
        m1_neg_idx["milestone_index"] = -5
        res3 = appraise(m1_neg_idx, self.trusted_pins)
        self.assertFalse(res3.is_valid())
        self.assertTrue(any("REJECTED_INVALID_MILESTONE_INDEX" in r for r in res3.rejection_reasons))

        # 4. Milestone 1 declaring non-null predecessor_digest
        m1_has_pred = copy.deepcopy(self.m1_proof_base)
        m1_has_pred["target"]["predecessor_digest"] = "sha256:" + "00" * 32
        # resign target
        new_target_bytes = canonical_json_dumps(m1_has_pred["target"])
        m1_has_pred["signatures"] = [sign_data(m1_has_pred["target"], self.lead_privkey, "slot_lead")]
        # update timestamp
        tsq = build_tsq(sha256(new_target_bytes), self.m1_nonce_bytes)
        tsr = self.tsa.respond(tsq)
        m1_has_pred["timestamp_token"] = {
            "format": "RFC3161_DER",
            "tsr_der_hex": tsr.hex(),
            "expected_nonce": self.m1_nonce_int
        }
        res4 = appraise(m1_has_pred, self.trusted_pins)
        self.assertFalse(res4.is_valid())
        self.assertTrue(any("REJECTED_GENESIS_HAS_PREDECESSOR" in r for r in res4.rejection_reasons))

        # 5. Milestone 2 missing predecessor_digest
        m2_missing_pred = copy.deepcopy(self.m2_proof_base)
        m2_missing_pred["target"]["predecessor_digest"] = None
        new_m2_bytes = canonical_json_dumps(m2_missing_pred["target"])
        m2_missing_pred["signatures"] = [sign_data(m2_missing_pred["target"], self.lead_privkey, "slot_lead")]
        m2_nonce_bytes = os.urandom(8)
        tsq2 = build_tsq(sha256(new_m2_bytes), m2_nonce_bytes)
        tsr2 = self.tsa.respond(tsq2)
        m2_missing_pred["timestamp_token"] = {
            "format": "RFC3161_DER",
            "tsr_der_hex": tsr2.hex(),
            "expected_nonce": int.from_bytes(m2_nonce_bytes, "big")
        }
        res5 = appraise(m2_missing_pred, self.trusted_pins, predecessor_proof=self.m1_proof_base)
        self.assertFalse(res5.is_valid())
        self.assertTrue(any("REJECTED_MISSING_PREDECESSOR_DIGEST" in r for r in res5.rejection_reasons))

    # -------------------------------------------------------------------------
    # REG-24: Merkle DOS Protection on Astronomical Leaf Counts
    # -------------------------------------------------------------------------
    def test_reg24_merkle_dos_large_leaf_count_and_malformed_steps(self):
        """REG-24: Giant catalog_leaf_count rejected immediately without OOM/range allocation."""
        # 1. Astronomical leaf count (10**18) rejected as unsafe integer by JCS
        m1_giant = copy.deepcopy(self.m1_proof_base)
        m1_giant["target"]["catalog_leaf_count"] = 10**18
        res1 = appraise(m1_giant, self.trusted_pins)
        self.assertFalse(res1.is_valid())
        self.assertTrue(any("REJECTED_NON_CANONICAL_JSON" in r and "UNSAFE_INTEGER" in r for r in res1.rejection_reasons))

        # 2. Exceeds MAX_CATALOG_LEAF_COUNT (1,000,000 > 65,536)
        m1_excess = copy.deepcopy(self.m1_proof_base)
        m1_excess["target"]["catalog_leaf_count"] = 1000000
        res2 = appraise(m1_excess, self.trusted_pins)
        self.assertFalse(res2.is_valid())
        self.assertTrue(any("REJECTED_CATALOG_LEAF_COUNT_EXCEEDED" in r for r in res2.rejection_reasons))



if __name__ == "__main__":
    unittest.main(verbosity=2)
