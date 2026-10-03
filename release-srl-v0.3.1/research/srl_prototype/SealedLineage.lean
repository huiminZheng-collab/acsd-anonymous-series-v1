/-!
# Sealed Research Lineage (SRL) Formal Specification and Invariant Proofs

This Lean 4 formalization models the core claim calculus of Sealed Research
Lineage (SRL) as defined in docs/SPEC-SEALED-LINEAGE-PROFILE.md.

Scope & Boundaries:
- Proves the typed appraisal output algebra: compatible predicates, refusal of terminal
  credit, isolation of assumption strengthening, and non-claims closure.
- Boundary Notice: This formal model explicitly DOES NOT prove concrete low-level Merkle
  tree bit-level path direction math, DER/CMS ASN.1 parsing, multi-milestone state machines,
  or physical-world legal originality/credit. Those guarantees are provided by the
  verified Python implementation (srl_verifier.py, test_srl_fixtures.py) and external
  cryptographic assumptions (SHA-256 collision resistance, Ed25519 EUF-CMA).
-/

set_option autoImplicit false
set_option warningAsError true

namespace SRL

structure Digest where
  value : Nat
  deriving DecidableEq, Repr

structure KeyId where
  value : Nat
  deriving DecidableEq, Repr

structure Timestamp where
  utcSeconds : Nat
  deriving DecidableEq, Repr

/-- Status of a scientific claim within an evolving research milestone. -/
inductive ClaimStatus where
  | conjectured
  | conditionallyProved
  | unconditionallyProved
  | disproved
  | abandoned
  deriving DecidableEq, Repr

/-- A single typed item in a milestone's claim catalog.
    Note: raw un-salted materialDigest is removed to prevent dictionary attacks;
    only the 256-bit salted commitment is retained. -/
structure ClaimItem where
  id : Nat
  status : ClaimStatus
  assumptions : List Nat
  obligations : List Nat
  saltCommitment : Digest
  deriving DecidableEq, Repr

/-- Sealed research milestone payload metadata. -/
structure Milestone where
  lineageId : Nat
  milestoneIndex : Nat
  attestedTime : Timestamp
  predecessorDigest : Option Digest
  catalog : List ClaimItem
  deriving DecidableEq, Repr

/-- Kinds of verifiable evidence that can be presented to the verifier. -/
inductive SRLEvidenceKind where
  | partialOpeningEvidence
  | completeOpeningEvidence
  | predecessorTransitionEvidence
  | targetTimestampEvidence
  | archiveTimestampEvidence
  deriving DecidableEq, Repr

/-- Vocabulary of verifiable claims and strictly prohibited non-claims. -/
inductive SRLClaim where
  -- Admissible claims
  | exactClaimPresentAtMilestone
  | partialLineageVerified
  | completeLineageVerified
  | predecessorAuthorized
  | approvalTargetExistedNotAfter
  | archiveDigestExistedNotAfter
  -- Prohibited Non-claims (Adjudication overreach)
  | firstProvedFinalTarget
  | laterProverPlagiarized
  | retroactiveStrengthenedClaim
  | naturalPersonAuthorship
  deriving DecidableEq, Repr

/-- Compatibility relation: defines which evidence kind can establish which claim.
    Notice that the prohibited non-claims have NO constructor here. -/
inductive Compatible : SRLEvidenceKind → SRLClaim → Prop where
  | partialOpeningClaim :
      Compatible .partialOpeningEvidence .exactClaimPresentAtMilestone
  | partialLineage :
      Compatible .partialOpeningEvidence .partialLineageVerified
  | completeOpeningClaim :
      Compatible .completeOpeningEvidence .exactClaimPresentAtMilestone
  | completeLineage :
      Compatible .completeOpeningEvidence .completeLineageVerified
  | transition :
      Compatible .predecessorTransitionEvidence .predecessorAuthorized
  | targetTimestamp :
      Compatible .targetTimestampEvidence .approvalTargetExistedNotAfter
  | archiveTimestamp :
      Compatible .archiveTimestampEvidence .archiveDigestExistedNotAfter

/-- Verified evidence atom arriving at the verifier boundary. -/
structure SRLEvidence where
  kind : SRLEvidenceKind
  lineageId : Nat
  milestoneIndex : Nat
  signatureValid : Bool
  merkleProofValid : Bool
  imprintValid : Bool
  deriving Repr

/-- Verifier evaluation policy. -/
structure SRLPolicy where
  permitted : SRLEvidenceKind → List SRLClaim

/-- The central appraisal derivation: evidence grants claim under policy if and only if
    all cryptographic premises hold and the claim is strictly compatible. -/
def SRLGrant (policy : SRLPolicy) (ev : SRLEvidence) (claim : SRLClaim) : Prop :=
  ev.signatureValid = true ∧
  ev.merkleProofValid = true ∧
  ev.imprintValid = true ∧
  claim ∈ policy.permitted ev.kind ∧
  Compatible ev.kind claim

-- ============================================================================
-- Theorem 1: Terminal Credit Output Non-Derivability (终局功劳类型边界)
-- Note: This is an output-filtering type boundary of the verifier algebra,
-- establishing that the closed deduction rules cannot construct .firstProvedFinalTarget.
-- It does NOT prove human credit or historical priority in the external world.
-- ============================================================================

theorem no_compatible_firstProvedFinalTarget (k : SRLEvidenceKind) :
    ¬ Compatible k .firstProvedFinalTarget := by
  intro h
  cases k <;> cases h

theorem srl_evidence_cannot_grant_terminal_credit
    {policy : SRLPolicy} {ev : SRLEvidence} :
    ¬ SRLGrant policy ev .firstProvedFinalTarget := by
  intro ⟨_, _, _, _, compat⟩
  exact no_compatible_firstProvedFinalTarget ev.kind compat

-- ============================================================================
-- Theorem 2: Independent Prover Plagiarism Non-Accusation (剽窃指控类型边界)
-- Note: This reflects the verifier's inability to output .laterProverPlagiarized.
-- ============================================================================

theorem no_compatible_plagiarism (k : SRLEvidenceKind) :
    ¬ Compatible k .laterProverPlagiarized := by
  intro h
  cases k <;> cases h

theorem srl_evidence_cannot_grant_plagiarism_accusation
    {policy : SRLPolicy} {ev : SRLEvidence} :
    ¬ SRLGrant policy ev .laterProverPlagiarized := by
  intro ⟨_, _, _, _, compat⟩
  exact no_compatible_plagiarism ev.kind compat

-- ============================================================================
-- Theorem 3: Natural Person Authorship Non-Inference (自然人身份不可推导边界)
-- ============================================================================

theorem no_compatible_natural_authorship (k : SRLEvidenceKind) :
    ¬ Compatible k .naturalPersonAuthorship := by
  intro h
  cases k <;> cases h

theorem srl_evidence_cannot_grant_natural_authorship
    {policy : SRLPolicy} {ev : SRLEvidence} :
    ¬ SRLGrant policy ev .naturalPersonAuthorship := by
  intro ⟨_, _, _, _, compat⟩
  exact no_compatible_natural_authorship ev.kind compat

-- ============================================================================
-- Theorem 4: Scope Non-Amplification (作用域非放大定理)
-- Partial opening evidence CANNOT grant complete lineage verification.
-- ============================================================================

theorem partial_opening_cannot_grant_complete_lineage
    {policy : SRLPolicy} {ev : SRLEvidence}
    (h_partial : ev.kind = .partialOpeningEvidence) :
    ¬ SRLGrant policy ev .completeLineageVerified := by
  intro granted
  have compat := granted.2.2.2.2
  rw [h_partial] at compat
  cases compat

-- ============================================================================
-- Theorem 5: No Retroactive Strengthening (防晚期加强回溯边界)
-- Prohibited retroactive claim cannot be derived from any evidence kind.
-- ============================================================================

theorem no_compatible_retroactive (k : SRLEvidenceKind) :
    ¬ Compatible k .retroactiveStrengthenedClaim := by
  intro h
  cases k <;> cases h

theorem srl_evidence_cannot_grant_retroactive_strengthening
    {policy : SRLPolicy} {ev : SRLEvidence} :
    ¬ SRLGrant policy ev .retroactiveStrengthenedClaim := by
  intro ⟨_, _, _, _, compat⟩
  exact no_compatible_retroactive ev.kind compat

-- ============================================================================
-- Theorem 6: Exact Predecessor Authorization Soundness (前驅授權健全性定理)
-- Only predecessorTransitionEvidence can authorize a successor transition.
-- ============================================================================

theorem target_timestamp_evidence_cannot_authorize_successor
    {policy : SRLPolicy} {ev : SRLEvidence}
    (h_ts : ev.kind = .targetTimestampEvidence) :
    ¬ SRLGrant policy ev .predecessorAuthorized := by
  intro granted
  have compat := granted.2.2.2.2
  rw [h_ts] at compat
  cases compat

theorem archive_timestamp_evidence_cannot_authorize_successor
    {policy : SRLPolicy} {ev : SRLEvidence}
    (h_ts : ev.kind = .archiveTimestampEvidence) :
    ¬ SRLGrant policy ev .predecessorAuthorized := by
  intro granted
  have compat := granted.2.2.2.2
  rw [h_ts] at compat
  cases compat

theorem partial_opening_cannot_authorize_successor
    {policy : SRLPolicy} {ev : SRLEvidence}
    (h_partial : ev.kind = .partialOpeningEvidence) :
    ¬ SRLGrant policy ev .predecessorAuthorized := by
  intro granted
  have compat := granted.2.2.2.2
  rw [h_partial] at compat
  cases compat

-- ============================================================================
-- Theorem 7: Strict Chronological Predecessor Ordering (時間單調非倒流定理)
-- ============================================================================

def ChronologicallySound (parent child : Milestone) : Prop :=
  parent.attestedTime.utcSeconds < child.attestedTime.utcSeconds

theorem no_temporal_inversion
    {parent child : Milestone}
    (h_order : ChronologicallySound parent child) :
    ¬ (child.attestedTime.utcSeconds ≤ parent.attestedTime.utcSeconds) := by
  intro h_le
  have h_lt := h_order
  exact Nat.lt_le_asymm h_lt h_le

-- ============================================================================
-- Theorem 8: Archive Timestamp Soundness Boundary (REG-14 归档时间戳不可推导目标存在性定理)
-- An archive timestamp evidence ONLY attests to the archive digest, NOT to the
-- approval target or milestone existence.
-- ============================================================================

theorem no_compatible_archive_target_existence :
    ¬ Compatible .archiveTimestampEvidence .approvalTargetExistedNotAfter := by
  intro h
  cases h

theorem archive_timestamp_cannot_grant_target_existence
    {policy : SRLPolicy} {ev : SRLEvidence}
    (h_archive : ev.kind = .archiveTimestampEvidence) :
    ¬ SRLGrant policy ev .approvalTargetExistedNotAfter := by
  intro granted
  have compat := granted.2.2.2.2
  rw [h_archive] at compat
  exact no_compatible_archive_target_existence compat


-- ============================================================================
-- Part II: Security-Property Projection (v0.3.0 Audit Fixes)
--
-- These theorems use the "projection" approach: we do not formalize the full
-- Python implementation, but instead define a thin abstract layer that captures
-- the essential invariant of each security fix, prove it in Lean, and document
-- the correspondence. The Python side is trusted for everything below this layer
-- (hash computation, Ed25519, DER parsing).
--
-- Correspondence table:
--   Thm 9  ↔ REG-33: public appraise() has no trust-flag parameter
--   Thm 10 ↔ REG-25/S1: governance public-key uniqueness
--   Thm 11 ↔ REG-28/S4: milestone transition sequence integrity
--   Thm 12 ↔ REG-29/S5: chain timestamp monotonicity
--   Thm 13 ↔ REG-36/P1: forged chain rejected by full re-appraisal
-- ============================================================================

-- ============================================================================
-- Theorem 9: Public API Type Separation — No Trust Shortcut (P1/S9)
--
-- The public appraiser can ONLY grant predecessorAuthorized when Compatible
-- evidence exists. It has no "already_verified" flag in its type signature.
--
-- Python correspondence:
--   appraise(proof, trust_pins, query, predecessor_proof)
--   — four parameters, none of which is a trust flag.
--   Passing _predecessor_verified=True raises TypeError.
-- ============================================================================

/-- Abstract model of the public appraisal function:
    takes (evidence, predecessor_evidence) with no trust flag. -/
structure PublicAppraisalInput where
  evidence     : SRLEvidence
  predecessor  : Option SRLEvidence   -- always re-appraised, never "pre-trusted"

/-- The public evaluator grants a claim iff Compatible evidence exists. -/
def publicGrant (input : PublicAppraisalInput) (policy : SRLPolicy)
    (claim : SRLClaim) : Prop :=
  SRLGrant policy input.evidence claim

/-- Theorem 9: predecessorAuthorized requires Compatible evidence; no bypass path. -/
theorem public_api_predecessor_requires_compatible_evidence
    (input : PublicAppraisalInput) (policy : SRLPolicy)
    (h : publicGrant input policy .predecessorAuthorized) :
    Compatible input.evidence.kind .predecessorAuthorized :=
  h.2.2.2.2

/-- Corollary: archive timestamp cannot grant predecessorAuthorized. -/
theorem public_api_archive_cannot_authorize_predecessor
    (input : PublicAppraisalInput) (policy : SRLPolicy)
    (h_kind : input.evidence.kind = .archiveTimestampEvidence)
    (h : publicGrant input policy .predecessorAuthorized) : False := by
  have compat := public_api_predecessor_requires_compatible_evidence input policy h
  rw [h_kind] at compat
  cases compat

-- ============================================================================
-- Theorem 10: Governance Key Uniqueness (S1)
-- ============================================================================

/-- Well-formed governance: slot IDs and canonical key IDs are both pairwise distinct. -/
structure GovernanceWF where
  slots        : List (Nat × Nat)
  threshold    : Nat
  h_pos        : 0 < threshold
  h_cover      : threshold ≤ slots.length
  h_ids_nodup  : (slots.map Prod.fst).Nodup
  h_keys_nodup : (slots.map Prod.snd).Nodup   -- S1: unique canonical public key

theorem governance_wf_keys_unique (g : GovernanceWF) :
    (g.slots.map Prod.snd).Nodup :=
  g.h_keys_nodup

/-- Duplicate key in two slots always violates Nodup. -/
theorem duplicate_key_not_wf (slotA slotB : Nat) (k : Nat) :
    ¬ ([(slotA, k), (slotB, k)].map Prod.snd).Nodup := by
  simp [List.Nodup]

-- ============================================================================
-- Theorem 11: Milestone Transition Sequence Integrity (S4)
-- ============================================================================

structure MilestoneIdx where
  val   : Nat
  h_pos : 0 < val
  deriving Repr

/-- Transition carries a type-level proof that successor = predecessor + 1. -/
structure LineageTransitionWF where
  predIdx    : MilestoneIdx
  succIdx    : MilestoneIdx
  h_seq      : succIdx.val = predIdx.val + 1
  predDigest : Nat
  succDigest : Nat

theorem transition_wf_seq (t : LineageTransitionWF) :
    t.succIdx.val = t.predIdx.val + 1 :=
  t.h_seq

theorem transition_no_skip (t : LineageTransitionWF)
    (h_skip : t.succIdx.val ≥ t.predIdx.val + 2) : False := by
  have := t.h_seq; omega

-- ============================================================================
-- Theorem 12: Chain Timestamp Monotonicity (S5 / R3)
-- ============================================================================

def TimestampsMonotone (ts : List Nat) : Prop :=
  ts.Pairwise (· ≤ ·)

/-- Backward time is non-monotone. -/
theorem backward_timestamp_not_monotone (t_prev t_curr : Nat)
    (h_back : t_curr < t_prev) :
    ¬ TimestampsMonotone [t_prev, t_curr] := by
  simp [TimestampsMonotone, List.pairwise_cons, List.mem_cons]
  omega

/-- Appending a non-decreasing timestamp preserves monotonicity. -/
theorem timestamps_monotone_snoc (ts : List Nat) (t_new : Nat)
    (h_mono : TimestampsMonotone ts)
    (h_last : ∀ t_old ∈ ts, t_old ≤ t_new) :
    TimestampsMonotone (ts ++ [t_new]) := by
  unfold TimestampsMonotone at *
  induction ts with
  | nil => simp
  | cons hd tl ih =>
      rw [List.pairwise_cons] at h_mono
      apply List.Pairwise.cons
      · intro x hx
        simp [List.mem_append] at hx
        rcases hx with hx_tl | rfl
        · exact h_mono.1 x hx_tl
        · exact h_last hd (List.mem_cons.mpr (Or.inl rfl))
      · exact ih h_mono.2 (fun t ht => h_last t (List.mem_cons_of_mem _ ht))

theorem timestamps_monotone_singleton (t : Nat) :
    TimestampsMonotone [t] :=
  List.pairwise_singleton _ _

-- ============================================================================
-- Theorem 13: Forged-Chain Rejection via Full Re-Appraisal (P1/S9)
-- ============================================================================

/-- A chain where every link is independently validated (no pre-trust).
    Semantic boundary (F2): this is a PARALLEL ABSTRACT MODEL, not a faithful
    abstraction of appraise_lineage_chain. Specifically, the cons branch requires
    Compatible .predecessorAuthorized for every non-head element — this is stronger
    than the Python verifier, which also permits opening evidence in intermediate slots.
    The theorem captures the "no shortcut" invariant (P1/S9) but is not a complete
    refinement of the Python chain semantics. -/
def ChainGranted (policy : SRLPolicy) : List SRLEvidence → Prop
  | []         => True
  | [ev]       => ev.signatureValid = true ∧ ev.merkleProofValid = true ∧ ev.imprintValid = true
  | ev :: rest =>
      ev.signatureValid = true ∧ ev.merkleProofValid = true ∧ ev.imprintValid = true ∧
      (∀ ev_succ ∈ rest, Compatible ev_succ.kind .predecessorAuthorized) ∧
      ChainGranted policy rest

/-- Every link in a ChainGranted list has a valid signature. -/
theorem chain_granted_every_link_sig_valid
    (policy : SRLPolicy) (chain : List SRLEvidence)
    (h : ChainGranted policy chain) :
    ∀ ev ∈ chain, ev.signatureValid = true := by
  induction chain with
  | nil =>
      intro ev hev; simp at hev
  | cons hd tl ih =>
      intro ev hev
      rw [List.mem_cons] at hev
      rcases hev with rfl | hev_tl
      · match tl with
        | []     => exact h.1
        | _ :: _ => exact h.1
      · match tl, h with
        | [],     _                   => simp at hev_tl
        | _ :: _, ⟨_, _, _, _, h_tl⟩ => exact ih h_tl ev hev_tl

/-- A chain with any invalid-signature link cannot be ChainGranted. -/
theorem invalid_sig_breaks_chain
    (policy : SRLPolicy) (ev : SRLEvidence) (chain : List SRLEvidence)
    (h_invalid : ev.signatureValid = false)
    (h_mem : ev ∈ chain) :
    ¬ ChainGranted policy chain := by
  intro h_granted
  have := chain_granted_every_link_sig_valid policy chain h_granted ev h_mem
  rw [h_invalid] at this; exact absurd this (by decide)

end SRL
