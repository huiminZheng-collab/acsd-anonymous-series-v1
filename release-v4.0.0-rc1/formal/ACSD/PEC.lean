import ACSD.Core

set_option autoImplicit false
set_option warningAsError true

namespace ACSD

structure KeyId where
  value : Nat
  deriving DecidableEq, Repr

/-- Closed verifier-result vocabulary. Social assertions are deliberately not
constructors of this type. -/
inductive Outcome where
  | keyAssent
  | governanceAssent
  | committedEvidenceMatch
  | externallyNotAfter
  | approvalSetExistedNotAfter
  deriving DecidableEq, Repr

inductive NonClaim where
  | naturalPersonAuthorship
  | contributionTruth
  | originalityTruth
  | legalNonrepudiation
  | peerReview
  deriving DecidableEq, Repr

def requiredNonClaims : List NonClaim := [
  .naturalPersonAuthorship, .contributionTruth, .originalityTruth,
  .legalNonrepudiation, .peerReview
]

/-- Compact object jointly signed by every required author key. -/
structure ApprovalTarget where
  digest : Digest
  releaseDigest : Digest
  governanceDigest : Digest
  pecDigest : Digest
  requiredKeys : List KeyId
  deriving Repr

/-- Signature validity is an input established by the executable verifier. -/
structure Approval where
  key : KeyId
  targetDigest : Digest
  signatureValid : Bool
  deriving Repr

def ApprovalValid (target : ApprovalTarget) (approval : Approval) : Prop :=
  approval.targetDigest = target.digest ∧ approval.signatureValid = true

def AllApproved (target : ApprovalTarget) (approvals : List Approval) : Prop :=
  ∀ k, k ∈ target.requiredKeys →
    ∃ approval, approval ∈ approvals ∧ approval.key = k ∧ ApprovalValid target approval

/-- The link contains the digest of the exact preceding event, not merely its
display identifier. -/
structure Event where
  sequence : Nat
  eventId : String
  eventDigest : Digest
  previousEventDigest : Option Digest
  deriving Repr

def ChainLink : List Event → Event → Prop
  | [], _ => True
  | e :: rest, prev =>
      e.sequence = prev.sequence + 1 ∧
      e.previousEventDigest = some prev.eventDigest ∧
      ChainLink rest e

def ChainValid : List Event → Prop
  | [] => True
  | e0 :: rest =>
      e0.sequence = 0 ∧ e0.previousEventDigest = none ∧ ChainLink rest e0

def SequenceChain : List Event → Prop
  | [] => True
  | [_] => True
  | a :: b :: rest => a.sequence + 1 = b.sequence ∧ SequenceChain (b :: rest)

structure ClaimPolicy where
  permittedOutcomes : List Outcome
  globalNonClaims : List NonClaim

def CompleteNonClaims (policy : ClaimPolicy) : Prop :=
  ∀ claim, claim ∈ requiredNonClaims → claim ∈ policy.globalNonClaims

inductive TimeSubjectKind where
  | approvalTarget
  | approvalSet
  deriving DecidableEq, Repr

/-- Fields established by the RFC 3161 adapter are kept separate so one
"timestamp valid" bit cannot hide a missing trust decision. -/
structure TimeEvidence where
  subjectKind : TimeSubjectKind
  exactSubject : Bool
  trustedSignerPin : Bool
  nonceMatches : Bool
  profileValid : Bool
  isLocalTest : Bool

def ExternalTimeValid (evidence : TimeEvidence) : Prop :=
  evidence.exactSubject = true ∧
  evidence.trustedSignerPin = true ∧
  evidence.nonceMatches = true ∧
  evidence.profileValid = true ∧
  evidence.isLocalTest = false

structure PEC where
  target : ApprovalTarget
  approvals : List Approval
  events : List Event
  policy : ClaimPolicy
  targetBindingsValid : Bool
  committedEvidenceValid : Bool
  timeEvidence : TimeEvidence

def Accepted (pec : PEC) : Prop :=
  AllApproved pec.target pec.approvals ∧
  ChainValid pec.events ∧
  CompleteNonClaims pec.policy ∧
  pec.targetBindingsValid = true

def CapabilityEstablished (pec : PEC) : Outcome → Prop
  | .keyAssent => True
  | .governanceAssent => pec.targetBindingsValid = true
  | .committedEvidenceMatch => pec.committedEvidenceValid = true
  | .externallyNotAfter =>
      pec.timeEvidence.subjectKind = .approvalTarget ∧ ExternalTimeValid pec.timeEvidence
  | .approvalSetExistedNotAfter =>
      pec.timeEvidence.subjectKind = .approvalSet ∧ ExternalTimeValid pec.timeEvidence

/-- Permission is only an upper bound; granting also requires acceptance and
a separately established capability. -/
def Granted (pec : PEC) (outcome : Outcome) : Prop :=
  Accepted pec ∧ outcome ∈ pec.policy.permittedOutcomes ∧
  CapabilityEstablished pec outcome

theorem chain_link_sequence_increments {e prev : Event} {rest : List Event}
    (h : ChainLink (e :: rest) prev) : e.sequence = prev.sequence + 1 := h.1

theorem chain_link_previous_links {e prev : Event} {rest : List Event}
    (h : ChainLink (e :: rest) prev) :
    e.previousEventDigest = some prev.eventDigest := h.2.1

theorem chain_link_sequence_chain {prev : Event} {events : List Event}
    (h : ChainLink events prev) : SequenceChain (prev :: events) := by
  induction events generalizing prev with
  | nil => trivial
  | cons e rest ih =>
      cases rest with
      | nil =>
          unfold SequenceChain
          exact And.intro h.1.symm trivial
      | cons e2 rest2 =>
          have hrest : ChainLink (e2 :: rest2) e := h.2.2
          have hind : SequenceChain (e :: e2 :: rest2) := ih hrest
          change (prev.sequence + 1 = e.sequence) ∧ SequenceChain (e :: e2 :: rest2)
          exact And.intro h.1.symm hind

theorem chain_valid_sequence_chain {e0 : Event} {rest : List Event}
    (h : ChainValid (e0 :: rest)) : SequenceChain (e0 :: rest) :=
  chain_link_sequence_chain h.2.2

/-- A valid signature for one target digest cannot be reused for a distinct
target digest. Collision resistance and signature verification remain explicit
assumptions of the executable boundary. -/
theorem approval_not_reusable {approval : Approval}
    {oldTarget newTarget : ApprovalTarget}
    (hvalid : ApprovalValid oldTarget approval)
    (hdifferent : oldTarget.digest ≠ newTarget.digest) :
    ¬ ApprovalValid newTarget approval := by
  intro hnew
  apply hdifferent
  exact hvalid.1.symm.trans hnew.1

theorem accepted_implies_all_approved {pec : PEC} (h : Accepted pec) :
    AllApproved pec.target pec.approvals := h.1

theorem granted_implies_accepted {pec : PEC} {outcome : Outcome}
    (h : Granted pec outcome) : Accepted pec := h.1

theorem granted_implies_permitted {pec : PEC} {outcome : Outcome}
    (h : Granted pec outcome) : outcome ∈ pec.policy.permittedOutcomes := h.2.1

theorem key_assent_requires_all_approvals {pec : PEC}
    (h : Granted pec .keyAssent) : AllApproved pec.target pec.approvals := h.1.1

theorem governance_assent_requires_bound_target {pec : PEC}
    (h : Granted pec .governanceAssent) : pec.targetBindingsValid = true := h.2.2

theorem external_time_requires_exact_subject {pec : PEC}
    (h : Granted pec .externallyNotAfter) : pec.timeEvidence.exactSubject = true := h.2.2.2.1

theorem external_time_requires_signer_pin {pec : PEC}
    (h : Granted pec .externallyNotAfter) : pec.timeEvidence.trustedSignerPin = true := h.2.2.2.2.1

theorem external_time_requires_nonce {pec : PEC}
    (h : Granted pec .externallyNotAfter) : pec.timeEvidence.nonceMatches = true := h.2.2.2.2.2.1

theorem external_time_requires_profile {pec : PEC}
    (h : Granted pec .externallyNotAfter) : pec.timeEvidence.profileValid = true := h.2.2.2.2.2.2.1

theorem external_time_is_not_local_test {pec : PEC}
    (h : Granted pec .externallyNotAfter) : pec.timeEvidence.isLocalTest = false := h.2.2.2.2.2.2.2

theorem approval_set_time_requires_set_subject {pec : PEC}
    (h : Granted pec .approvalSetExistedNotAfter) :
    pec.timeEvidence.subjectKind = .approvalSet := h.2.2.1

theorem local_test_never_grants_external_time {pec : PEC}
    (hlocal : pec.timeEvidence.isLocalTest = true) :
    ¬ Granted pec .externallyNotAfter := by
  intro h
  have hfalse : pec.timeEvidence.isLocalTest = false := external_time_is_not_local_test h
  rw [hlocal] at hfalse
  exact Bool.noConfusion hfalse

end ACSD
