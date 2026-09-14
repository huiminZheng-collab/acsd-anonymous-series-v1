import ACSD.PEC

set_option autoImplicit false
set_option warningAsError true

namespace ACSD

/-! A small common skeleton for authenticated, scope-limited statements.
Event disclosure, identity disclosure, and time evidence share authorization
and non-amplification rules without pretending that their predicates are the
same. Cryptographic validity remains an executable-boundary input. -/

inductive EvidenceKind where
  | unanimousApproval
  | eventDisclosure
  | identityDisclosure
  | approvalTargetTimestamp
  | approvalSetTimestamp
  | scittInclusion
  | lineageAuthorization
  deriving DecidableEq, Repr

inductive ScopedClaim where
  | keyAssent
  | governanceAssent
  | committedEvidenceMatch
  | slotKeyIdentityAssent
  | approvalTargetExistedNotAfter
  | approvalSetExistedNotAfter
  | statementRegistered
  | authorizedSuccessor
  | naturalPersonIdentityVerified
  | originalityVerified
  | signersUncompromisedAtTime
  deriving DecidableEq, Repr

inductive Compatible : EvidenceKind → ScopedClaim → Prop where
  | keyApproval : Compatible .unanimousApproval .keyAssent
  | governanceApproval : Compatible .unanimousApproval .governanceAssent
  | event : Compatible .eventDisclosure .committedEvidenceMatch
  | identity : Compatible .identityDisclosure .slotKeyIdentityAssent
  | targetTime : Compatible .approvalTargetTimestamp .approvalTargetExistedNotAfter
  | approvalTime : Compatible .approvalSetTimestamp .approvalSetExistedNotAfter
  | registration : Compatible .scittInclusion .statementRegistered
  | lineage : Compatible .lineageAuthorization .authorizedSuccessor

structure ScopedEvidence where
  kind : EvidenceKind
  subject : Digest
  signer : KeyId
  signatureValid : Bool
  scopeValid : Bool
  deriving Repr

structure ScopedPolicy where
  authorized : EvidenceKind → Digest → KeyId → Prop
  permitted : EvidenceKind → List ScopedClaim

def ScopedGrant
    (policy : ScopedPolicy) (evidence : ScopedEvidence)
    (claim : ScopedClaim) : Prop :=
  evidence.signatureValid = true ∧
  evidence.scopeValid = true ∧
  policy.authorized evidence.kind evidence.subject evidence.signer ∧
  claim ∈ policy.permitted evidence.kind ∧
  Compatible evidence.kind claim

theorem scoped_grant_requires_signature
    {policy : ScopedPolicy} {evidence : ScopedEvidence} {claim : ScopedClaim}
    (granted : ScopedGrant policy evidence claim) :
    evidence.signatureValid = true := granted.1

theorem scoped_grant_requires_exact_scope
    {policy : ScopedPolicy} {evidence : ScopedEvidence} {claim : ScopedClaim}
    (granted : ScopedGrant policy evidence claim) :
    evidence.scopeValid = true := granted.2.1

theorem scoped_grant_requires_authorized_signer
    {policy : ScopedPolicy} {evidence : ScopedEvidence} {claim : ScopedClaim}
    (granted : ScopedGrant policy evidence claim) :
    policy.authorized evidence.kind evidence.subject evidence.signer :=
  granted.2.2.1

theorem scoped_grant_cannot_amplify_policy
    {policy : ScopedPolicy} {evidence : ScopedEvidence} {claim : ScopedClaim}
    (granted : ScopedGrant policy evidence claim) :
    claim ∈ policy.permitted evidence.kind := granted.2.2.2.1

theorem identity_evidence_cannot_grant_event_match
    {policy : ScopedPolicy} {evidence : ScopedEvidence}
    (identityKind : evidence.kind = .identityDisclosure) :
    ¬ ScopedGrant policy evidence .committedEvidenceMatch := by
  intro granted
  have compatible := granted.2.2.2.2
  rw [identityKind] at compatible
  cases compatible

theorem event_evidence_cannot_grant_identity_assent
    {policy : ScopedPolicy} {evidence : ScopedEvidence}
    (eventKind : evidence.kind = .eventDisclosure) :
    ¬ ScopedGrant policy evidence .slotKeyIdentityAssent := by
  intro granted
  have compatible := granted.2.2.2.2
  rw [eventKind] at compatible
  cases compatible

/-! Atomic event disclosure: all four predicates are required by the one
acceptance relation, so a valid Merkle opening cannot be detached from policy
or signer authorization. -/

structure EventDisclosureEvidence where
  pecScopeMatches : Bool
  policyAllowsMode : Bool
  openingMatchesCommitment : Bool
  allRequiredSignaturesValid : Bool
  deriving Repr

def EventDisclosureAccepted (evidence : EventDisclosureEvidence) : Prop :=
  evidence.pecScopeMatches = true ∧
  evidence.policyAllowsMode = true ∧
  evidence.openingMatchesCommitment = true ∧
  evidence.allRequiredSignaturesValid = true

theorem event_acceptance_requires_policy
    {evidence : EventDisclosureEvidence}
    (accepted : EventDisclosureAccepted evidence) :
    evidence.policyAllowsMode = true := accepted.2.1

theorem event_acceptance_requires_opening
    {evidence : EventDisclosureEvidence}
    (accepted : EventDisclosureAccepted evidence) :
    evidence.openingMatchesCommitment = true := accepted.2.2.1

theorem event_acceptance_requires_all_signatures
    {evidence : EventDisclosureEvidence}
    (accepted : EventDisclosureAccepted evidence) :
    evidence.allRequiredSignaturesValid = true := accepted.2.2.2

/-! Per-slot identity assent. Full-byline status is quantified over all slots;
one revealed author therefore cannot be silently promoted to a full reveal. -/

structure SlotIdentityEvidence where
  releaseDigest : Digest
  slot : Nat
  key : KeyId
  signatureValid : Bool
  slotKeyMatches : Bool
  deriving Repr

def SlotIdentityAssent
    (releaseDigest : Digest) (slot : Nat)
    (evidence : SlotIdentityEvidence) : Prop :=
  evidence.releaseDigest = releaseDigest ∧
  evidence.slot = slot ∧
  evidence.signatureValid = true ∧
  evidence.slotKeyMatches = true

def FullBylineAssent
    (releaseDigest : Digest) (requiredSlots : List Nat)
    (evidence : List SlotIdentityEvidence) : Prop :=
  ∀ slot, slot ∈ requiredSlots →
    ∃ item, item ∈ evidence ∧ SlotIdentityAssent releaseDigest slot item

theorem slot_assent_requires_exact_release
    {releaseDigest : Digest} {slot : Nat} {evidence : SlotIdentityEvidence}
    (assent : SlotIdentityAssent releaseDigest slot evidence) :
    evidence.releaseDigest = releaseDigest := assent.1

theorem missing_slot_prevents_full_byline
    {releaseDigest : Digest} {requiredSlots : List Nat}
    {evidence : List SlotIdentityEvidence} {missing : Nat}
    (required : missing ∈ requiredSlots)
    (absent : ∀ item, item ∈ evidence → item.slot ≠ missing) :
    ¬ FullBylineAssent releaseDigest requiredSlots evidence := by
  intro full
  obtain ⟨item, member, assent⟩ := full missing required
  exact absent item member assent.2.1

/-! Typed timestamp subjects prevent an old timestamp over an unsigned target
from being interpreted as evidence that the completed approval set existed. -/

abbrev TypedTimeEvidence := TimeEvidence

def ApprovalSetTimeValid (evidence : TypedTimeEvidence) : Prop :=
  evidence.subjectKind = .approvalSet ∧
  ExternalTimeValid evidence

theorem approval_set_time_requires_closed_subject
    {evidence : TypedTimeEvidence}
    (valid : ApprovalSetTimeValid evidence) :
    evidence.subjectKind = .approvalSet := valid.1

theorem target_timestamp_cannot_be_approval_set_time
    {evidence : TypedTimeEvidence}
    (targetOnly : evidence.subjectKind = .approvalTarget) :
    ¬ ApprovalSetTimeValid evidence := by
  intro valid
  have closed : evidence.subjectKind = .approvalSet := valid.1
  rw [targetOnly] at closed
  exact TimeSubjectKind.noConfusion closed

/-! Evidence-set derivation.  Composition is union-only: a claim derived from
two evidence sets already has a supporting atom in one of them.  There is no
implicit rule that synthesizes human identity, originality, or signer health. -/

structure EvidenceAtom where
  kind : EvidenceKind
  subject : Digest
  verified : Bool
  deriving Repr

structure ClaimRequest where
  kind : ScopedClaim
  subject : Digest
  deriving Repr

structure DerivationPolicy where
  permittedClaims : List ScopedClaim

def Derives
    (policy : DerivationPolicy) (evidence : EvidenceAtom → Prop)
    (request : ClaimRequest) : Prop :=
  request.kind ∈ policy.permittedClaims ∧
  ∃ item, evidence item ∧
    item.verified = true ∧ item.subject = request.subject ∧
    Compatible item.kind request.kind

theorem derives_requires_permitted
    {policy : DerivationPolicy} {evidence : EvidenceAtom → Prop}
    {request : ClaimRequest} (h : Derives policy evidence request) :
    request.kind ∈ policy.permittedClaims := h.1

theorem derives_requires_matching_verified_atom
    {policy : DerivationPolicy} {evidence : EvidenceAtom → Prop}
    {request : ClaimRequest} (h : Derives policy evidence request) :
    ∃ item, evidence item ∧ item.verified = true ∧
      item.subject = request.subject ∧ Compatible item.kind request.kind := h.2

theorem derivation_over_union_has_component_support
    {policy : DerivationPolicy} {left right : EvidenceAtom → Prop}
    {request : ClaimRequest}
    (h : Derives policy (fun item => left item ∨ right item) request) :
    Derives policy left request ∨ Derives policy right request := by
  rcases h with ⟨permitted, item, member, verified, subject, compatible⟩
  rcases member with inLeft | inRight
  · exact Or.inl ⟨permitted, item, inLeft, verified, subject, compatible⟩
  · exact Or.inr ⟨permitted, item, inRight, verified, subject, compatible⟩

theorem target_timestamp_cannot_derive_approval_set_time
    {policy : DerivationPolicy} {item : EvidenceAtom} {subject : Digest}
    (targetOnly : item.kind = .approvalTargetTimestamp) :
    ¬ Derives policy (fun witness => witness = item) {
      kind := .approvalSetExistedNotAfter, subject := subject
    } := by
  intro h
  rcases h.2 with ⟨witness, member, _verified, _subject, compatible⟩
  subst witness
  rw [targetOnly] at compatible
  cases compatible

end ACSD
