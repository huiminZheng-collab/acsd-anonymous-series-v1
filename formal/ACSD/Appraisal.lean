import ACSD.ScopedClaims

set_option autoImplicit false
set_option warningAsError true

namespace ACSD

/-! Parameterized subjects for the pure appraisal boundary.  Unlike the
earlier enum-only skeleton, exact event windows, author slots, assertion
digests, and timestamp subjects are part of the claim itself. -/

inductive ScopedSubject where
  | approvalTarget (target : Digest)
  | approvalSet (set : Digest)
  | eventWindow (pec : Digest) (eventId : String) (eventSequence : Nat)
      (commitment : Digest) (firstIndex lastIndex : Nat)
  | identityAssertion (release : Digest) (slot : Nat) (key : KeyId)
      (assertion : Digest)
  | registeredStatement (statement : Digest)
  deriving DecidableEq, Repr

structure AppraisedAtom where
  kind : EvidenceKind
  subject : ScopedSubject
  certificateDigest : Digest
  deriving DecidableEq, Repr

structure AppraisalRequest where
  kind : ScopedClaim
  subject : ScopedSubject
  deriving DecidableEq, Repr

structure AppraisalPolicy where
  permittedClaims : List ScopedClaim
  deriving Repr

/-! The declarative rule relation is separate from the executable Boolean
table below. -/
inductive AppraisalRule : EvidenceKind → ScopedClaim → Prop where
  | keyApproval : AppraisalRule .unanimousApproval .keyAssent
  | governanceApproval : AppraisalRule .unanimousApproval .governanceAssent
  | event : AppraisalRule .eventDisclosure .committedEvidenceMatch
  | identity : AppraisalRule .identityDisclosure .slotKeyIdentityAssent
  | targetTime : AppraisalRule .approvalTargetTimestamp .approvalTargetExistedNotAfter
  | approvalTime : AppraisalRule .approvalSetTimestamp .approvalSetExistedNotAfter
  | registration : AppraisalRule .scittInclusion .statementRegistered

def compatibleB : EvidenceKind → ScopedClaim → Bool
  | .unanimousApproval, .keyAssent => true
  | .unanimousApproval, .governanceAssent => true
  | .eventDisclosure, .committedEvidenceMatch => true
  | .identityDisclosure, .slotKeyIdentityAssent => true
  | .approvalTargetTimestamp, .approvalTargetExistedNotAfter => true
  | .approvalSetTimestamp, .approvalSetExistedNotAfter => true
  | .scittInclusion, .statementRegistered => true
  | _, _ => false

def evidenceSubjectB : EvidenceKind → ScopedSubject → Bool
  | .unanimousApproval, .approvalTarget _ => true
  | .approvalTargetTimestamp, .approvalTarget _ => true
  | .approvalSetTimestamp, .approvalSet _ => true
  | .eventDisclosure, .eventWindow _ _ _ _ first last => decide (first ≤ last)
  | .identityDisclosure, .identityAssertion _ _ _ _ => true
  | .scittInclusion, .registeredStatement _ => true
  | _, _ => false

def claimSubjectB : ScopedClaim → ScopedSubject → Bool
  | .keyAssent, .approvalTarget _ => true
  | .governanceAssent, .approvalTarget _ => true
  | .committedEvidenceMatch, .eventWindow _ _ _ _ first last => decide (first ≤ last)
  | .slotKeyIdentityAssent, .identityAssertion _ _ _ _ => true
  | .approvalTargetExistedNotAfter, .approvalTarget _ => true
  | .approvalSetExistedNotAfter, .approvalSet _ => true
  | .statementRegistered, .registeredStatement _ => true
  | .naturalPersonIdentityVerified, .identityAssertion _ _ _ _ => true
  | .originalityVerified, .approvalTarget _ => true
  | .signersUncompromisedAtTime, .approvalSet _ => true
  | _, _ => false

theorem compatibleB_of_rule
    {kind : EvidenceKind} {claim : ScopedClaim}
    (rule : AppraisalRule kind claim) : compatibleB kind claim = true := by
  cases rule <;> rfl

theorem rule_of_compatibleB
    {kind : EvidenceKind} {claim : ScopedClaim}
    (compatible : compatibleB kind claim = true) :
    AppraisalRule kind claim := by
  cases kind <;> cases claim <;> simp [compatibleB] at compatible
  all_goals constructor

theorem compatibleB_iff_rule (kind : EvidenceKind) (claim : ScopedClaim) :
    compatibleB kind claim = true ↔ AppraisalRule kind claim :=
  ⟨rule_of_compatibleB, compatibleB_of_rule⟩

/-! `Checkable` is the finite executable condition. `Derives` is the
independent declarative meaning. Their only bridge is the proved correspondence
between the Boolean table and `AppraisalRule`. -/
def AppraisalCheckable
    (policy : AppraisalPolicy) (evidence : List AppraisedAtom)
    (request : AppraisalRequest) : Prop :=
  request.kind ∈ policy.permittedClaims ∧
  claimSubjectB request.kind request.subject = true ∧
  ∃ item, item ∈ evidence ∧
    evidenceSubjectB item.kind item.subject = true ∧
    item.subject = request.subject ∧ compatibleB item.kind request.kind = true

def AppraisalDerives
    (policy : AppraisalPolicy) (evidence : List AppraisedAtom)
    (request : AppraisalRequest) : Prop :=
  request.kind ∈ policy.permittedClaims ∧
  claimSubjectB request.kind request.subject = true ∧
  ∃ item, item ∈ evidence ∧
    evidenceSubjectB item.kind item.subject = true ∧
    item.subject = request.subject ∧ AppraisalRule item.kind request.kind

def checkClaim
    (policy : AppraisalPolicy) (evidence : List AppraisedAtom)
    (request : AppraisalRequest) : Bool :=
  policy.permittedClaims.contains request.kind &&
  claimSubjectB request.kind request.subject &&
  evidence.any fun item =>
    evidenceSubjectB item.kind item.subject &&
    decide (item.subject = request.subject) &&
    compatibleB item.kind request.kind

theorem checkClaim_iff_checkable
    {policy : AppraisalPolicy} {evidence : List AppraisedAtom}
    {request : AppraisalRequest} :
    checkClaim policy evidence request = true ↔
      AppraisalCheckable policy evidence request := by
  simp [checkClaim, AppraisalCheckable, and_assoc]

theorem checkable_iff_derives
    {policy : AppraisalPolicy} {evidence : List AppraisedAtom}
    {request : AppraisalRequest} :
    AppraisalCheckable policy evidence request ↔
      AppraisalDerives policy evidence request := by
  constructor
  · rintro ⟨permitted, scopeOk, item, member, itemScoped, exactSubject, compatible⟩
    exact ⟨permitted, scopeOk, item, member, itemScoped, exactSubject,
      (compatibleB_iff_rule item.kind request.kind).mp compatible⟩
  · rintro ⟨permitted, scopeOk, item, member, itemScoped, exactSubject, rule⟩
    exact ⟨permitted, scopeOk, item, member, itemScoped, exactSubject,
      (compatibleB_iff_rule item.kind request.kind).mpr rule⟩

theorem checkClaim_sound
    {policy : AppraisalPolicy} {evidence : List AppraisedAtom}
    {request : AppraisalRequest}
    (accepted : checkClaim policy evidence request = true) :
    AppraisalDerives policy evidence request := by
  have checkable : AppraisalCheckable policy evidence request :=
    checkClaim_iff_checkable.mp accepted
  exact checkable_iff_derives.mp checkable

theorem checkClaim_complete
    {policy : AppraisalPolicy} {evidence : List AppraisedAtom}
    {request : AppraisalRequest}
    (derived : AppraisalDerives policy evidence request) :
    checkClaim policy evidence request = true := by
  exact checkClaim_iff_checkable.mpr (checkable_iff_derives.mpr derived)

theorem derives_has_exact_support
    {policy : AppraisalPolicy} {evidence : List AppraisedAtom}
    {request : AppraisalRequest}
    (derived : AppraisalDerives policy evidence request) :
    ∃ item, item ∈ evidence ∧ item.subject = request.subject ∧
      AppraisalRule item.kind request.kind := by
  rcases derived with ⟨_, _, item, member, _, exactSubject, rule⟩
  exact ⟨item, member, exactSubject, rule⟩

theorem derivation_over_append_has_component_support
    {policy : AppraisalPolicy} {left right : List AppraisedAtom}
    {request : AppraisalRequest}
    (derived : AppraisalDerives policy (left ++ right) request) :
    AppraisalDerives policy left request ∨
      AppraisalDerives policy right request := by
  rcases derived with ⟨permitted, scopeOk, item, member, itemScoped, exactSubject, rule⟩
  rw [List.mem_append] at member
  rcases member with inLeft | inRight
  · exact Or.inl ⟨permitted, scopeOk, item, inLeft, itemScoped, exactSubject, rule⟩
  · exact Or.inr ⟨permitted, scopeOk, item, inRight, itemScoped, exactSubject, rule⟩

theorem target_time_cannot_derive_approval_set_time
    {policy : AppraisalPolicy} {item : AppraisedAtom}
    {setDigest : Digest}
    (targetKind : item.kind = .approvalTargetTimestamp) :
    ¬ AppraisalDerives policy [item] {
      kind := .approvalSetExistedNotAfter,
      subject := .approvalSet setDigest
    } := by
  intro derived
  rcases derives_has_exact_support derived with ⟨witness, member, _, rule⟩
  simp only [List.mem_singleton] at member
  subst witness
  have impossible := compatibleB_of_rule rule
  rw [targetKind] at impossible
  simp [compatibleB] at impossible

theorem unsupported_natural_identity_has_no_rule
    {policy : AppraisalPolicy} {evidence : List AppraisedAtom}
    {subject : ScopedSubject} :
    ¬ AppraisalDerives policy evidence {
      kind := .naturalPersonIdentityVerified,
      subject := subject
    } := by
  intro derived
  rcases derives_has_exact_support derived with ⟨item, _, _, rule⟩
  have impossible := compatibleB_of_rule rule
  cases item.kind <;> simp [compatibleB] at impossible

end ACSD
