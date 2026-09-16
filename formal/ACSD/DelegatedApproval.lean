import ACSD.PEC

set_option autoImplicit false
set_option warningAsError true

namespace ACSD

/-! An exact-target delegation is intentionally a single-purpose capability.
It does not model signatures internally: certificate and delegate-signature
validity are appraised inputs supplied by the executable cryptographic adapter. -/

inductive DelegatedAction where
  | approveExactTarget
  | authorizeLineage
  | discloseIdentity
  | redelegate
  deriving DecidableEq, Repr

structure ExactApprovalDelegation where
  authorKey : KeyId
  delegateKey : KeyId
  target : Digest
  nonRedelegable : Bool
  deriving Repr

structure DelegatedApprovalEvidence where
  claimedAuthor : KeyId
  signer : KeyId
  target : Digest
  authorCertificateValid : Bool
  delegateSignatureValid : Bool
  deriving Repr

def DelegatedApprovalAccepted
    (delegation : ExactApprovalDelegation)
    (evidence : DelegatedApprovalEvidence) : Prop :=
  evidence.authorCertificateValid = true ∧
  evidence.delegateSignatureValid = true ∧
  delegation.authorKey = evidence.claimedAuthor ∧
  delegation.delegateKey = evidence.signer ∧
  delegation.target = evidence.target ∧
  delegation.nonRedelegable = true

def DelegationPermits
    (delegation : ExactApprovalDelegation)
    (action : DelegatedAction) (target : Digest) : Prop :=
  action = .approveExactTarget ∧
  target = delegation.target ∧
  delegation.nonRedelegable = true

theorem delegated_approval_requires_author_certificate
    {delegation : ExactApprovalDelegation}
    {evidence : DelegatedApprovalEvidence}
    (accepted : DelegatedApprovalAccepted delegation evidence) :
    evidence.authorCertificateValid = true := accepted.1

theorem delegated_approval_requires_delegate_signature
    {delegation : ExactApprovalDelegation}
    {evidence : DelegatedApprovalEvidence}
    (accepted : DelegatedApprovalAccepted delegation evidence) :
    evidence.delegateSignatureValid = true := accepted.2.1

theorem delegated_approval_binds_author_signer_and_target
    {delegation : ExactApprovalDelegation}
    {evidence : DelegatedApprovalEvidence}
    (accepted : DelegatedApprovalAccepted delegation evidence) :
    delegation.authorKey = evidence.claimedAuthor ∧
    delegation.delegateKey = evidence.signer ∧
    delegation.target = evidence.target :=
  ⟨accepted.2.2.1, accepted.2.2.2.1, accepted.2.2.2.2.1⟩

theorem exact_delegation_not_reusable_for_other_target
    {delegation : ExactApprovalDelegation}
    {evidence : DelegatedApprovalEvidence}
    (_accepted : DelegatedApprovalAccepted delegation evidence)
    {otherTarget : Digest} (different : otherTarget ≠ delegation.target) :
    ¬ DelegationPermits delegation .approveExactTarget otherTarget := by
  intro permitted
  exact different permitted.2.1

theorem approval_delegation_cannot_authorize_lineage
    {delegation : ExactApprovalDelegation} {target : Digest} :
    ¬ DelegationPermits delegation .authorizeLineage target := by
  intro permitted
  cases permitted.1

theorem approval_delegation_cannot_disclose_identity
    {delegation : ExactApprovalDelegation} {target : Digest} :
    ¬ DelegationPermits delegation .discloseIdentity target := by
  intro permitted
  cases permitted.1

theorem approval_delegation_cannot_redelegate
    {delegation : ExactApprovalDelegation} {target : Digest} :
    ¬ DelegationPermits delegation .redelegate target := by
  intro permitted
  cases permitted.1

end ACSD
