import ACSD.PEC

set_option autoImplicit false
set_option warningAsError true

namespace ACSD

/-!
This model isolates the v3 authorization question from signature parsing.
`quorum` is an input established by the executable COSE verifier, just as
`Approval.signatureValid` is an executable-boundary input in `PEC.lean`.
-/

structure LineageAuthority where
  keys : List KeyId
  threshold : Nat
  deriving DecidableEq, Repr

structure VersionedRelease where
  work : Nat
  line : Nat
  version : Nat
  releaseDigest : Digest
  pecDigest : Digest
  authority : LineageAuthority
  deriving DecidableEq, Repr

structure LineageTransition where
  work : Nat
  parentReleaseDigest : Digest
  parentPecDigest : Digest
  childReleaseDigest : Digest
  childPecDigest : Digest
  oldAuthority : LineageAuthority
  newAuthority : LineageAuthority
  deriving DecidableEq, Repr

structure LineageApprovalEvidence where
  signerKeys : List KeyId
  deriving Repr

structure LineageAuthModel where
  quorum : LineageAuthority → LineageApprovalEvidence → Prop

def StructuralSuccessor (parent child : VersionedRelease) : Prop :=
  child.work = parent.work ∧
    ((child.line = parent.line ∧ child.version = parent.version + 1) ∨
     (child.line ≠ parent.line ∧ child.version = 1))

def ExactTransition
    (transition : LineageTransition) (parent child : VersionedRelease) : Prop :=
  transition.work = child.work ∧
  transition.parentReleaseDigest = parent.releaseDigest ∧
  transition.parentPecDigest = parent.pecDigest ∧
  transition.childReleaseDigest = child.releaseDigest ∧
  transition.childPecDigest = child.pecDigest ∧
  transition.oldAuthority = parent.authority ∧
  transition.newAuthority = child.authority

inductive SuccessionProof where
  /-- The child approval signatures also count as predecessor authorization
  only when the authority object is unchanged. -/
  | continuity (childApprovals : LineageApprovalEvidence)
  /-- A key/team change requires a separate exact transition signed under the
  predecessor authority. The ordinary PEC layer separately checks the new
  authors' approval target. -/
  | transition (body : LineageTransition) (oldApprovals : LineageApprovalEvidence)

def AuthorizedSuccessor
    (model : LineageAuthModel) (parent child : VersionedRelease)
    (proof : SuccessionProof) : Prop :=
  StructuralSuccessor parent child ∧
  match proof with
  | .continuity childApprovals =>
      child.authority = parent.authority ∧
      model.quorum parent.authority childApprovals
  | .transition body oldApprovals =>
      ExactTransition body parent child ∧
      model.quorum parent.authority oldApprovals

theorem authorized_successor_has_parent_quorum
    {model : LineageAuthModel} {parent child : VersionedRelease}
    {proof : SuccessionProof}
    (accepted : AuthorizedSuccessor model parent child proof) :
    ∃ evidence, model.quorum parent.authority evidence := by
  cases proof with
  | continuity childApprovals =>
      exact ⟨childApprovals, accepted.2.2⟩
  | transition body oldApprovals =>
      exact ⟨oldApprovals, accepted.2.2⟩

theorem fresh_authority_without_transition_is_not_successor
    {model : LineageAuthModel} {parent child : VersionedRelease}
    {childApprovals : LineageApprovalEvidence}
    (differentAuthority : child.authority ≠ parent.authority) :
    ¬ AuthorizedSuccessor model parent child (.continuity childApprovals) := by
  intro accepted
  exact differentAuthority accepted.2.1

theorem transition_successor_binds_exact_transition
    {model : LineageAuthModel} {parent child : VersionedRelease}
    {body : LineageTransition} {oldApprovals : LineageApprovalEvidence}
    (accepted : AuthorizedSuccessor model parent child (.transition body oldApprovals)) :
    ExactTransition body parent child :=
  accepted.2.1

theorem transition_authorization_not_reusable_for_other_child
    {body : LineageTransition} {parent child other : VersionedRelease}
    (exact : ExactTransition body parent child)
    (differentChild : child.releaseDigest ≠ other.releaseDigest) :
    ¬ ExactTransition body parent other := by
  intro reused
  apply differentChild
  exact exact.2.2.2.1.symm.trans reused.2.2.2.1

theorem authorized_successor_preserves_work
    {model : LineageAuthModel} {parent child : VersionedRelease}
    {proof : SuccessionProof}
    (accepted : AuthorizedSuccessor model parent child proof) :
    child.work = parent.work :=
  accepted.1.1

end ACSD
