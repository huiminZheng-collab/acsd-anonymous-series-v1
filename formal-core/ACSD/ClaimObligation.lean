import ACSD.Core

set_option autoImplicit false
set_option warningAsError true

namespace ACSD

/-!
This is a deliberately small model of the optional claim--obligation layer.
It does not discover attacks, assess real TSAs, or establish social facts.  It
only checks that a version-bound, finite policy model cannot be silently
weakened after a request has named a claim.
-/

structure ClaimId where
  value : Nat
  deriving DecidableEq, Repr

structure AttackId where
  value : Nat
  deriving DecidableEq, Repr

structure ClaimObligationModel where
  digest : Digest
  blocks : ClaimId → AttackId → Prop
  requires : AttackId → Capability → Prop

structure ClaimRequest where
  base : Request
  modelRef : Digest
  requestedClaim : ClaimId → Prop
  directlyRequested : CapabilitySet

structure ObligationReceipt where
  modelRef : Digest
  residualAttack : AttackId → Prop

def RequestedAttack
    (model : ClaimObligationModel) (request : ClaimRequest) (attack : AttackId) : Prop :=
  ∃ claim, request.requestedClaim claim ∧ model.blocks claim attack

def RequiredByClaims
    (model : ClaimObligationModel) (request : ClaimRequest) (capability : Capability) : Prop :=
  ∃ claim attack, request.requestedClaim claim ∧ model.blocks claim attack ∧
    model.requires attack capability

def ObligationCovered
    (model : ClaimObligationModel) (catalog : Catalog) (plan : Plan) (attack : AttackId) : Prop :=
  ∀ capability, model.requires attack capability → Covers catalog plan.selected capability

/-! This layer also applies to an UNSAT assessment, so residual completeness
is stated separately from ordinary plan acceptance. -/
structure ClaimObligationAssessment
    (model : ClaimObligationModel) (catalog : Catalog) (request : ClaimRequest)
    (plan : Plan) (receipt : ObligationReceipt) : Prop where
  request_binds_model : request.modelRef = model.digest
  receipt_binds_model : receipt.modelRef = model.digest
  residual_complete : ∀ attack, RequestedAttack model request attack →
    ¬ ObligationCovered model catalog plan attack → receipt.residualAttack attack

structure ClaimObligationAcceptance
    (auth : AuthModel) (model : ClaimObligationModel) (catalog : Catalog)
    (request : ClaimRequest) (plan : Plan) (receipt : ObligationReceipt) : Prop
    extends ClaimObligationAssessment model catalog request plan receipt where
  base : Acceptance auth catalog request.base plan
  requirements_derived : ∀ capability, request.base.required capability ↔
    request.directlyRequested capability ∨ RequiredByClaims model request capability

theorem accepted_requested_attack_is_covered
    {auth : AuthModel} {model : ClaimObligationModel} {catalog : Catalog}
    {request : ClaimRequest} {plan : Plan} {receipt : ObligationReceipt}
    {claim : ClaimId} {attack : AttackId}
    (accepted : ClaimObligationAcceptance auth model catalog request plan receipt)
    (requested : request.requestedClaim claim)
    (blocked : model.blocks claim attack) :
    ObligationCovered model catalog plan attack := by
  intro capability requiresCapability
  apply accepted_covers_required accepted.base capability
  exact (accepted.requirements_derived capability).mpr
    (Or.inr ⟨claim, attack, requested, blocked, requiresCapability⟩)

theorem undischarged_requested_attack_is_listed_residual
    {model : ClaimObligationModel} {catalog : Catalog} {request : ClaimRequest}
    {plan : Plan} {receipt : ObligationReceipt} {attack : AttackId}
    (assessment : ClaimObligationAssessment model catalog request plan receipt)
    (requested : RequestedAttack model request attack)
    (notCovered : ¬ ObligationCovered model catalog plan attack) :
    receipt.residualAttack attack :=
  assessment.residual_complete attack requested notCovered

theorem accepted_claim_obligation_model_binds_request_and_receipt
    {auth : AuthModel} {model : ClaimObligationModel} {catalog : Catalog}
    {request : ClaimRequest} {plan : Plan} {receipt : ObligationReceipt}
    (accepted : ClaimObligationAcceptance auth model catalog request plan receipt) :
    request.modelRef = model.digest ∧ receipt.modelRef = model.digest :=
  ⟨accepted.request_binds_model, accepted.receipt_binds_model⟩

end ACSD
