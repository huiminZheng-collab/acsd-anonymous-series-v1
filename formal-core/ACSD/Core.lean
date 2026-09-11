set_option autoImplicit false
set_option warningAsError true

namespace ACSD

/-! Identifiers are separate types so that the model cannot accidentally use
one kind of identifier where another is required.  Their cryptographic
representation is intentionally outside this semantic core. -/
structure CatalogId where
  value : Nat
  deriving DecidableEq, Repr

structure RequestId where
  value : Nat
  deriving DecidableEq, Repr

structure PlanId where
  value : Nat
  deriving DecidableEq, Repr

structure Digest where
  value : Nat
  deriving DecidableEq, Repr

inductive Capability where
  | exactObjectIntegrity
  | keyEndorsement
  | independentNotAfterTime
  | dialogueOriginCommitment
  | teamRoleAttestation
  | teamContributionTruth
  | revisionLineageAttestation
  | citationBundleAttestation
  | citationTemporalPriorityTruth
  | historicalAuthorshipTruth
  deriving DecidableEq, Repr

inductive ComponentId where
  | signatureSeal
  | timestamp
  | dialogueOrigin
  deriving DecidableEq, Repr

structure Catalog where
  id : CatalogId
  active : ComponentId → Prop
  grants : ComponentId → Capability → Prop
  dependsOn : ComponentId → ComponentId → Prop
  assumption : ComponentId → String → Prop
  disclosure : ComponentId → String → Prop

abbrev Selection := ComponentId → Prop
abbrev CapabilitySet := Capability → Prop

def Covers (catalog : Catalog) (selection : Selection) (capability : Capability) : Prop :=
  ∃ component, selection component ∧ catalog.grants component capability

def SelectionActive (catalog : Catalog) (selection : Selection) : Prop :=
  ∀ component, selection component → catalog.active component

def DependencyClosed (catalog : Catalog) (selection : Selection) : Prop :=
  ∀ component dependency, selection component → catalog.dependsOn component dependency → selection dependency

structure Request where
  id : RequestId
  catalogRef : CatalogId
  objectDigest : Digest
  required : CapabilitySet
  forbiddenAssumption : String → Prop
  forbiddenDisclosure : String → Prop

structure Plan where
  id : PlanId
  requestRef : RequestId
  catalogRef : CatalogId
  roleManifestRef : Option Digest
  lineageManifestRef : Option Digest
  citationBundleRef : Option Digest
  selected : Selection
  asserted : CapabilitySet

structure AuthModel where
  policyAuthentic : Catalog → Prop
  authorAuthentic : Request → Prop
  serviceAuthentic : Plan → Prop

def ConstraintsHold (catalog : Catalog) (request : Request) (selection : Selection) : Prop :=
  (∀ component assumption, selection component → catalog.assumption component assumption → ¬ request.forbiddenAssumption assumption) ∧
  (∀ component disclosure, selection component → catalog.disclosure component disclosure → ¬ request.forbiddenDisclosure disclosure)

def Feasible (catalog : Catalog) (request : Request) (selection : Selection) : Prop :=
  SelectionActive catalog selection ∧
  DependencyClosed catalog selection ∧
  ConstraintsHold catalog request selection ∧
  ∀ capability, request.required capability → Covers catalog selection capability

structure Acceptance (model : AuthModel) (catalog : Catalog) (request : Request) (plan : Plan) : Prop where
  policy_authentic : model.policyAuthentic catalog
  author_authentic : model.authorAuthentic request
  service_authentic : model.serviceAuthentic plan
  request_binds_catalog : request.catalogRef = catalog.id
  plan_binds_request : plan.requestRef = request.id
  plan_binds_catalog : plan.catalogRef = catalog.id
  feasible : Feasible catalog request plan.selected
  asserted_derived : ∀ capability, plan.asserted capability → Covers catalog plan.selected capability

def Verify (model : AuthModel) (catalog : Catalog) (request : Request) (plan : Plan) : Prop :=
  Acceptance model catalog request plan

theorem accepted_covers_required
    {model : AuthModel} {catalog : Catalog} {request : Request} {plan : Plan}
    (accepted : Verify model catalog request plan) :
    ∀ capability, request.required capability → Covers catalog plan.selected capability :=
  accepted.feasible.2.2.2

theorem semantic_nonamplification
    {model : AuthModel} {catalog : Catalog} {request : Request} {plan : Plan}
    (accepted : Verify model catalog request plan) :
    ∀ capability, plan.asserted capability → Covers catalog plan.selected capability :=
  accepted.asserted_derived

/-!
The model deliberately gives no component the ability to establish the
real-world proposition `historicalAuthorshipTruth` by itself.  The following
theorem is a useful boundary check: if the signed catalog makes no such grant,
an accepted plan cannot assert it.  This is not a theorem of authorship; it is
a theorem that the verifier cannot silently upgrade provenance evidence into
an authorship verdict.
-/
theorem asserted_capability_not_accepted_without_catalog_grant
    {model : AuthModel} {catalog : Catalog} {request : Request} {plan : Plan}
    {capability : Capability}
    (no_grant : ∀ component, ¬ catalog.grants component capability)
    (accepted : Verify model catalog request plan)
    (asserted : plan.asserted capability) :
    False := by
  rcases semantic_nonamplification accepted capability asserted with
    ⟨component, _selected, granted⟩
  exact no_grant component granted

theorem authorship_truth_not_accepted_without_catalog_grant
    {model : AuthModel} {catalog : Catalog} {request : Request} {plan : Plan}
    (no_grant : ∀ component, ¬ catalog.grants component Capability.historicalAuthorshipTruth)
    (accepted : Verify model catalog request plan)
    (asserted : plan.asserted Capability.historicalAuthorshipTruth) :
    False :=
  asserted_capability_not_accepted_without_catalog_grant no_grant accepted asserted

theorem binding_exact
    {model : AuthModel} {catalog : Catalog} {request : Request} {plan : Plan}
    (accepted : Verify model catalog request plan) :
    request.catalogRef = catalog.id ∧ plan.requestRef = request.id ∧ plan.catalogRef = catalog.id :=
  ⟨accepted.request_binds_catalog, accepted.plan_binds_request, accepted.plan_binds_catalog⟩

theorem missing_requirement_rejected
    {model : AuthModel} {catalog : Catalog} {request : Request} {plan : Plan}
    (missing : ¬ ∀ capability, request.required capability → Covers catalog plan.selected capability) :
    ¬ Verify model catalog request plan := by
  intro accepted
  exact missing (accepted_covers_required accepted)

theorem accepted_selection_is_active
    {model : AuthModel} {catalog : Catalog} {request : Request} {plan : Plan}
    (accepted : Verify model catalog request plan) :
    SelectionActive catalog plan.selected :=
  accepted.feasible.1

theorem accepted_selection_is_dependency_closed
    {model : AuthModel} {catalog : Catalog} {request : Request} {plan : Plan}
    (accepted : Verify model catalog request plan) :
    DependencyClosed catalog plan.selected :=
  accepted.feasible.2.1

end ACSD
