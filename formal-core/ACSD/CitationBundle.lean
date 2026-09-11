import ACSD.Lineage

set_option autoImplicit false
set_option warningAsError true

namespace ACSD

/-!
A citation edge is a digest-exact reference, not a temporal-priority claim.
`CitationBundle` permits a set of contemporaneously anchored revisions to cite
one another.  This models a series or a mutually-referential release package
without manufacturing a false “A precedes B” assertion from the graph cycle.
-/

structure CitationBundle where
  digest : Digest
  requestRef : RequestId
  member : RevisionRef → Prop
  cites : RevisionRef → RevisionRef → Prop

structure CitationBundleAuthModel where
  memberApproved : ParticipantId → CitationBundle → Prop

def BundleWellFormed (bundle : CitationBundle) : Prop :=
  ∀ source target, bundle.cites source target → bundle.member source

def MutualCitation (bundle : CitationBundle) (left right : RevisionRef) : Prop :=
  bundle.cites left right ∧ bundle.cites right left

structure CitationBundleAcceptance
    (model : AuthModel) (teamAuth : TeamAuthModel) (lineageAuth : LineageAuthModel)
    (bundleAuth : CitationBundleAuthModel)
    (catalog : Catalog) (request : Request) (plan : Plan)
    (roleManifest : RoleManifest) (lineageManifest : RevisionManifest)
    (bundle : CitationBundle) : Prop where
  lineage : LineageAcceptance model teamAuth lineageAuth catalog request plan roleManifest lineageManifest
  bundle_binds_request : bundle.requestRef = request.id
  current_revision_is_member : bundle.member lineageManifest.revision
  plan_binds_bundle : plan.citationBundleRef = some bundle.digest
  citation_bundle_attestation_asserted : plan.asserted Capability.citationBundleAttestation
  well_formed : BundleWellFormed bundle
  every_declared_team_member_approved :
    ∀ participant, roleManifest.member participant → bundleAuth.memberApproved participant bundle

theorem citation_bundle_acceptance_binds_all_manifests
    {model : AuthModel} {teamAuth : TeamAuthModel} {lineageAuth : LineageAuthModel}
    {bundleAuth : CitationBundleAuthModel}
    {catalog : Catalog} {request : Request} {plan : Plan}
    {roleManifest : RoleManifest} {lineageManifest : RevisionManifest} {bundle : CitationBundle}
    (accepted : CitationBundleAcceptance model teamAuth lineageAuth bundleAuth catalog request plan
      roleManifest lineageManifest bundle) :
    plan.roleManifestRef = some roleManifest.digest ∧
      plan.lineageManifestRef = some lineageManifest.digest ∧
      plan.citationBundleRef = some bundle.digest ∧
      bundle.requestRef = request.id ∧ bundle.member lineageManifest.revision :=
  ⟨accepted.lineage.team.plan_binds_manifest, accepted.lineage.plan_binds_manifest,
    accepted.plan_binds_bundle, accepted.bundle_binds_request,
    accepted.current_revision_is_member⟩

theorem accepted_citation_has_internal_source
    {model : AuthModel} {teamAuth : TeamAuthModel} {lineageAuth : LineageAuthModel}
    {bundleAuth : CitationBundleAuthModel}
    {catalog : Catalog} {request : Request} {plan : Plan}
    {roleManifest : RoleManifest} {lineageManifest : RevisionManifest} {bundle : CitationBundle}
    (accepted : CitationBundleAcceptance model teamAuth lineageAuth bundleAuth catalog request plan
      roleManifest lineageManifest bundle)
    {source target : RevisionRef}
    (citation : bundle.cites source target) :
    bundle.member source :=
  accepted.well_formed source target citation

theorem accepted_mutual_citation_has_both_internal_sources
    {model : AuthModel} {teamAuth : TeamAuthModel} {lineageAuth : LineageAuthModel}
    {bundleAuth : CitationBundleAuthModel}
    {catalog : Catalog} {request : Request} {plan : Plan}
    {roleManifest : RoleManifest} {lineageManifest : RevisionManifest} {bundle : CitationBundle}
    (accepted : CitationBundleAcceptance model teamAuth lineageAuth bundleAuth catalog request plan
      roleManifest lineageManifest bundle)
    {left right : RevisionRef}
    (bothDirections : MutualCitation bundle left right) :
    bundle.member left ∧ bundle.member right :=
  ⟨accepted.well_formed left right bothDirections.1,
    accepted.well_formed right left bothDirections.2⟩

theorem citation_bundle_attestation_is_catalog_covered
    {model : AuthModel} {teamAuth : TeamAuthModel} {lineageAuth : LineageAuthModel}
    {bundleAuth : CitationBundleAuthModel}
    {catalog : Catalog} {request : Request} {plan : Plan}
    {roleManifest : RoleManifest} {lineageManifest : RevisionManifest} {bundle : CitationBundle}
    (accepted : CitationBundleAcceptance model teamAuth lineageAuth bundleAuth catalog request plan
      roleManifest lineageManifest bundle) :
    Covers catalog plan.selected Capability.citationBundleAttestation :=
  semantic_nonamplification accepted.lineage.team.base
    Capability.citationBundleAttestation accepted.citation_bundle_attestation_asserted

/-! Mutual citation is evidence of an exact declared graph only.  It cannot be
silently upgraded into a claim that one cited work temporally preceded another. -/
theorem citation_temporal_priority_truth_not_accepted_without_catalog_grant
    {model : AuthModel} {teamAuth : TeamAuthModel} {lineageAuth : LineageAuthModel}
    {bundleAuth : CitationBundleAuthModel}
    {catalog : Catalog} {request : Request} {plan : Plan}
    {roleManifest : RoleManifest} {lineageManifest : RevisionManifest} {bundle : CitationBundle}
    (no_grant : ∀ component, ¬ catalog.grants component Capability.citationTemporalPriorityTruth)
    (accepted : CitationBundleAcceptance model teamAuth lineageAuth bundleAuth catalog request plan
      roleManifest lineageManifest bundle)
    (asserted : plan.asserted Capability.citationTemporalPriorityTruth) :
    False :=
  asserted_capability_not_accepted_without_catalog_grant no_grant accepted.lineage.team.base asserted

end ACSD
