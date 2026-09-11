import ACSD.CitationBundle

set_option autoImplicit false
set_option warningAsError true

namespace ACSD

/-!
A series graph separates two different kinds of edge.

`semanticCites` is the citation relation written in a paper body.  It is over
stable `WorkId`s, so it may contain a cycle such as A <-> B without requiring
either final content digest to contain the other final digest.  `resolves` is
the later series-package mapping from a `WorkId` to an exact versioned
`RevisionRef`.  The corresponding commitment edge is deliberately one-way:
the package commits to releases, but a release does not commit back to the
package that later resolves its citations.

`releaseTextCites` is the idealized result of parsing the exact release named
by a `RevisionRef`.  It is separate from `semanticCites`: an accepted semantic
edge must have a resolved source release whose parsed text supports that edge.
The kernel model therefore enforces the intended relation, but a real parser
and its mapping from bytes to this predicate remain a refinement obligation.

This idealized layer proves an interpretation discipline, not a hash-function
or publication-time theorem.
-/

structure SeriesGraph where
  digest : Digest
  requestRef : RequestId
  declaredWork : WorkId → Prop
  semanticCites : WorkId → WorkId → Prop
  resolves : WorkId → RevisionRef → Prop
  releaseTextCites : RevisionRef → WorkId → Prop

def SeriesGraphWellFormed (graph : SeriesGraph) : Prop :=
  (∀ source target, graph.semanticCites source target →
    graph.declaredWork source ∧ graph.declaredWork target) ∧
  ∀ work revision, graph.resolves work revision →
    graph.declaredWork work ∧ revision.work = work

/-! A finite published series package can provide this witness by choosing an
anchor rank above every resolved revision version (for example, one plus the
maximum version in the package).  It is a structural topological certificate,
not a publication-time or priority claim. -/
structure SeriesCommitmentRankWitness (graph : SeriesGraph) where
  anchorRank : Nat
  every_resolved_revision_is_below_anchor :
    ∀ work revision, graph.resolves work revision → revision.version < anchorRank

def HasSeriesCommitmentRank (graph : SeriesGraph) : Prop :=
  ∃ anchorRank : Nat, ∀ work revision,
    graph.resolves work revision → revision.version < anchorRank

def MutualWorkCitation (graph : SeriesGraph) (left right : WorkId) : Prop :=
  graph.semanticCites left right ∧ graph.semanticCites right left

/-! Nodes and edges of the *local* series commitment graph.  Semantic citation
edges intentionally do not occur in this relation. -/
inductive SeriesCommitmentNode where
  | graphAnchor
  | release (revision : RevisionRef)

inductive SeriesCommitmentEdge (graph : SeriesGraph) :
    SeriesCommitmentNode → SeriesCommitmentNode → Prop where
  | resolution (work : WorkId) (revision : RevisionRef)
      (resolves : graph.resolves work revision) :
      SeriesCommitmentEdge graph .graphAnchor (.release revision)

structure SeriesGraphAuthModel where
  memberApproved : ParticipantId → SeriesGraph → Prop

structure SeriesGraphAcceptance
    (model : AuthModel) (teamAuth : TeamAuthModel) (lineageAuth : LineageAuthModel)
    (graphAuth : SeriesGraphAuthModel)
    (catalog : Catalog) (request : Request) (plan : Plan)
    (roleManifest : RoleManifest) (lineageManifest : RevisionManifest)
    (graph : SeriesGraph) : Prop where
  lineage : LineageAcceptance model teamAuth lineageAuth catalog request plan roleManifest lineageManifest
  graph_binds_request : graph.requestRef = request.id
  current_revision_is_resolved : graph.resolves lineageManifest.revision.work lineageManifest.revision
  plan_binds_graph : plan.citationBundleRef = some graph.digest
  series_graph_attestation_asserted : plan.asserted Capability.citationBundleAttestation
  well_formed : SeriesGraphWellFormed graph
  semantic_edges_text_supported :
    ∀ source target, graph.semanticCites source target →
      ∃ sourceRevision, graph.resolves source sourceRevision ∧
        graph.releaseTextCites sourceRevision target
  commitment_rank_exists : HasSeriesCommitmentRank graph
  every_declared_team_member_approved :
    ∀ participant, roleManifest.member participant → graphAuth.memberApproved participant graph

theorem resolved_work_binds_exact_work
    {graph : SeriesGraph} {work : WorkId} {revision : RevisionRef}
    (wellFormed : SeriesGraphWellFormed graph)
    (resolution : graph.resolves work revision) :
    graph.declaredWork work ∧ revision.work = work :=
  wellFormed.2 work revision resolution

theorem mutual_work_citation_declares_both_works
    {graph : SeriesGraph} {left right : WorkId}
    (wellFormed : SeriesGraphWellFormed graph)
    (mutualCitation : MutualWorkCitation graph left right) :
    graph.declaredWork left ∧ graph.declaredWork right :=
  wellFormed.1 left right mutualCitation.1

theorem series_graph_acceptance_binds_all_manifests
    {model : AuthModel} {teamAuth : TeamAuthModel} {lineageAuth : LineageAuthModel}
    {graphAuth : SeriesGraphAuthModel}
    {catalog : Catalog} {request : Request} {plan : Plan}
    {roleManifest : RoleManifest} {lineageManifest : RevisionManifest} {graph : SeriesGraph}
    (accepted : SeriesGraphAcceptance model teamAuth lineageAuth graphAuth catalog request plan
      roleManifest lineageManifest graph) :
    plan.roleManifestRef = some roleManifest.digest ∧
      plan.lineageManifestRef = some lineageManifest.digest ∧
      plan.citationBundleRef = some graph.digest ∧
      graph.requestRef = request.id :=
  ⟨accepted.lineage.team.plan_binds_manifest, accepted.lineage.plan_binds_manifest,
    accepted.plan_binds_graph, accepted.graph_binds_request⟩

theorem accepted_series_graph_resolves_current_revision
    {model : AuthModel} {teamAuth : TeamAuthModel} {lineageAuth : LineageAuthModel}
    {graphAuth : SeriesGraphAuthModel}
    {catalog : Catalog} {request : Request} {plan : Plan}
    {roleManifest : RoleManifest} {lineageManifest : RevisionManifest} {graph : SeriesGraph}
    (accepted : SeriesGraphAcceptance model teamAuth lineageAuth graphAuth catalog request plan
      roleManifest lineageManifest graph) :
    graph.declaredWork lineageManifest.revision.work ∧
      graph.resolves lineageManifest.revision.work lineageManifest.revision :=
  ⟨(accepted.well_formed.2 lineageManifest.revision.work lineageManifest.revision
      accepted.current_revision_is_resolved).1,
    accepted.current_revision_is_resolved⟩

theorem accepted_series_graph_has_commitment_rank
    {model : AuthModel} {teamAuth : TeamAuthModel} {lineageAuth : LineageAuthModel}
    {graphAuth : SeriesGraphAuthModel}
    {catalog : Catalog} {request : Request} {plan : Plan}
    {roleManifest : RoleManifest} {lineageManifest : RevisionManifest} {graph : SeriesGraph}
    (accepted : SeriesGraphAcceptance model teamAuth lineageAuth graphAuth catalog request plan
      roleManifest lineageManifest graph) :
    HasSeriesCommitmentRank graph :=
  accepted.commitment_rank_exists

/-! Acceptance cannot certify a semantic series edge solely because a series
key asserted it.  The edge requires a resolved source release and the
idealized parsed-text relation for that exact release. -/
theorem accepted_semantic_citation_has_resolved_text_support
    {model : AuthModel} {teamAuth : TeamAuthModel} {lineageAuth : LineageAuthModel}
    {graphAuth : SeriesGraphAuthModel}
    {catalog : Catalog} {request : Request} {plan : Plan}
    {roleManifest : RoleManifest} {lineageManifest : RevisionManifest} {graph : SeriesGraph}
    {source target : WorkId}
    (accepted : SeriesGraphAcceptance model teamAuth lineageAuth graphAuth catalog request plan
      roleManifest lineageManifest graph)
    (citation : graph.semanticCites source target) :
    ∃ sourceRevision, graph.resolves source sourceRevision ∧
      graph.releaseTextCites sourceRevision target :=
  accepted.semantic_edges_text_supported source target citation

theorem accepted_mutual_work_citation_has_two_resolved_text_witnesses
    {model : AuthModel} {teamAuth : TeamAuthModel} {lineageAuth : LineageAuthModel}
    {graphAuth : SeriesGraphAuthModel}
    {catalog : Catalog} {request : Request} {plan : Plan}
    {roleManifest : RoleManifest} {lineageManifest : RevisionManifest} {graph : SeriesGraph}
    {left right : WorkId}
    (accepted : SeriesGraphAcceptance model teamAuth lineageAuth graphAuth catalog request plan
      roleManifest lineageManifest graph)
    (mutualCitation : MutualWorkCitation graph left right) :
    ∃ leftRevision rightRevision,
      graph.resolves left leftRevision ∧ graph.releaseTextCites leftRevision right ∧
      graph.resolves right rightRevision ∧ graph.releaseTextCites rightRevision left := by
  obtain ⟨leftRevision, leftResolves, leftText⟩ :=
    accepted_semantic_citation_has_resolved_text_support accepted mutualCitation.1
  obtain ⟨rightRevision, rightResolves, rightText⟩ :=
    accepted_semantic_citation_has_resolved_text_support accepted mutualCitation.2
  exact ⟨leftRevision, rightRevision, leftResolves, leftText, rightResolves, rightText⟩

theorem series_commitment_never_points_from_release_to_anchor
    (graph : SeriesGraph) (revision : RevisionRef) :
    ¬ SeriesCommitmentEdge graph (.release revision) .graphAnchor := by
  intro reverseEdge
  cases reverseEdge

theorem mutual_citation_two_resolution_edges_are_one_way
    {graph : SeriesGraph} {left right : WorkId}
    {leftRevision rightRevision : RevisionRef}
    (wellFormed : SeriesGraphWellFormed graph)
    (mutualCitation : MutualWorkCitation graph left right)
    (leftResolution : graph.resolves left leftRevision)
    (rightResolution : graph.resolves right rightRevision) :
    graph.declaredWork left ∧ graph.declaredWork right ∧
      leftRevision.work = left ∧ rightRevision.work = right ∧
      SeriesCommitmentEdge graph .graphAnchor (.release leftRevision) ∧
      SeriesCommitmentEdge graph .graphAnchor (.release rightRevision) ∧
      ¬ SeriesCommitmentEdge graph (.release leftRevision) .graphAnchor ∧
      ¬ SeriesCommitmentEdge graph (.release rightRevision) .graphAnchor := by
  have citationWorks := mutual_work_citation_declares_both_works wellFormed mutualCitation
  have leftExact := resolved_work_binds_exact_work wellFormed leftResolution
  have rightExact := resolved_work_binds_exact_work wellFormed rightResolution
  exact ⟨citationWorks.1, citationWorks.2, leftExact.2, rightExact.2,
    SeriesCommitmentEdge.resolution left leftRevision leftResolution,
    SeriesCommitmentEdge.resolution right rightRevision rightResolution,
    series_commitment_never_points_from_release_to_anchor graph leftRevision,
    series_commitment_never_points_from_release_to_anchor graph rightRevision⟩

theorem series_citation_temporal_priority_truth_not_accepted_without_catalog_grant
    {model : AuthModel} {teamAuth : TeamAuthModel} {lineageAuth : LineageAuthModel}
    {graphAuth : SeriesGraphAuthModel}
    {catalog : Catalog} {request : Request} {plan : Plan}
    {roleManifest : RoleManifest} {lineageManifest : RevisionManifest} {graph : SeriesGraph}
    (no_grant : ∀ component, ¬ catalog.grants component Capability.citationTemporalPriorityTruth)
    (accepted : SeriesGraphAcceptance model teamAuth lineageAuth graphAuth catalog request plan
      roleManifest lineageManifest graph)
    (asserted : plan.asserted Capability.citationTemporalPriorityTruth) :
    False :=
  asserted_capability_not_accepted_without_catalog_grant no_grant accepted.lineage.team.base asserted

end ACSD
