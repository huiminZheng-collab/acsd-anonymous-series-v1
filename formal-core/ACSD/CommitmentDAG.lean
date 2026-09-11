import ACSD.SeriesGraph

set_option autoImplicit false
set_option warningAsError true

namespace ACSD

/-!
This module combines the two commitment directions that matter for a series
package: the package anchor resolves a stable work to a release, and a later
release names its exact direct predecessor.  Semantic citations are intentionally
absent: they may be cyclic without becoming commitment dependencies.

The rank witness is structural only.  It must not be interpreted as a wall-clock
timestamp or as evidence of creative priority.
-/

inductive CommitmentNode where
  | graphAnchor
  | release (revision : RevisionRef)

inductive CommitmentStep (graph : SeriesGraph)
    (rankWitness : SeriesCommitmentRankWitness graph) :
    CommitmentNode → CommitmentNode → Prop where
  | resolution (work : WorkId) (revision : RevisionRef)
      (resolves : graph.resolves work revision) :
      CommitmentStep graph rankWitness .graphAnchor (.release revision)
  | predecessor (later earlier : RevisionManifest)
      (direct : DirectRevisionOf later earlier) :
      CommitmentStep graph rankWitness (.release later.revision) (.release earlier.revision)

def CommitmentRank {graph : SeriesGraph} (rankWitness : SeriesCommitmentRankWitness graph) :
    CommitmentNode → Nat
  | .graphAnchor => rankWitness.anchorRank
  | .release revision => revision.version

inductive CommitmentPath (graph : SeriesGraph)
    (rankWitness : SeriesCommitmentRankWitness graph) :
    CommitmentNode → CommitmentNode → Prop where
  | single {source target : CommitmentNode} :
      CommitmentStep graph rankWitness source target →
      CommitmentPath graph rankWitness source target
  | append {source middle target : CommitmentNode} :
      CommitmentPath graph rankWitness source middle →
      CommitmentStep graph rankWitness middle target →
      CommitmentPath graph rankWitness source target

def CommitmentAcyclic (graph : SeriesGraph)
    (rankWitness : SeriesCommitmentRankWitness graph) : Prop :=
  ∀ node, ¬ CommitmentPath graph rankWitness node node

theorem commitment_step_strictly_descends
    {graph : SeriesGraph} {rankWitness : SeriesCommitmentRankWitness graph}
    {source target : CommitmentNode}
    (step : CommitmentStep graph rankWitness source target) :
    CommitmentRank rankWitness target < CommitmentRank rankWitness source := by
  cases step with
  | resolution work revision resolves =>
      exact rankWitness.every_resolved_revision_is_below_anchor work revision resolves
  | predecessor later earlier direct =>
      change earlier.revision.version < later.revision.version
      rw [direct.2.1]
      exact Nat.lt_succ_self earlier.revision.version

theorem commitment_path_strictly_descends
    {graph : SeriesGraph} {rankWitness : SeriesCommitmentRankWitness graph}
    {source target : CommitmentNode}
    (path : CommitmentPath graph rankWitness source target) :
    CommitmentRank rankWitness target < CommitmentRank rankWitness source := by
  induction path with
  | single step =>
      exact commitment_step_strictly_descends step
  | append path step inductionHypothesis =>
      exact Nat.lt_trans (commitment_step_strictly_descends step) inductionHypothesis

theorem ranked_commitment_skeleton_is_acyclic
    (graph : SeriesGraph) (rankWitness : SeriesCommitmentRankWitness graph) :
    CommitmentAcyclic graph rankWitness := by
  intro node cycle
  exact (Nat.lt_irrefl (CommitmentRank rankWitness node))
    (commitment_path_strictly_descends cycle)

theorem accepted_mutual_work_citation_has_acyclic_commitment_skeleton
    {model : AuthModel} {teamAuth : TeamAuthModel} {lineageAuth : LineageAuthModel}
    {graphAuth : SeriesGraphAuthModel}
    {catalog : Catalog} {request : Request} {plan : Plan}
    {roleManifest : RoleManifest} {lineageManifest : RevisionManifest} {graph : SeriesGraph}
    {left right : WorkId}
    (accepted : SeriesGraphAcceptance model teamAuth lineageAuth graphAuth catalog request plan
      roleManifest lineageManifest graph)
    (mutualCitation : MutualWorkCitation graph left right) :
    graph.declaredWork left ∧ graph.declaredWork right ∧
      ∃ rankWitness : SeriesCommitmentRankWitness graph,
        CommitmentAcyclic graph rankWitness := by
  rcases accepted.commitment_rank_exists with ⟨anchorRank, belowAnchor⟩
  let rankWitness : SeriesCommitmentRankWitness graph := {
    anchorRank := anchorRank
    every_resolved_revision_is_below_anchor := belowAnchor
  }
  exact ⟨(mutual_work_citation_declares_both_works accepted.well_formed mutualCitation).1,
    (mutual_work_citation_declares_both_works accepted.well_formed mutualCitation).2,
    rankWitness, ranked_commitment_skeleton_is_acyclic graph rankWitness⟩

end ACSD
