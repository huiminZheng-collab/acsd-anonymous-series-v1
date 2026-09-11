import ACSD.Team

set_option autoImplicit false
set_option warningAsError true

namespace ACSD

/-!
The lineage layer makes updates and series citations immutable references to a
work, version and object digest.  A citation to “v1” is therefore not merely a
mutable URL or a work name; replacing its digest while retaining its apparent
work/version slot is detectable by the verifier.

This layer records signed attestations about lineage.  It does not establish
the priority, novelty, or factual authorship of the cited work.
-/

structure WorkId where
  value : Nat
  deriving DecidableEq, Repr

structure RevisionRef where
  work : WorkId
  version : Nat
  objectDigest : Digest
  deriving DecidableEq, Repr

structure RevisionManifest where
  digest : Digest
  requestRef : RequestId
  revision : RevisionRef
  predecessor : Option RevisionRef
  cites : RevisionRef → Prop

structure LineageAuthModel where
  memberApproved : ParticipantId → RevisionManifest → Prop

def DirectRevisionOf (later earlier : RevisionManifest) : Prop :=
  later.revision.work = earlier.revision.work ∧
  later.revision.version = earlier.revision.version + 1 ∧
  later.predecessor = some earlier.revision

def SameRevisionSlot (left right : RevisionRef) : Prop :=
  left.work = right.work ∧ left.version = right.version

def IsSameSlotDigestSwitch (candidate target : RevisionRef) : Prop :=
  SameRevisionSlot candidate target ∧ candidate.objectDigest ≠ target.objectDigest

structure LineageAcceptance
    (model : AuthModel) (teamAuth : TeamAuthModel) (lineageAuth : LineageAuthModel)
    (catalog : Catalog) (request : Request) (plan : Plan)
    (roleManifest : RoleManifest) (lineageManifest : RevisionManifest) : Prop where
  team : TeamRoleAcceptance model teamAuth catalog request plan roleManifest
  manifest_binds_request : lineageManifest.requestRef = request.id
  manifest_binds_object : lineageManifest.revision.objectDigest = request.objectDigest
  plan_binds_manifest : plan.lineageManifestRef = some lineageManifest.digest
  lineage_attestation_asserted : plan.asserted Capability.revisionLineageAttestation
  every_declared_team_member_approved :
    ∀ participant, roleManifest.member participant → lineageAuth.memberApproved participant lineageManifest

theorem direct_revision_preserves_work
    {later earlier : RevisionManifest}
    (direct : DirectRevisionOf later earlier) :
    later.revision.work = earlier.revision.work :=
  direct.1

theorem direct_revision_increments_version
    {later earlier : RevisionManifest}
    (direct : DirectRevisionOf later earlier) :
    later.revision.version = earlier.revision.version + 1 :=
  direct.2.1

theorem direct_revision_binds_exact_predecessor
    {later earlier : RevisionManifest}
    (direct : DirectRevisionOf later earlier) :
    later.predecessor = some earlier.revision :=
  direct.2.2

theorem same_slot_digest_switch_has_distinct_reference
    {target candidate : RevisionRef}
    (switched : IsSameSlotDigestSwitch candidate target) :
    candidate ≠ target := by
  intro equal_ref
  exact switched.2 (congrArg RevisionRef.objectDigest equal_ref)

theorem lineage_acceptance_binds_exact_team_and_revision_manifests
    {model : AuthModel} {teamAuth : TeamAuthModel} {lineageAuth : LineageAuthModel}
    {catalog : Catalog} {request : Request} {plan : Plan}
    {roleManifest : RoleManifest} {lineageManifest : RevisionManifest}
    (accepted : LineageAcceptance model teamAuth lineageAuth catalog request plan roleManifest lineageManifest) :
    roleManifest.requestRef = request.id ∧ roleManifest.objectDigest = request.objectDigest ∧
      plan.roleManifestRef = some roleManifest.digest ∧
      lineageManifest.requestRef = request.id ∧
      lineageManifest.revision.objectDigest = request.objectDigest ∧
      plan.lineageManifestRef = some lineageManifest.digest := by
  exact ⟨accepted.team.manifest_binds_request, accepted.team.manifest_binds_object,
    accepted.team.plan_binds_manifest, accepted.manifest_binds_request,
    accepted.manifest_binds_object, accepted.plan_binds_manifest⟩

theorem lineage_acceptance_has_all_declared_team_approvals
    {model : AuthModel} {teamAuth : TeamAuthModel} {lineageAuth : LineageAuthModel}
    {catalog : Catalog} {request : Request} {plan : Plan}
    {roleManifest : RoleManifest} {lineageManifest : RevisionManifest}
    (accepted : LineageAcceptance model teamAuth lineageAuth catalog request plan roleManifest lineageManifest) :
    ∀ participant, roleManifest.member participant → lineageAuth.memberApproved participant lineageManifest :=
  accepted.every_declared_team_member_approved

theorem lineage_attestation_is_catalog_covered
    {model : AuthModel} {teamAuth : TeamAuthModel} {lineageAuth : LineageAuthModel}
    {catalog : Catalog} {request : Request} {plan : Plan}
    {roleManifest : RoleManifest} {lineageManifest : RevisionManifest}
    (accepted : LineageAcceptance model teamAuth lineageAuth catalog request plan roleManifest lineageManifest) :
    Covers catalog plan.selected Capability.revisionLineageAttestation :=
  semantic_nonamplification accepted.team.base Capability.revisionLineageAttestation
    accepted.lineage_attestation_asserted

end ACSD
