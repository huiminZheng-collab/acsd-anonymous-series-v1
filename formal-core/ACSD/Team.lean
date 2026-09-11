import ACSD.Core

set_option autoImplicit false
set_option warningAsError true

namespace ACSD

/-!
`Team.lean` models an auditable *declaration* of team roles.  It deliberately
does not model, or infer, the real-world amount of intellectual work done by a
person.  The capability names make that distinction visible to a verifier:
`teamRoleAttestation` is attainable evidence, whereas
`teamContributionTruth` requires an independent grant and cannot arise merely
from coauthor signatures.
-/

structure ParticipantId where
  value : Nat
  deriving DecidableEq, Repr

structure RoleManifest where
  digest : Digest
  requestRef : RequestId
  objectDigest : Digest
  member : ParticipantId → Prop
  firstAuthor : ParticipantId
  correspondingAuthor : ParticipantId
  dialogueOriginCommitment : Option Digest

/-! This predicate abstracts verification of each participant's signature on
the exact manifest.  It says nothing about the participant's civil identity or
whether the declared role accurately describes work performed. -/
structure TeamAuthModel where
  memberApproved : ParticipantId → RoleManifest → Prop

structure TeamAgreement (auth : TeamAuthModel) (manifest : RoleManifest) : Prop where
  first_is_member : manifest.member manifest.firstAuthor
  corresponding_is_member : manifest.member manifest.correspondingAuthor
  every_member_approved : ∀ participant, manifest.member participant → auth.memberApproved participant manifest

def HasDeclaredRole (manifest : RoleManifest) (participant : ParticipantId) : Prop :=
  manifest.member participant

structure TeamRoleAcceptance
    (model : AuthModel) (teamAuth : TeamAuthModel)
    (catalog : Catalog) (request : Request) (plan : Plan)
    (manifest : RoleManifest) : Prop where
  base : Acceptance model catalog request plan
  manifest_binds_request : manifest.requestRef = request.id
  manifest_binds_object : manifest.objectDigest = request.objectDigest
  plan_binds_manifest : plan.roleManifestRef = some manifest.digest
  role_attestation_asserted : plan.asserted Capability.teamRoleAttestation
  agreement : TeamAgreement teamAuth manifest

theorem team_acceptance_binds_exact_manifest
    {model : AuthModel} {teamAuth : TeamAuthModel}
    {catalog : Catalog} {request : Request} {plan : Plan} {manifest : RoleManifest}
    (accepted : TeamRoleAcceptance model teamAuth catalog request plan manifest) :
    manifest.requestRef = request.id ∧ manifest.objectDigest = request.objectDigest ∧
      plan.roleManifestRef = some manifest.digest :=
  ⟨accepted.manifest_binds_request, accepted.manifest_binds_object,
    accepted.plan_binds_manifest⟩

theorem team_acceptance_has_signed_first_author
    {model : AuthModel} {teamAuth : TeamAuthModel}
    {catalog : Catalog} {request : Request} {plan : Plan} {manifest : RoleManifest}
    (accepted : TeamRoleAcceptance model teamAuth catalog request plan manifest) :
    manifest.member manifest.firstAuthor ∧ teamAuth.memberApproved manifest.firstAuthor manifest := by
  exact ⟨accepted.agreement.first_is_member,
    accepted.agreement.every_member_approved manifest.firstAuthor accepted.agreement.first_is_member⟩

theorem team_acceptance_has_signed_corresponding_author
    {model : AuthModel} {teamAuth : TeamAuthModel}
    {catalog : Catalog} {request : Request} {plan : Plan} {manifest : RoleManifest}
    (accepted : TeamRoleAcceptance model teamAuth catalog request plan manifest) :
    manifest.member manifest.correspondingAuthor ∧
      teamAuth.memberApproved manifest.correspondingAuthor manifest := by
  exact ⟨accepted.agreement.corresponding_is_member,
    accepted.agreement.every_member_approved manifest.correspondingAuthor
      accepted.agreement.corresponding_is_member⟩

theorem team_acceptance_all_declared_members_approved
    {model : AuthModel} {teamAuth : TeamAuthModel}
    {catalog : Catalog} {request : Request} {plan : Plan} {manifest : RoleManifest}
    (accepted : TeamRoleAcceptance model teamAuth catalog request plan manifest) :
    ∀ participant, HasDeclaredRole manifest participant → teamAuth.memberApproved participant manifest :=
  accepted.agreement.every_member_approved

theorem team_attestation_is_catalog_covered
    {model : AuthModel} {teamAuth : TeamAuthModel}
    {catalog : Catalog} {request : Request} {plan : Plan} {manifest : RoleManifest}
    (accepted : TeamRoleAcceptance model teamAuth catalog request plan manifest) :
    Covers catalog plan.selected Capability.teamRoleAttestation :=
  semantic_nonamplification accepted.base Capability.teamRoleAttestation
    accepted.role_attestation_asserted

/-!
Even unanimous signatures make the declared roles auditable, not a proof of
the contribution facts themselves.  This is the exact analogue of the core
anti-upgrade theorem for authorship truth.
-/
theorem team_contribution_truth_not_accepted_without_catalog_grant
    {model : AuthModel} {teamAuth : TeamAuthModel}
    {catalog : Catalog} {request : Request} {plan : Plan} {manifest : RoleManifest}
    (no_grant : ∀ component, ¬ catalog.grants component Capability.teamContributionTruth)
    (accepted : TeamRoleAcceptance model teamAuth catalog request plan manifest)
    (asserted : plan.asserted Capability.teamContributionTruth) :
    False :=
  asserted_capability_not_accepted_without_catalog_grant no_grant accepted.base asserted

end ACSD
