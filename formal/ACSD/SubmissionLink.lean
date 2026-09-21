import ACSD.PEC

set_option autoImplicit false
set_option warningAsError true

namespace ACSD

/-! A small model of the submission-link profile.  Cryptographic verification,
canonical decoding, wall-clock evaluation, and venue-key authentication are
adapter inputs.  The model checks that those inputs cannot be recombined into
a claim about another release, manuscript, venue context, round, or byline. -/

inductive SubmissionDisclosureMode where
  | editorConfidential
  | publiclyDisclosable
  deriving DecidableEq, Repr

structure SubmissionContext where
  releaseDigest : Digest
  manuscriptDigest : Digest
  venueKey : KeyId
  submissionHandleCommitment : Digest
  reviewRound : Nat
  challengeNonce : Digest
  orderedBylineDigest : Digest
  disclosureMode : SubmissionDisclosureMode
  deriving DecidableEq, Repr

structure VenueChallengeEvidence where
  context : SubmissionContext
  venueSignatureValid : Bool
  currentAtVerification : Bool
  deriving Repr

def AuthenticatedChallenge
    (expected : SubmissionContext) (evidence : VenueChallengeEvidence) : Prop :=
  evidence.context = expected ∧
  evidence.venueSignatureValid = true ∧
  evidence.currentAtVerification = true

inductive OpeningAuthorization where
  | editorConfidentialOnly
  | publicSubmissionLink
  deriving DecidableEq, Repr

def RequiredOpeningAuthorization :
    SubmissionDisclosureMode → OpeningAuthorization
  | .editorConfidential => .editorConfidentialOnly
  | .publiclyDisclosable => .publicSubmissionLink

structure SubmissionOpeningEvidence where
  context : SubmissionContext
  slot : Nat
  slotKey : KeyId
  slotSignatureValid : Bool
  slotKeyMatches : Bool
  authorization : OpeningAuthorization
  deriving Repr

def SlotSubmissionAssent
    (expected : SubmissionContext) (slot : Nat)
    (evidence : SubmissionOpeningEvidence) : Prop :=
  evidence.context = expected ∧
  evidence.slot = slot ∧
  evidence.slotSignatureValid = true ∧
  evidence.slotKeyMatches = true ∧
  evidence.authorization = RequiredOpeningAuthorization expected.disclosureMode

def SubmissionLinkAccepted
    (expected : SubmissionContext) (requiredSlots : List Nat)
    (challenge : VenueChallengeEvidence)
    (openings : List SubmissionOpeningEvidence) : Prop :=
  AuthenticatedChallenge expected challenge ∧
  ∀ slot, slot ∈ requiredSlots →
    ∃ opening, opening ∈ openings ∧ SlotSubmissionAssent expected slot opening

theorem accepted_link_has_exact_challenge_context
    {expected : SubmissionContext} {requiredSlots : List Nat}
    {challenge : VenueChallengeEvidence}
    {openings : List SubmissionOpeningEvidence}
    (accepted : SubmissionLinkAccepted expected requiredSlots challenge openings) :
    challenge.context = expected := accepted.1.1

theorem accepted_link_requires_current_challenge
    {expected : SubmissionContext} {requiredSlots : List Nat}
    {challenge : VenueChallengeEvidence}
    {openings : List SubmissionOpeningEvidence}
    (accepted : SubmissionLinkAccepted expected requiredSlots challenge openings) :
    challenge.currentAtVerification = true := accepted.1.2.2

theorem accepted_link_covers_every_required_slot
    {expected : SubmissionContext} {requiredSlots : List Nat}
    {challenge : VenueChallengeEvidence}
    {openings : List SubmissionOpeningEvidence}
    (accepted : SubmissionLinkAccepted expected requiredSlots challenge openings)
    {slot : Nat} (required : slot ∈ requiredSlots) :
    ∃ opening, opening ∈ openings ∧ SlotSubmissionAssent expected slot opening :=
  accepted.2 slot required

theorem opening_cannot_cross_context
    {left right : SubmissionContext} {slot : Nat}
    {opening : SubmissionOpeningEvidence}
    (assent : SlotSubmissionAssent left slot opening)
    (different : left ≠ right) :
    ¬ SlotSubmissionAssent right slot opening := by
  intro other
  apply different
  calc
    left = opening.context := assent.1.symm
    _ = right := other.1

theorem missing_slot_prevents_submission_link
    {expected : SubmissionContext} {requiredSlots : List Nat}
    {challenge : VenueChallengeEvidence}
    {openings : List SubmissionOpeningEvidence} {missing : Nat}
    (required : missing ∈ requiredSlots)
    (absent : ∀ opening, opening ∈ openings → opening.slot ≠ missing) :
    ¬ SubmissionLinkAccepted expected requiredSlots challenge openings := by
  intro accepted
  obtain ⟨opening, member, assent⟩ := accepted.2 missing required
  exact absent opening member assent.2.1

theorem confidential_opening_is_not_public_authorization
    {expected : SubmissionContext} {slot : Nat}
    {opening : SubmissionOpeningEvidence}
    (mode : expected.disclosureMode = .editorConfidential)
    (assent : SlotSubmissionAssent expected slot opening) :
    opening.authorization ≠ .publicSubmissionLink := by
  have authorization := assent.2.2.2.2
  rw [mode] at authorization
  have confidential : opening.authorization = .editorConfidentialOnly := by
    simpa [RequiredOpeningAuthorization] using authorization
  rw [confidential]
  decide

theorem manuscript_substitution_changes_context
    {left right : SubmissionContext}
    (different : left.manuscriptDigest ≠ right.manuscriptDigest) :
    left ≠ right := by
  intro equal
  apply different
  exact congrArg SubmissionContext.manuscriptDigest equal

theorem byline_substitution_changes_context
    {left right : SubmissionContext}
    (different : left.orderedBylineDigest ≠ right.orderedBylineDigest) :
    left ≠ right := by
  intro equal
  apply different
  exact congrArg SubmissionContext.orderedBylineDigest equal

end ACSD
