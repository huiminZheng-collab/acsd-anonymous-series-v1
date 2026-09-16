import ACSD.GenericAppraisal

set_option autoImplicit false
set_option warningAsError true

namespace ACSD

/-! A small reusable boundary for finite, nondelegating evidence profiles.
The profile does not make subject binding automatic: each admitted rule must
say that every one of its premises matches the subject of its conclusion, and
must contain at least one premise.  The two theorems below then make explicit
what follows for every derived conclusion. -/

structure SubjectBoundProfile (Subject Fact Claim : Type) where
  policy : MultiPremisePolicy Claim
  rules : List (MultiPremiseRule Fact Claim)
  claimSubject : Claim → Subject
  factMatches : Fact → Subject → Prop
  nonemptyPremises :
    ∀ rule, rule ∈ rules → rule.premises ≠ []
  exactPremises :
    ∀ rule, rule ∈ rules → ∀ premise, premise ∈ rule.premises →
      factMatches premise (claimSubject rule.conclusion)

def SubjectBoundDerives
    {Subject Fact Claim : Type}
    (profile : SubjectBoundProfile Subject Fact Claim)
    (evidence : List Fact) (claim : Claim) : Prop :=
  MultiPremiseDerives profile.policy evidence profile.rules claim

theorem subjectBoundDerives_has_exact_subject_support
    {Subject Fact Claim : Type}
    {profile : SubjectBoundProfile Subject Fact Claim}
    {evidence : List Fact} {claim : Claim}
    (derived : SubjectBoundDerives profile evidence claim) :
    ∃ fact, fact ∈ evidence ∧ profile.factMatches fact (profile.claimSubject claim) := by
  rcases multiPremiseDerives_has_complete_rule derived with
    ⟨rule, inRules, conclusion, allPremises⟩
  cases premises : rule.premises with
  | nil =>
      exact False.elim ((profile.nonemptyPremises rule inRules) premises)
  | cons fact rest =>
      refine ⟨fact, ?_, ?_⟩
      · exact allPremises fact (by simp [premises])
      · have bound := profile.exactPremises rule inRules fact (by simp [premises])
        rw [conclusion] at bound
        exact bound

theorem no_subject_matched_evidence_blocks_derivation
    {Subject Fact Claim : Type}
    {profile : SubjectBoundProfile Subject Fact Claim}
    {evidence : List Fact} {claim : Claim} {subject : Subject}
    (claimIsAboutSubject : profile.claimSubject claim = subject)
    (noMatch : ∀ fact, fact ∈ evidence → ¬ profile.factMatches fact subject) :
    ¬ SubjectBoundDerives profile evidence claim := by
  intro derived
  rcases subjectBoundDerives_has_exact_subject_support derived with
    ⟨fact, inEvidence, matched⟩
  rw [claimIsAboutSubject] at matched
  exact (noMatch fact inEvidence) matched

end ACSD
