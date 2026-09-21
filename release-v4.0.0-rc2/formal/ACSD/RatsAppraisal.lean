import ACSD.SubjectBoundEvidence

set_option autoImplicit false
set_option warningAsError true

namespace ACSD

/-! A compact, standards-aligned second-domain instance for the formal
generalization gate.  RFC 9334 separates Evidence, appraisal policy, and an
Attestation Result; RFC 9711 describes signed claims and freshness in an EAT.

This module does not parse EAT, verify COSE, or assert that a device is safe.
Those are adapter and relying-party decisions.  It proves only the narrow
appraisal statement below: a named verifier policy may yield an appraisal
result for one exact subject when a token binding, measurement, reference
value, freshness binding, and verifier authorization are all present. -/

inductive RatsFact where
  | tokenSignature (token attester : Nat)
  | measurementBinding (token measurement : Nat)
  | freshnessBinding (token nonce : Nat)
  | referenceValue (measurement reference : Nat)
  | verifierAuthorization (verifier policy : Nat)
  deriving DecidableEq, Repr

structure RatsSubject where
  token : Nat
  attester : Nat
  measurement : Nat
  reference : Nat
  nonce : Nat
  verifier : Nat
  policy : Nat
  deriving DecidableEq, Repr

inductive RatsClaim where
  | appraisalResult (subject : RatsSubject)
  deriving DecidableEq, Repr

def ratsAppraisalRule (subject : RatsSubject) :
    MultiPremiseRule RatsFact RatsClaim := {
  conclusion := .appraisalResult subject
  premises := [
    .tokenSignature subject.token subject.attester,
    .measurementBinding subject.token subject.measurement,
    .freshnessBinding subject.token subject.nonce,
    .referenceValue subject.measurement subject.reference,
    .verifierAuthorization subject.verifier subject.policy
  ]
}

def RatsAppraises
    (policy : MultiPremisePolicy RatsClaim)
    (evidence : List RatsFact)
    (subject : RatsSubject) : Prop :=
  MultiPremiseDerives policy evidence [ratsAppraisalRule subject]
    (.appraisalResult subject)

def ratsClaimSubject : RatsClaim → RatsSubject
  | .appraisalResult subject => subject

def ratsFactMatches (fact : RatsFact) (subject : RatsSubject) : Prop :=
  match fact with
  | .tokenSignature token attester =>
      token = subject.token ∧ attester = subject.attester
  | .measurementBinding token measurement =>
      token = subject.token ∧ measurement = subject.measurement
  | .freshnessBinding token nonce =>
      token = subject.token ∧ nonce = subject.nonce
  | .referenceValue measurement reference =>
      measurement = subject.measurement ∧ reference = subject.reference
  | .verifierAuthorization verifier policy =>
      verifier = subject.verifier ∧ policy = subject.policy

def ratsSubjectBoundProfile
    (policy : MultiPremisePolicy RatsClaim) (subject : RatsSubject) :
    SubjectBoundProfile RatsSubject RatsFact RatsClaim := {
  policy := policy
  rules := [ratsAppraisalRule subject]
  claimSubject := ratsClaimSubject
  factMatches := ratsFactMatches
  nonemptyPremises := by
    intro rule inRules
    have onlyRule : rule = ratsAppraisalRule subject := by
      simpa using inRules
    subst rule
    simp [ratsAppraisalRule]
  exactPremises := by
    intro rule inRules premise required
    have onlyRule : rule = ratsAppraisalRule subject := by
      simpa using inRules
    subst rule
    simp [ratsAppraisalRule, ratsFactMatches] at required ⊢
    rcases required with rfl | rfl | rfl | rfl | rfl <;>
      simp [ratsClaimSubject]
}

theorem complete_exact_rats_evidence_derives
    {policy : MultiPremisePolicy RatsClaim} {subject : RatsSubject}
    (permitted : policy.permits (.appraisalResult subject)) :
    RatsAppraises policy (ratsAppraisalRule subject).premises subject := by
  refine ⟨permitted, ratsAppraisalRule subject, ?_, rfl, ?_⟩
  · simp
  · intro premise isRequired
    exact isRequired

private theorem rats_rule_is_only_candidate
    {policy : MultiPremisePolicy RatsClaim} {evidence : List RatsFact}
    {subject : RatsSubject}
    (derived : RatsAppraises policy evidence subject) :
    ∀ premise, premise ∈ (ratsAppraisalRule subject).premises → premise ∈ evidence := by
  rcases multiPremiseDerives_has_complete_rule derived with
    ⟨rule, inRules, _conclusion, allPremises⟩
  have sameRule : rule = ratsAppraisalRule subject := by
    simpa using inRules
  simpa [sameRule] using allPremises

theorem rats_appraisal_requires_token_signature
    {policy : MultiPremisePolicy RatsClaim} {evidence : List RatsFact}
    {subject : RatsSubject}
    (derived : RatsAppraises policy evidence subject) :
    .tokenSignature subject.token subject.attester ∈ evidence := by
  exact rats_rule_is_only_candidate derived _ (by simp [ratsAppraisalRule])

theorem rats_appraisal_requires_measurement_binding
    {policy : MultiPremisePolicy RatsClaim} {evidence : List RatsFact}
    {subject : RatsSubject}
    (derived : RatsAppraises policy evidence subject) :
    .measurementBinding subject.token subject.measurement ∈ evidence := by
  exact rats_rule_is_only_candidate derived _ (by simp [ratsAppraisalRule])

theorem rats_appraisal_requires_exact_freshness
    {policy : MultiPremisePolicy RatsClaim} {evidence : List RatsFact}
    {subject : RatsSubject}
    (derived : RatsAppraises policy evidence subject) :
    .freshnessBinding subject.token subject.nonce ∈ evidence := by
  exact rats_rule_is_only_candidate derived _ (by simp [ratsAppraisalRule])

theorem rats_appraisal_requires_reference_value
    {policy : MultiPremisePolicy RatsClaim} {evidence : List RatsFact}
    {subject : RatsSubject}
    (derived : RatsAppraises policy evidence subject) :
    .referenceValue subject.measurement subject.reference ∈ evidence := by
  exact rats_rule_is_only_candidate derived _ (by simp [ratsAppraisalRule])

theorem rats_appraisal_requires_verifier_authorization
    {policy : MultiPremisePolicy RatsClaim} {evidence : List RatsFact}
    {subject : RatsSubject}
    (derived : RatsAppraises policy evidence subject) :
    .verifierAuthorization subject.verifier subject.policy ∈ evidence := by
  exact rats_rule_is_only_candidate derived _ (by simp [ratsAppraisalRule])

theorem missing_exact_nonce_blocks_rats_appraisal
    {policy : MultiPremisePolicy RatsClaim} {evidence : List RatsFact}
    {subject : RatsSubject}
    (absent : .freshnessBinding subject.token subject.nonce ∉ evidence) :
    ¬ RatsAppraises policy evidence subject := by
  intro derived
  exact absent (rats_appraisal_requires_exact_freshness derived)

def ratsEvidenceWithOtherNonce (subject : RatsSubject) (otherNonce : Nat) :
    List RatsFact := [
  .tokenSignature subject.token subject.attester,
  .measurementBinding subject.token subject.measurement,
  .freshnessBinding subject.token otherNonce,
  .referenceValue subject.measurement subject.reference,
  .verifierAuthorization subject.verifier subject.policy
]

theorem different_nonce_fixture_does_not_satisfy_exact_freshness
    {policy : MultiPremisePolicy RatsClaim} {subject : RatsSubject}
    {otherNonce : Nat}
    (different : otherNonce ≠ subject.nonce) :
    ¬ RatsAppraises policy (ratsEvidenceWithOtherNonce subject otherNonce) subject := by
  apply missing_exact_nonce_blocks_rats_appraisal
  simp [ratsEvidenceWithOtherNonce, Ne.symm different]

theorem unpermitted_rats_result_has_no_derivation
    {policy : MultiPremisePolicy RatsClaim} {evidence : List RatsFact}
    {subject : RatsSubject}
    (forbidden : ¬ policy.permits (.appraisalResult subject)) :
    ¬ RatsAppraises policy evidence subject := by
  exact nonpermitted_claim_has_no_derivation forbidden

/-! The generic profile is instantiated here only after the concrete RATS
rule has fixed five nonempty, exact-subject premises.  This is a structural
re-use check, not a claim that this abstract model parses or validates EAT. -/

theorem rats_appraisal_has_subject_matched_support
    {policy : MultiPremisePolicy RatsClaim} {evidence : List RatsFact}
    {subject : RatsSubject}
    (derived : RatsAppraises policy evidence subject) :
    ∃ fact, fact ∈ evidence ∧ ratsFactMatches fact subject := by
  exact subjectBoundDerives_has_exact_subject_support
    (profile := ratsSubjectBoundProfile policy subject) derived

theorem no_subject_matched_rats_evidence_blocks_appraisal
    {policy : MultiPremisePolicy RatsClaim} {evidence : List RatsFact}
    {subject : RatsSubject}
    (noMatch : ∀ fact, fact ∈ evidence → ¬ ratsFactMatches fact subject) :
    ¬ RatsAppraises policy evidence subject := by
  exact no_subject_matched_evidence_blocks_derivation
    (profile := ratsSubjectBoundProfile policy subject) rfl noMatch

end ACSD
