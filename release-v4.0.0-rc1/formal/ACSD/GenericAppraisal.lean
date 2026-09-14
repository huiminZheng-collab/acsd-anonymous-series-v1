set_option autoImplicit false
set_option warningAsError true

namespace ACSD

/-! A deliberately small multi-premise appraisal calculus.  This module is a
formal generalization experiment, not a new ACSD wire format or policy
language.  It says only that a permitted conclusion follows from one named
rule when every exact premise of that rule is present. -/

structure MultiPremiseRule (Fact Claim : Type) where
  conclusion : Claim
  premises : List Fact

structure MultiPremisePolicy (Claim : Type) where
  permits : Claim → Prop

def MultiPremiseDerives
    {Fact Claim : Type}
    (policy : MultiPremisePolicy Claim)
    (evidence : List Fact)
    (rules : List (MultiPremiseRule Fact Claim))
    (claim : Claim) : Prop :=
  policy.permits claim ∧
  ∃ rule, rule ∈ rules ∧ rule.conclusion = claim ∧
    ∀ premise, premise ∈ rule.premises → premise ∈ evidence

theorem multiPremiseDerives_requires_permission
    {Fact Claim : Type}
    {policy : MultiPremisePolicy Claim} {evidence : List Fact}
    {rules : List (MultiPremiseRule Fact Claim)} {claim : Claim}
    (derived : MultiPremiseDerives policy evidence rules claim) :
    policy.permits claim := derived.1

theorem multiPremiseDerives_has_complete_rule
    {Fact Claim : Type}
    {policy : MultiPremisePolicy Claim} {evidence : List Fact}
    {rules : List (MultiPremiseRule Fact Claim)} {claim : Claim}
    (derived : MultiPremiseDerives policy evidence rules claim) :
    ∃ rule, rule ∈ rules ∧ rule.conclusion = claim ∧
      ∀ premise, premise ∈ rule.premises → premise ∈ evidence := derived.2

theorem missing_required_premise_blocks_derivation
    {Fact Claim : Type}
    {policy : MultiPremisePolicy Claim} {evidence : List Fact}
    {rules : List (MultiPremiseRule Fact Claim)} {claim : Claim} {missing : Fact}
    (required : ∀ rule, rule ∈ rules → rule.conclusion = claim → missing ∈ rule.premises)
    (absent : missing ∉ evidence) :
    ¬ MultiPremiseDerives policy evidence rules claim := by
  intro derived
  rcases multiPremiseDerives_has_complete_rule derived with
    ⟨rule, inRules, conclusion, allPremises⟩
  exact absent (allPremises missing (required rule inRules conclusion))

theorem nonpermitted_claim_has_no_derivation
    {Fact Claim : Type}
    {policy : MultiPremisePolicy Claim} {evidence : List Fact}
    {rules : List (MultiPremiseRule Fact Claim)} {claim : Claim}
    (forbidden : ¬ policy.permits claim) :
    ¬ MultiPremiseDerives policy evidence rules claim := by
  intro derived
  exact forbidden (multiPremiseDerives_requires_permission derived)

end ACSD
