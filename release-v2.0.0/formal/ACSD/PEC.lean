import ACSD.Core

set_option autoImplicit false
set_option warningAsError true

namespace ACSD

structure KeyId where
  value : Nat
  deriving DecidableEq

/-! Abstract PEC safety model. Hashes and signatures are assumptions; the
theorems state only binding and claim-policy consequences. -/
structure PECPolicy where
  permitsKeyAssent : Prop
  permitsEvidenceMatch : Prop
  forbidsSocialClaims : Prop

structure PEC where
  body : Digest
  policy : PECPolicy
  requiredKeys : KeyId → Prop
  approvedKeys : KeyId → Prop
  eventSequenceValid : Prop

def AllApproved (p : PEC) : Prop := ∀ key, p.requiredKeys key → p.approvedKeys key

def Accepted (p : PEC) : Prop :=
  AllApproved p ∧ p.eventSequenceValid ∧ p.policy.forbidsSocialClaims

theorem accepted_implies_all_required_keys_approved
    {p : PEC} (h : Accepted p) : AllApproved p := h.1

theorem accepted_cannot_emit_social_claim
    {p : PEC} (h : Accepted p) : p.policy.forbidsSocialClaims := h.2.2

theorem missing_approval_prevents_acceptance
    {p : PEC} {key : KeyId}
    (required : p.requiredKeys key) (missing : ¬ p.approvedKeys key) :
    ¬ Accepted p := by
  intro accepted
  exact missing (accepted.1 key required)

theorem invalid_event_sequence_prevents_acceptance
    {p : PEC} (invalid : ¬ p.eventSequenceValid) : ¬ Accepted p := by
  intro accepted
  exact invalid accepted.2.1

end ACSD
