import ACSD.Core

set_option autoImplicit false
set_option warningAsError true

namespace ACSD

structure Head where
  version : Nat
  digest : Digest
  deriving DecidableEq, Repr

def Extends (continuation : Head → Head → Prop) (candidate known : Head) : Prop :=
  continuation known candidate ∧ known.version < candidate.version

def AcceptCurrent (continuation : Head → Head → Prop) (known : Option Head) (candidate : Head) : Prop :=
  match known with
  | none => True
  | some head => candidate = head ∨ Extends continuation candidate head

theorem same_version_switch_rejected
    {continuation : Head → Head → Prop} {known candidate : Head}
    (same_version : candidate.version = known.version)
    (different_digest : candidate.digest ≠ known.digest) :
    ¬ AcceptCurrent continuation (some known) candidate := by
  intro accepted
  change candidate = known ∨ Extends continuation candidate known at accepted
  rcases accepted with same | extended
  · exact different_digest (congrArg Head.digest same)
  · have version_transport :
        (known.version < candidate.version) = (known.version < known.version) :=
      congrArg (fun version => known.version < version) same_version
    have impossible : known.version < known.version := version_transport.mp extended.2
    exact (Nat.lt_irrefl known.version) impossible

theorem observed_head_preserved
    {continuation : Head → Head → Prop} {known candidate : Head}
    (accepted : AcceptCurrent continuation (some known) candidate) :
    candidate = known ∨ Extends continuation candidate known := by
  simpa only [AcceptCurrent] using accepted

def HistoricalPolicyValid (model : AuthModel) (catalog : Catalog) (request : Request) (plan : Plan) : Prop :=
  Verify model catalog request plan

def AcceptAsPreSuspension
    (prior : Plan → Nat → Prop) (cutoff : Nat)
    (model : AuthModel) (catalog : Catalog) (request : Request) (plan : Plan) : Prop :=
  HistoricalPolicyValid model catalog request plan ∧ prior plan cutoff

theorem historical_label_requires_prior
    {prior : Plan → Nat → Prop} {cutoff : Nat}
    {model : AuthModel} {catalog : Catalog} {request : Request} {plan : Plan}
    (accepted : AcceptAsPreSuspension prior cutoff model catalog request plan) :
    prior plan cutoff :=
  accepted.2

theorem no_postcutoff_backfill
    {prior : Plan → Nat → Prop} {issuedAt : Plan → Nat} {cutoff : Nat}
    (prior_sound : ∀ plan cutoff, prior plan cutoff → issuedAt plan < cutoff)
    {model : AuthModel} {catalog : Catalog} {request : Request} {plan : Plan}
    (after_cutoff : cutoff ≤ issuedAt plan) :
    ¬ AcceptAsPreSuspension prior cutoff model catalog request plan := by
  intro accepted
  have before_cutoff : issuedAt plan < cutoff := prior_sound plan cutoff accepted.2
  exact (Nat.not_lt_of_ge after_cutoff) before_cutoff

def Necessary (catalog : Catalog) (request : Request) (component : ComponentId) : Prop :=
  ∀ selection, Feasible catalog request selection → selection component

theorem suspension_unsat_if_necessary
    {model : AuthModel} {catalog : Catalog} {request : Request} {component : ComponentId}
    (necessary : Necessary catalog request component)
    (suspended : ¬ catalog.active component) :
    ¬ ∃ plan, Verify model catalog request plan := by
  rintro ⟨plan, accepted⟩
  apply suspended
  exact accepted.feasible.1 component (necessary plan.selected accepted.feasible)

end ACSD
