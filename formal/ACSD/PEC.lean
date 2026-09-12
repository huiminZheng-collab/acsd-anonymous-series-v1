import ACSD.Core

set_option autoImplicit false
set_option warningAsError true

namespace ACSD

/-- A pseudonymous author key identifier. -/
structure KeyId where
  value : Nat
  deriving DecidableEq, Repr

/-- One provenance event: a sequence number, an id, and the digest of the
preceding event (none for the first event). -/
structure Event where
  sequence : Nat
  eventId : Nat
  previousEventDigest : Option Nat
  deriving Repr

/-- The claim policy: permitted outcomes and the globally forbidden social
claims that must never be emitted. -/
structure ClaimPolicy where
  permittedOutcomes : List Nat
  globalNonClaims : List Nat

/-- A provenance evidence capsule modeled as real data structures, not
uninterpreted propositions. -/
structure PEC where
  requiredKeys : List KeyId
  approvedKeys : List KeyId
  events : List Event
  policy : ClaimPolicy

-- ---------------------------------------------------------------------------
-- Event chain: sequences are consecutive from 0, and each event's
-- previousEventDigest links to the preceding event's id.
-- ---------------------------------------------------------------------------

def ChainLink : List Event → Event → Prop
  | [], _ => True
  | e :: rest, prev =>
      e.sequence = prev.sequence + 1 ∧
      e.previousEventDigest = some prev.eventId ∧
      ChainLink rest e

def ChainValid : List Event → Prop
  | [] => True
  | e0 :: rest =>
      e0.sequence = 0 ∧ e0.previousEventDigest = none ∧ ChainLink rest e0

-- Adjacent events have consecutive (+1) sequences.
def SequenceChain : List Event → Prop
  | [] => True
  | [_] => True
  | a :: b :: rest => a.sequence + 1 = b.sequence ∧ SequenceChain (b :: rest)

-- ---------------------------------------------------------------------------
-- Approval and claim policy.
-- ---------------------------------------------------------------------------

def AllApproved (required approved : List KeyId) : Prop :=
  ∀ k, k ∈ required → k ∈ approved

def ForbidsSocialClaims (p : ClaimPolicy) : Prop :=
  ∀ o, o ∈ p.globalNonClaims → o ∉ p.permittedOutcomes

def Accepted (p : PEC) : Prop :=
  AllApproved p.requiredKeys p.approvedKeys ∧ ChainValid p.events ∧ ForbidsSocialClaims p.policy

-- ---------------------------------------------------------------------------
-- Theorems.
-- ---------------------------------------------------------------------------

theorem chain_link_sequence_increments {e prev : Event} {rest : List Event}
    (h : ChainLink (e :: rest) prev) : e.sequence = prev.sequence + 1 := h.1

theorem chain_link_previous_links {e prev : Event} {rest : List Event}
    (h : ChainLink (e :: rest) prev) : e.previousEventDigest = some prev.eventId := h.2.1

/-- ChainLink preserves consecutive sequences by induction on the tail. -/
theorem chain_link_sequence_chain {prev : Event} {events : List Event}
    (h : ChainLink events prev) : SequenceChain (prev :: events) := by
  induction events generalizing prev with
  | nil => trivial
  | cons e rest ih =>
      cases rest with
      | nil =>
          unfold SequenceChain
          exact And.intro h.1.symm trivial
      | cons e2 rest2 =>
          have hrest : ChainLink (e2 :: rest2) e := h.2.2
          have hind : SequenceChain (e :: e2 :: rest2) := ih hrest
          change (prev.sequence + 1 = e.sequence) ∧ SequenceChain (e :: e2 :: rest2)
          exact And.intro h.1.symm hind

/-- A valid chain has consecutive sequences (via ChainLink). -/
theorem chain_valid_sequence_chain {e0 : Event} {rest : List Event}
    (h : ChainValid (e0 :: rest)) : SequenceChain (e0 :: rest) :=
  chain_link_sequence_chain h.2.2

/-- Approval is transitive across three lists. -/
theorem all_approved_trans {a b c : List KeyId}
    (h1 : AllApproved a b) (h2 : AllApproved b c) : AllApproved a c := by
  intro k hk
  exact h2 k (h1 k hk)

/-- Adding an approver never breaks approval. -/
theorem all_approved_cons {k : KeyId} {required approved : List KeyId}
    (h : AllApproved required approved) : AllApproved required (k :: approved) := by
  intro x hx
  exact List.mem_cons_of_mem k (h x hx)

/-- A forbidden social claim is not a permitted outcome. -/
theorem forbids_social_claims_apply {p : ClaimPolicy} {o : Nat}
    (h : ForbidsSocialClaims p) (ho : o ∈ p.globalNonClaims) : o ∉ p.permittedOutcomes :=
  h o ho

/-- Acceptance implies every required key approved. -/
theorem accepted_implies_all_approved {p : PEC} (h : Accepted p) :
    AllApproved p.requiredKeys p.approvedKeys := h.1

/-- Acceptance implies the claim policy forbids social claims. -/
theorem accepted_forbids_social_claims {p : PEC} (h : Accepted p) :
    ForbidsSocialClaims p.policy := h.2.2

/-- Acceptance implies the event chain is valid. -/
theorem accepted_chain_valid {p : PEC} (h : Accepted p) : ChainValid p.events := h.2.1

end ACSD
