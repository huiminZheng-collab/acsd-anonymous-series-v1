import ACSD.RatsAppraisal
import ACSD.StrictJson
import Lean.Data.Json.Parser
import Lean.Data.Json.Printer

set_option autoImplicit false
set_option warningAsError true

namespace ACSD

open Lean

/-! A research-only, claim-free canonical transcript for the RATS appraisal
instance.  It does not parse EAT, verify COSE, or assess a device.  Each fact
stands for a result supplied by an external adapter. -/

private def ratsFactRank : RatsFact → Nat
  | .tokenSignature .. => 0
  | .measurementBinding .. => 1
  | .freshnessBinding .. => 2
  | .referenceValue .. => 3
  | .verifierAuthorization .. => 4

private def ratsCanonicalEvidenceB (facts : List RatsFact) : Bool :=
  decide (facts.Pairwise fun left right => ratsFactRank left < ratsFactRank right)

private def ratsSubject (json : Json) : Except String RatsSubject := do
  StrictJson.expectFields json ["token", "attester", "measurement", "reference",
    "nonce", "verifier", "policy"] "RATS_TRANSCRIPT_SUBJECT"
  pure {
    token := ← StrictJson.positiveNatField json "token" "RATS_TRANSCRIPT_SUBJECT"
    attester := ← StrictJson.positiveNatField json "attester" "RATS_TRANSCRIPT_SUBJECT"
    measurement := ← StrictJson.positiveNatField json "measurement" "RATS_TRANSCRIPT_SUBJECT"
    reference := ← StrictJson.positiveNatField json "reference" "RATS_TRANSCRIPT_SUBJECT"
    nonce := ← StrictJson.positiveNatField json "nonce" "RATS_TRANSCRIPT_SUBJECT"
    verifier := ← StrictJson.positiveNatField json "verifier" "RATS_TRANSCRIPT_SUBJECT"
    policy := ← StrictJson.positiveNatField json "policy" "RATS_TRANSCRIPT_SUBJECT"
  }

private def ratsFact (json : Json) : Except String RatsFact := do
  let kind ← StrictJson.stringField json "kind" "RATS_TRANSCRIPT_EVIDENCE_KIND"
  match kind with
  | "TOKEN_SIGNATURE" =>
      StrictJson.expectFields json ["index", "kind", "token", "attester"]
        "RATS_TRANSCRIPT_EVIDENCE_ITEM"
      pure <| .tokenSignature
        (← StrictJson.positiveNatField json "token" "RATS_TRANSCRIPT_EVIDENCE_ITEM")
        (← StrictJson.positiveNatField json "attester" "RATS_TRANSCRIPT_EVIDENCE_ITEM")
  | "MEASUREMENT_BINDING" =>
      StrictJson.expectFields json ["index", "kind", "token", "measurement"]
        "RATS_TRANSCRIPT_EVIDENCE_ITEM"
      pure <| .measurementBinding
        (← StrictJson.positiveNatField json "token" "RATS_TRANSCRIPT_EVIDENCE_ITEM")
        (← StrictJson.positiveNatField json "measurement" "RATS_TRANSCRIPT_EVIDENCE_ITEM")
  | "FRESHNESS_BINDING" =>
      StrictJson.expectFields json ["index", "kind", "token", "nonce"]
        "RATS_TRANSCRIPT_EVIDENCE_ITEM"
      pure <| .freshnessBinding
        (← StrictJson.positiveNatField json "token" "RATS_TRANSCRIPT_EVIDENCE_ITEM")
        (← StrictJson.positiveNatField json "nonce" "RATS_TRANSCRIPT_EVIDENCE_ITEM")
  | "REFERENCE_VALUE" =>
      StrictJson.expectFields json ["index", "kind", "measurement", "reference"]
        "RATS_TRANSCRIPT_EVIDENCE_ITEM"
      pure <| .referenceValue
        (← StrictJson.positiveNatField json "measurement" "RATS_TRANSCRIPT_EVIDENCE_ITEM")
        (← StrictJson.positiveNatField json "reference" "RATS_TRANSCRIPT_EVIDENCE_ITEM")
  | "VERIFIER_AUTHORIZATION" =>
      StrictJson.expectFields json ["index", "kind", "verifier", "policy"]
        "RATS_TRANSCRIPT_EVIDENCE_ITEM"
      pure <| .verifierAuthorization
        (← StrictJson.positiveNatField json "verifier" "RATS_TRANSCRIPT_EVIDENCE_ITEM")
        (← StrictJson.positiveNatField json "policy" "RATS_TRANSCRIPT_EVIDENCE_ITEM")
  | _ => throw "RATS_TRANSCRIPT_EVIDENCE_KIND"

private structure IndexedRatsFact where
  index : Nat
  fact : RatsFact
  deriving DecidableEq, Repr

private def indexedRatsFact (json : Json) : Except String IndexedRatsFact := do
  pure {
    index := ← StrictJson.natField json "index" "RATS_TRANSCRIPT_EVIDENCE_INDEX"
    fact := ← ratsFact json
  }

private def ratsPermission (json : Json) : Except String Bool := do
  StrictJson.expectFields json ["permitted_outcomes"] "RATS_TRANSCRIPT_POLICY"
  let names ← (← StrictJson.arrayField json "permitted_outcomes"
    "RATS_TRANSCRIPT_POLICY").toList.mapM fun item =>
      StrictJson.remap "RATS_TRANSCRIPT_POLICY" item.getStr?
  StrictJson.requireB (names == [] || names == ["APPRAISAL_RESULT"])
    "RATS_TRANSCRIPT_POLICY"
  pure (names == ["APPRAISAL_RESULT"])

structure RawRatsAppraisalTranscript where
  permitted : Bool
  subject : RatsSubject
  evidence : List RatsFact
  deriving Repr

def decodeRatsAppraisalTranscriptJson
    (json : Json) : Except String RawRatsAppraisalTranscript := do
  StrictJson.expectFields json ["schema", "policy", "subject", "evidence"]
    "RATS_TRANSCRIPT_FIELDS"
  StrictJson.requireB ((← StrictJson.stringField json "schema"
    "RATS_TRANSCRIPT_SCHEMA") == "acsd-rats-appraisal-transcript/v1")
    "RATS_TRANSCRIPT_SCHEMA"
  let indexed ← (← StrictJson.arrayField json "evidence"
    "RATS_TRANSCRIPT_EVIDENCE").toList.mapM indexedRatsFact
  StrictJson.requireB (decide (indexed.map (·.index) = List.range indexed.length))
    "RATS_TRANSCRIPT_EVIDENCE_ORDER"
  let evidence := indexed.map (·.fact)
  StrictJson.requireB (ratsCanonicalEvidenceB evidence)
    "RATS_TRANSCRIPT_EVIDENCE_ORDER"
  pure {
    permitted := ← ratsPermission
      (← StrictJson.field json "policy" "RATS_TRANSCRIPT_POLICY")
    subject := ← ratsSubject
      (← StrictJson.field json "subject" "RATS_TRANSCRIPT_SUBJECT")
    evidence := evidence
  }

def decodeRatsAppraisalTranscriptText
    (text : String) : Except String RawRatsAppraisalTranscript := do
  let json ← StrictJson.remap "RATS_TRANSCRIPT_JSON_INVALID" (Json.parse text)
  let compressed := json.compress
  StrictJson.requireB (text == compressed || text == compressed ++ "\n")
    "RATS_TRANSCRIPT_JSON_NONCANONICAL"
  decodeRatsAppraisalTranscriptJson json

def ratsTranscriptPolicy
    (raw : RawRatsAppraisalTranscript) : MultiPremisePolicy RatsClaim := {
  permits := fun claim => raw.permitted = true ∧ claim = .appraisalResult raw.subject
}

def ratsEvidenceCompleteB (raw : RawRatsAppraisalTranscript) : Bool :=
  (ratsAppraisalRule raw.subject).premises.all fun premise =>
    decide (premise ∈ raw.evidence)

def ratsTranscriptCheckB (raw : RawRatsAppraisalTranscript) : Bool :=
  raw.permitted && ratsEvidenceCompleteB raw

theorem ratsTranscriptCheckB_sound
    {raw : RawRatsAppraisalTranscript}
    (accepted : ratsTranscriptCheckB raw = true) :
    RatsAppraises (ratsTranscriptPolicy raw) raw.evidence raw.subject := by
  have parts : raw.permitted = true ∧ ratsEvidenceCompleteB raw = true := by
    simpa [ratsTranscriptCheckB] using accepted
  refine ⟨⟨parts.1, rfl⟩, ratsAppraisalRule raw.subject, ?_, rfl, ?_⟩
  · simp
  · intro premise required
    have allPresent := List.all_eq_true.mp parts.2
    exact of_decide_eq_true (allPresent premise required)

def deriveRatsAppraisalTranscript
    (raw : RawRatsAppraisalTranscript) : List RatsClaim :=
  if ratsTranscriptCheckB raw = true then [.appraisalResult raw.subject] else []

theorem derivedRatsAppraisalTranscript_sound
    {raw : RawRatsAppraisalTranscript} {claim : RatsClaim}
    (member : claim ∈ deriveRatsAppraisalTranscript raw) :
    RatsAppraises (ratsTranscriptPolicy raw) raw.evidence raw.subject := by
  by_cases accepted : ratsTranscriptCheckB raw = true
  · have exactClaim : claim = .appraisalResult raw.subject := by
      simpa [deriveRatsAppraisalTranscript, accepted] using member
    subst claim
    exact ratsTranscriptCheckB_sound accepted
  · simp [deriveRatsAppraisalTranscript, accepted] at member

theorem decodedRatsAppraisalTranscriptOutcome_sound
    {text : String} {raw : RawRatsAppraisalTranscript} {claim : RatsClaim}
    (decoded : decodeRatsAppraisalTranscriptText text = .ok raw)
    (member : claim ∈ deriveRatsAppraisalTranscript raw) :
    decodeRatsAppraisalTranscriptText text = .ok raw ∧
      RatsAppraises (ratsTranscriptPolicy raw) raw.evidence raw.subject := by
  exact ⟨decoded, derivedRatsAppraisalTranscript_sound member⟩

end ACSD
