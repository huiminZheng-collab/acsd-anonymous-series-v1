import ACSD.Transcript
import Lean.Data.Json.Parser
import Lean.Data.Json.Printer

set_option autoImplicit false
set_option warningAsError true

namespace ACSD

open Lean

private def maxSafeInteger : Nat := 9007199254740991

private def requireB (condition : Bool) (code : String) : Except String Unit :=
  if condition then pure () else throw code

private def remap {α : Type} (code : String)
    (result : Except String α) : Except String α :=
  result.mapError fun _ => code

private def expectFields
    (json : Json) (fields : List String) (code : String) : Except String Unit := do
  let object ← remap code json.getObj?
  let count := object.foldl (fun total _ _ => total + 1) 0
  requireB (count == fields.length) code
  for field in fields do
    let _ ← remap code (json.getObjVal? field)

private def field (json : Json) (name code : String) : Except String Json :=
  remap code (json.getObjVal? name)

private def stringField
    (json : Json) (name code : String) : Except String String := do
  remap code (← field json name code).getStr?

private def natField
    (json : Json) (name code : String) : Except String Nat := do
  let value ← remap code (← field json name code).getNat?
  requireB (decide (value ≤ maxSafeInteger)) code
  pure value

private def arrayValue (json : Json) (code : String) : Except String (Array Json) :=
  remap code json.getArr?

private def arrayField
    (json : Json) (name code : String) : Except String (Array Json) := do
  arrayValue (← field json name code) code

private def hexNibble : Char → Option Nat
  | '0' => some 0 | '1' => some 1 | '2' => some 2 | '3' => some 3
  | '4' => some 4 | '5' => some 5 | '6' => some 6 | '7' => some 7
  | '8' => some 8 | '9' => some 9 | 'a' => some 10 | 'b' => some 11
  | 'c' => some 12 | 'd' => some 13 | 'e' => some 14 | 'f' => some 15
  | _ => none

private def hexNat (text code : String) : Except String Nat := do
  requireB (text.length == 64) code
  let digits ← text.toList.mapM fun character =>
    match hexNibble character with
    | some digit => pure digit
    | none => throw code
  pure <| digits.foldl (fun value digit => value * 16 + digit) 0

def decodeDigestText (text : String) : Except String Digest := do
  pure { value := ← hexNat text "TRANSCRIPT_CERTIFICATE_DIGEST" }

private def digestField
    (json : Json) (name code : String) : Except String Digest := do
  pure { value := ← hexNat (← stringField json name code) code }

private def keyValue (json : Json) (code : String) : Except String KeyId := do
  let text ← remap code json.getStr?
  pure { value := ← hexNat text code }

private def keyArrayField
    (json : Json) (name code : String) : Except String (List KeyId) := do
  let keys ← (← arrayField json name code).toList.mapM fun item => keyValue item code
  requireB (!keys.isEmpty && decide keys.Nodup) code
  pure keys

private def decodeClaim (json : Json) : Except String ScopedClaim := do
  match ← remap "TRANSCRIPT_POLICY_CLAIM" json.getStr? with
  | "KEY_ASSENT" => pure .keyAssent
  | "GOVERNANCE_ASSENT" => pure .governanceAssent
  | "COMMITTED_EVIDENCE_MATCH" => pure .committedEvidenceMatch
  | "SLOT_KEY_ASSENT_TO_IDENTITY_ASSERTION" => pure .slotKeyIdentityAssent
  | _ => throw "TRANSCRIPT_POLICY_CLAIM"

private def allowedInputRole (role : String) : Bool :=
  ["approval-target", "pec", "event-disclosure", "public-key",
    "author-approval-cose", "event-disclosure-cose", "release",
    "identity-disclosure", "identity-disclosure-cose"].contains role

structure RawTranscriptInput where
  role : String
  path : String
  digest : Digest
  deriving DecidableEq, Repr

private def decodeInput (json : Json) : Except String RawTranscriptInput := do
  expectFields json ["role", "path", "sha256"] "TRANSCRIPT_INPUT"
  let role ← stringField json "role" "TRANSCRIPT_INPUT_ROLE"
  requireB (allowedInputRole role) "TRANSCRIPT_INPUT_ROLE"
  let path ← stringField json "path" "TRANSCRIPT_INPUT_PATH"
  requireB (!path.isEmpty) "TRANSCRIPT_INPUT_PATH"
  pure {
    role := role
    path := path
    digest := ← digestField json "sha256" "TRANSCRIPT_INPUT_DIGEST"
  }

private def decodePurpose (json : Json) : Except String SignaturePurpose := do
  match ← remap "TRANSCRIPT_SIGNATURE_PURPOSE" json.getStr? with
  | "author-approval" => pure .authorApproval
  | "event-disclosure" => pure .eventDisclosure
  | "identity-disclosure" => pure .identityDisclosure
  | _ => throw "TRANSCRIPT_SIGNATURE_PURPOSE"

private def decodeSignature (json : Json) : Except String TranscriptSignature := do
  expectFields json ["purpose", "key_id", "payload_digest", "cose_digest"]
    "TRANSCRIPT_SIGNATURE_FACT"
  pure {
    purpose := ← decodePurpose (← field json "purpose" "TRANSCRIPT_SIGNATURE_PURPOSE")
    key := ← keyValue (← field json "key_id" "TRANSCRIPT_SIGNATURE_KEY")
      "TRANSCRIPT_SIGNATURE_KEY"
    payloadDigest := ← digestField json "payload_digest" "TRANSCRIPT_SIGNATURE_PAYLOAD"
    coseDigest := ← digestField json "cose_digest" "TRANSCRIPT_SIGNATURE_COSE"
  }

private def decodeMerkle (json : Json) : Except String TranscriptMerkle := do
  expectFields json ["body_digest", "commitment_digest", "first_index",
    "last_index", "opened_leaf_count"] "TRANSCRIPT_MERKLE_FACT"
  pure {
    bodyDigest := ← digestField json "body_digest" "TRANSCRIPT_MERKLE_BODY"
    commitmentDigest := ← digestField json "commitment_digest"
      "TRANSCRIPT_MERKLE_COMMITMENT"
    firstIndex := ← natField json "first_index" "TRANSCRIPT_MERKLE_FIRST_INDEX"
    lastIndex := ← natField json "last_index" "TRANSCRIPT_MERKLE_LAST_INDEX"
    openedLeafCount := ← natField json "opened_leaf_count"
      "TRANSCRIPT_MERKLE_LEAF_COUNT"
  }

private def decodeAuthorSlot (json : Json) : Except String (Nat × KeyId) := do
  expectFields json ["slot", "key_id"] "TRANSCRIPT_AUTHOR_SLOT"
  let slot ← natField json "slot" "TRANSCRIPT_AUTHOR_SLOT"
  requireB (decide (0 < slot)) "TRANSCRIPT_AUTHOR_SLOT"
  pure (slot, ← keyValue (← field json "key_id" "TRANSCRIPT_AUTHOR_SLOT_KEY")
    "TRANSCRIPT_AUTHOR_SLOT_KEY")

private def decodeIdentity (json : Json) : Except String TranscriptIdentity := do
  expectFields json ["body_digest", "release_digest", "author_slot",
    "author_key_id", "assertion_digest", "cose_digest"]
    "TRANSCRIPT_IDENTITY_ASSERTION"
  let slot ← natField json "author_slot" "TRANSCRIPT_IDENTITY_SLOT"
  requireB (decide (0 < slot)) "TRANSCRIPT_IDENTITY_SLOT"
  pure {
    bodyDigest := ← digestField json "body_digest" "TRANSCRIPT_IDENTITY_BODY"
    releaseDigest := ← digestField json "release_digest" "TRANSCRIPT_IDENTITY_RELEASE"
    authorSlot := slot
    authorKey := ← keyValue (← field json "author_key_id" "TRANSCRIPT_IDENTITY_KEY")
      "TRANSCRIPT_IDENTITY_KEY"
    assertionDigest := ← digestField json "assertion_digest"
      "TRANSCRIPT_IDENTITY_ASSERTION_DIGEST"
    coseDigest := ← digestField json "cose_digest" "TRANSCRIPT_IDENTITY_COSE"
  }

structure RawCertificate where
  inputs : List RawTranscriptInput
  targetDigest : Digest
  approvalPecDigest : Digest
  approvalKeys : List KeyId
  policyPecDigest : Digest
  policyClaims : List ScopedClaim
  eventBodyDigest : Digest
  eventPecDigest : Digest
  eventId : String
  eventSequence : Nat
  eventCommitmentDigest : Digest
  eventFirstIndex : Nat
  eventLastIndex : Nat
  eventKeys : List KeyId
  releaseDigest : Option Digest
  releaseSlots : List (Nat × KeyId)
  identityFacts : List TranscriptIdentity
  signatures : List TranscriptSignature
  merkleFacts : List TranscriptMerkle
  deriving DecidableEq, Repr

private def inputDigests
    (role : String) (inputs : List RawTranscriptInput) : List Digest :=
  (inputs.filter fun item => item.role == role).map (·.digest)

def refineCertificate (raw : RawCertificate) : VerificationTranscript := {
  targetDigest := raw.targetDigest
  approvalPecDigest := raw.approvalPecDigest
  eventPecDigest := raw.eventPecDigest
  policyPecDigest := raw.policyPecDigest
  policyClaims := raw.policyClaims
  approvalKeys := raw.approvalKeys
  approvalCoseDigests := inputDigests "author-approval-cose" raw.inputs
  eventBodyDigest := raw.eventBodyDigest
  eventId := raw.eventId
  eventSequence := raw.eventSequence
  eventCommitmentDigest := raw.eventCommitmentDigest
  eventFirstIndex := raw.eventFirstIndex
  eventLastIndex := raw.eventLastIndex
  eventKeys := raw.eventKeys
  eventCoseDigests := inputDigests "event-disclosure-cose" raw.inputs
  releaseDigest := raw.releaseDigest
  releaseSlots := raw.releaseSlots
  identityFacts := raw.identityFacts
  identityCoseDigests := inputDigests "identity-disclosure-cose" raw.inputs
  signatures := raw.signatures
  merkleFacts := raw.merkleFacts
}

private def decodeCertificateCore
    (json : Json) (releaseDigest : Option Digest)
    (releaseSlots : List (Nat × KeyId))
    (identityFacts : List TranscriptIdentity) : Except String RawCertificate := do
  let inputs ← (← arrayField json "inputs" "TRANSCRIPT_INPUTS").toList.mapM decodeInput
  requireB (decide ((inputs.map (·.path)).Nodup)) "TRANSCRIPT_DUPLICATE_INPUT"

  let approval ← field json "approval_target" "TRANSCRIPT_APPROVAL_TARGET"
  expectFields approval ["target_digest", "pec_digest", "required_key_ids"]
    "TRANSCRIPT_APPROVAL_TARGET"

  let policy ← field json "policy" "TRANSCRIPT_POLICY"
  expectFields policy ["pec_digest", "permitted_outcomes"] "TRANSCRIPT_POLICY"
  let policyClaims ← (← arrayField policy "permitted_outcomes"
    "TRANSCRIPT_POLICY_CLAIMS").toList.mapM decodeClaim
  requireB (decide policyClaims.Nodup) "TRANSCRIPT_POLICY_DUPLICATE_CLAIM"

  let event ← field json "event_disclosure" "TRANSCRIPT_EVENT"
  expectFields event ["body_digest", "pec_digest", "event_id", "event_sequence",
    "commitment_digest", "first_index", "last_index", "required_key_ids"]
    "TRANSCRIPT_EVENT"
  let eventId ← stringField event "event_id" "TRANSCRIPT_EVENT_ID"
  requireB (!eventId.isEmpty) "TRANSCRIPT_EVENT_ID"
  let eventFirstIndex ← natField event "first_index" "TRANSCRIPT_EVENT_FIRST_INDEX"
  let eventLastIndex ← natField event "last_index" "TRANSCRIPT_EVENT_LAST_INDEX"
  requireB (decide (eventFirstIndex ≤ eventLastIndex)) "TRANSCRIPT_EVENT_WINDOW"

  let signatures ← (← arrayField json "signature_facts"
    "TRANSCRIPT_SIGNATURE_FACTS").toList.mapM decodeSignature
  let merkleFacts ← (← arrayField json "merkle_facts"
    "TRANSCRIPT_MERKLE_FACTS").toList.mapM decodeMerkle

  pure {
    inputs := inputs
    targetDigest := ← digestField approval "target_digest" "TRANSCRIPT_TARGET_DIGEST"
    approvalPecDigest := ← digestField approval "pec_digest" "TRANSCRIPT_APPROVAL_PEC"
    approvalKeys := ← keyArrayField approval "required_key_ids" "TRANSCRIPT_APPROVAL_KEYS"
    policyPecDigest := ← digestField policy "pec_digest" "TRANSCRIPT_POLICY_PEC"
    policyClaims := policyClaims
    eventBodyDigest := ← digestField event "body_digest" "TRANSCRIPT_EVENT_BODY"
    eventPecDigest := ← digestField event "pec_digest" "TRANSCRIPT_EVENT_PEC"
    eventId := eventId
    eventSequence := ← natField event "event_sequence" "TRANSCRIPT_EVENT_SEQUENCE"
    eventCommitmentDigest := ← digestField event "commitment_digest"
      "TRANSCRIPT_EVENT_COMMITMENT"
    eventFirstIndex := eventFirstIndex
    eventLastIndex := eventLastIndex
    eventKeys := ← keyArrayField event "required_key_ids" "TRANSCRIPT_EVENT_KEYS"
    releaseDigest := releaseDigest
    releaseSlots := releaseSlots
    identityFacts := identityFacts
    signatures := signatures
    merkleFacts := merkleFacts
  }

def decodeCertificateV1 (json : Json) : Except String RawCertificate := do
  expectFields json ["schema", "inputs", "approval_target", "policy",
    "event_disclosure", "signature_facts", "merkle_facts",
    "identity_assertions", "timestamp_facts", "trusted_inputs"]
    "TRANSCRIPT_FIELDS"
  requireB ((← stringField json "schema" "TRANSCRIPT_SCHEMA") ==
    "acsd-verification-certificate/v1") "TRANSCRIPT_SCHEMA"
  for extension in ["identity_assertions", "timestamp_facts", "trusted_inputs"] do
    requireB ((← arrayField json extension "TRANSCRIPT_UNSUPPORTED_EXTENSION").isEmpty)
      "TRANSCRIPT_UNSUPPORTED_EXTENSION"
  decodeCertificateCore json none [] []

def decodeCertificateV2 (json : Json) : Except String RawCertificate := do
  expectFields json ["schema", "inputs", "approval_target", "policy",
    "event_disclosure", "signature_facts", "merkle_facts",
    "identity_assertions", "timestamp_facts", "trusted_inputs",
    "release_context"] "TRANSCRIPT_FIELDS"
  requireB ((← stringField json "schema" "TRANSCRIPT_SCHEMA") ==
    "acsd-verification-certificate/v2") "TRANSCRIPT_SCHEMA"

  let release ← field json "release_context" "TRANSCRIPT_RELEASE_CONTEXT"
  expectFields release ["release_digest", "author_slots"] "TRANSCRIPT_RELEASE_CONTEXT"
  let releaseDigest ← digestField release "release_digest" "TRANSCRIPT_RELEASE_DIGEST"
  let releaseSlots ← (← arrayField release "author_slots"
    "TRANSCRIPT_AUTHOR_SLOTS").toList.mapM decodeAuthorSlot
  requireB (!releaseSlots.isEmpty &&
    decide ((releaseSlots.map Prod.fst).Nodup) &&
    decide ((releaseSlots.map Prod.snd).Nodup))
    "TRANSCRIPT_AUTHOR_SLOTS"

  let identityFacts ← (← arrayField json "identity_assertions"
    "TRANSCRIPT_IDENTITY_ASSERTIONS").toList.mapM decodeIdentity
  requireB (!identityFacts.isEmpty &&
    decide ((identityFacts.map (·.authorSlot)).Nodup))
    "TRANSCRIPT_IDENTITY_ASSERTIONS"

  for extension in ["timestamp_facts", "trusted_inputs"] do
    requireB ((← arrayField json extension "TRANSCRIPT_UNSUPPORTED_EXTENSION").isEmpty)
      "TRANSCRIPT_UNSUPPORTED_EXTENSION"
  decodeCertificateCore json (some releaseDigest) releaseSlots identityFacts

def decodeCertificateText (text : String) : Except String RawCertificate := do
  let json ← remap "TRANSCRIPT_JSON_INVALID" (Json.parse text)
  let compressed := json.compress
  requireB (text == compressed || text == compressed ++ "\n")
    "TRANSCRIPT_JSON_NONCANONICAL"
  match ← stringField json "schema" "TRANSCRIPT_SCHEMA" with
  | "acsd-verification-certificate/v1" => decodeCertificateV1 json
  | "acsd-verification-certificate/v2" => decodeCertificateV2 json
  | _ => throw "TRANSCRIPT_SCHEMA"

def deriveCertificate
    (raw : RawCertificate) (certificate : Digest) : List AppraisalRequest :=
  transcriptClaims (refineCertificate raw) certificate

theorem decodedCertificateV1Claims_sound
    {json : Json} {raw : RawCertificate} {certificate : Digest}
    {request : AppraisalRequest}
    (decoded : decodeCertificateV1 json = .ok raw)
    (member : request ∈ deriveCertificate raw certificate) :
    ∃ transcript,
      decodeCertificateV1 json = .ok raw ∧
      refineCertificate raw = transcript ∧
      TranscriptPolicyBound transcript ∧
      ∃ atom,
        TranscriptSupports transcript certificate atom ∧
        atom.subject = request.subject ∧ AppraisalRule atom.kind request.kind := by
  exact ⟨refineCertificate raw, decoded, rfl, transcriptClaims_sound member⟩

theorem decodedCertificateV2Claims_sound
    {json : Json} {raw : RawCertificate} {certificate : Digest}
    {request : AppraisalRequest}
    (decoded : decodeCertificateV2 json = .ok raw)
    (member : request ∈ deriveCertificate raw certificate) :
    ∃ transcript,
      decodeCertificateV2 json = .ok raw ∧
      refineCertificate raw = transcript ∧
      TranscriptPolicyBound transcript ∧
      ∃ atom,
        TranscriptSupports transcript certificate atom ∧
        atom.subject = request.subject ∧ AppraisalRule atom.kind request.kind := by
  exact ⟨refineCertificate raw, decoded, rfl, transcriptClaims_sound member⟩

end ACSD
