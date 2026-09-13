import ACSD.Transcript
import ACSD.LineageTranscript
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
  | "APPROVAL_SET_EXISTED_NOT_AFTER" => pure .approvalSetExistedNotAfter
  | "AUTHORIZED_SUCCESSOR" => pure .authorizedSuccessor
  | _ => throw "TRANSCRIPT_POLICY_CLAIM"

private def allowedInputRole (role : String) : Bool :=
  ["approval-target", "pec", "event-disclosure", "public-key",
    "author-approval-cose", "event-disclosure-cose", "release",
    "identity-disclosure", "identity-disclosure-cose", "approval-set",
    "time-request", "time-response", "tsa-certificate",
    "time-report"].contains role

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

private def decodeApprovalEntry (json : Json) : Except String (KeyId × Digest) := do
  expectFields json ["key_id", "cose_sha256"] "TRANSCRIPT_APPROVAL_SET_ENTRY"
  pure (
    ← keyValue (← field json "key_id" "TRANSCRIPT_APPROVAL_SET_KEY")
      "TRANSCRIPT_APPROVAL_SET_KEY",
    ← digestField json "cose_sha256" "TRANSCRIPT_APPROVAL_SET_COSE")

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
  timeFacts : List TranscriptTime
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
  timeFacts := raw.timeFacts
  approvalSetInputDigests := inputDigests "approval-set" raw.inputs
  timeRequestDigests := inputDigests "time-request" raw.inputs
  timeResponseDigests := inputDigests "time-response" raw.inputs
  tsaCertificateDigests := inputDigests "tsa-certificate" raw.inputs
  timeReportDigests := inputDigests "time-report" raw.inputs
  signatures := raw.signatures
  merkleFacts := raw.merkleFacts
}

private def decodeCertificateCore
    (json : Json) (releaseDigest : Option Digest)
    (releaseSlots : List (Nat × KeyId))
    (identityFacts : List TranscriptIdentity)
    (timeFacts : List TranscriptTime) : Except String RawCertificate := do
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
    timeFacts := timeFacts
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
  decodeCertificateCore json none [] [] []

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
  decodeCertificateCore json (some releaseDigest) releaseSlots identityFacts []

def decodeCertificateV3 (json : Json) : Except String RawCertificate := do
  expectFields json ["schema", "inputs", "approval_target", "policy",
    "event_disclosure", "signature_facts", "merkle_facts",
    "identity_assertions", "timestamp_facts", "trusted_inputs",
    "release_context", "approval_set"] "TRANSCRIPT_FIELDS"
  requireB ((← stringField json "schema" "TRANSCRIPT_SCHEMA") ==
    "acsd-verification-certificate/v3") "TRANSCRIPT_SCHEMA"

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

  let approvalSet ← field json "approval_set" "TRANSCRIPT_APPROVAL_SET"
  expectFields approvalSet ["body_digest", "approval_target_digest",
    "author_approvals", "lineage_authorizations"] "TRANSCRIPT_APPROVAL_SET"
  let authorApprovals ← (← arrayField approvalSet "author_approvals"
    "TRANSCRIPT_APPROVAL_SET_AUTHORS").toList.mapM decodeApprovalEntry
  let lineageAuthorizations ← (← arrayField approvalSet "lineage_authorizations"
    "TRANSCRIPT_APPROVAL_SET_LINEAGE").toList.mapM decodeApprovalEntry
  let approval ← field json "approval_target" "TRANSCRIPT_APPROVAL_TARGET"
  requireB ((← digestField approval "target_digest" "TRANSCRIPT_TARGET_DIGEST") =
    (← digestField approvalSet "approval_target_digest"
      "TRANSCRIPT_APPROVAL_SET_TARGET")) "TRANSCRIPT_APPROVAL_SET_TARGET"

  let timeItems := (← arrayField json "timestamp_facts" "TRANSCRIPT_TIME_FACTS").toList
  let timeJson ← match timeItems with
    | [item] => pure item
    | _ => throw "TRANSCRIPT_TIME_FACTS"
  expectFields timeJson ["schema", "subject_kind", "subject_digest",
    "not_after_utc", "request_digest", "response_digest", "certificate_digest",
    "report_digest", "approval_set_input_digest", "nonce", "signer_fingerprint",
    "trust_model", "authority_class", "policy_oid", "serial_hex"]
    "TRANSCRIPT_TIME_FACT"
  requireB ((← stringField timeJson "schema" "TRANSCRIPT_TIME_SCHEMA") ==
    "acsd-rfc3161-appraisal/v1") "TRANSCRIPT_TIME_SCHEMA"
  requireB ((← stringField timeJson "subject_kind" "TRANSCRIPT_TIME_SUBJECT") ==
    "approval-set") "TRANSCRIPT_TIME_SUBJECT"
  requireB ((← stringField timeJson "trust_model" "TRANSCRIPT_TIME_TRUST") ==
    "exact-signer-pin") "TRANSCRIPT_TIME_TRUST"
  let authorityExternal ← match ← stringField timeJson "authority_class"
      "TRANSCRIPT_TIME_AUTHORITY" with
    | "external" => pure true
    | "local-test" => pure false
    | _ => throw "TRANSCRIPT_TIME_AUTHORITY"
  let notAfterUtc ← stringField timeJson "not_after_utc" "TRANSCRIPT_TIME_INSTANT"
  requireB (!notAfterUtc.isEmpty) "TRANSCRIPT_TIME_INSTANT"
  let nonce ← stringField timeJson "nonce" "TRANSCRIPT_TIME_NONCE"
  requireB (!nonce.isEmpty) "TRANSCRIPT_TIME_NONCE"
  let policyOid ← stringField timeJson "policy_oid" "TRANSCRIPT_TIME_METADATA"
  let serialHex ← stringField timeJson "serial_hex" "TRANSCRIPT_TIME_METADATA"
  requireB (!policyOid.isEmpty && !serialHex.isEmpty) "TRANSCRIPT_TIME_METADATA"

  let trustItems := (← arrayField json "trusted_inputs"
    "TRANSCRIPT_TRUSTED_INPUTS").toList
  let trustJson ← match trustItems with
    | [item] => pure item
    | _ => throw "TRANSCRIPT_TRUSTED_INPUTS"
  expectFields trustJson ["kind", "signer_fingerprint", "certificate_digest",
    "authority_class"] "TRANSCRIPT_TRUSTED_INPUT"
  requireB ((← stringField trustJson "kind" "TRANSCRIPT_TRUST_KIND") ==
    "tsa-exact-signer-pin") "TRANSCRIPT_TRUST_KIND"
  let trustedExternal ← match ← stringField trustJson "authority_class"
      "TRANSCRIPT_TRUST_AUTHORITY" with
    | "external" => pure true
    | "local-test" => pure false
    | _ => throw "TRANSCRIPT_TRUST_AUTHORITY"

  let timeFact : TranscriptTime := {
    approvalSetDigest := ← digestField approvalSet "body_digest"
      "TRANSCRIPT_APPROVAL_SET_DIGEST"
    approvalTargetDigest := ← digestField approvalSet "approval_target_digest"
      "TRANSCRIPT_APPROVAL_SET_TARGET"
    authorApprovals := authorApprovals
    lineageAuthorizations := lineageAuthorizations
    notAfterUtc := notAfterUtc
    policyOid := policyOid
    serialHex := serialHex
    requestDigest := ← digestField timeJson "request_digest" "TRANSCRIPT_TIME_REQUEST"
    responseDigest := ← digestField timeJson "response_digest" "TRANSCRIPT_TIME_RESPONSE"
    certificateDigest := ← digestField timeJson "certificate_digest"
      "TRANSCRIPT_TIME_CERTIFICATE"
    reportDigest := ← digestField timeJson "report_digest" "TRANSCRIPT_TIME_REPORT"
    approvalSetInputDigest := ← digestField timeJson "approval_set_input_digest"
      "TRANSCRIPT_TIME_APPROVAL_SET_INPUT"
    signerFingerprint := ← digestField timeJson "signer_fingerprint"
      "TRANSCRIPT_TIME_SIGNER"
    trustedSignerFingerprint := ← digestField trustJson "signer_fingerprint"
      "TRANSCRIPT_TRUST_SIGNER"
    trustedCertificateDigest := ← digestField trustJson "certificate_digest"
      "TRANSCRIPT_TRUST_CERTIFICATE"
    authorityExternal := authorityExternal
    trustedAuthorityExternal := trustedExternal
  }
  requireB ((← digestField timeJson "subject_digest" "TRANSCRIPT_TIME_SUBJECT") =
    timeFact.approvalSetDigest) "TRANSCRIPT_TIME_SUBJECT"
  decodeCertificateCore json (some releaseDigest) releaseSlots identityFacts [timeFact]

def decodeCertificateText (text : String) : Except String RawCertificate := do
  let json ← remap "TRANSCRIPT_JSON_INVALID" (Json.parse text)
  let compressed := json.compress
  requireB (text == compressed || text == compressed ++ "\n")
    "TRANSCRIPT_JSON_NONCANONICAL"
  match ← stringField json "schema" "TRANSCRIPT_SCHEMA" with
  | "acsd-verification-certificate/v1" => decodeCertificateV1 json
  | "acsd-verification-certificate/v2" => decodeCertificateV2 json
  | "acsd-verification-certificate/v3" => decodeCertificateV3 json
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

theorem decodedCertificateV3Claims_sound
    {json : Json} {raw : RawCertificate} {certificate : Digest}
    {request : AppraisalRequest}
    (decoded : decodeCertificateV3 json = .ok raw)
    (member : request ∈ deriveCertificate raw certificate) :
    ∃ transcript,
      decodeCertificateV3 json = .ok raw ∧
      refineCertificate raw = transcript ∧
      TranscriptPolicyBound transcript ∧
      ∃ atom,
        TranscriptSupports transcript certificate atom ∧
        atom.subject = request.subject ∧ AppraisalRule atom.kind request.kind := by
  exact ⟨refineCertificate raw, decoded, rfl, transcriptClaims_sound member⟩

/-! A separate closed profile carries an authorized lineage edge without
forcing identity, event, or time facts into the same certificate. -/

structure RawLineageCertificate where
  transcript : LineageVerificationTranscript
  deriving DecidableEq, Repr

private def allowedLineageInputRole (role : String) : Bool :=
  ["parent-release", "parent-pec", "child-release", "child-governance",
    "child-pec", "child-approval-target", "lineage-transition",
    "approval-set", "child-public-key", "child-approval-cose",
    "parent-public-key", "predecessor-authorization-cose"].contains role

private def decodeLineageInput (json : Json) : Except String RawTranscriptInput := do
  expectFields json ["role", "path", "sha256"] "LINEAGE_TRANSCRIPT_INPUT"
  let role ← stringField json "role" "LINEAGE_TRANSCRIPT_INPUT_ROLE"
  requireB (allowedLineageInputRole role) "LINEAGE_TRANSCRIPT_INPUT_ROLE"
  let path ← stringField json "path" "LINEAGE_TRANSCRIPT_INPUT_PATH"
  requireB (!path.isEmpty) "LINEAGE_TRANSCRIPT_INPUT_PATH"
  pure {
    role := role
    path := path
    digest := ← digestField json "sha256" "LINEAGE_TRANSCRIPT_INPUT_DIGEST"
  }

private def decodeLineageAuthority (json : Json) : Except String LineageAuthority := do
  expectFields json ["key_ids", "threshold"] "LINEAGE_TRANSCRIPT_AUTHORITY"
  let keys ← keyArrayField json "key_ids" "LINEAGE_TRANSCRIPT_AUTHORITY_KEYS"
  let threshold ← natField json "threshold" "LINEAGE_TRANSCRIPT_AUTHORITY_THRESHOLD"
  requireB (decide (0 < threshold ∧ threshold ≤ keys.length))
    "LINEAGE_TRANSCRIPT_AUTHORITY_THRESHOLD"
  pure { keys := keys, threshold := threshold }

private def decodeLineagePurpose (json : Json) :
    Except String LineageSignaturePurpose := do
  match ← remap "LINEAGE_TRANSCRIPT_SIGNATURE_PURPOSE" json.getStr? with
  | "child-approval" => pure .childApproval
  | "predecessor-authorization" => pure .predecessorAuthorization
  | _ => throw "LINEAGE_TRANSCRIPT_SIGNATURE_PURPOSE"

private def decodeLineageSignature (json : Json) :
    Except String LineageSignatureFact := do
  expectFields json ["purpose", "key_id", "payload_digest", "cose_digest",
    "public_key_digest"] "LINEAGE_TRANSCRIPT_SIGNATURE"
  pure {
    purpose := ← decodeLineagePurpose
      (← field json "purpose" "LINEAGE_TRANSCRIPT_SIGNATURE_PURPOSE")
    key := ← keyValue (← field json "key_id" "LINEAGE_TRANSCRIPT_SIGNATURE_KEY")
      "LINEAGE_TRANSCRIPT_SIGNATURE_KEY"
    payloadDigest := ← digestField json "payload_digest"
      "LINEAGE_TRANSCRIPT_SIGNATURE_PAYLOAD"
    coseDigest := ← digestField json "cose_digest"
      "LINEAGE_TRANSCRIPT_SIGNATURE_COSE"
    publicKeyDigest := ← digestField json "public_key_digest"
      "LINEAGE_TRANSCRIPT_SIGNATURE_PUBLIC_KEY"
  }

def refineLineageCertificate (raw : RawLineageCertificate) :
    LineageVerificationTranscript := raw.transcript

def decodeLineageCertificateJson (json : Json) :
    Except String RawLineageCertificate := do
  expectFields json ["schema", "inputs", "policy", "lineage_edge",
    "approval_set", "signature_facts"] "LINEAGE_TRANSCRIPT_FIELDS"
  requireB ((← stringField json "schema" "LINEAGE_TRANSCRIPT_SCHEMA") ==
    "acsd-lineage-verification-certificate/v1") "LINEAGE_TRANSCRIPT_SCHEMA"

  let inputs ← (← arrayField json "inputs" "LINEAGE_TRANSCRIPT_INPUTS").toList.mapM
    decodeLineageInput
  requireB (decide ((inputs.map (·.path)).Nodup))
    "LINEAGE_TRANSCRIPT_DUPLICATE_INPUT"

  let policy ← field json "policy" "LINEAGE_TRANSCRIPT_POLICY"
  expectFields policy ["pec_digest", "permitted_outcomes"]
    "LINEAGE_TRANSCRIPT_POLICY"
  let policyClaims ← (← arrayField policy "permitted_outcomes"
    "LINEAGE_TRANSCRIPT_POLICY_CLAIMS").toList.mapM decodeClaim
  requireB (decide policyClaims.Nodup) "LINEAGE_TRANSCRIPT_POLICY_CLAIMS"

  let edge ← field json "lineage_edge" "LINEAGE_TRANSCRIPT_EDGE"
  expectFields edge ["work_id_digest", "transition_digest",
    "transition_input_digest", "transition_kind", "authorization_mode",
    "parent", "child"] "LINEAGE_TRANSCRIPT_EDGE"
  let work ← digestField edge "work_id_digest" "LINEAGE_TRANSCRIPT_WORK"
  let transitionDigest ← digestField edge "transition_digest"
    "LINEAGE_TRANSCRIPT_TRANSITION"
  let transitionKind ← stringField edge "transition_kind"
    "LINEAGE_TRANSCRIPT_TRANSITION_KIND"
  requireB (["continuation", "branch", "team-change", "threshold-change"].contains
    transitionKind) "LINEAGE_TRANSCRIPT_TRANSITION_KIND"
  let mode ← match ← stringField edge "authorization_mode"
      "LINEAGE_TRANSCRIPT_MODE" with
    | "continuity" => pure LineageAuthorizationMode.continuity
    | "transition" => pure LineageAuthorizationMode.transition
    | _ => throw "LINEAGE_TRANSCRIPT_MODE"

  let parentJson ← field edge "parent" "LINEAGE_TRANSCRIPT_PARENT"
  expectFields parentJson ["release_digest", "pec_digest", "line_digest",
    "version", "authority", "release_input_digest", "pec_input_digest"]
    "LINEAGE_TRANSCRIPT_PARENT"
  let parentLine ← digestField parentJson "line_digest" "LINEAGE_TRANSCRIPT_PARENT_LINE"
  let parentVersion ← natField parentJson "version" "LINEAGE_TRANSCRIPT_PARENT_VERSION"
  requireB (decide (0 < parentVersion)) "LINEAGE_TRANSCRIPT_PARENT_VERSION"
  let parentAuthority ← decodeLineageAuthority
    (← field parentJson "authority" "LINEAGE_TRANSCRIPT_PARENT_AUTHORITY")
  let parent : VersionedRelease := {
    work := work.value
    line := parentLine.value
    version := parentVersion
    releaseDigest := ← digestField parentJson "release_digest"
      "LINEAGE_TRANSCRIPT_PARENT_RELEASE"
    pecDigest := ← digestField parentJson "pec_digest"
      "LINEAGE_TRANSCRIPT_PARENT_PEC"
    authority := parentAuthority
  }

  let childJson ← field edge "child" "LINEAGE_TRANSCRIPT_CHILD"
  expectFields childJson ["release_digest", "pec_digest",
    "line_digest", "version", "authority", "approval_target_digest",
    "bound_transition_digest", "release_input_digest",
    "governance_input_digest", "pec_input_digest",
    "approval_target_input_digest"] "LINEAGE_TRANSCRIPT_CHILD"
  let childLine ← digestField childJson "line_digest" "LINEAGE_TRANSCRIPT_CHILD_LINE"
  let childVersion ← natField childJson "version" "LINEAGE_TRANSCRIPT_CHILD_VERSION"
  requireB (decide (0 < childVersion)) "LINEAGE_TRANSCRIPT_CHILD_VERSION"
  let childAuthority ← decodeLineageAuthority
    (← field childJson "authority" "LINEAGE_TRANSCRIPT_CHILD_AUTHORITY")
  let child : VersionedRelease := {
    work := work.value
    line := childLine.value
    version := childVersion
    releaseDigest := ← digestField childJson "release_digest"
      "LINEAGE_TRANSCRIPT_CHILD_RELEASE"
    pecDigest := ← digestField childJson "pec_digest"
      "LINEAGE_TRANSCRIPT_CHILD_PEC"
    authority := childAuthority
  }

  let approvalSet ← field json "approval_set" "LINEAGE_TRANSCRIPT_APPROVAL_SET"
  expectFields approvalSet ["approval_target_digest",
    "author_approvals", "lineage_authorizations", "input_digest"]
    "LINEAGE_TRANSCRIPT_APPROVAL_SET"
  let authorEntries ← (← arrayField approvalSet "author_approvals"
    "LINEAGE_TRANSCRIPT_APPROVAL_SET_AUTHORS").toList.mapM decodeApprovalEntry
  let lineageEntries ← (← arrayField approvalSet "lineage_authorizations"
    "LINEAGE_TRANSCRIPT_APPROVAL_SET_LINEAGE").toList.mapM decodeApprovalEntry
  requireB (decide (authorEntries.Nodup ∧ lineageEntries.Nodup))
    "LINEAGE_TRANSCRIPT_APPROVAL_SET_ENTRIES"

  let signatures ← (← arrayField json "signature_facts"
    "LINEAGE_TRANSCRIPT_SIGNATURES").toList.mapM decodeLineageSignature

  let transcript : LineageVerificationTranscript := {
    work := work
    transitionDigest := transitionDigest
    transitionInputDigest := ← digestField edge "transition_input_digest"
      "LINEAGE_TRANSCRIPT_TRANSITION_INPUT"
    transitionKind := transitionKind
    mode := mode
    parent := parent
    child := child
    childTargetDigest := ← digestField childJson "approval_target_digest"
      "LINEAGE_TRANSCRIPT_CHILD_TARGET"
    boundTransitionDigest := ← digestField childJson "bound_transition_digest"
      "LINEAGE_TRANSCRIPT_BOUND_TRANSITION"
    policyPecDigest := ← digestField policy "pec_digest" "LINEAGE_TRANSCRIPT_POLICY_PEC"
    policyClaims := policyClaims
    approvalSetTargetDigest := ← digestField approvalSet "approval_target_digest"
      "LINEAGE_TRANSCRIPT_APPROVAL_SET_TARGET"
    approvalSetAuthorEntries := authorEntries
    approvalSetLineageEntries := lineageEntries
    approvalSetInputDigest := ← digestField approvalSet "input_digest"
      "LINEAGE_TRANSCRIPT_APPROVAL_SET_INPUT"
    parentReleaseInputDigests := inputDigests "parent-release" inputs
    parentPecInputDigests := inputDigests "parent-pec" inputs
    childReleaseInputDigests := inputDigests "child-release" inputs
    childGovernanceInputDigests := inputDigests "child-governance" inputs
    childPecInputDigests := inputDigests "child-pec" inputs
    childTargetInputDigests := inputDigests "child-approval-target" inputs
    transitionInputDigests := inputDigests "lineage-transition" inputs
    approvalSetInputDigests := inputDigests "approval-set" inputs
    childApprovalCoseDigests := inputDigests "child-approval-cose" inputs
    childPublicKeyDigests := inputDigests "child-public-key" inputs
    predecessorCoseDigests := inputDigests "predecessor-authorization-cose" inputs
    predecessorPublicKeyDigests := inputDigests "parent-public-key" inputs
    parentReleaseInputDigest := ← digestField parentJson "release_input_digest"
      "LINEAGE_TRANSCRIPT_PARENT_RELEASE_INPUT"
    parentPecInputDigest := ← digestField parentJson "pec_input_digest"
      "LINEAGE_TRANSCRIPT_PARENT_PEC_INPUT"
    childReleaseInputDigest := ← digestField childJson "release_input_digest"
      "LINEAGE_TRANSCRIPT_CHILD_RELEASE_INPUT"
    childGovernanceInputDigest := ← digestField childJson "governance_input_digest"
      "LINEAGE_TRANSCRIPT_CHILD_GOVERNANCE_INPUT"
    childPecInputDigest := ← digestField childJson "pec_input_digest"
      "LINEAGE_TRANSCRIPT_CHILD_PEC_INPUT"
    childTargetInputDigest := ← digestField childJson "approval_target_input_digest"
      "LINEAGE_TRANSCRIPT_CHILD_TARGET_INPUT"
    signatures := signatures
  }
  pure { transcript := transcript }

def decodeLineageCertificateText (text : String) :
    Except String RawLineageCertificate := do
  let json ← remap "LINEAGE_TRANSCRIPT_JSON_INVALID" (Json.parse text)
  let compressed := json.compress
  requireB (text == compressed || text == compressed ++ "\n")
    "LINEAGE_TRANSCRIPT_JSON_NONCANONICAL"
  decodeLineageCertificateJson json

def deriveLineageCertificate
    (raw : RawLineageCertificate) (certificate : Digest) : List AppraisalRequest :=
  let transcript := refineLineageCertificate raw
  if lineageTranscriptClaim transcript certificate then
    [lineageTranscriptRequest transcript]
  else []

theorem decodedLineageCertificateClaims_sound
    {json : Json} {raw : RawLineageCertificate} {certificate : Digest}
    {request : AppraisalRequest}
    (_decoded : decodeLineageCertificateJson json = .ok raw)
    (member : request ∈ deriveLineageCertificate raw certificate) :
    LineageGroupClosed (refineLineageCertificate raw) ∧
    AppraisalDerives
      (lineageTranscriptPolicy (refineLineageCertificate raw))
      [lineageTranscriptAtom (refineLineageCertificate raw) certificate]
      request := by
  simp only [deriveLineageCertificate] at member
  split at member
  · have sound := lineageTranscriptClaim_sound ‹_›
    simp only [List.mem_singleton] at member
    subst request
    exact sound
  · simp at member

end ACSD
