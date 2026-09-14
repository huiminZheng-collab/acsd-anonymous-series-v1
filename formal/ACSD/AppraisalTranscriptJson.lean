import ACSD.Appraisal
import ACSD.StrictJson
import Lean.Data.Json.Parser
import Lean.Data.Json.Printer

set_option autoImplicit false
set_option warningAsError true

namespace ACSD

open Lean

/-! Compatibility aliases keep established parser names and error paths while
centralizing their byte-format primitives in `StrictJson`. -/
private abbrev appraisalRequire := StrictJson.requireB
private def appraisalRemap {α : Type} (code : String)
    (result : Except String α) : Except String α :=
  StrictJson.remap code result
private abbrev appraisalFields := StrictJson.expectFields
private abbrev appraisalField := StrictJson.field
private abbrev appraisalString := StrictJson.stringField
private abbrev appraisalNat := StrictJson.natField
private abbrev appraisalArray := StrictJson.arrayField

private def appraisalHexNibble : Char → Option Nat
  | '0' => some 0 | '1' => some 1 | '2' => some 2 | '3' => some 3
  | '4' => some 4 | '5' => some 5 | '6' => some 6 | '7' => some 7
  | '8' => some 8 | '9' => some 9 | 'a' => some 10 | 'b' => some 11
  | 'c' => some 12 | 'd' => some 13 | 'e' => some 14 | 'f' => some 15
  | _ => none

private def appraisalHex (text code : String) : Except String Nat := do
  appraisalRequire (text.length == 64) code
  let digits ← text.toList.mapM fun character =>
    match appraisalHexNibble character with
    | some digit => pure digit
    | none => throw code
  pure <| digits.foldl (fun value digit => value * 16 + digit) 0

private def appraisalDigest
    (json : Json) (name code : String) : Except String Digest := do
  pure { value := ← appraisalHex (← appraisalString json name code) code }

private def appraisalKey
    (json : Json) (name code : String) : Except String KeyId := do
  pure { value := ← appraisalHex (← appraisalString json name code) code }

private def appraisalAsciiDigit (character : Char) : Bool :=
  ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9'].contains character

private def appraisalUtcSuffix (characters : List Char) : Bool :=
  match characters with
  | ['+', '0', '0', ':', '0', '0'] => true
  | '.' :: tail =>
      let digitCount := tail.length - 6
      decide (1 ≤ digitCount ∧ digitCount ≤ 6) &&
        (tail.take digitCount).all appraisalAsciiDigit &&
        tail.drop digitCount == ['+', '0', '0', ':', '0', '0']
  | _ => false

private def appraisalUtcInstant (text : String) : Bool :=
  match text.toList with
  | y0 :: y1 :: y2 :: y3 :: '-' :: m0 :: m1 :: '-' :: d0 :: d1 ::
      'T' :: h0 :: h1 :: ':' :: n0 :: n1 :: ':' :: s0 :: s1 :: rest =>
      [y0, y1, y2, y3, m0, m1, d0, d1, h0, h1, n0, n1, s0, s1].all
        appraisalAsciiDigit && appraisalUtcSuffix rest
  | _ => false

private def appraisalClaim (json : Json) : Except String ScopedClaim := do
  match ← appraisalRemap "APPRAISAL_TRANSCRIPT_POLICY" json.getStr? with
  | "KEY_ASSENT" => pure .keyAssent
  | "GOVERNANCE_ASSENT" => pure .governanceAssent
  | "COMMITTED_EVIDENCE_MATCH" => pure .committedEvidenceMatch
  | "EXTERNALLY_NOT_AFTER" => pure .approvalTargetExistedNotAfter
  | "APPROVAL_SET_EXISTED_NOT_AFTER" => pure .approvalSetExistedNotAfter
  | "STATEMENT_REGISTERED" => pure .statementRegistered
  | "SLOT_KEY_ASSENT_TO_IDENTITY_ASSERTION" => pure .slotKeyIdentityAssent
  | "AUTHORIZED_SUCCESSOR" => pure .authorizedSuccessor
  | _ => throw "APPRAISAL_TRANSCRIPT_POLICY"

def appraisalClaimOrder : List ScopedClaim := [
  .keyAssent,
  .governanceAssent,
  .committedEvidenceMatch,
  .approvalTargetExistedNotAfter,
  .approvalSetExistedNotAfter,
  .statementRegistered,
  .slotKeyIdentityAssent,
  .authorizedSuccessor
]

private def appraisalEvidenceKind (json : Json) : Except String EvidenceKind := do
  match ← appraisalRemap "APPRAISAL_TRANSCRIPT_EVIDENCE_KIND" json.getStr? with
  | "UNANIMOUS_APPROVAL" => pure .unanimousApproval
  | "EVENT_DISCLOSURE" => pure .eventDisclosure
  | "APPROVAL_TARGET_TIMESTAMP" => pure .approvalTargetTimestamp
  | "APPROVAL_SET_TIMESTAMP" => pure .approvalSetTimestamp
  | "SCITT_INCLUSION" => pure .scittInclusion
  | "SLOT_IDENTITY_ASSENT" => pure .identityDisclosure
  | "LINEAGE_AUTHORIZATION" => pure .lineageAuthorization
  | _ => throw "APPRAISAL_TRANSCRIPT_EVIDENCE_KIND"

private def appraisalSubject (json : Json) : Except String ScopedSubject := do
  let kind ← appraisalString json "kind" "APPRAISAL_TRANSCRIPT_SUBJECT"
  match kind with
  | "approval-target" =>
      appraisalFields json ["kind", "target_digest"] "APPRAISAL_TRANSCRIPT_SUBJECT"
      pure <| .approvalTarget
        (← appraisalDigest json "target_digest" "APPRAISAL_TRANSCRIPT_SUBJECT")
  | "approval-target-time" =>
      appraisalFields json ["kind", "target_digest", "not_after_utc"]
        "APPRAISAL_TRANSCRIPT_SUBJECT"
      let instant ← appraisalString json "not_after_utc" "APPRAISAL_TRANSCRIPT_SUBJECT"
      appraisalRequire (appraisalUtcInstant instant) "APPRAISAL_TRANSCRIPT_SUBJECT"
      pure <| .approvalTargetTime
        (← appraisalDigest json "target_digest" "APPRAISAL_TRANSCRIPT_SUBJECT") instant
  | "approval-set-time" =>
      appraisalFields json ["kind", "approval_set_digest", "not_after_utc"]
        "APPRAISAL_TRANSCRIPT_SUBJECT"
      let instant ← appraisalString json "not_after_utc" "APPRAISAL_TRANSCRIPT_SUBJECT"
      appraisalRequire (appraisalUtcInstant instant) "APPRAISAL_TRANSCRIPT_SUBJECT"
      pure <| .approvalSetTime
        (← appraisalDigest json "approval_set_digest" "APPRAISAL_TRANSCRIPT_SUBJECT")
        instant
  | "event-window" =>
      appraisalFields json ["kind", "pec_digest", "event_id", "event_sequence",
        "commitment_digest", "first_index", "last_index"]
        "APPRAISAL_TRANSCRIPT_SUBJECT"
      let eventId ← appraisalString json "event_id" "APPRAISAL_TRANSCRIPT_SUBJECT"
      appraisalRequire (!eventId.isEmpty) "APPRAISAL_TRANSCRIPT_SUBJECT"
      let first ← appraisalNat json "first_index" "APPRAISAL_TRANSCRIPT_SUBJECT"
      let last ← appraisalNat json "last_index" "APPRAISAL_TRANSCRIPT_SUBJECT"
      appraisalRequire (decide (first ≤ last)) "APPRAISAL_TRANSCRIPT_SUBJECT"
      pure <| .eventWindow
        (← appraisalDigest json "pec_digest" "APPRAISAL_TRANSCRIPT_SUBJECT")
        eventId
        (← appraisalNat json "event_sequence" "APPRAISAL_TRANSCRIPT_SUBJECT")
        (← appraisalDigest json "commitment_digest" "APPRAISAL_TRANSCRIPT_SUBJECT")
        first last
  | "identity-assertion" =>
      appraisalFields json ["kind", "release_digest", "author_slot",
        "author_key_id", "assertion_digest"] "APPRAISAL_TRANSCRIPT_SUBJECT"
      let slot ← appraisalNat json "author_slot" "APPRAISAL_TRANSCRIPT_SUBJECT"
      appraisalRequire (decide (0 < slot)) "APPRAISAL_TRANSCRIPT_SUBJECT"
      pure <| .identityAssertion
        (← appraisalDigest json "release_digest" "APPRAISAL_TRANSCRIPT_SUBJECT")
        slot
        (← appraisalKey json "author_key_id" "APPRAISAL_TRANSCRIPT_SUBJECT")
        (← appraisalDigest json "assertion_digest" "APPRAISAL_TRANSCRIPT_SUBJECT")
  | "registered-statement" =>
      appraisalFields json ["kind", "statement_digest"]
        "APPRAISAL_TRANSCRIPT_SUBJECT"
      pure <| .registeredStatement
        (← appraisalDigest json "statement_digest" "APPRAISAL_TRANSCRIPT_SUBJECT")
  | "lineage-edge" =>
      appraisalFields json ["kind", "work_id_digest", "parent_release_digest",
        "parent_pec_digest", "parent_line_digest", "parent_version",
        "child_release_digest", "child_pec_digest", "child_line_digest",
        "child_version", "transition_digest"] "APPRAISAL_TRANSCRIPT_SUBJECT"
      let parentVersion ← appraisalNat json "parent_version"
        "APPRAISAL_TRANSCRIPT_SUBJECT"
      let childVersion ← appraisalNat json "child_version"
        "APPRAISAL_TRANSCRIPT_SUBJECT"
      appraisalRequire (decide (0 < parentVersion ∧ 0 < childVersion))
        "APPRAISAL_TRANSCRIPT_SUBJECT"
      pure <| .lineageEdge
        (← appraisalDigest json "work_id_digest" "APPRAISAL_TRANSCRIPT_SUBJECT")
        (← appraisalDigest json "parent_release_digest" "APPRAISAL_TRANSCRIPT_SUBJECT")
        (← appraisalDigest json "parent_pec_digest" "APPRAISAL_TRANSCRIPT_SUBJECT")
        (← appraisalDigest json "parent_line_digest" "APPRAISAL_TRANSCRIPT_SUBJECT")
        parentVersion
        (← appraisalDigest json "child_release_digest" "APPRAISAL_TRANSCRIPT_SUBJECT")
        (← appraisalDigest json "child_pec_digest" "APPRAISAL_TRANSCRIPT_SUBJECT")
        (← appraisalDigest json "child_line_digest" "APPRAISAL_TRANSCRIPT_SUBJECT")
        childVersion
        (← appraisalDigest json "transition_digest" "APPRAISAL_TRANSCRIPT_SUBJECT")
  | _ => throw "APPRAISAL_TRANSCRIPT_SUBJECT_KIND"

private structure IndexedAppraisedAtom where
  index : Nat
  atom : AppraisedAtom
  deriving DecidableEq, Repr

private def appraisalEvidence (json : Json) : Except String IndexedAppraisedAtom := do
  appraisalFields json ["index", "kind", "subject", "certificate_digest"]
    "APPRAISAL_TRANSCRIPT_EVIDENCE_ITEM"
  let kind ← appraisalEvidenceKind
    (← appraisalField json "kind" "APPRAISAL_TRANSCRIPT_EVIDENCE_KIND")
  let subject ← appraisalSubject
    (← appraisalField json "subject" "APPRAISAL_TRANSCRIPT_SUBJECT")
  appraisalRequire (evidenceSubjectB kind subject)
    "APPRAISAL_TRANSCRIPT_SUBJECT_KIND_MISMATCH"
  pure {
    index := ← appraisalNat json "index" "APPRAISAL_TRANSCRIPT_EVIDENCE_INDEX"
    atom := {
      kind := kind
      subject := subject
      certificateDigest := ← appraisalDigest json "certificate_digest"
        "APPRAISAL_TRANSCRIPT_CERTIFICATE_DIGEST"
    }
  }

structure RawAppraisalTranscript where
  policy : AppraisalPolicy
  evidence : List AppraisedAtom
  deriving Repr

def decodeAppraisalTranscriptJson (json : Json) : Except String RawAppraisalTranscript := do
  appraisalFields json ["schema", "policy", "evidence"]
    "APPRAISAL_TRANSCRIPT_FIELDS"
  appraisalRequire ((← appraisalString json "schema" "APPRAISAL_TRANSCRIPT_SCHEMA") ==
    "acsd-appraisal-transcript/v1") "APPRAISAL_TRANSCRIPT_SCHEMA"
  let policyJson ← appraisalField json "policy" "APPRAISAL_TRANSCRIPT_POLICY"
  appraisalFields policyJson ["permitted_outcomes"] "APPRAISAL_TRANSCRIPT_POLICY"
  let policyClaims ← (← appraisalArray policyJson "permitted_outcomes"
    "APPRAISAL_TRANSCRIPT_POLICY").toList.mapM appraisalClaim
  let expectedOrder := appraisalClaimOrder.filter fun claim => policyClaims.contains claim
  appraisalRequire (decide (policyClaims = expectedOrder))
    "APPRAISAL_TRANSCRIPT_POLICY_ORDER"
  let indexed ← (← appraisalArray json "evidence"
    "APPRAISAL_TRANSCRIPT_EVIDENCE").toList.mapM appraisalEvidence
  appraisalRequire (decide (indexed.map (·.index) = List.range indexed.length))
    "APPRAISAL_TRANSCRIPT_EVIDENCE_ORDER"
  let evidence : List AppraisedAtom := indexed.map (·.atom)
  appraisalRequire (decide evidence.Nodup) "APPRAISAL_TRANSCRIPT_EVIDENCE_DUPLICATE"
  pure {
    policy := { permittedClaims := policyClaims }
    evidence := evidence
  }

def decodeAppraisalTranscriptText (text : String) : Except String RawAppraisalTranscript := do
  let json ← appraisalRemap "APPRAISAL_TRANSCRIPT_JSON_INVALID" (Json.parse text)
  let compressed := json.compress
  appraisalRequire (text == compressed || text == compressed ++ "\n")
    "APPRAISAL_TRANSCRIPT_JSON_NONCANONICAL"
  decodeAppraisalTranscriptJson json

def appraisalCandidateRequests
    (raw : RawAppraisalTranscript) : List AppraisalRequest :=
  (raw.evidence.flatMap fun item =>
    appraisalClaimOrder.map fun kind =>
      ({ kind := kind, subject := item.subject } : AppraisalRequest)).eraseDups

def deriveAppraisalTranscript
    (raw : RawAppraisalTranscript) : List AppraisalRequest :=
  (appraisalCandidateRequests raw).filter fun request =>
    checkClaim raw.policy raw.evidence request

def appraisalSupportingDigests
    (raw : RawAppraisalTranscript) (request : AppraisalRequest) : List Digest :=
  ((raw.evidence.filter fun item =>
      evidenceSubjectB item.kind item.subject &&
      decide (item.subject = request.subject) &&
      compatibleB item.kind request.kind).map (·.certificateDigest)).eraseDups

theorem appraisalTranscriptClaims_sound
    {raw : RawAppraisalTranscript} {request : AppraisalRequest}
    (member : request ∈ deriveAppraisalTranscript raw) :
    AppraisalDerives raw.policy raw.evidence request := by
  have accepted := (List.mem_filter.mp member).2
  exact checkClaim_sound accepted

theorem decodedAppraisalTranscriptClaims_sound
    {text : String} {raw : RawAppraisalTranscript} {request : AppraisalRequest}
    (decoded : decodeAppraisalTranscriptText text = .ok raw)
    (member : request ∈ deriveAppraisalTranscript raw) :
    decodeAppraisalTranscriptText text = .ok raw ∧
      AppraisalDerives raw.policy raw.evidence request := by
  exact ⟨decoded, appraisalTranscriptClaims_sound member⟩

theorem decodedAppraisalTranscriptClaims_refine_abstract
    (project : ScopedSubject → Digest)
    {text : String} {raw : RawAppraisalTranscript} {request : AppraisalRequest}
    (decoded : decodeAppraisalTranscriptText text = .ok raw)
    (member : request ∈ deriveAppraisalTranscript raw) :
    decodeAppraisalTranscriptText text = .ok raw ∧
      Derives (abstractPolicy raw.policy)
        (fun item => item ∈ raw.evidence.map (abstractAtom project))
        (abstractRequest project request) := by
  exact ⟨decoded, appraisalDerives_refines_abstract project
    (appraisalTranscriptClaims_sound member)⟩

end ACSD
