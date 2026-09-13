import ACSD.TranscriptJson
import Lean.Data.Json.Printer

set_option autoImplicit false
set_option warningAsError true

open Lean
open ACSD

private def digestJson (digest : Digest) : Json := digest.value.repr
private def keyJson (key : KeyId) : Json := key.value.repr

private def claimName : ScopedClaim → String
  | .keyAssent => "KEY_ASSENT"
  | .governanceAssent => "GOVERNANCE_ASSENT"
  | .committedEvidenceMatch => "COMMITTED_EVIDENCE_MATCH"
  | .slotKeyIdentityAssent => "SLOT_KEY_ASSENT_TO_IDENTITY_ASSERTION"
  | .approvalTargetExistedNotAfter => "EXTERNALLY_NOT_AFTER"
  | .approvalSetExistedNotAfter => "APPROVAL_SET_EXISTED_NOT_AFTER"
  | .statementRegistered => "STATEMENT_REGISTERED"
  | .naturalPersonIdentityVerified => "NATURAL_PERSON_IDENTITY_VERIFIED"
  | .originalityVerified => "ORIGINALITY_VERIFIED"
  | .signersUncompromisedAtTime => "SIGNERS_UNCOMPROMISED_AT_TIME"
  | .authorizedSuccessor => "AUTHORIZED_SUCCESSOR"

private def subjectJson : ScopedSubject → Json
  | .approvalTarget target => Json.mkObj [
      ("kind", "approval-target"), ("target_digest_nat", digestJson target)]
  | .approvalTargetTime target time => Json.mkObj [
      ("kind", "approval-target-time"), ("target_digest_nat", digestJson target),
      ("not_after_utc", time)]
  | .approvalSetTime set time => Json.mkObj [
      ("kind", "approval-set-time"), ("set_digest_nat", digestJson set),
      ("not_after_utc", time)]
  | .eventWindow pec eventId sequence commitment first last => Json.mkObj [
      ("kind", "event-window"), ("pec_digest_nat", digestJson pec),
      ("event_id", eventId), ("event_sequence", sequence),
      ("commitment_digest_nat", digestJson commitment),
      ("first_index", first), ("last_index", last)]
  | .identityAssertion release slot key assertion => Json.mkObj [
      ("kind", "identity-assertion"), ("release_digest_nat", digestJson release),
      ("author_slot", slot), ("key_id_nat", keyJson key),
      ("assertion_digest_nat", digestJson assertion)]
  | .registeredStatement statement => Json.mkObj [
      ("kind", "registered-statement"),
      ("statement_digest_nat", digestJson statement)]
  | .lineageEdge work parentRelease parentPec parentLine parentVersion
      childRelease childPec childLine childVersion transition => Json.mkObj [
      ("kind", "lineage-edge"), ("work_id_digest_nat", digestJson work),
      ("parent_release_digest_nat", digestJson parentRelease),
      ("parent_pec_digest_nat", digestJson parentPec),
      ("parent_line_digest_nat", digestJson parentLine),
      ("parent_version", parentVersion),
      ("child_release_digest_nat", digestJson childRelease),
      ("child_pec_digest_nat", digestJson childPec),
      ("child_line_digest_nat", digestJson childLine),
      ("child_version", childVersion),
      ("transition_digest_nat", digestJson transition)]

private def requestJson (certificate : Digest) (request : AppraisalRequest) : Json :=
  Json.mkObj [
    ("kind", claimName request.kind), ("subject", subjectJson request.subject),
    ("supporting_certificate_digests_nat", Json.arr #[digestJson certificate])]

private def resultJson
    (certificate : Digest) (claims : List AppraisalRequest) : Json := Json.mkObj [
  ("schema", "acsd-lean-transcript-result/v1"),
  ("certificate_digest_nat", digestJson certificate),
  ("claims", Json.arr (claims.map (requestJson certificate)).toArray)]

private def errorJson (message : String) : Json := Json.mkObj [
  ("schema", "acsd-lean-transcript-result/v1"),
  ("error", message)]

def main (args : List String) : IO UInt32 := do
  match args with
  | [path, certificateText] =>
      let text ← IO.FS.readFile path
      match decodeDigestText certificateText with
      | .error message =>
          IO.eprintln <| (errorJson message).compress
          pure 2
      | .ok certificate =>
          match decodeCertificateText text with
          | .ok raw =>
              let transcript := refineCertificate raw
              if transcriptPolicyBoundB transcript then
                IO.println <| (resultJson certificate
                  (deriveCertificate raw certificate)).compress
                pure 0
              else
                IO.eprintln <| (errorJson "TRANSCRIPT_POLICY_SCOPE").compress
                pure 2
          | .error standardError =>
              match decodeLineageCertificateText text with
              | .ok raw =>
                  IO.println <| (resultJson certificate
                    (deriveLineageCertificate raw certificate)).compress
                  pure 0
              | .error _ =>
                  IO.eprintln <| (errorJson standardError).compress
                  pure 2
  | _ =>
      IO.eprintln <| (errorJson "USAGE: TranscriptCli <certificate> <sha256>").compress
      pure 2
