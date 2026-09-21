import ACSD.RatsTranscriptJson
import Lean.Data.Json.Printer

set_option autoImplicit false
set_option warningAsError true

open Lean
open ACSD

private def subjectJson (subject : RatsSubject) : Json := Json.mkObj [
  ("token", subject.token), ("attester", subject.attester),
  ("measurement", subject.measurement), ("reference", subject.reference),
  ("nonce", subject.nonce), ("verifier", subject.verifier),
  ("policy", subject.policy)]

private def outcomeJson : RatsClaim → Json
  | .appraisalResult subject => Json.mkObj [
      ("kind", "APPRAISAL_RESULT"), ("subject", subjectJson subject)]

private def resultJson (outcomes : List RatsClaim) : Json := Json.mkObj [
  ("schema", "acsd-rats-lean-result/v1"),
  ("outcomes", Json.arr (outcomes.map outcomeJson).toArray)]

private def errorJson (message : String) : Json := Json.mkObj [
  ("schema", "acsd-rats-lean-result/v1"), ("error", message)]

def main (args : List String) : IO UInt32 := do
  match args with
  | [path] =>
      let text ← IO.FS.readFile path
      match decodeRatsAppraisalTranscriptText text with
      | .ok raw =>
          IO.println <| (resultJson (deriveRatsAppraisalTranscript raw)).compress
          pure 0
      | .error message =>
          IO.eprintln <| (errorJson message).compress
          pure 2
  | _ =>
      IO.eprintln <| (errorJson "USAGE: RatsTranscriptCli <transcript>").compress
      pure 2
