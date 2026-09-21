import Lean.Data.Json

set_option autoImplicit false
set_option warningAsError true

namespace ACSD.StrictJson

open Lean

/-! Minimal strict-JSON primitives shared by transcript adapters. They validate
object shape and safe JSON integers; domain meanings stay in the calling
module. -/

def maxSafeInteger : Nat := 9007199254740991

def requireB (condition : Bool) (code : String) : Except String Unit :=
  if condition then pure () else throw code

def remap {α : Type} (code : String)
    (result : Except String α) : Except String α :=
  result.mapError fun _ => code

def expectFields
    (json : Json) (fields : List String) (code : String) : Except String Unit := do
  let object ← remap code json.getObj?
  let count := object.foldl (fun total _ _ => total + 1) 0
  requireB (count == fields.length) code
  for name in fields do
    let _ ← remap code (json.getObjVal? name)

def field (json : Json) (name code : String) : Except String Json :=
  remap code (json.getObjVal? name)

def stringField
    (json : Json) (name code : String) : Except String String := do
  remap code (← field json name code).getStr?

def natField
    (json : Json) (name code : String) : Except String Nat := do
  let value ← remap code (← field json name code).getNat?
  requireB (decide (value ≤ maxSafeInteger)) code
  pure value

def positiveNatField
    (json : Json) (name code : String) : Except String Nat := do
  let value ← natField json name code
  requireB (decide (0 < value)) code
  pure value

def arrayField
    (json : Json) (name code : String) : Except String (Array Json) := do
  remap code (← field json name code).getArr?

end ACSD.StrictJson
