set_option autoImplicit false
set_option warningAsError true

namespace ACSD

/-! The v3 capsule model needs only the digest sort from the v1 semantic core.
Cryptographic representation and collision resistance remain outside this
abstract model. -/
structure Digest where
  value : Nat
  deriving DecidableEq, Repr

end ACSD
