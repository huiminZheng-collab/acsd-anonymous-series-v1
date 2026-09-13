# ACSD v3 acceptance matrix

| Requirement | Evidence | Status |
|---|---|---|
| Canonical JSON and safe integers | `pec_core.py`, `test_pec_core.py` | PASS |
| v1 release/package binding | `adapt_v1_release`, `validate_v1_standalone_package`, adapter tests | PASS |
| Real COSE/SCITT endorsement path | `verify_v1_package_with_node`, `test_node_integration.py`, bundled v1 fixture | PASS |
| Unanimous author approval and target binding | CLI approval verifier, Node cross-check, substitution attacks | PASS |
| Authorized n+1 lineage edge | `test_lineage_authorization.py`: exact parent, same-key continuation, old-threshold transition | PASS |
| Unauthorized fresh-key successor rejection | valid child approvals without predecessor quorum | PASS; `VALID_OBJECT_BUT_UNAUTHORIZED_SUCCESSOR` |
| Transition replay resistance | old signature copied to a different child body | PASS; payload mismatch |
| Authorized sibling conflict detection | `compare-successors` on two same-parent/same-slot children | PASS; no winner inferred |
| Event predecessor and sequence integrity | `validate_pec`, corpus tests | PASS |
| Claim-policy non-amplification | forbidden outcome gate, attack corpus | PASS |
| Dialogue Merkle commitment | `dialogue_root`, `dialogue_proof`, `verify_dialogue_window` | PASS |
| Selective contiguous dialogue opening | `test_dialogue_merkle.py`, `test_demo.py` | PASS |
| External sidecar subject/capability binding | `verify_sidecar_subject`, `test_sidecar.py` | PASS |
| End-to-end file package | `generate_demo.py`, `verify_pec.py`, demo manifest | PASS |
| Independent one-command gate | `run_all.ps1` | PASS; reports formal status explicitly |
| Lean formal compilation | `formal/ACSD/PEC.lean`, `formal/ACSD/Lineage.lean`, pinned 4.33.1 project | PASS; 6 Lake jobs |

The formal row contains 21 PEC/composition/lineage theorems; the explicit axiom
audit checks seven central boundary theorems. It does not claim parser
refinement, cryptographic security, or natural-person truth. The separately
published v1 formal core's 53 release/team/series theorems are not recounted as
new v3 theorems.
