# ACSD v2 PEC acceptance matrix

| Requirement | Evidence | Status |
|---|---|---|
| Canonical JSON and safe integers | `pec_core.py`, `test_pec_core.py` | PASS |
| v1 release/package binding | `adapt_v1_release`, `validate_v1_standalone_package`, adapter tests | PASS |
| Real COSE/SCITT endorsement path | `verify_v1_package_with_node`, `test_node_integration.py` | PASS when v1 fixture workspace is present |
| Unanimous author approval | `validate_pec`, disclosure approval test | PASS |
| Event predecessor and sequence integrity | `validate_pec`, corpus tests | PASS |
| Claim-policy non-amplification | forbidden outcome gate, attack corpus | PASS |
| Dialogue Merkle commitment | `dialogue_root`, `dialogue_proof`, `verify_dialogue_window` | PASS |
| Selective contiguous dialogue opening | `test_dialogue_merkle.py`, `test_demo.py` | PASS |
| External sidecar subject/capability binding | `verify_sidecar_subject`, `test_sidecar.py` | PASS |
| End-to-end file package | `generate_demo.py`, `verify_pec.py`, demo manifest | PASS |
| Independent one-command gate | `run_all.ps1` | PASS; reports formal status explicitly |
| Lean formal compilation | `formal/ACSD/PEC.lean`, pinned 4.33.1 project | PASS; 5 Lake jobs |

The formal row covers the four abstract PEC acceptance theorems only. It does
not claim parser refinement, cryptographic security, or natural-person truth.
