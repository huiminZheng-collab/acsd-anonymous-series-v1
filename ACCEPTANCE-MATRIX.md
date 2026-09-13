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
| Typed evidence/claim non-confusion | `claim_derivation.py`, complete 6-by-10 unit matrix, selected 4-by-4 checked-in challenge | PASS; no undeclared conversion |
| Single production claim path | architecture gate plus release, time, event, identity, and demo adapters | PASS; no manual string grant append |
| Adapter transcript agreement | independent Python/Node adapters over exact approval, disclosure, key, and Merkle inputs | PASS; canonical certificate bytes identical |
| Critical-evidence deletion | remove one author/event signature or substitute Merkle scope | PASS; only dependent claims disappear |
| Transcript-to-appraisal formal bridge | Lean executable closure checks plus independent support/appraisal relations | PASS; composed soundness theorem and weak-rule counterexample |
| Canonical transcript to Lean refinement | strict Lean JSON decoder plus complete scoped-derivation differential | PASS; 27/27 positive/adverse cases agree across v1 and v2 |
| Selective identity transcript closure | v2 release/slot/key/assertion/signature/input checks and adverse mutations | PASS; substitutions remove only the identity claim |
| Dialogue Merkle commitment | `dialogue_root`, `dialogue_proof`, `verify_dialogue_window` | PASS |
| Selective contiguous dialogue opening | `test_dialogue_merkle.py`, `test_demo.py` | PASS |
| External sidecar subject/capability binding | `verify_sidecar_subject`, `test_sidecar.py` | PASS |
| End-to-end file package | `generate_demo.py`, `verify_pec.py`, demo manifest | PASS |
| Self-contained evidence package | artifact-mode `check.py`, strict manifest pre/post check, deterministic rebuild | PASS |
| Installed wheel execution | temporary venv, console-script keygen/release/verify outside source | PASS |
| Independent one-command gate | `run_all.ps1`, `run_all.sh` | PASS; reports formal status explicitly |
| Lean formal compilation | PEC, lineage, scoped-claim, and parameterized appraisal modules; pinned 4.33.1 project | PASS |

The formal row contains 64 PEC/composition/lineage/scoped-appraisal/transcript
theorems; the explicit axiom audit checks 32 central boundary theorems. It proves
soundness after strict decoding and empirically checks the restricted JSON
projection; it does not claim cryptographic implementation correctness or
natural-person truth. The separately
published v1 formal core's 53 release/team/series theorems are not recounted as
new v3 theorems.
