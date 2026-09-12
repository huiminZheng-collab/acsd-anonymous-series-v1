# ACSD v2 PEC status

## Implemented and tested

- canonical JSON and SHA-256 PEC bindings (Python/Node differential, 64 vectors);
- v1 PaperRelease and standalone-package adapters;
- delegation to the audited v1 COSE/SCITT verifier;
- unanimous author approval checks;
- event predecessor and sequence checks;
- claim-policy non-amplification;
- salted Merkle dialogue roots, paths, and contiguous-window openings;
- generated attack corpus and end-to-end demo;
- demo manifest and command-line verification;
- CLI (`acsd.py`): keygen/init/approve/finalize/verify/inspect with a state machine;
- Ed25519 COSE Sign1 endorsements (`cose.py`);
- RFC 3161 timestamp request construction and TSTInfo parsing (`tsa.py`, local test TSA);
- inherited v1 fixture corpus (`v1-fixture/`) with a reproduction wrapper (`verify_v1_fixture.py`) for the paper's evaluation numbers;
- frozen TEST-PLAN attack matrix: 15 of 17 cases exercised across `validate_pec` / `verify_disclosure` / `verify_dialogue_window` / `verify_sidecar_subject` (the two series-layer EQUIVOCATION / INDETERMINATE cases are documented out of v0.1 scope).

## Acceptance evidence

The local standard-library suite has 31 test methods: 28 run and pass by
default, and 3 v1-integration tests skip unless a v1 fixture workspace is
present (via `ACSD_V1_ROOT`). The demo verifier reports `status: VALID` and
five manifest entries. The standalone formal project
builds successfully with the pinned official Lean 4.33.1 Windows toolchain
(verified 2026-09-12 via `~/.elan/bin/lake.exe`; the `run_all.ps1` gate
auto-detects it).

## Formal scope

`formal/ACSD/PEC.lean` models the PEC as concrete data structures (key lists,
claim policy, event list) and proves ten axiom-free theorems: by induction, a
valid event chain has consecutive sequences; approval is transitive and
monotone; a forbidden social claim is never a permitted outcome; and acceptance
implies full approval, a valid chain, and a non-amplifying policy. Hash and
signature security, and refinement of the Python implementation into this
model, remain explicitly outside the model.
