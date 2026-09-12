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
- RFC 3161 timestamp request construction and TSTInfo parsing (`tsa.py`, local test TSA).

## Acceptance evidence

The local standard-library suite has 28 test methods: 25 run and pass by
default, and 3 v1-integration tests skip unless a v1 fixture workspace is
present (via `ACSD_V1_ROOT`). The demo verifier reports `status: VALID` and
five manifest entries. The standalone formal project
builds successfully with the pinned official Lean 4.33.1 Windows toolchain.

## Formal scope

`formal/ACSD/PEC.lean` contains four axiom-free theorems over an abstract
acceptance model: accepted capsules have all required approvals, accepted
capsules preserve the no-social-claim policy, and missing approval or an
invalid event sequence prevents acceptance. Hash and signature security, and
refinement of the Python implementation into this model, are explicitly
outside these four theorems.
