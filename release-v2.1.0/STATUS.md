# ACSD v2 PEC status

Checked 2026-09-12 in the local work tree. This is a release candidate, not a
public deployment or venue submission.

## Implemented

- installable Python CLI: `keygen`, `init`, `approve`, `finalize`, `release`,
  `verify`, and `inspect`;
- one-command single- or local multi-author release, plus distributed staged
  approval;
- restricted canonical JSON and SHA-256 bindings;
- standard tagged COSE Sign1 with Ed25519/EdDSA `-8`, strict CBOR decoding, and
  an independent zero-dependency Node verifier;
- key-id-to-public-key verification, preventing public-key substitution;
- unanimous signatures over an approval target binding the release,
  governance statement, PEC, work id, and required key set;
- a closed outcome vocabulary in which permission is distinct from evidence;
- event predecessor-digest and sequence checks, salted dialogue Merkle openings,
  and the inherited v1 standalone/series/cyclic-citation corpus;
- RFC 3161 request and CMS verification with nonce, imprint, TSTInfo content
  type, signer id, critical/exclusive timeStamping EKU, ESS certificate id,
  signature algorithm, and exact externally supplied signer pin;
- deterministic release building, PowerShell and POSIX gates, and three-platform
  CI plus the official Lean action.

## Acceptance evidence

- Python: 51 offline tests pass; one live TSA test is skipped offline.
- Canonical JSON: 64 fixed vectors have no unexpected divergence; 1,000/1,000
  seeded generated cases agree between Python and Node on bytes and text-layer
  verdicts.
- COSE: Python-produced approvals verify on the independent Node path, and
  corrupted signatures are rejected.
- RFC 3161: local adverse cases pass; a real freeTSA ECDSA P-384/SHA-512
  response passed the complete pinned-signer profile on 2026-09-12.
- Inherited v1: 8 releases, 18 endorsements, 7 signed series objects, 13
  scenarios, 30/30 profile checks, and 113/113 manifest entries.
- Lean 4.33.1: 5-job build succeeds; 16 theorems; no `sorry` or `admit` in the
  formal sources.

## Formal scope

Lean proves the composition rules over typed inputs: exact approval-target
reuse is impossible when target digests differ; granted results require
acceptance, policy permission, and their capability; and external time requires
an exact subject, signer pin, nonce, RFC profile, and a non-local authority.
The closed `Outcome` type has no constructor for human-authorship or originality
claims. Signature unforgeability, SHA-256 collision resistance, DER/CBOR/JSON
parser refinement, and PKIX governance are implementation assumptions.

## Remaining product hardening

- encrypted or OS-backed private-key storage (generated keys are presently
  unencrypted PEM files);
- installer binaries and shell completion beyond `pip install`;
- general PKIX path construction/revocation, if a service level needs more than
  exact TSA signer pinning;
- editor integration for WorkID citation witnesses;
- deployed transparency/gossip services and cross-series federation.
