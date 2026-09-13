# ACSD v3 authorized-lineage status

Checked 2026-09-13 in the local work tree. This is a release candidate, not a
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
- explicit lineage authority with a predecessor-selected threshold;
- unchanged-authority continuation through child approvals, and old-threshold/new-team
  double control for key-set or threshold changes;
- exact transition binding and replay rejection, authorized branch handling,
  and same-parent/same-slot fork detection without an invented winner.

## Acceptance evidence

- Python: 59 offline tests pass; one live TSA test is skipped offline.
- Canonical JSON: 64 fixed vectors have no unexpected divergence; 1,000/1,000
  seeded generated cases agree between Python and Node on bytes and text-layer
  verdicts.
- COSE: Python-produced approvals verify on the independent Node path, and
  corrupted signatures are rejected.
- RFC 3161: local adverse cases pass; a real freeTSA ECDSA P-384/SHA-512
  response passed the complete pinned-signer profile on 2026-09-12.
- Inherited v1: 8 releases, 18 endorsements, 7 signed series objects, 13
  scenarios, 30/30 profile checks, and 113/113 manifest entries.
- Lean 4.33.1: 6-job build succeeds; 21 PEC/composition/lineage theorems; no
  `sorry` or `admit` in the formal sources. The separately published v1 core's
  53 release/team/series theorems remain a distinct inherited model and are not
  included in this v3 count.

## Formal scope

Lean proves the composition rules over typed inputs: exact approval-target
reuse is impossible when target digests differ; granted results require
acceptance, policy permission, and their capability; and external time requires
an exact subject, signer pin, nonce, RFC profile, and a non-local authority.
The closed `Outcome` type has no constructor for human-authorship or originality
claims. Signature unforgeability, SHA-256 collision resistance, DER/CBOR/JSON
parser refinement, and PKIX governance are implementation assumptions.

The lineage model proves that every accepted successor has predecessor-authority
quorum evidence, fresh keys cannot use the continuity path, and a transition
authorization bound to one child digest cannot be replayed for another child.
The executable verifier classifies an otherwise self-consistent attacker n+1
as `VALID_OBJECT_BUT_UNAUTHORIZED_SUCCESSOR`.

## Remaining product hardening

- encrypted or OS-backed private-key storage (generated keys are presently
  unencrypted PEM files);
- installer binaries and shell completion beyond `pip install`;
- general PKIX path construction/revocation, if a service level needs more than
  exact TSA signer pinning;
- editor integration for WorkID citation witnesses;
- deployed transparency/gossip services and cross-series federation.
- precommitted recovery authorities or hardware-backed recovery workflows;
  without one, loss of the predecessor threshold safely freezes the lineage.
