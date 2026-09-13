# ACSD live-source status after v3.1.0-rc1

Checked 2026-09-13 in the local work tree. The committed v3.1.0-rc1 snapshot
remains immutable; the typed-appraisal changes described here are live-source
work toward a later candidate, not a public deployment or venue submission.

## Implemented

- installable Python CLI: `keygen`, `init`, `approve`, `finalize`, `release`,
  `verify`, `inspect`, `disclose-identity`, and `verify-identity`;
- one-command single- or local multi-author release, plus distributed staged
  approval;
- restricted canonical JSON and SHA-256 bindings;
- standard tagged COSE Sign1 with Ed25519/EdDSA `-8`, strict CBOR decoding, and
  an independent zero-dependency Node verifier;
- key-id-to-public-key verification, preventing public-key substitution;
- unanimous signatures over an approval target binding the release,
  governance statement, PEC, work id, and required key set;
- a canonical approval set over every exact author and predecessor-authority
  COSE byte string, with RFC 3161 applied only after that set is complete;
- a closed outcome vocabulary in which permission is distinct from evidence;
- event predecessor-digest and sequence checks plus atomic disclosure-policy,
  Merkle-opening, key-binding, and real COSE signature verification;
- external per-author-slot identity sidecars, partial/full-byline separation,
  cross-release replay rejection, and no mutation of the frozen release;
- RFC 3161 request and CMS verification with nonce, imprint, TSTInfo content
  type, signer id, critical/exclusive timeStamping EKU, ESS certificate id,
  signature algorithm, and exact externally supplied signer pin;
- separate wheel and immutable evidence-package builds, installed-wheel CLI
  execution outside the source tree, artifact-mode self-verification, one read-only
  authoritative gate, PowerShell/POSIX wrappers, Python 3.9 minimum-version CI,
  and the official Lean action;
- explicit lineage authority with a predecessor-selected threshold;
- unchanged-authority continuation through child approvals, and old-threshold/new-team
  double control for key-set or threshold changes;
- exact transition binding and replay rejection, authorized branch handling,
  and same-parent/same-slot fork detection without an invented winner.
- a pure typed appraisal kernel used by every public granting path, with
  domain-separated approval-target, approval-set, event-window, identity-slot,
  and registration subjects and exact supporting-certificate digests.
- an experimental claim-free verification certificate produced independently
  by Python and Node, plus a pure structural checker that grants evidence atoms
  only after exact signer, payload, input-digest, and Merkle-fact closure.

## Acceptance evidence

- Python: 108 tests pass locally; the live TSA test and two unavailable Windows
  capability cases are skipped.
- Canonical JSON: 64 fixed vectors have no unexpected divergence; 1,000/1,000
  seeded generated cases agree between Python and Node on bytes and text-layer
  verdicts.
- COSE: Python-produced approvals verify on the independent Node path, and
  corrupted signatures are rejected.
- RFC 3161: local adverse cases pass; a real freeTSA ECDSA P-384/SHA-512
  response passed the complete pinned-signer profile on 2026-09-12.
- Inherited v1: 8 releases, 18 endorsements, 7 signed series objects, 13
  scenarios, 30/30 profile checks, and 113/113 manifest entries.
- Typed derivation: the complete 6-by-10 unary compatibility test has no
  undeclared conversion; the checked-in 4-by-4 challenge retains all 16
  expected decisions, and three unsupported social claims have no rule.
- Verification transcript: Python and Node produce byte-identical canonical
  certificates for the two-author approval/event fixture; corrupt or missing
  COSE produces no certificate, and deleting one fact removes only its dependent
  claims in the pure checker.
- Lean 4.33.1: build succeeds; 50 PEC/lineage/scoped-appraisal theorems; no
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

The scoped-claim layer proves that a grant requires its exact scope, signer
authorization, and declared policy; identity evidence cannot grant an event
claim; a missing author slot prevents full-byline status; and a legacy target
timestamp cannot be treated as time evidence for a completed approval set.
Every derivation over a union of evidence sets also has a compatible, verified,
exact-subject supporting atom in one component; union does not manufacture a
new capability.

The newer appraisal layer additionally parameterizes the exact subject, keeps
its declarative rule relation separate from the executable Boolean checker, and
proves checker soundness and completeness, exact-support provenance,
append-component support, target/set separation, and absence of a natural-person
identity rule. Adapter correctness is still an explicit boundary assumption.

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
- extend the current approval/event Python-Node transcript to identity,
  approval-set time, and lineage, then refine it into the Lean appraisal checker.
