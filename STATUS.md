# ACSD v3.2.0-rc1 live-source status

Checked 2026-09-14 in the local work tree. This document describes the
v3.2.0-rc1 candidate; the committed v3.1.0-rc1 and earlier snapshots remain
immutable. A release candidate is not a venue submission or deployed service.

## Implemented

- installable Python CLI: `keygen`, `init`, `approve`, `finalize`, `release`,
  `verify`, `inspect`, `disclose-identity`, `verify-identity`, and
  `audit-key-reuse`;
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
- a separate claim-free authorized-lineage certificate, independently produced
  by Python and Node, whose pure Python and Lean checkers require structural
  succession, exact transition binding, child approval, predecessor quorum,
  input closure, approval-set closure, and policy permission.
- one dependency-light `bundle_validation.py` implementation for PEC,
  governance, event-chain, and claim-policy rules, reached through both the CLI
  and legacy `pec_core.validate_pec` facade; canonical JSON and public-key
  identifiers likewise each have one implementation;
- a pure `release_adapter.py` projection used by the live application, an
  explicit `legacy_adapter.py` boundary containing all v1 filesystem/Node and
  metadata-only paths, and a standalone `cli_output.py` process contract;
- an I/O-free `protocol_objects.py` layer owning release, governance, PEC,
  approval-target, and lineage schemas/builders/validators. `acsd.py` re-exports
  the old public names;
- canonical artifact I/O, key material, lineage signature checking, and full
  offline release verification now form an acyclic adapter chain in
  `artifact_io.py`, `key_material.py`, `lineage_adapter.py`, and
  `release_verifier.py`. The verifier imports no CLI module and `acsd.py`
  retains only routing and authoring/finalization workflows.

## Acceptance evidence

- Authoritative read-only gate: 24/24 source, package, installed-wheel,
  differential, formal, and workspace-byte-identity checks pass.
- Python: 156 tests pass locally; the live TSA test and two unavailable Windows
  capability cases are skipped.
- Canonical JSON: 64 fixed vectors have no unexpected divergence; 1,000/1,000
  seeded generated cases agree between Python and Node on bytes and text-layer
  verdicts.
- COSE: Python-produced approvals verify on the independent Node path, and
  corrupted signatures are rejected.
- RFC 3161: local adverse cases pass; a checked-in freeTSA fixture timestamps
  the exact complete demo approval set at `2026-09-13T11:37:22+00:00` and
  passes offline verification against its explicitly pinned signer. This is an
  interoperability existence check, not a service-reliability study.
- Inherited v1: 8 releases, 18 endorsements, 7 signed series objects, 13
  scenarios, 30/30 profile checks, and 113/113 manifest entries.
- Typed derivation: the complete 7-by-11 unary compatibility test has no
  undeclared conversion; the checked-in 4-by-4 challenge retains all 16
  expected decisions, and three unsupported social claims have no rule.
- Verification transcript: Python and Node produce byte-identical canonical
  v1 approval/event, v2 identity, and v3 approval-set-time certificates;
  corrupt or missing COSE
  produces no certificate, and deleting or substituting one fact removes only
  its dependent claims in the pure checker.
- JSON-to-Lean refinement: Lean directly and strictly decodes all three canonical
  schemas and independently emits the same complete scoped derivations as
  Python in 35/35 positive and adverse cases. The strict text decoder is now
  connected by theorem to the exact-subject declarative derivation.
- Authorized-lineage refinement: Python and Node emit byte-identical canonical
  certificates; Python and Lean agree on all 15 valid, deletion, substitution,
  policy, and structural cases.
- Production appraisal boundary: `acsd verify` derives its displayed outcomes
  only after constructing and strictly parsing `acsd-appraisal-transcript/v1`;
  optional CLI output exposes the same claim-free value, and Python/Lean agree
  on 19/19 complete derivation/rejection cases.
- Lean 4.33.1: build succeeds; 84 PEC/lineage/scoped-appraisal/transcript
  theorems; no
  `sorry` or `admit` in the formal sources. The separately published v1 core's
  53 release/team/series theorems remain a distinct inherited model and are not
  included in this v3 count.

## Formal scope

Lean proves the composition rules over typed inputs: exact approval-target
reuse is impossible when target digests differ; granted results require
acceptance, policy permission, and their capability; and external time requires
an exact subject, signer pin, nonce, RFC profile, and a non-local authority.
The closed `Outcome` type has no constructor for human-authorship or originality
claims. Signature unforgeability, SHA-256 collision resistance, filesystem and
release-object parser refinement, DER/CBOR adapter correctness, and PKIX
governance are implementation assumptions. The restricted claim-free
certificate JSON is decoded directly and strictly in Lean.

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

The newer appraisal layer additionally parameterizes the exact subject and
reuses the one declarative `Compatible` relation while keeping it separate from
the executable Boolean checker. It proves checker soundness and completeness,
exact-support provenance, append-component support, target/set separation,
absence of a natural-person identity rule, and that every exact derivation
refines the earlier digest-scoped abstraction under any chosen subject
projection. Adapter correctness is still an explicit boundary assumption.

The transcript layer independently checks exact author/event/identity signature
projections, nonempty signer sets, COSE-input closure, three-way PEC scope,
event sequence, window bounds, one exact Merkle fact, and exact
release/slot/key/assertion identity binding before constructing appraisal atoms.
Its composed soundness
theorem traces every accepted claim to both a closed transcript group and an
explicit appraisal rule. A concrete two-key countermodel proves that the weak
"any approval signature" rule accepts a missing signer while closure rejects it.

The modular lineage-transcript layer performs the corresponding check for one
edge without importing timestamp or disclosure facts. Its soundness chain runs
from strict canonical JSON decoding through exact input/signature/approval-set
closure to a parameterized `AUTHORIZED_SUCCESSOR` claim. This closes the
previous gap between the executable n+1 authorization mechanism and the
claim-free/Lean appraisal path; adapter refinement remains an explicit boundary.

The production release verifier now serializes its already appraised evidence
through a small generic transcript before entering the granting kernel. Lean
strictly decodes the same closed policy, evidence kinds, exact subjects,
support digests, and consecutive indices. Every Lean-emitted request is proved
derivable in the exact-subject semantics and refines the abstract model. This
connects the product decision to the formal kernel; it does not verify the
filesystem, COSE, RFC 3161, or other adapters inside Lean.

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
- a second standards-based domain instance for testing how far the appraisal
  kernel generalizes beyond scholarly provenance.

## Post-v3.2 candidate work

The frozen v3.2.0-rc1 candidate remains unchanged on the
`post-v3.2-lifecycle` branch. A new executable submission-lifecycle experiment
uses the public CLI to distinguish no-action rejection, authorized scientific
revision, and explicit per-slot publication crosswalks. It intentionally keeps
venue acceptance outside the derived claim vocabulary and rejects cross-release
replay or mutation of a signed publication reference.

The post-candidate source gate passes 26/26 checks, including 162 Python tests.
A fresh 288-file evidence package built from this branch passes all 22
artifact-mode checks, including
Lean compilation, the three formal differential bridges, manifest stability,
and source/package byte identity. These results qualify the workflow mechanics;
they do not establish that a venue accepted, rejected, or received a paper.

The same post-candidate branch now also exercises the cross-paper key-reuse
boundary. Exact release binding prevents a disclosure sidecar from granting an
identity-assent result for another release, but equal public key IDs remain an
observable link. The recommended privacy default is therefore one independent
key per unrelated lineage; this is an operational policy, not a universal
unlinkability guarantee. The read-only `audit-key-reuse` command now checks
that policy across two or more fully verified releases and can fail closed in
release CI without treating key equality as proof of a common natural person.
