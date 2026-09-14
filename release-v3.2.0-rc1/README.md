# ACSD v3.2.0-rc1 Authorized Scholarly Lineage and Provenance Evidence Capsule

ACSD expands to **Anonymous Scholarly Claim and Disclosure**.  This repository
contains a content-anonymous paper, an executable command-line prototype, an
adversarial corpus, and a Lean model for a narrow question: what exact research
objects did a declared set of pseudonymous keys jointly approve, and which
carefully limited conclusions follow from that evidence?

## Motivation

During the interval before an arXiv submission becomes publicly available -
including endorsement or moderation delays - an author may want to freeze a
manuscript, preserve pseudonymous team assent, and obtain independent time
evidence without claiming that GitHub itself proves priority.  ACSD is an
intermediate evidence package, not an alternative submission, moderation, or
peer-review service.

The design also covers revisions and series of papers.  Stable random WorkIDs
permit P to cite Q and Q to cite P, while exact release digests and predecessor
links remain an acyclic commitment graph.  A single paper does not depend on a
series package to verify.

## What the verifier establishes

- the manuscript bytes match the signed release digest;
- every required pseudonymous key signed one compact approval target binding
  the release, governance statement, and PEC policy;
- the finalized approval set binds the exact bytes of every author signature
  and every required predecessor-authority signature;
- ordered author roles, corresponding-author choice, and AI-use declaration
  have not changed since that assent;
- a claimed successor is on the same exact WorkID lineage only when the
  predecessor authority approved the parent-to-child edge;
- a disclosed dialogue fragment matches its earlier commitment and its
  disclosure was separately signed by every policy-required author;
- `APPROVAL_SET_EXISTED_NOT_AFTER` only when a nonce-bearing RFC 3161 response
  over the complete approval set verifies against a verifier-supplied TSA
  signer certificate or fingerprint pin.

It does not establish natural-person identity, historical authorship,
contribution truth, originality, plagiarism, legal nonrepudiation, peer review,
or global first discovery.  The package is content-anonymous; its hosting
account, network timing, or public keys may still be linkable.

## Jointly bound objects and outcomes

The `AuthorshipGovernanceStatement` records the exact manuscript digest,
ordered pseudonymous byline roles, corresponding-author key, and AI-use field.
The **Provenance Evidence Capsule (PEC)** binds that statement and the release
to evidence events and a closed claim policy.  Neither object is trusted merely
because it exists: every required key signs one `acsd-approval-target/v2`
containing their exact digests and the complete sorted key set.

The verifier grants an outcome only when the package is accepted, the signed
policy permits that outcome, and its required capability is independently
established.  Thus changing roles or adding a policy outcome breaks the target;
recomputing the target cannot reuse the old COSE approvals.  This rule is the
paper's **closed capability calculus**.  It is a small inference discipline,
not a new cryptographic primitive or a claim that declarations are true.

## Install

```text
python -m pip install .
acsd --version
acsd --help
```

Requirements are Python 3.9+, `cryptography`, and Node.js for the independent
differential verifier.  Lean is only needed to rebuild the formal model.

## One-command release

Generate a private key once, outside any public release directory:

```text
acsd keygen --name author --out-dir private-keys
```

Then build, approve, and finalize a single-author package in one command:

```text
acsd release paper.pdf --key private-keys/author.key --out release-dir
```

If all coauthor keys are legitimately available on one machine, repeat
`--key`:

```text
acsd release paper.pdf --key private-keys/a.key --key private-keys/b.key --out release-dir
```

The CLI rejects private keys located inside the release directory.  Generated
private PEM files are currently unencrypted, so their directory needs operating
system access control and backup protection; encrypted key-store integration is
a remaining product-hardening item.

For coauthors signing on separate machines, use the staged flow:

```text
acsd init paper.pdf --team team.json --out release-dir
acsd approve release-dir --key author-a.key
acsd approve release-dir --key author-b.key
acsd finalize release-dir
acsd verify release-dir
```

## Authorized revisions

Continue a lineage with the same author keys in one command:

```text
acsd revise release-v1 paper-v2.pdf --key author.key --out release-v2
acsd verify release-v2 --expected-parent-release-id urn:sha256:<known-parent-digest>
```

When the authority changes (key set or threshold), the old authority signs the exact transition
and the new authors sign the child approval target:

```text
acsd revise release-v1 paper-v2.pdf --key new-author.key \
  --parent-key old-author-a.key --parent-key old-author-b.key --out release-v2
```

The predecessor fixes its future authorization threshold; the default is all
listed author keys. A staged multi-machine flow uses `init --parent`, one or
more `authorize` calls with predecessor keys, ordinary `approve` calls with
new-version keys, and `finalize`. An attacker may possess a valid new key,
correct WorkID, exact parent digest, and the next version number; without the
old threshold the verifier returns
`VALID_OBJECT_BUT_UNAUTHORIZED_SUCCESSOR`.

Lineage verification is relative to an exact predecessor object. Supplying
`--expected-parent-release-id` pins the child to a parent ReleaseID already
accepted by the verifier; without it, the report says
`UNPINNED_EXACT_PARENT`. This prevents a fabricated parallel genesis that
merely reuses a visible WorkID from being confused with the known lineage.

`compare-successors LEFT RIGHT` reports two valid, distinct children in the
same parent and slot as `LINEAGE_EQUIVOCATION_DETECTED`, but deliberately does
not choose a winner. A different line is an authorized branch, not a conflict.

An authorization is immutable evidence, not something cryptography can erase.
Key loss can therefore freeze a lineage, and a malicious transition already
validly authorized cannot be retroactively made false. Recovery must be
precommitted in a future policy or handled as a visibly separate social fork;
transparent ordering remains a deployment-layer option.

For a machine-auditable account of the exact typed facts used to produce the
release-level outcomes, request the optional appraisal transcript:

```text
acsd verify release-v2 --emit-appraisal-transcript --json
```

The verifier strictly parses this claim-free intermediate object and derives
`granted_outcomes` from it; the transcript is not a substitute for rerunning
the byte-level COSE, lineage, manifest, and time adapters.

Approval state is derived from verified COSE files, not trusted from mutable
`state.json`.  COSE uses the registered EdDSA algorithm value `-8`, requires
tag 18, and is checked by independent Python and Node implementations.

## Independent time evidence

`--tsa local` is a protocol test and can never grant external time:

```text
acsd finalize release-dir --tsa local
acsd verify release-dir --allow-local-test-tsa
```

For an external TSA, finalize first constructs `approval/approval-set.json`
over the exact COSE signature byte strings, then timestamps that closed object.
It preserves the request, response, and signer certificate. A later verifier
must supply trust independently:

```text
acsd finalize release-dir --tsa https://tsa.example/tsr
acsd verify release-dir --tsa-trust-cert independently-obtained-tsa.crt
```

Without `--tsa-trust-cert` or `--tsa-trust-fingerprint`, verification reports
`PRESENT_UNVERIFIED_NO_EXTERNAL_TRUST` and does not emit
`APPROVAL_SET_EXISTED_NOT_AFTER`. `--require-external-time` turns missing trust or a
missing receipt into a nonzero result.  The current adapter implements exact
signer-certificate pinning, nonce/imprint binding, critical and exclusive
timeStamping EKU, id-ct-TSTInfo, ESS certificate identifiers, signer identity,
and CMS signature checks.  It does not implement general PKIX path building or
revocation checking.

Older v0.1/v0.2 packages timestamped the unsigned approval target. They remain
verifiable as legacy evidence, but that timestamp is never upgraded into a
claim that the completed signature set existed then.

## Selective author unblinding

A finalized anonymous release remains immutable. One author can publish a
separate, slot-scoped identity sidecar without revealing coauthors or altering
the release:

```text
acsd disclose-identity release-dir --key private-keys/author.key \
  --display-name "Alice Example" --publication-ref "doi:10.x/example" \
  --out identity-sidecars
acsd verify-identity release-dir \
  --disclosure identity-sidecars/identity-slot-1.json \
  --signature identity-sidecars/identity-slot-1.cose
```

The result means that the exact key assigned to that release slot assented to
the displayed mapping. It does not verify a natural person or venue status.
Partial slot disclosure is never reported as a complete byline; conflicting
same-slot assertions have no automatically selected winner.

## Reproduce the evidence

PowerShell:

```text
./run_all.ps1
```

Linux/macOS:

```text
./run_all.sh
```

The authoritative `check.py` gate is read-only and finishes by comparing all
source-tree file hashes with its starting snapshot. It contains:

- 24/24 source, package, installed-wheel, differential, formal, and byte-identity
  checks passing as one command;
- 155 Python tests passing, with the live-network and two unavailable Windows
  capability cases skipped locally;
- 64 fixed Python-Node canonical-JSON vectors with no unexpected divergence;
- 1,000 seeded generated differential cases with 1,000 byte and verdict
  agreements;
- independent Node verification of Python-produced approval COSE;
- byte-identical Python/Node `acsd-verification-certificate/v1` approval/event,
  v2 release-slot identity, and v3 exact approval-set time output, with no
  embedded verdict;
- a separate byte-identical Python/Node
  `acsd-lineage-verification-certificate/v1` for one exact authorized edge,
  avoiding a cumulative certificate that forces unrelated evidence into every
  verification;
- a pure structural transcript checker with critical-evidence deletion tests;
- a strict Lean decoder and executable checker over all three canonical schemas,
  with 35/35 complete scoped-derivation differential cases across all three
  certificate schemas;
- a strict Lean decoder and executable checker for the lineage profile, with
  15/15 complete derivation/rejection differential cases;
- the production `acsd-appraisal-transcript/v1` decision boundary, strictly
  decoded by Python and Lean with 19/19 complete derivation/rejection cases;
- one declarative evidence/claim compatibility relation shared by the coarse
  and exact-subject models, with proved strict-decoder-to-exact-derivation and
  exact-to-arbitrary-digest-projection refinement for both certificate profiles;
- a complete 7-by-11 typed unary compatibility test plus a checked-in selected
  4-by-4 semantic-confusion challenge with all 12 off-diagonal substitutions
  denied and a key-compromise timeline;
- the frozen v1 corpus: 8 releases, 18 endorsements, 7 series objects, 13
  scenarios, 30/30 profile checks, and 113/113 manifest entries;
- a scaling sample from 10 to 5,000 in-memory objects, recorded in
  `design/performance_report.json`;
- an offline-verified freeTSA fixture over the demo's complete approval set,
  binding its exact request, response, signer certificate, nonce, policy OID,
  serial number, and `2026-09-13T11:37:22+00:00` time;
- a Lean 4.33.1 build with 84 theorems covering PEC, lineage, scoped claims,
  parameterized appraisal/checker correspondence, transcript-group closure,
  selective identity, atomic event disclosure, and typed time subjects with no
  `sorry`/`admit`; the separately published v1 formal core's 53
  release/series/team theorems are a distinct inherited proof surface.

The GitHub workflow runs the Python/Node gate on Windows, macOS, and Linux,
including the declared Python 3.9 minimum dependency set, builds a wheel and
executes its installed console script outside the source tree, builds and
self-verifies a temporary immutable evidence package, verifies the frozen v3
manifests, and uses the
official Lean action with an axiom audit. The checked-in freeTSA receipt is
verified offline in ordinary CI; acquisition and any fresh live-service probe
remain opt-in because CI must not depend on network availability.

## Repository map

- `acsd.py`: CLI routing and authoring/finalization workflows;
- `canonical_json.py`, `bundle_validation.py`, `release_adapter.py`,
  `protocol_objects.py`, `appraisal_transcript.py`, and `claim_derivation.py`: the restricted byte format,
  single pure PEC/policy validator, release projection, I/O-free protocol
  object layer, and typed granting kernel respectively;
- `key_identity.py`, `cose.py`, and `tsa.py`: shared key identity and
  cryptographic adapter boundaries;
- `artifact_io.py`, `key_material.py`, and `lineage_adapter.py`: canonical-file,
  key-material, and exact lineage-edge I/O/signature boundaries;
- `release_verifier.py`: CLI-independent offline verification orchestration and
  the sole live release-level path into the typed granting kernel;
- `legacy_adapter.py`: the only v1 filesystem and optional Node-subprocess
  compatibility boundary; `pec_core.py` preserves published import names and
  the dependency-free dialogue/sidecar primitives;
- `cli_output.py`: stable exit-code and human/JSON process-output contract;
- `approval_set.py`, `event_disclosure.py`, `identity_disclosure.py`, and
  `package_manifest.py`: narrow protocol components shared by CLI and tests;
- `SPEC.md`: object, trust, and claim semantics;
- `ANONYMITY.md`: content-anonymous scope and known linkability;
- `TEST-PLAN.md` and `design/SECURITY-ROUTE-LEDGER.md`: attacks and design
  decisions;
- `design/canonical_*`, `design/semantic_confusion_*`, and
  `design/verify_approval.cjs`: independent tests and checked-in reports;
- `design/LINEAGE-VERIFICATION-CERTIFICATE-V1.md`: the modular authorized-edge
  transcript, closure rule, and trust boundary;
- `design/APPRAISAL-TRANSCRIPT-V1.md`: the live verifier-to-kernel wire
  boundary and its formal trust statement;
- `formal/`: the Lean model, strict transcript decoder, executable checker, and proofs;
- `v1-fixture/`: frozen standalone/series/cyclic-citation reference corpus;
- `paper/acsd-v3.tex`: content-anonymous manuscript source;
- `release-v3.2.0-rc1/`: current self-contained deterministic release candidate;
  `release-v3.1.0-rc1/`, `release-v3.0.0/`, and the earlier
  `release-v2.0.0/`, `release-v2.1.0/`, and `release-v2.1.1/` trees are retained rather than
  overwritten.

Build a new evidence snapshot, or verify a frozen snapshot's manifest, with:

```text
python build_release.py --out release-v3.2.0-rc1
python verify_release.py release-v3.2.0-rc1
python release-v3.2.0-rc1/check.py --artifact
python build_release.py --check release-v3.2.0-rc1
```

The installable wheel and the immutable paper/evidence snapshot are separate
artifacts. The root tree and current candidate identify as `3.2.0rc1`;
`release-v3.1.0-rc1/` and earlier release trees remain frozen historical
packages and are not rebuilt from later source.

The benchmark prints fresh measurements without modifying the frozen release
report.  A maintainer can deliberately refresh that report with
`python design/benchmark_core.py --output design/performance_report.json`.

No command in this README uploads a paper, pushes Git, creates a DOI, or submits
to a venue.  Those remain separate, explicitly authorized actions.

## License and citation

Code and documentation in this v3 work tree are released under the MIT license;
vendored components retain their own notices.  `CITATION.cff` supplies a
provisional software citation.  The manuscript is content-anonymous and has
not thereby been submitted, accepted, or peer reviewed.
