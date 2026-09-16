# ACSD v4.0.0-rc1 Authorized Scholarly Lineage and Provenance Evidence Capsule

ACSD expands to **Anonymous Scholarly Claim and Disclosure**.  This repository
contains a content-anonymous paper, an executable command-line prototype, an
adversarial corpus, and a Lean model for a narrow question: what exact research
objects did a declared set of pseudonymous keys jointly approve, and which
carefully limited conclusions follow from that evidence?

**Discovery terms:** anonymous research release; scholarly communication;
research provenance; authorship governance; digital signatures; RFC 3161
timestamping; cryptographic protocol; formal verification; Lean 4.
For the GitHub repository's separately managed **Topics** field, use:
`anonymous-research`, `scholarly-communication`, `research-provenance`,
`authorship`, `digital-signatures`, `rfc3161`, `timestamping`,
`cryptographic-protocols`, `formal-verification`, and `lean4`.

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

Generate a private key once, outside any public release directory. For normal
author use, encrypt the local PKCS#8 PEM and enter the passphrase twice at the
terminal:

```text
acsd keygen --name author --out-dir private-keys --encrypt
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

The CLI rejects private keys located inside the release directory. An encrypted
key prompts only at an interactive terminal; a one-command release prompts
once for a key reused inside that command. ACSD deliberately has no passphrase
argument, environment-variable, or release-file option. A noninteractive use
of an encrypted key fails closed as `PRIVATE_KEY_PASSPHRASE_REQUIRED`.

Omitting `--encrypt` preserves the legacy unencrypted PEM format for
compatibility only. It is a lower protection level and still requires OS access
control and a separate backup plan. The current profile is not an OS keystore,
HSM, malware defense, or unattended-signing solution; see
[`design/KEY-PROTECTION.md`](design/KEY-PROTECTION.md).

For coauthors signing on separate machines, the corresponding author supplies
only their public keys, in byline order. The CLI generates and validates
`team.json`; nobody has to hand-edit protocol JSON:

```text
acsd init paper.pdf --public-key author-a.pub --public-key author-b.pub \
  --role first-author --role senior-author --corresponding 1 \
  --contribution 1:conceptualization --contribution 2:supervision \
  --ai-tool ChatGPT --ai-purpose brainstorming --ai-reviewed-by 1 \
  --out release-dir
acsd author-approve release-dir --key author-a.key
acsd author-approve release-dir --key author-b.key
acsd finalize release-dir
acsd verify release-dir
```

`author-approve` validates the package, shows the same signing checklist as the
read-only `review` command, identifies the author's exact slot from the private
key, and requires the author to type `APPROVE` before writing a signature.
Noninteractive automation must opt out explicitly with `--yes`; `--json`
without `--yes` fails closed. `review` itself never loads a private key and
never changes the package. Both commands show the manuscript
digest and size, ordered byline and roles, corresponding-author choice, AI-use
declaration, claim policy, lineage edge, and exact approval-target digest. It is
the recommended signing surface for each author. Existing advanced users may
still use separate `review` and `approve` commands or pass a reviewed
`--team team.json` declaration.

AI use is declared only when both a tool and a purpose are supplied. Repeat
`--ai-tool` and `--ai-purpose` as needed; `--ai-reviewed-by` records a 1-based
author slot that performed human review. These facts and repeatable
`SLOT:CONTRIBUTION` declarations are inside the exact approval target, so every
author sees and approves the same statement.

When authors are on separate machines, the corresponding author need not send
the mutable working directory or ask anyone to copy signature files by hand:

```text
# corresponding author
acsd export-approval-request release-dir --for-author <author-b-key-id> \
  --out author-b-request

# author B, on another machine
acsd respond-approval-request author-b-request --key author-b.key \
  --out author-b-response

# corresponding author
acsd import-approval-response release-dir author-b-response
```

The request is a private-key-free snapshot with a strict SHA-256 manifest. The
response contains only a canonical routing record and the exact COSE approval;
it does not return the author's private key or a second mutable release tree.
Both sides revalidate the manuscript, protocol bindings, requested author slot,
and approval-target digest. Rewriting a transport manifest cannot make a
modified manuscript satisfy the signed target. An author may add
`--delegate-public-key coordinator-agent.pub` while responding; the returned
response then contains the author-signed exact-target delegation. The
coordinator can exercise it without copying an author key ID by supplying the
agent key to `coordinator-finalize`.

These are directory packages rather than a custom archive format. They can be
transported directly or compressed by the user's file-transfer tool and
extracted before verification. ACSD intentionally does not parse untrusted ZIP
files in this profile, avoiding a second archive-security surface.

For a larger team, the coordinator can batch the same protocol:

```text
acsd export-approval-requests release-dir --out requests
# Send each slot-* child directory to that author; collect returned response
# directories immediately below responses/.
acsd import-approval-responses release-dir --from-dir responses
```

Batch import is transactional: every response is verified in a same-parent
staging copy, and the live candidate is replaced only after all responses pass.
A duplicate author, forged signature, wrong target, malformed response, or
failed manifest leaves the original candidate unchanged.

The coordinator may combine batch import and finalization:

```text
acsd coordinator-finalize release-dir --responses-dir responses \
  --delegate-key coordinator-agent.key \
  --tsa https://tsa.example/tsr
```

This operation is also transactional across response validation and RFC 3161
acquisition. It refuses to run without either `--tsa` or the explicit downgrade
`--allow-untimestamped`; absence of an option never silently becomes a timeless
release. This command prepares and timestamps a local artifact only. It does
not upload, push, or submit it.

The corresponding author may perform all package assembly, timestamping, and
publication without receiving coauthor private keys. If a coauthor explicitly
wants the corresponding author to exercise a lower-authority key, ACSD supports
an exact-target, non-redelegable approval capability. The coauthor signs the
capability with the author key; the coordinator holds only the distinct agent
key:

```text
acsd init paper.pdf --public-key author-a.pub --public-key author-b.pub \
  --out release-dir \
  --allow-delegated-approval
acsd author-approve release-dir --key author-b.key \
  --delegate-public-key coordinator-agent.pub
acsd coordinator-finalize release-dir \
  --delegate-key coordinator-agent.key \
  --tsa https://tsa.example/tsr
```

`--delegate-key` discovers every still-pending exact delegation addressed to
that key and signs them in the same staging transaction. Multiple agent keys
may be supplied by repeating the option. `approve-delegations` provides the
same automatic discovery as a separate transactional step when finalization is
not yet desired; `approve-as --for-author` remains an advanced single-slot
interface.

The capability is bound to the complete approval-target digest, including the
exact manuscript, WorkID, version, governance, PEC, and optional lineage edge.
It cannot authorize another draft, lineage transition, identity disclosure, or
further delegation. Verification reports `direct` versus `delegated` per author.
An all-direct set may establish `KEY_ASSENT` and `GOVERNANCE_ASSENT`; a mixed set
establishes the narrower `AUTHORIZED_TARGET_APPROVAL`, not a claim that every
author personally operated a key on the final target. See
[`design/DELEGATED-APPROVAL.md`](design/DELEGATED-APPROVAL.md).

For a successor, delegated child approval never substitutes for predecessor
authority. The old author threshold must additionally run `authorize` on the
exact lineage transition; a future one-screen client can combine these two
author confirmations without combining their protocol meanings.

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

A genesis or successor may additionally precommit a disjoint recovery key set:

```text
acsd release paper-v1.pdf --key author.key \
  --recovery-public-key guardian-a.pub \
  --recovery-public-key guardian-b.pub --recovery-threshold 2 \
  --out release-v1

acsd revise release-v1 paper-v2.pdf --key replacement-author.key \
  --recovery-key guardian-a.key --recovery-key guardian-b.key \
  --out release-v2
```

The recovery quorum signs the same exact transition as an ordinary predecessor
quorum, and all child authors still approve the child target. The public
recovery authority is inherited unless an authorized transition replaces or
clears it. Recovery and ordinary lineage signatures cannot be mixed on one
edge, and recovery is refused for an unchanged online authority.

Lineage verification is relative to an exact predecessor object. Supplying
`--expected-parent-release-id` pins the child to a parent ReleaseID already
accepted by the verifier; without it, the report says
`UNPINNED_EXACT_PARENT`. This prevents a fabricated parallel genesis that
merely reuses a visible WorkID from being confused with the known lineage.

`compare-successors LEFT RIGHT` reports two valid, distinct children in the
same parent and slot as `LINEAGE_EQUIVOCATION_DETECTED`, but deliberately does
not choose a winner. A different line is an authorized branch, not a conflict.

Before publishing otherwise unrelated releases, audit visible signing-key
reuse across their verified WorkIDs:

```text
acsd audit-key-reuse release-a release-b --fail-on-cross-work
```

Without `--fail-on-cross-work` the command is informational and exits 0; with
it, any key occurring under more than one WorkID returns exit 1. Reuse inside
one WorkID lineage is reported separately because it commonly expresses
intended continuity. Exact-release identity sidecars remain scope-isolated,
but no later disclosure mechanism can erase equality of public keys that were
already published. Use independent keys for unrelated lineages when that
direct link is unwanted.

An authorization is immutable evidence, not something cryptography can erase.
Without a precommitted recovery authority, key loss freezes the lineage. With
one, the verifier can establish `RECOVERY_AUTHORIZED_TRANSITION` for an exact
authority-changing child. This does not silently revoke a competing child made
with stolen online keys: if both are presented, `compare-successors` still
reports an unranked fork. Discovery or global ordering remains a transparency,
pinning, or governance service decision.

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

Verify one or more slot sidecars together, optionally requiring a complete
byline:

```text
acsd verify-identity-set release-dir \
  --disclosure identity-sidecars/identity-slot-1.json \
  --disclosure identity-sidecars/identity-slot-2.json \
  --signature identity-sidecars/identity-slot-1.cose \
  --signature identity-sidecars/identity-slot-2.cose \
  --require-full-byline
```

The result means that the exact key assigned to that release slot assented to
the displayed mapping. It does not verify a natural person or venue status.
Partial slot disclosure is never reported as a complete byline; conflicting
assertions do not acquire a protocol-selected winner. A malicious or compromised
slot key can sign a false name, and external collaboration clues may identify
undisclosed teammates. Publishing a sidecar is therefore practically irreversible:
inspect its exact release, slot and assertion, and review team-level privacy,
before making it public. Without
`--require-full-byline`, a valid partial set exits 0 and is explicitly labeled
`PARTIAL_BYLINE_KEY_ASSENT`; with it, a missing slot exits 5.

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

- 31/31 source, package, installed-wheel, differential, formal, and byte-identity
  checks passing as one command;
- 195 Python test methods, with three environment-dependent capability cases
  skipped locally;
- a scripted three-author role evaluation with two direct approvals, one exact
  delegation, seven post-key-setup commands, no JSON edits, no private-key
  transfers, no copied protocol identifiers, and atomic rollback after a
  returned signature is corrupted and its transport manifest regenerated;
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
- a separate, research-only canonical RATS appraisal transcript, strictly
  decoded by Python and Lean with 22/22 complete, premise-deletion,
  exact-substitution, policy, ordering, type, and noncanonical-input cases;
  it is not an ACSD release feature, EAT parser, COSE verifier, or device-safety
  claim;
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
- a controlled same-primitive comparison in which both ACSD and bare detached
  Ed25519 signatures preserve exact bytes; an explicit predecessor-signed
  transition, whether manual or ACSD, distinguishes authorized key rotation
  from fresh-key n+1 capture, while ACSD supplies the maintained closure,
  threshold, governance, and typed-claim profile;
- a precommitted-recovery experiment covering 2-of-2 recovery, incomplete
  quorum, unknown or absent recovery authority, cross-child replay, mixed
  authorization methods, and the residual unranked online-versus-recovery
  fork;
- an offline-verified freeTSA fixture over the demo's complete approval set,
  binding its exact request, response, signer certificate, nonce, policy OID,
  serial number, and `2026-09-13T11:37:22+00:00` time;
- a Lean 4.33.1 build with 106 theorems covering PEC, lineage and recovery,
  scoped claims, parameterized appraisal/checker correspondence,
  transcript-group closure, selective identity, atomic event disclosure, typed
  time subjects, and a bounded second-domain appraisal instance plus its strict
  transcript-decision soundness, with no `sorry`/`admit`; the separately published v1 formal core's 53
  release/series/team theorems are a distinct inherited proof surface.

The GitHub workflow runs the Python/Node gate on Windows, macOS, and Linux,
including the declared Python 3.9 minimum dependency set, builds a wheel and
executes its installed console script outside the source tree through genesis,
authorized revision, exact-parent verification, same-line key audit, and
successor-sidecar verification; it then builds and self-verifies a temporary
immutable evidence package, verifies the frozen v3
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
- `linkability_audit.py`: I/O-free classification of same-lineage and cross-
  WorkID public-key reuse;
- `SPEC.md`: object, trust, and claim semantics;
- `V4-ACCEPTANCE-REPORT.md`: local v4 candidate gate results and formal scope;
- `ANONYMITY.md`: content-anonymous scope and known linkability;
- `TEST-PLAN.md` and `design/SECURITY-ROUTE-LEDGER.md`: attacks and design
  decisions;
- `design/canonical_*`, `design/semantic_confusion_*`, and
  `design/verify_approval.cjs`: independent tests and checked-in reports;
- `design/LINEAGE-VERIFICATION-CERTIFICATE-V1.md`: the modular authorized-edge
  transcript, closure rule, and trust boundary;
- `design/APPRAISAL-TRANSCRIPT-V1.md`: the live verifier-to-kernel wire
  boundary and its formal trust statement;
- `design/ADJACENT-BASELINE-EVALUATION.md`: scope-limited executable comparison
  with a non-strawman exact-transition baseline;
- `design/PRECOMMITTED-RECOVERY.md`: precommitted alternate-authority design,
  attack obligations, and the explicit non-revocation/view-completeness
  boundary;
  with bare detached Ed25519 policies and an explicit external-validity gap;
- `formal/`: the Lean model, shared strict-JSON primitives, production
  transcript checker, separate research-only RATS transcript checker, and
  proofs;
- `design/V5-ROUTE-AUDIT.md` and `design/GENERALIZATION-GATE.md`: the
  prior-art-bounded v5 theory route and its completed smallest validation;
- `design/DOUBLE-BLIND-SUBMISSION-PLAN.md`: an isolated future review-package
  plan that does not alter the public evidence release;
- `design/CLI-PRODUCTIZATION-AUDIT.md`: the bounded installed-command workflow
  and its explicit key-custody/usability boundary;
- `v1-fixture/`: frozen standalone/series/cyclic-citation reference corpus;
- `paper/acsd-v4.tex`: content-anonymous manuscript source;
- `paper/acsd-acsac.tex`: thin IEEE conference-format entry point over the
  same source (no duplicated manuscript);
- `release-v4.0.0-rc1/`: current self-contained deterministic release candidate
  once built locally; `release-v3.3.0-rc1/`, `release-v3.2.0-rc1/`,
  `release-v3.1.0-rc1/`, `release-v3.0.0/`, and the earlier
  `release-v2.0.0/`, `release-v2.1.0/`, and `release-v2.1.1/` trees are retained rather than
  overwritten.

Build a new evidence snapshot, or verify a frozen snapshot's manifest, with:

```text
python build_release.py --out release-v4.0.0-rc1
python verify_release.py release-v4.0.0-rc1
python release-v4.0.0-rc1/check.py --artifact
python build_release.py --check release-v4.0.0-rc1
```

The installable wheel and the immutable paper/evidence snapshot are separate
artifacts. The root tree and v4 candidate identify as `4.0.0rc1`; all v3 and
earlier release trees remain frozen historical
packages and are not rebuilt from later source.

The benchmark prints fresh measurements without modifying the frozen release
report.  A maintainer can deliberately refresh that report with
`python design/benchmark_core.py --output design/performance_report.json`.

The manuscript has two local renderings from one scientific source:

```text
latexmk -pdf -outdir=paper/build paper/acsd-v4.tex
latexmk -pdf -outdir=paper/build paper/acsd-acsac.tex
```

The second is a planning build against the verified ACSAC 2026 format, not a
claim about a future call and not a submission action.

No command in this README uploads a paper, pushes Git, creates a DOI, or submits
to a venue.  Those remain separate, explicitly authorized actions.

## Comparative evaluation

The [security and operational-cost report](design/COMPARATIVE-EVALUATION.md)
includes actual GnuPG 2.4.9, an independent detached-Ed25519 client, and ACSD:
18 input/team/recipe configurations, 90 measured samples plus 18 warm-ups,
full command logs, artifact sizes, and adversarial successor/disclosure cases.
A separate experiment measures offline verification of a real RFC 3161 receipt.
The report distinguishes measured client costs from unmeasured archival/network
services and records a successful manual-signature authorization baseline.

## License and citation

Code and documentation in this v4 work tree are released under the MIT license;
vendored components retain their own notices.  `CITATION.cff` supplies a
provisional software citation.  The manuscript is content-anonymous and has
not thereby been submitted, accepted, or peer reviewed.
