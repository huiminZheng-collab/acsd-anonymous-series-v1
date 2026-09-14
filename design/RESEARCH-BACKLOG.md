# ACSD research backlog and idea ledger

Checked 2026-09-14 against the post-v3.2 work tree. This is a working research
document, not part of the frozen `release-v3.0.0` payload and not a claim that
the listed ideas are novel, implemented, secure, or suitable for publication.
No identity-bearing material, private keys, submission credentials, or private
evidence belongs in this file.

## How to use this ledger

Each research item records a concrete problem, the smallest experiment that
could distinguish candidate approaches, and the evidence needed before the
idea can enter the protocol or paper. Route status uses only:

- `unexplored`: no adequate experiment or source audit has been completed;
- `attempted`: some design, code, test, proof, or source audit exists, but the
  stated missing check remains;
- `ruled out`: a precise counterexample or requirement mismatch is recorded.

When an item becomes an adopted mechanism, move its decisive alternatives and
evidence to `SECURITY-ROUTE-LEDGER.md`; update `SPEC.md`, the executable tests,
the Lean abstraction, and the paper separately. Conversation agreement alone
does not promote an idea. Before claiming novelty, perform a dated primary-
literature and standards search.

Priority is a planning label rather than a security claim:

- `P0`: closes a concrete attack or semantic ambiguity in a core workflow;
- `P1`: materially improves the research contribution or real deployment;
- `P2`: useful hardening or evaluation after the core is stable.

## Current research thesis

ACSD should make a narrow, checkable distinction between:

1. exact bytes existed no later than an independently attested time;
2. specified pseudonymous keys approved exact scholarly and governance objects;
3. a successor was authorized by the predecessor's declared authority;
4. a later disclosure binds selected identities or evidence to an exact prior
   release without silently widening its scope.

It does not infer natural-person authorship, originality, contribution truth,
plagiarism, peer review, acceptance, or legal non-repudiation. The direct
per-slot form of D-01 is now implemented and formally modeled. The next step
is to evaluate that narrow mechanism against replay, linkability, and real
submission/unblinding workflows before considering credential machinery or a
transparency service.

## Research backlog

### D-01 — Scoped identity disclosure

- **Priority / route status:** P0 / `implemented`.
- **Problem:** after an anonymous release, an author may want to reveal one
  paper, one author slot, or one identity assertion without authorizing a
  broader statement about other papers, coauthors, contributions, or committed
  evidence.
- **Candidate minimal object:** a canonical, separately signed disclosure that
  binds an exact `WorkID`, `ReleaseID`, author slot, pseudonymous approval key,
  identity claim, disclosure purpose, and optional publication identifier.
  It does not mutate the old release or become a successor merely by existing.
- **Competing approaches:** direct per-slot signatures; a unanimous full-byline
  manifest assembled from per-slot signatures; anonymous credentials or
  selective-disclosure credentials for richer policies. Start with direct
  signatures; the credential route remains unexplored rather than presumed
  necessary.
- **Attack obligations:** reject altered work/release/slot/key/identity/DOI;
  reject one author revealing another slot; reject replay into another work;
  reject treating partial disclosure as full-team disclosure; keep publication
  evidence distinct from a venue-acceptance claim.
- **Formal obligations:** scope non-amplification; slot authorization; exact
  target binding; composition of independently signed slots; disclosure absence
  has no effect on release validity; a published disclosure cannot be made
  cryptographically unseen.
- **Smallest experiment:** two works and two author slots. Reveal slot 1 of work
  A, then verify that forged slot 2, work B replay, changed DOI, and a synthesized
  full-team claim are all rejected.
- **Implemented evidence:** `identity_disclosure.py`, the
  `disclose-identity`/`verify-identity` commands, adversarial fixtures, and
  Lean scope/partial-byline theorems.
- **Missing checks:** usability evaluation and primary-literature comparison with verifiable credentials,
  selective-disclosure signatures, provenance disclosure, and preprint
  unblinding practices.
- **Paper value if validated:** potentially a substantive contribution rather
  than a convenience feature, because the claim is a negative authority
  property: disclosed evidence cannot grant a larger verified scope.

### D-02 — Conference submission and unblinding lifecycle

- **Priority / route status:** P0 / `attempted`.
- **Problem:** a public anonymous version `n`, a private venue submission, a
  rejection, a revision, and an accepted named camera-ready version are
  different states. The protocol must not imply that submission, rejection, or
  acceptance occurred merely from local release metadata.
- **Candidate lifecycle:** keep a submission candidate private; rejection causes
  no public transition; ordinary scientific revision creates an authorized
  successor; acceptance permits a named `n+1` or a scoped disclosure bound to
  the venue's persistent publication object.
- **Safety rule under consideration:** do not finalize several incompatible
  same-line/same-version submission candidates. If this occurs, preserve them
  as detectable branches rather than selecting a winner from local or Git time.
- **Attack obligations:** fresh-key `n+1` capture is already rejected by v3;
  additionally reject fake acceptance metadata, wrong-parent disclosure, and
  post-rejection automatic unblinding.
- **Smallest experiment:** simulate accepted, rejected-without-change, and
  rejected-then-revised paths from one anonymous parent and compare verifier
  outcomes.
- **Implemented evidence:** `design/SUBMISSION-LIFECYCLE.md` defines a workflow
  without adding self-asserted venue state;
  `design/submission_lifecycle_runner.py` exercises rejection-as-no-action,
  authorized revision, explicit full-byline publication crosswalks, and replay
  or metadata-substitution attacks through the public CLI. The runner is part
  of the read-only engineering gate.
- **Missing checks:** a real venue's externally verifiable publication object,
  withdrawal semantics, privacy/usability review, and official-policy checks
  before any real submission. No claim is made that the author-signed
  `publication_ref` proves venue acceptance.

### D-03 — Cross-paper isolation and the public-key reuse boundary

- **Priority / route status:** P0 / `attempted`.
- **Problem:** if several public releases reuse one key, revealing the identity
  behind that key links every occurrence. No later disclosure scheme can undo
  linkability already present in public data.
- **Candidate policy:** independently generated per-paper or per-lineage keys;
  keep any identity root private; disclose only the chosen leaf key-to-identity
  binding. A publicly visible common root or delegation may itself restore
  cross-paper linkability.
- **Formal obligations:** isolation under distinct uncompromised keys; an
  explicit impossibility/linkability theorem for reused public keys; no claim
  of unlinkability against timing, account, network, writing-style, or venue
  metadata correlation.
- **Smallest experiment:** publish two model releases under either one reused
  key or two independent keys, disclose only work A, and compute the exact
  protocol-level links available in each case.
- **Implemented evidence:** `design/CROSS-PAPER-ISOLATION.md` distinguishes
  exact verifier scope from observer linkability;
  `design/cross_paper_isolation_runner.py` shows that a release-A sidecar is
  rejected against release B even when both expose the same key ID, while also
  recording that the releases remain publicly linkable by that equality. The
  existing Lean theorem `slot_assent_requires_exact_release` covers the exact-
  release grant boundary.
- **Missing checks:** primary-literature comparison with anonymous credential
  and key-evolving pseudonym systems, recovery without a common public link,
  and a user-facing key-policy lint before release creation. The current
  experiment does not claim stylometric, timing, network, or repository
  unlinkability.

### D-04 — Multi-author partial and full unblinding

- **Priority / route status:** P1 / `attempted`.
- **Problem:** first author, corresponding author, author order, contribution
  claims, and consent to reveal are separate assertions. One collaborator must
  not be able to create an ACSD-certified identity disclosure for another.
- **Candidate rule:** each author slot signs its own identity mapping; a complete
  byline is a manifest of all required valid slot disclosures. Contribution
  disclosure is a separate exact object and is not inferred from slot order.
- **Tradeoff:** protocol authorization cannot stop a malicious collaborator or
  publisher from socially leaking a name; it can only refuse to certify an
  unauthorized or over-broad disclosure.
- **Smallest experiment:** a three-slot paper with one, two, and all three slot
  disclosures, plus a forged disclosure and an unauthorized contribution claim.
- **Implemented evidence:** exact per-slot signatures, full-byline universal
  quantification, duplicate-slot conflict rejection, and two-slot fixtures.
- **Missing checks:** withdrawal semantics, threshold versus unanimity for team
  statements, corresponding-author metadata, and real collaborative usability.

### D-05 — Prospective revocation, rotation, and precommitted recovery

- **Priority / route status:** P1 / `attempted`.
- **Established boundary:** a later statement cannot erase the historical fact
  that a valid signature or transition existed. V3 therefore treats authorized
  transitions as immutable evidence and freezes a lineage when predecessor
  quorum can no longer be met.
- **Open problem:** warn verifiers not to trust new statements after compromise,
  and recover availability without enabling post-hoc identity takeover.
- **Candidate approaches:** precommitted offline recovery keys; hardware-backed
  recovery; threshold guardians; prospective key-rotation statements; an
  external transparency policy for ordering competing notices.
- **Ruled-out subroute:** unconditional retroactive deletion of a once-valid
  transition, because it contradicts immutable historical evidence.
- **Smallest experiment:** a parent precommits a recovery threshold, loses its
  online keys, and authorizes one exact successor. Test stolen-key races,
  recovery replay, guardian substitution, and non-precommitted takeover.
- **Missing checks:** privacy-preserving policy, compromise-time semantics,
  transparency assumptions, fixtures, formal model, and comparison with TUF,
  in-toto, key-transparency, and certificate-revocation designs.

### D-06 — One selective-disclosure calculus for identity and evidence

- **Priority / route status:** P1 / `attempted`.
- **Existing evidence:** v3 already supports salted event commitments and
  Merkle openings for a contiguous dialogue window under unanimous disclosure
  approval.
- **Idea:** give identity disclosure, contribution disclosure, dialogue windows,
  research notes, and publication crosswalks one shared notion of exact scope
  and non-amplification, while retaining distinct schemas and authorization
  principals.
- **Risk:** an overly general policy language may enlarge the trusted parser and
  formal model without improving the main claim.
- **Smallest experiment:** express one dialogue-window opening and one single-
  slot identity opening in a tiny typed model; test whether shared rules reduce
  proof duplication without weakening either authorization boundary.
- **Implemented evidence:** `ACSD.ScopedClaims` shares only signature, exact-
  scope, authorization, policy, and type-compatibility rules; event and identity
  predicates remain distinct. Negative type-confusion theorems and executable
  tests pass. The production release verifier now crosses a strict generic
  appraisal transcript decoded by both Python and Lean.
- **Missing checks:** a second real disclosure workflow using the production
  transcript and evidence that a richer policy language would improve real
  workflows.

### D-07 — Transparency and gossip for forks and revocation notices

- **Priority / route status:** P1 / `unexplored`.
- **Problem:** offline verification detects two presented authorized successors,
  but cannot guarantee that all observers see the same set or safely infer a
  global first child.
- **Candidate approaches:** append-only transparency log; signed checkpoints
  with inclusion and consistency proofs; multiple independent witnesses;
  cross-log gossip. Git commit time is not a substitute.
- **Smallest experiment:** one parent, two authorized same-slot children, two
  split-view observers, and a gossip exchange that exposes the inconsistency.
- **Missing checks:** trust model, deployment cost, privacy leakage, failure and
  recovery semantics, and comparison with Certificate Transparency, SCITT,
  Sigstore/Rekor, and key-transparency systems.

### D-08 — Citation-witness authoring integration

- **Priority / route status:** P2 / `unexplored`.
- **Problem:** literal WorkID tokens and byte offsets are brittle under ordinary
  editing and impose an adoption cost.
- **Candidate approaches:** LaTeX/Pandoc/editor plugin that inserts stable
  semantic markers and regenerates witnesses; a structured-source locator plus
  a final-byte witness; or a canonical citation sidecar.
- **Smallest experiment:** edit a small manuscript through ten realistic changes
  and measure witness repair frequency, false rejection, and whether automation
  changes the exact published bytes.
- **Missing checks:** usability data, multi-format support, hidden-marker ethics,
  and preservation across publisher transformations.

### D-09 — Private-key protection profiles

- **Priority / route status:** P1 / `unexplored`.
- **Problem:** the current CLI generates unencrypted PEM keys; this is acceptable
  only as a plainly documented prototype boundary, not an author-ready security
  posture.
- **Candidate service levels:** encrypted local PEM; operating-system keystore;
  FIDO2/HSM-backed signing; offline recovery material. The protocol should bind
  public keys and signatures without standardizing one storage backend.
- **Smallest experiment:** implement one encrypted-key backend and one
  hardware/OS-backed adapter behind the same signing interface; test key export,
  loss, cancellation, and non-interactive misuse.
- **Missing checks:** cross-platform availability, secret-handling audit,
  migration/backup UX, packaging, and threat-specific recommendations.

### D-10 — Release-safe test and packaging workflow

- **Priority / route status:** P0 / `attempted`.
- **Problem:** running tests inside a strict candidate tree may create Python
  `__pycache__` or Lean `.lake` files and invalidate the manifest even though
  scientific inputs are unchanged.
- **Candidate approaches:** verify from a fresh temporary extraction with caches
  redirected outside the release; ship an immutable archive; make the verifier
  report generated extras separately from payload corruption only when a
  profile explicitly permits it.
- **Smallest experiment:** verify the same fresh candidate twice on Windows,
  macOS, and Linux, then assert that its tree hash and manifest membership are
  byte-identical before and after both runs.
- **Implemented evidence:** `check.py` runs Python without bytecode, builds Lean
  in a temporary copy, generates demos and evidence packages in temporary
  directories, and compares every source-tree file, directory, symlink, mode,
  and content signature before and after. The evidence package contains an
  artifact-mode gate that validates its strict manifest before and after its
  common checks and reproduces itself. The installable wheel is installed into
  a temporary environment and its console script runs a keygen/release/verify
  flow outside the source checkout.
- **Missing checks:** completion of the four-job GitHub matrix on the next push
  and an optional immutable archive transport profile.

### D-11 — Executable-to-Lean refinement boundary

- **Priority / route status:** P1 / `attempted`.
- **Existing evidence:** Lean proves typed composition and lineage properties;
  Python and Node independently exercise canonicalization and signatures. An
  executable 4-by-4 evidence/claim confusion matrix now matches the closed
  compatibility relation, and Lean proves that every derivation over a union
  has a matching verified support atom in one component. The strict certificate
  path now covers v1 approval/event, v2 selective identity, and v3 exact
  approval-set time; Python and Lean agree on 35/35 positive and adverse cases.
  The v3 time subject retains both the exact approval-set digest and normalized
  UTC instant, while exact receipt/trust inputs remain visible assumptions. A
  separate authorized-lineage profile agrees in 15/15 cases. Both strict
  canonical-text decoders now lead by theorem to exact-subject declarative
  derivations. The exact model reuses the single declarative compatibility
  relation and refines the earlier digest-scoped abstraction under any subject
  projection.
- **Problem:** the proof still assumes the facts emitted by filesystem,
  DER/CBOR, signature, and hashing adapters. It does not prove that the
  production release verifier establishes those predicates.
- **Candidate approaches:** a small extracted/reference checker; proof-producing
  test vectors; parser refinement for only the restricted canonical subset;
  property-based correspondence tests as empirical evidence.
- **Smallest experiment:** make the production offline verifier optionally emit
  the same claim-free certificate facts and require its granted outcomes to
  agree with certificate-derived outcomes before exposing that mode publicly.
- **Missing checks:** production-verifier certificate emission, a second-domain
  instance, and a maintained trusted-computing-base inventory.

### D-12 — Comparative and human evaluation

- **Priority / route status:** P2 / `unexplored`.
- **Problem:** current results establish correctness checks and smoke-test scale,
  not whether authors can use ACSD correctly or whether the extra machinery is
  justified against simpler alternatives.
- **Candidate studies:** task-based comparison with detached signatures,
  OpenTimestamps, Software Heritage, and Zenodo; coauthor approval usability;
  citation-witness editing; recovery drills; verifier interpretation tests.
- **Smallest experiment:** five scripted tasks performed by maintainers first,
  measuring commands, artifacts, time, mistakes, and claims each system can
  actually establish. A later user study requires appropriate consent and
  research governance.
- **Missing checks:** protocol parity, current tool versions, study design,
  participants, variance, and independent replication.

## Writing and positioning questions

These are not protocol outcomes and should not drive implementation until the
mechanism and evidence are stable:

- Is scoped disclosure sufficiently novel after a primary-source audit, or is
  it best presented as a rigorous composition/application of known primitives?
- Does the completed paper fit an applied-security venue, a digital-library/
  scholarly-communication venue, or a provenance venue best?
- Which claims belong in the main paper, and which engineering service levels
  belong in an artifact or follow-up paper?
- Can the core be stated as a small authorization calculus whose scholarly
  application is one case study, increasing impact without overstating scope?

Current venue names, deadlines, rankings, and indexing should not be frozen in
this file without a dated check of official sources.

## Intake template

Copy this block for a new idea:

```text
### D-XX — Short name

- Priority / route status: P0|P1|P2 / unexplored|attempted|ruled out
- Problem:
- Security or research value:
- Candidate approaches:
- Smallest distinguishing experiment:
- Attack obligations:
- Formal obligations:
- Evidence already available:
- Missing checks:
- Privacy/anonymity impact:
- Paper value if validated:
- Dated source-audit status:
```

## Promotion checklist

An idea is not ready for `SPEC.md` merely because its happy path works. Before
promotion, require:

1. a named attacker or failure mode and explicit non-claims;
2. at least one accepted and several rejecting executable fixtures;
3. independent verification where the trust boundary warrants it;
4. a Lean statement for the claimed protocol invariant, or a written reason
   why the property is implementation-only;
5. a source audit before any novelty claim;
6. documentation of key loss, replay, concurrency, and privacy consequences;
7. a release-version decision so frozen artifacts are never overwritten.
