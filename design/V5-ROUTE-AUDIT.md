# v5 research route audit: sealed evidence profiles

Status: **design gate, not a v5 protocol claim**.  Checked 2026-09-14.
The frozen `release-v4.0.0-rc1/` package is out of scope for this work.

## Question

Can the small formal core behind ACSD become a useful, independently testable
research contribution without pretending to be a new general authorization
language or expanding the production release verifier?

The candidate is a *sealed evidence profile*: a finite set of typed,
exact-subject evidence facts; an explicit allow-list of conclusions; and a
non-recursive rule whose every premise must be present for that exact subject.
It is deliberately weaker than a trust-management language.  In particular it
has no delegation, recursive derivation, open-world inference, identity
recovery, or global-completeness oracle.

## Prior-art boundary

This is not an unoccupied area.

* [SecPAL](https://doi.org/10.3233/JCS-2009-0364) is a declarative
  decentralized authorization language with delegation, revocation, and a
  Datalog-with-constraints execution strategy.
* The [RT framework](https://www.cs.purdue.edu/homes/ninghui/abstracts/rt_oakland02.html)
  similarly treats role-based trust management and delegation through a logic
  programming translation.
* [FLAC](https://privacytools.seas.harvard.edu/publications/calculus-flow-limited-authorization)
  studies dynamic authorization together with information-flow security,
  including noninterference and robust declassification.
* Provenance-enabled authorization logics also already study the provenance of
  authorization conclusions; ACSD must therefore not describe merely keeping
  evidence beside a decision as novel.

These systems make the proposed kernel neither a replacement nor a smaller
version of their languages.  The narrow prospective distinction is instead:

1. a conclusion is scoped to an equality-defined subject, rather than a
   principal/role query;
2. evidence is closed and named in a canonical transcript before the kernel is
   run;
3. no fact can itself grant a broader claim: a claim additionally needs a
   policy permission and a compatible, exact-subject rule; and
4. the ACSD instance couples that theorem to an exact, predecessor-committed
   authorization transition.

This is a hypothesis to test, not a novelty conclusion.  The new
`FAVA` preprint (2026) and the *Evidence Model for Agentic Processes* preprint
(2026) make it especially important to state the boundary precisely: the
former evaluates a dynamic permission graph, while the latter is explicitly a
conceptual vocabulary and does not validate a particular implementation.

## Route ledger

| Route | Target or obstruction | Evidence now | Missing informative check | Cost | Status |
|---|---|---|---|---|---|
| Rebrand the present core as a general authorization calculus | Conflicts with SecPAL, RT, and FLAC scope; risks a false novelty claim | Source check above | None; the framing is wrong | low | ruled out |
| Add more ACSD-specific predicates | Increases vocabulary without testing a reusable boundary | Existing 106-theorem ACSD model | Independent instance | low | ruled out |
| Generic finite, nondelegating sealed-evidence kernel | Test exact-subject/policy/premise closure independent of papers | ACSD and RATS instances; strict Python--Lean RATS transcript agreement on 22 mutations | A third independently motivated profile only if a broader claim becomes necessary | medium | bounded validation complete |
| Full EAT/COSE/hardware-attestation support | Would test an adapter deployment, not the kernel | No audited local profile or reference-value source | A concrete deployment partner and interoperability plan | high | deferred |
| Supply-chain provenance instance | Potentially useful but too close to ACSD's existing statement-registration path | Only one SCITT registration fact today | Independent policy, source artifact, and threat model | medium | unexplored |
| Symbolic network-protocol analysis | Does not match the current offline evidence-validation threat model | No network protocol or adversary channel in scope | New protocol scope | high | deferred |

## Completed smallest informative object

Build a *claim-free canonical RATS appraisal transcript* solely for
cross-checking the adapter-to-kernel boundary.  It contains one exact subject,
one allow-list decision, and five evidence records: token signature,
measurement binding, nonce freshness, reference-value binding, and verifier
policy authorization.  A Python checker and a strict Lean decoder/checker must
agree on a complete case plus deletion and substitution of each required
premise.

This object is not an EAT parser, a COSE verifier, an ACSD release feature, or
a claim that a device is safe.  Its facts represent results already supplied
by those external adapters.

The validation succeeded: Python and Lean agree on the complete instance,
policy denial, deletion and substitution of every premise, index/order and
type violations, duplicate policy output, and noncanonical text. This supports
one strictly bounded second instance. It does not establish a new general
authorization logic.

## Decoder-consolidation route

The completed second instance exposed a separate engineering risk: the two
pre-existing strict Lean decoders and the new RATS decoder each needed the same
safe-integer, exact-field, string, array, and error-remapping primitives.

| Route | Target or obstruction | Evidence | Missing check | Cost | Status |
|---|---|---|---|---|---|
| Leave local copies in every decoder | Avoids touching old code, but allows silent semantic drift in common byte rules | Three visibly equivalent local implementations | None; duplicates already exist | low | ruled out |
| Centralize all domain decoding | Would blur object-specific error codes and increase regression scope | Hash/UTC/claim parsing are domain-specific | A separately justified domain grammar | medium | ruled out for this refactor |
| Centralize only seven shape/type primitives behind local compatibility aliases | Preserve domain semantics while making common byte rules single-sourced | `StrictJson.lean` now serves all three decoders; 35/35 certificate, 15/15 lineage, 19/19 appraisal, and 22/22 RATS differentials still agree; full 30-check gate and axiom audit pass | A future decoder with a materially different primitive need | low | bounded refactor complete |

The behavioral validation succeeded: the old certificate, lineage, and
appraisal differentials retained their exact acceptance and rejection results,
as did the RATS differential, and the final read-only gate passed all 30
checks. Future grammar-specific parsing remains local; only shape/type
primitives are shared.

## Pre-mortem

| Likely failure | Early warning | Mitigation / stop rule |
|---|---|---|
| The second instance is only renamed ACSD data | It reuses release, PEC, or author fields | Keep the transcript in `design/` and use only RATS-style token, measurement, nonce, reference, verifier, and policy identifiers |
| The parser becomes a shadow EAT implementation | New CBOR, COSE, x509, or hardware code appears | Stop; retain only abstract canonical JSON and document external adapter assumptions |
| The generic theorem is tautological and adds no security argument | All new theorems restate one list-membership definition | Publish it only as validation infrastructure; do not elevate it to a paper contribution |
| Cross-language agreement is shallow | Only an all-positive fixture passes | Require independent deletion/substitution, policy-denial, duplicate, noncanonical, and unsafe-integer cases |
| The work bloats the shipped CLI | Product modules/imports grow to support this experiment | Keep it out of `acsd.py`, package entry points, and release format; put runners under `design/` and a separate Lean executable |

## Acceptance threshold for the route

Proceed to a v5 theory section only if all of the following hold:

1. the transcript has a strict Python checker and a strict Lean decoder;
2. their output agrees on the positive and every negative mutation class;
3. Lean proves exact-premise necessity and policy denial for the decoded
   decision; and
4. the resulting paper claim remains narrow: *a reusable sealed-evidence
   validation kernel with two bounded instances*, not a general authorization
   language or a deployed RATS implementation.

Otherwise the route is closed without modifying the frozen v4 package.
