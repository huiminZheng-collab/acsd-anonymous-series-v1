# Proof status — 2026-09-11

## What exists

The Lean source is a minimal abstract model, with no external package
dependency.  It contains the following intended kernel-checkable statements:

- an accepted plan covers every required capability;
- an asserted capability is derived from a selected signed-catalog component;
- without an explicit catalog grant, a plan cannot assert
  `historicalAuthorshipTruth`;
- request/catalog/plan bindings are exact;
- a different digest at the already observed version is rejected;
- a signed team-role manifest is tied to the exact request and plan, and its
  declared first and corresponding authors are members who each approved that
  exact manifest;
- a team-role attestation must itself be covered by a signed-catalog
  capability, while contribution truth cannot be silently upgraded from the
  attestation; and
- a v2 revision names an exact v1 predecessor, and a same-work/same-version
  reference whose object digest changes is a distinct reference rather than a
  transparent replacement;
- a team-attested lineage manifest is tied to the exact request object and to
  both the team and lineage manifest digests in the service plan; and
- a citation bundle is tied to that same request and to the exact team-role,
  lineage, and bundle digests; a mutual-citation edge is an internal declared
  graph edge, not an implicit temporal-priority fact; and
- a series graph keeps cyclic semantic citations over stable `WorkId`s
  separate from later `WorkId → RevisionRef` resolutions.  Its local
  commitment relation contains only anchor-to-release witnesses, so a mutual
  semantic citation cannot manufacture a reverse release-to-anchor edge or a
  temporal-priority capability.  In addition, every accepted semantic edge
  has a resolved source release whose idealized parsed-text relation cites the
  target `WorkId`; and
- an accepted series graph asserts the existence of a structural rank above
  every resolved revision.  With that rank certificate, the combined
  anchor-to-release and direct-release-to-predecessor skeleton is acyclic;
  this rank is not a timestamp or priority assertion; and
- a post-cutoff plan cannot be labelled pre-suspension unless its independent
  `Prior` witness, bound to the full abstract plan, satisfies the abstract
  soundness contract; and
- a claim named in a version-bound attack/obligation model derives its blocking
  capability requirements; an accepted plan covers each such obligation, and
  an uncovered requested obligation is listed as residual; and
- a signed citation witness names an exact UTF-8 byte range for a `WorkId`.
  Acceptance equates signed witnesses with the scanner result and equates the
  published reference list with their target projection: a shifted signed
  offset or an omitted exact token prevents acceptance.  A separately stated
  refinement can then connect that byte-level contract to the idealized
  `releaseTextCites` relation; and
- suspending a component makes acceptance impossible only when that component
  is actually necessary for feasible selections.

This wording matters.  These are claims about an *idealized verifier*, not
claims that a digital signature identifies a human author, nor a proof of any
cryptographic implementation.

## Current verification state

**Verified on this host.**  The source-level token audit passed: no `sorry`,
`admit`, or project-defined `axiom` declaration occurs in the Lean modules.
The official Lean 4.33.1 Windows archive was SHA-256 checked before extraction.
`scripts/check-proofs.ps1` then completed `lake build` and the full
`#print axioms` audit.  All 53 listed theorems, including the six team-role
theorems in `ACSD/Team.lean`, seven lineage theorems in `ACSD/Lineage.lean`,
five citation-bundle theorems in `ACSD/CitationBundle.lean`, ten
series-graph theorems in `ACSD/SeriesGraph.lean`, four combined-DAG theorems
in `ACSD/CommitmentDAG.lean`, and three claim-obligation theorems in
`ACSD/ClaimObligation.lean`, plus five citation-witness theorems in
`ACSD/CitationWitness.lean`, reported that they do not depend on any axioms.

The model proves the consequences of an abstract exact-token scanner, not that
the JavaScript or Python release parser computes it correctly from manuscript
bytes.  The scanner-to-`releaseTextCites` refinement is represented explicitly
in `CitationWitness.lean`; connecting either side to real UTF-8, JSON, hashes,
and signatures remains an implementation refinement obligation.  The analogous
JSON signature/canonicalization mapping for the finite claim-obligation fixture
is also outside this Lean model.

## Completion gate

Run:

```powershell
Set-Location formal/acsd-core
pwsh ./scripts/check-proofs.ps1
```

The gate must complete `lake build` and the `AxiomAudit.lean` check without
any axiom dependency.  Preserve `out/lean-version.txt`, `out/build.log`, and
`out/axioms.txt` with the research artifacts.
