# ACSD Lean core

This is the deliberately small Lean 4 core extracted from ACSD v1.6.8/v1.6.9. It proves logical properties of an idealized verifier; it does not implement or prove Ed25519, SHA-256, JSON canonicalization, RFC 3161, BBS, transparency logs, or real-world authorship.

Pinned toolchain: `leanprover/lean4:v4.33.1` (Lean 4.33.1). This project keeps a verified local copy under `tools/toolchains/lean-4.33.1-windows/`, and the proof gate prefers that copy over a global PATH installation. Do not present the source as a completed formal proof until `scripts/check-proofs.ps1` succeeds.

The intended acceptance condition retains only security-relevant facts:

```text
policy-authentic catalog
author-authentic request bound to catalog
service-authentic plan bound to request and catalog
active dependency-closed selection
required capabilities and asserted capabilities are derived from the signed catalog
```

One consequence is intentionally negative.  The core treats
`historicalAuthorshipTruth` as a named claim but gives no provenance component
an automatic grant to it.  It contains a theorem showing that, unless a signed
catalog explicitly (and therefore accountably) grants that claim, an accepted
plan cannot assert it.  This is the formal version of the project's boundary:
timestamps, signatures, Git history, and protected AI dialogue can support
provenance claims, but they do not by themselves prove who the human author is.

`Prior` in the lifecycle file is deliberately a predicate of the **whole
abstract plan**, not merely `plan.id`.  The implementation obligation is that
an external receipt binds a canonical digest of the full plan and that digest
binds the same abstract plan.  Otherwise a timestamp for an old identifier
could be replayed for new contents.

`ACSD/CitationWitness.lean` is the corresponding narrow bridge for citation
text.  It does not parse real manuscripts.  Instead it proves that if an
accepted release says its signed UTF-8 byte witnesses are exactly the scanner
output, then every listed `WorkId` has an exact signed witness, every scanner
token is listed, and a one-byte offset shift or an omitted token makes
acceptance impossible.  A separate refinement assumption connects that
contract to `SeriesGraph.releaseTextCites`; real UTF-8 scanning, JSON parsing,
hashing, and signing remain implementation obligations.

Once Lean is installed locally, run `pwsh ./scripts/check-proofs.ps1`. The script refuses `sorry`, `admit`, and project-defined `axiom` declarations before it accepts a build.

The gate passed locally on 2026-09-10 with Lean 4.33.1.  It also rejects any
`#print axioms` result that contains an axiom dependency, not only `sorryAx`.
See `TOOLCHAIN-PROVENANCE.md` for the release identity and verified digest.
