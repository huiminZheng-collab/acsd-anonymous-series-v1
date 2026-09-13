# Trusted-kernel roadmap

Checked against source commit `932425c` on 2026-09-13. This roadmap concerns
the live source tree. Immutable `release-*` snapshots are evidence, not code to
deduplicate in place.

## Objective

Reduce the security decision surface while preserving all wire formats and
user-visible capabilities. Byte-level adapters establish narrowly typed facts;
one pure kernel is the only component allowed to turn those facts into claims.

```text
JSON / COSE / RFC 3161 / Merkle / filesystem adapters
                         |
                  appraised evidence
                         |
              pure evidence-to-claim kernel
                         |
             claims plus supporting digests
```

This is not a claim that parsers or cryptography disappear from the trusted
computing base. Their soundness remains an explicit assumption until a checked
adapter transcript or refinement proof discharges it.

## Priority decisions

### P0 — one granting path

1. Replace the unscoped `(kind, digest, verified)` atom with exact subject
   types for approval targets, approval sets, events, identity slots, and
   registration statements.
2. Remove the caller-controlled `verified` Boolean. Successful adapters emit
   an `AppraisedEvidence` carrying the digest of its exact support object or
   transcript.
3. Route release approval, external time, event disclosure, identity
   disclosure, and the demo verifier through the same closed derivation table.
4. Preserve legacy wire names only at the serialization boundary.
5. Enforce architecture tests: the pure kernel imports no I/O, crypto, CLI, or
   application modules, and production code cannot append claim strings.

The first source implementation of this phase is the current working change;
the frozen v3.1.0-rc1 package is intentionally untouched.

### P0 — independent formal semantics

1. Parameterize Lean claims by their exact release, PEC/event/window,
   approval-set, slot/key/assertion, or lineage scope.
2. Define an inductive `Derives` relation independently of an executable
   `checkBundle` function.
3. Prove checker soundness: every emitted claim has a finite derivation whose
   leaves are exact appraised facts.
4. Prove exact-subject preservation, target/set separation, signer-set
   closure, critical-evidence deletion, full-byline exactness, anchored lineage
   membership, replay separation, and cross-kind exclusion.
5. Give executable countermodels for deleting each critical premise. The main
   results must not be projections from a conjunction called `Accepted`.

### P1 — checked adapter boundary

1. Define a canonical `acsd-verification-certificate/v1` transcript containing
   exact input, signature, Merkle, approval-set, timestamp, transition, policy,
   and externally supplied trust-input digests. It contains no final verdict.
2. Make Python and Node independently produce the same transcript from the
   same immutable byte snapshot.
3. Let the Lean checker reconstruct parameterized claims from that transcript;
   compare exact claims, not self-reported success bits.
4. Keep RFC 3161 CMS/PKIX verification as an explicit oracle initially, but
   bind the receipt, subject, signer fingerprint, and external pin exactly.

Current status: `attempted`. Python and Node now emit identical canonical
certificates for the two-author approval and event-window fixture, and the pure
structural checker enforces signer/payload/input/Merkle closure. Lean now has an
independent transcript closure checker and a composed soundness theorem from a
checked transcript group to a parameterized claim. Exact JSON-to-Lean decoding,
identity, approval-set time, and lineage remain open.

### P1 — structural simplification

1. Merge `pec_core.validate_pec` and `acsd.check_bindings` behind one pure
   bundle validator while retaining compatibility facades for one release.
2. Split approval-set file collection from pure set validation.
3. Move v1 filesystem, Node subprocess, and metadata-only paths to a named
   legacy adapter.
4. Reduce `acsd.py` to command routing and application orchestration only after
   the behavior corpus proves equivalence.
5. Centralize public-key identifiers and stable error serialization.

No dependency-injection framework, plugin framework, event bus, database, or
general policy language is planned. Those additions would enlarge the decision
surface without helping verification.

## Generalization gate

ACSD remains the primary complete instance. A general kernel claim requires at
least one second, standards-based instance with a genuinely multi-premise
rule. The smallest useful candidates are:

- RATS/EAT: measurement + reference value + freshness + authorized verifier
  derives a named appraisal result, but not the claim that a device is safe;
- software supply chain: provenance + expected builder/policy derives a bound
  build claim, while SCITT registration remains distinct from release approval.

Only after one such instance passes the same mutation and proof-certificate
checks should the project describe itself as cross-domain.

## Validation gate for every migration

- existing Python, Node, canonicalization, lineage, disclosure, TSA, manifest,
  wheel, and artifact tests remain green;
- the complete 6-by-10 unary compatibility table has no undeclared grant;
- wrong subject type, digest, event window, missing signer, forbidden policy,
  and unsupported social claims are rejected;
- old/new differential fixtures preserve successful outputs, exit codes, and
  first stable error codes unless a change is explicitly versioned;
- Lean builds without `sorry` or `admit`, and central theorems receive an axiom
  audit;
- a changed live protocol produces a new release candidate rather than
  overwriting v3.1.0-rc1.

## Route ledger

| Route | Evidence | Missing check | Status |
|---|---|---|---|
| Continue adding independent verifier-specific grants | Existing paths had manual string grants and vocabulary drift | None; this directly violates the single-kernel objective | ruled out |
| Typed exact-subject unary kernel | ACSD evidence families already have distinct safe unary claims | Production integration and full matrix | attempted |
| General-purpose recursive trust language | Mature systems such as SecPAL and RATS already occupy this space | No ACSD requirement justifies the complexity | ruled out for P0 |
| Finite multi-premise rules with proof certificates | Needed for quorum and a real second-domain instance | Approval/event transcript and pure checker now exist; Lean refinement and second adapter remain | attempted |
| Full parser/crypto verification in Lean | Would maximize assurance but dominates current project cost | First establish a narrow transcript and refinement boundary | unexplored P2 |

## Smallest next experiment

Use one two-author release containing one approval-set timestamp, one dialogue
window, one identity sidecar, and one authorized lineage edge. Python and Node
must emit byte-identical verification transcripts; Lean must emit the same
parameterized claims. Removing any single required support digest must remove
the corresponding exact claim. This is an empirical/refinement check; the Lean
soundness theorem is the proof result.
