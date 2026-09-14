# ACSD v4.0.0-rc1 local acceptance report

Checked locally on 2026-09-14. This report records the candidate prepared in
this work tree. It is not a GitHub release, archival deposit, venue submission,
or claim of external adoption.

## Candidate scope

The candidate integrates the previously implemented exact-lineage controls:

- predecessor-quorum authorization for an n+1 successor;
- opt-in, predecessor-committed, disjoint recovery authority for one exact
  authority-changing child, with no mixed ordinary/recovery authorization;
- interactive encrypted PKCS#8 private-key handling, which deliberately keeps
  passphrases out of arguments, environment variables, JSON, and release
  artifacts; and
- selective per-slot identity disclosure and publication crosswalks, neither of
  which establishes venue acceptance or natural-person identity.

The immutable package is `release-v4.0.0-rc1/`. Its manifest covers the paper
source/PDF, specifications, test corpus, formal sources, and reproducibility
scripts.

## Validation performed

- `check.py` completed in source mode: all 30 checks passed, including Python
  tests, Python--Node differentials, the recovery and lifecycle runners, a
  wheel installed outside the source tree, evidence-package construction, Lean
  build/audit, and source-tree byte-identity.
- `release-v4.0.0-rc1/check.py --artifact` completed: the packaged artifact
  passed its full independent gate and pre/post manifest checks.
- `verify_release.py release-v4.0.0-rc1` accepted the manifest, and
  `build_release.py --check release-v4.0.0-rc1` independently rebuilt a
  byte-identical tree.
- `paper/acsd-v4.tex` compiled cleanly to a 16-page PDF. Every rendered page
  was visually inspected; the final build has no unresolved reference or
  citation warning and no overfull box.

## Formal boundary

The current Lean project contains 103 theorem declarations and an explicit
64-entry axiom audit. It proves ACSD's typed authorization and claim-composition
rules: exact-target non-reuse, closed outcome permissions, lineage/recovery
preconditions, replay resistance at the abstract transition level, and scoped
disclosure constraints. It also strictly decodes the maintained restricted
appraisal transcripts and agrees with Python on 35 scoped-certificate, 15
lineage-certificate, and 19 production-appraisal cases.

The proof deliberately treats hash, signature, COSE/DER/CBOR, filesystem,
release-object parsing, RFC 3161, and external-service behavior as trusted
adapter boundaries. It does not claim primitive correctness, key custody,
guardian honesty, global fork visibility, natural-person identity, originality,
or venue acceptance.

## Content-anonymity audit

The candidate is classified as **content-anonymous**, not author-unlinkable.
The final package scan found no PEM private-key block, no `*.key` file, and no
actual local Windows or Unix home-directory path. `pdfinfo` reports an empty
PDF Author field, and the rendered paper displays `Anonymous authors`.

Two deliberate public-linkability surfaces remain: `CITATION.cff` names the
repository URL and the paper links to the archived v1 proof surface under the
same public repository account. These do not identify a natural person within
the artifact, but can link the release to that account. They are retained and
documented rather than misrepresented as double-blind anonymity. A generic
`/Users/` string in the attack-misuse documentation is a prohibited-path
example, not a local path.

## Release boundary

No push, GitHub Release, DOI/Zenodo deposit, TSA acquisition, or submission was
performed while preparing this candidate. Any such action requires a separate,
explicit authorization.
