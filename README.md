# ACSD public release archive

This repository is a **content-anonymous** research release. It contains an
additive sequence of anonymous papers and offline-verifiable prototypes for
scholarly releases, authorized version lineages, scoped disclosures, external
time evidence, and mutual citations. The current candidate is
[`v3.2.0-rc1/`](v3.2.0-rc1/); older releases remain frozen in place.

It is not author-unlinkable double-blind publication: a GitHub account, network
metadata, timing, or a public signing key can link a release to a person. No
claim of natural-person authorship, originality, independent discovery, peer
review, legal nonrepudiation, or venue acceptance is made here.

## Motivation

When a venue or repository puts a manuscript on hold—for example while an
arXiv endorsement or moderation step is pending—authors may want a public,
content-anonymous priority record without pretending that it proves who wrote
the work. ACSD provides that intermediate evidence package: signed releases,
explicit series lineage, citation witnesses, and independently checkable
manifests.

## Current quickstart

Verify the exact v3.2.0-rc1 payload, then run its read-only artifact gate:

```powershell
python .\v3.2.0-rc1\verify_release.py .\v3.2.0-rc1
Set-Location v3.2.0-rc1
python .\check.py --artifact --skip-formal
```

Omit `--skip-formal` when the pinned Lean toolchain is installed and `lake` is
on `PATH`, or set `ACSD_LAKE` to its executable. The candidate README contains
the authoring, revision, timestamp, selective-unblinding, and verification
commands.

## Historical v1 quickstart

To reproduce the original v1 fixture from a clean checkout:

```powershell
Set-Location artifact
.\run.ps1
Set-Location ..
node .\verify-release-manifest.cjs
```

The command regenerates the fixtures and verifies the public manifest. The
LaTeX source supplement is available under
[`paper-source-v1.0.1/`](paper-source-v1.0.1/); it is an additive source release
for this paper and does not alter the v1.0.0 artifact manifest.

## v2.0.0 Provenance Evidence Capsule

The additive [`v2.0.0/`](v2.0.0/) release introduces the Provenance Evidence
Capsule (PEC): exact release and governance bindings, unanimous pseudonymous-key
approval, event-chain checks, claim-policy non-amplification, and selectively
openable salted dialogue commitments. It includes a content-anonymous paper,
16 Python tests, a strict package-manifest verifier, and a standalone Lean
4.33.1 project with four new abstract PEC acceptance theorems.

Verify the v2 file set before executing it:

```powershell
python .\v2.0.0\verify_release.py .\v2.0.0
```

Then run its complete gate from `v2.0.0/`. Set `ACSD_LAKE` if `lake` is not on
`PATH`; the three v1 integration tests discover this repository through the
parent directory or an explicit `ACSD_V1_ROOT`.

## v3.2.0-rc1 Authorized lineage and typed appraisal

The additive [`v3.2.0-rc1/`](v3.2.0-rc1/) candidate closes the fresh-key
`n+1` version-capture gap with exact predecessor-authority quorum, supports
authorized key/team rotation and named branches, and timestamps the completed
approval set rather than an unsigned target. Its production verifier derives
outcomes only through a restricted claim-free appraisal transcript shared with
the Lean model. The package includes 156 Python tests, three maintained
Python--Lean differential suites, 84 v3 theorem statements with no
`sorry`/`admit`, and a checked-in real freeTSA interoperability fixture.

This remains a limited evidence system: it proves neither natural-person
identity nor originality, and its exact TSA signer pin is not general PKIX
revocation or path validation.

## Contents

- `paper/acsd-v1.pdf` - the anonymous technical paper.
- `artifact/` - deterministic fixture generation, independent Node.js
  verification, negative fixtures, and a public-file manifest for the ACSD
  series profile.
- `formal-core/` - the Lean 4.33.1 source for the abstract acceptance model.
- `rfc3161-adapter/` - an offline RFC 3161 request/receipt verification
  adapter with local test fixtures. It never contacts a TSA by itself.
- `RELEASE-MANIFEST.sha256` - SHA-256 manifest for the exact public payload.
- `v2.0.0/` - additive PEC paper, implementation, tests, formal model, and its
  own complete SHA-256 manifest.
- `v3.2.0-rc1/` - current authorized-lineage paper, CLI, adversarial corpus,
  strict appraisal transcript, Lean sources, and its own complete SHA-256
  manifest.

## Claims that can be checked

Running `artifact/run.ps1` regenerates the deterministic corpus and checks:

- 8 standalone release versions and 18 author endorsements;
- 7 signed series objects and 13 closed scenarios;
- 30 independent profile checks, including malformed JSON, path escapes, and
  citation-witness mismatch cases; and
- a 111-entry artifact manifest.

The Lean source records 53 theorem statements whose last local check completed
without theorem axiom dependencies. It is an abstract-model result: it does not
prove that the Python or Node.js implementations refine the model.

## Reproduction

Use PowerShell or bash and Node.js. The artifact driver is offline after
checkout; it uses the locked Python wheel in `artifact/vendor/`.

```powershell
Set-Location artifact
.\run.ps1
Set-Location ..
node .\verify-release-manifest.cjs
```

On Linux or macOS, run the equivalent entry point:

```bash
cd artifact && ./run.sh && cd ..
node ./verify-release-manifest.cjs
```

For the Lean source, install the pinned Lean 4.33.1 toolchain and run:

```powershell
Set-Location formal-core
pwsh .\scripts\check-proofs.ps1
```

The RFC 3161 adapter demonstrates request and receipt validation with a local
test TSA. It is a protocol test, not independent timestamp evidence. Its README
describes how a separately selected TSA receipt can be checked offline.

## Release status

- Current additive candidate: `v3.2.0-rc1`
- Historical base release: `v1.0.0`
- Anonymity level: content-anonymous only
- Timestamp status: v3 includes one pinned freeTSA response as an
  interoperability existence check; this is not a service-reliability claim
- Repository status: public prepublication only; no venue submission,
  acceptance, or peer review is asserted
- Signing status: this release manifest is hashed but not identity-signed, to
  avoid publishing an identity-bound key during anonymous release

See [ANONYMITY.md](ANONYMITY.md), [AI-USE-DISCLOSURE.md](AI-USE-DISCLOSURE.md),
and [BUILD-AND-VERIFY.md](BUILD-AND-VERIFY.md) before relying on the artifact.
The repository is released under [MIT](LICENSE); citation metadata is in
[CITATION.cff](CITATION.cff).
