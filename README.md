# ACSD v1.0.0 - anonymous scholarly release profile

This repository is a **content-anonymous** research release. It contains an
anonymous six-page technical paper and an offline-verifiable prototype for
anonymous scholarly releases, version lineages, and mutual citations.

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

## Quickstart

To reproduce this release from a clean checkout:

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

## Contents

- `paper/acsd-v1.pdf` - the anonymous technical paper.
- `artifact/` - deterministic fixture generation, independent Node.js
  verification, negative fixtures, and a public-file manifest for the ACSD
  series profile.
- `formal-core/` - the Lean 4.33.1 source for the abstract acceptance model.
- `rfc3161-adapter/` - an offline RFC 3161 request/receipt verification
  adapter with local test fixtures. It never contacts a TSA by itself.
- `RELEASE-MANIFEST.sha256` - SHA-256 manifest for the exact public payload.

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

Use PowerShell and Node.js. The artifact driver is offline after checkout; it
uses the locked Python wheel in `artifact/vendor/`.

```powershell
Set-Location artifact
.\run.ps1
Set-Location ..
node .\verify-release-manifest.cjs
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

- Version: `v1.0.0`
- Anonymity level: content-anonymous only
- Timestamp status: no live TSA request was made for this release
- Repository status: public prepublication only; no venue submission,
  acceptance, or peer review is asserted
- Signing status: this release manifest is hashed but not identity-signed, to
  avoid publishing an identity-bound key during anonymous release

See [ANONYMITY.md](ANONYMITY.md), [AI-USE-DISCLOSURE.md](AI-USE-DISCLOSURE.md),
and [BUILD-AND-VERIFY.md](BUILD-AND-VERIFY.md) before relying on the artifact.
