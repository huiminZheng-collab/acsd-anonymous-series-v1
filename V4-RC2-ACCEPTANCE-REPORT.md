# ACSD v4.0.0-rc2 local acceptance report

Checked 2026-09-21. This release candidate adds the optional exact
submission-link profile without changing the frozen release schema or the
submitted TCJ manuscript.

## Added profile

- A venue-authenticated challenge binds one source release, exact submitted
  manuscript, nonce-salted private submission-handle commitment, venue domain,
  review round, validity interval, disclosure mode, and ordered byline.
- Each author-slot response signs the digest of that same complete challenge.
- Complete release-slot coverage yields the narrow
  `SUBMISSION_LINEAGE_LINKED` result. Partial responses remain explicitly
  partial, and editor-confidential responses do not authorize public release.
- Discovery, civil identity, originality, plagiarism, peer review, and
  acceptance remain non-claims.

## Verification

- 203 Python tests pass; three environment-dependent tests are skipped.
- The full 31-check source, package, installed-wheel, differential, formal,
  and workspace-byte-identity gate passes.
- The submission-link tests reject manuscript replacement, wrong private
  handle, wrong venue key, signed-context mutation, response mixing, missing or
  duplicate slots, expired challenges, and disclosure-mode downgrade.
- `formal/ACSD/SubmissionLink.lean` compiles without `sorry` or `admit` and its
  central theorems are included in the axiom audit.

## Release boundary

The release candidate is a local, content-anonymous research artifact. It is
not a venue submission, acceptance, peer review, production deployment, civil
identity service, or guarantee that an editor will discover a public anonymous
release. No upload, DOI publication, or remote push is implied by this report.
