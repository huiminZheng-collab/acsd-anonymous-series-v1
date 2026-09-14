# Strict-double-blind submission plan

Status: pre-CFP local plan, checked 2026-09-14.  It does not submit, upload,
or change the frozen v4 evidence package.

## Why a separate package is necessary

The public v4 candidate is **content-anonymous but not author-unlinkable**:
it intentionally contains a public GitHub-account URL in its source/citation
material.  It is therefore unsuitable as a strict-double-blind artifact.
Submitting the same bytes under an anonymous author line would not repair that
linkage.

## Two isolated outputs

1. **Public evidence release.**  Preserve its current bytes, manifest,
   signature history, and account linkage.  It remains the priority and
   reproducibility record.
2. **Blind-review package.**  Create later in a fresh directory from a
   review-specific source copy.  It contains only the anonymous PDF and the
   artifacts specifically permitted by the target CFP.  Do not include Git
   history, repository metadata, `CITATION.cff`, release keys, or an unchanged
   source archive.

The two are related research objects, but no blind package may claim that an
anonymous link proves authorship.  After acceptance, an identity-disclosure
sidecar or signed event may bind the public release to the identified version
where appropriate; a rejected submission needs no cryptographic action.

## Review-package checks

Before a future submission, work from a clean staging directory and inspect:

* PDF metadata (author, creator, subject, custom fields) and visible author,
  affiliation, acknowledgements, self-citations, links, and URLs;
* text and source for personal names, usernames, ORCIDs, institutions, home
  paths, repository/worktree paths, build comments, and file provenance;
* archive contents for `.git`, CI configuration naming an account, identity
  materials, private-key material, release manifests that expose links, and
  generated timestamps not required by the CFP;
* reproducibility from two isolated clean builds if deterministic output is
  claimed; and
* compliance with the specific venue's then-current double-blind and artifact
  policies.  This plan intentionally does not guess an unpublished CFP's
  template, page limit, artifact rules, or disclosure policy.

The review PDF should replace direct public account URLs with a neutral
statement such as “anonymous artifact withheld for double-blind review,” but
only when that wording is permitted by the target venue.  The public v4
package is never edited to achieve this.

## Decision points

* **Before review:** do not add authorship disclosure to the public package
  merely because a paper is submitted.
* **On rejection:** retain the public record unchanged.  A rejected version
  has no obligation to reveal a key or identity.
* **On acceptance:** decide whether the camera-ready paper will cite the
  public release and whether the authors want a signed selective disclosure.
  That is an explicit author decision, not an automatic protocol transition.

## Deliverables when a target venue is known

1. a venue-specific compliance checklist tied to the actual CFP;
2. a freshly generated anonymous PDF plus inspection report;
3. an optional clean source/artifact archive only if permitted; and
4. a separate, identified camera-ready mapping plan.
