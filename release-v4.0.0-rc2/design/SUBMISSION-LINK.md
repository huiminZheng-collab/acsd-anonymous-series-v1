# Exact submission-link profile

Status: experimental small extension. It does not modify the submitted TCJ
manuscript and is not a submission service.

## Boundary

The profile answers one question after an editor or venue has identified a
possibly related anonymous ACSD release:

> Did the author-slot keys of that exact release assent to this exact submitted
> manuscript and ordered named byline in this venue context?

It does not discover the anonymous release, authenticate a civil identity,
decide plagiarism or originality, or prove review or acceptance. Failure to
produce a link is `UNVERIFIED`, not evidence of impersonation.

## Objects

1. `acsd-submission-challenge/v1` is signed by a venue/editor key. It binds the
   source release, submitted-manuscript SHA-256, venue domain, nonce-salted
   commitment to the private submission handle, review round, validity window,
   disclosure mode, and complete ordered slot-to-name mapping.
2. `acsd-submission-opening/v1` is signed by one exact release author-slot key.
   It binds the digest of the entire challenge, so responses from different
   manuscripts, venues, rounds, nonces, or bylines cannot be combined.
3. Set verification emits the narrow claim `SUBMISSION_LINEAGE_LINKED`. It
   reports full-byline status only when the challenge maps every release slot
   exactly once and every mapped slot supplies a valid response.

The `editor-confidential` mode authorizes verification by the editor only. Its
responses are not accepted as public-disclosure authorization. A separate
`public` challenge is required for a publicly distributable link.

## CLI flow

The venue creates a challenge. `--submission-handle` is not serialized in
plaintext; a nonce-salted commitment is stored instead.

```text
acsd create-submission-challenge release-dir named-paper.pdf \
  --venue-key venue.key --venue-domain journal.example \
  --submission-handle SUB-42 --round 1 \
  --expires-at 2026-09-24T00:00:00+00:00 \
  --byline "1:Alice Example:https://orcid.org/0000-0000-0000-0001" \
  --byline "2:Bob Example" --out challenge
```

Each author runs one command with their own slot key:

```text
acsd respond-submission-challenge release-dir named-paper.pdf \
  --challenge challenge/submission-challenge.json \
  --venue-signature challenge/submission-challenge.cose \
  --venue-public-key venue.pub --submission-handle SUB-42 \
  --key alice.key --out alice-opening
```

The editor verifies the common challenge and all responses:

```text
acsd verify-submission-link release-dir named-paper.pdf \
  --challenge challenge/submission-challenge.json \
  --venue-signature challenge/submission-challenge.cose \
  --venue-public-key venue.pub --submission-handle SUB-42 \
  --opening alice-opening/submission-opening-slot-1.json \
  --opening bob-opening/submission-opening-slot-2.json \
  --signature alice-opening/submission-opening-slot-1.cose \
  --signature bob-opening/submission-opening-slot-2.cose \
  --require-full-byline
```

The venue key must be authenticated through the venue's normal submission
channel. The profile deliberately does not create a new global venue PKI.
Challenge expiry is checked at response and verification time. Long-term
archival evidence would require a separately typed venue receipt; that is not
silently inferred from an expired challenge.

## Checked attacks and model

`test_submission_link.py` and `test_submission_link_cli.py` cover manuscript
replacement, wrong private submission handle, wrong venue key, challenge-field
mutation, cross-challenge response mixing, incomplete and duplicate slots,
expiry, disclosure-mode downgrade, and the full two-author CLI path.

`formal/ACSD/SubmissionLink.lean` models exact submission context, authenticated
challenge acceptance, full-slot coverage, cross-context non-reuse, manuscript
and byline substitution, and confidential/public authorization separation. It
treats cryptographic verification and wall-clock evaluation as adapter inputs;
it does not prove Ed25519 or civil identity.
