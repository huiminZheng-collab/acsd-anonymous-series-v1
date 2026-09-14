# Submission, revision, and unblinding lifecycle

Checked 2026-09-14 against the post-v3.2 source tree. This note specifies a
workflow over existing ACSD objects; it does not add a venue-status field or
claim that ACSD can independently verify acceptance or rejection.

## Decision

ACSD should model only protocol-visible evidence. A private venue submission,
review decision, or rejection is not automatically a public ACSD object.
Scientific changes are ordinary authorized successors. Later author or
publication disclosure uses external, per-slot signed sidecars and never
mutates the frozen anonymous release.

| Real-world event | ACSD action | Checkable result | Deliberate non-claim |
|---|---|---|---|
| Submit a private copy | None required | Existing public release remains fixed | Submission occurred |
| Rejection without public revision | None | Existing release remains valid and unchanged | Rejection occurred |
| Revision after review | `acsd revise` | Exact predecessor-authorized successor | Why the text changed |
| Publicly reveal one author | `acsd disclose-identity` | Slot key assented to one exact identity mapping | Civil identity independently verified |
| Publicly reveal a full byline | One sidecar per slot | All release slots supplied valid mappings | Joint venue statement or contribution truth |
| Bind a proceedings/DOI reference | Signed `publication_ref` in each sidecar | Keys assented to that exact string | Venue acceptance or registry truth |

If the camera-ready manuscript bytes differ, it is an authorized successor.
If the bytes are unchanged and only a public identity crosswalk is needed, a
new release version is not required: the immutable release plus signed
sidecars already binds the claimed names to its exact author slots. A venue's
own signed receipt, DOI registry record, or proceedings entry may be evaluated
as separate external evidence in a future profile; author-supplied metadata
must not silently stand in for it.

## Rejected alternatives

- A self-declared `accepted: true` field is not evidence and would invite
  semantic amplification.
- Automatically publishing an unblinding object after a local rejection state
  would expose identities without an explicit author action.
- Treating a named camera-ready file as a successor merely because it uses
  version `n+1` would reopen the fresh-key lineage-capture attack.
- Deleting or rewriting the anonymous parent would destroy the evidence the
  crosswalk is meant to identify.

## Executable experiment

Run:

```text
python design/submission_lifecycle_runner.py
```

The experiment uses only temporary keys and directories. It checks four small
cases: no-protocol-action rejection leaves the release tree unchanged; a
post-review revision derives `AUTHORIZED_SUCCESSOR`; full per-slot unblinding
shares one publication reference but keeps `publication_acceptance_verified`
as a non-claim; and cross-release replay or publication-reference mutation is
rejected. The engineering gate also compares the result against
`submission_lifecycle_report.json`; the checked-in report contains no key
material or personal identity.

This is executable validation of the existing choreography, not proof that a
venue made any decision. The remaining external-evidence question is whether a
specific venue exposes a stable signed or registry-backed object worth adding
as a separately typed evidence profile.
