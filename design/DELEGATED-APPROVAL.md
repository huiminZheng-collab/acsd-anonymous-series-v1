# Exact-target delegated approval

Status: implemented protocol substrate; author-facing invitation UI remains future work.

## Product scenario

The corresponding author performs preparation, packaging, timestamping, and
publication. A coauthor either approves the exact target directly or signs a
one-time delegation allowing a distinct coordinator-held key to approve that
same immutable target. Packaging and timestamp submission require no author
private key and are not treated as author approval.

## Evidence chain

For author key `A`, delegate key `D`, and approval-target digest `T`, delegated
coverage requires both:

1. an `acsd-approval-delegation/v1` object binding `A`, `D`, and `T`, signed by
   `A`; and
2. the exact approval target `T`, signed by `D`.

The delegation repeats the WorkID, release, governance, PEC, and lineage-edge
digests for inspectability, while `approval_target_digest` provides the single
canonical scope. It states `action = approve-exact-target` and
`redelegation = false`.

The finalized `acsd-approval-set/v2` closes over the exact delegate approval
and author-signed delegation certificate bytes before RFC 3161 timestamping.
The verifier reports each author slot as `direct` or `delegated`.

## Deliberate claim distinction

All-direct approval may establish `KEY_ASSENT` and `GOVERNANCE_ASSENT`.
A set containing delegated coverage establishes only
`AUTHORIZED_TARGET_APPROVAL`: each author slot is covered by either its own
signature or an exact author-signed delegation plus the named delegate's
signature. It does not claim that every author personally operated a key on
the final target.

## Command-line prototype

The coordinator generates a separate agent key and gives only its public key
to a coauthor. The coordinator opts into the narrower claim profile when the
candidate is initialized, before any author or lineage signature exists:

```text
acsd init paper.pdf --team team.json --out release-dir \
  --allow-delegated-approval
```

The coauthor then authorizes it for that already fixed package:

```text
acsd delegate-approval release-dir --author-key bob.key \
  --delegate-public-key coordinator-agent.pub
```

The coordinator can then discover and exercise every pending exact approval
addressed to the supplied agent key while finalizing:

```text
acsd coordinator-finalize release-dir \
  --delegate-key coordinator-agent.key \
  --tsa https://tsa.example/tsr
```

`approve-delegations --key coordinator-agent.key` performs the same automatic
discovery transaction without finalizing. The lower-level `approve-as
--for-author` form remains available for explicit single-slot operation.

Other authors may use ordinary `acsd approve`; direct and delegated approval
can coexist for different author slots but are rejected as ambiguous for the
same slot.

## Security boundary

The v1 delegation has no wildcard scope, version range, expiration based on a
local clock, lineage action, recovery action, identity-disclosure action, or
redelegation. Changing any bound object changes `T` and invalidates reuse.
The delegate key must be distinct from every author key.

On a successor, delegated child approval is not counted toward predecessor
authority continuity. Even when the author set is unchanged, the predecessor
threshold must sign the exact transition through `acsd authorize`; the
coordinator-held delegate cannot perform that command. This keeps approval
convenience from silently becoming control of the WorkID lineage.

Because the capability names one immutable target, revocation is handled by
not finalizing or publishing that candidate; an already published signed fact
cannot be erased. Long-lived, multi-version delegations would require expiry,
revocation discovery, ordering, and substantially different claims and are
not part of this profile.

## Remaining usability work

The current commands establish the safe protocol boundary but do not yet make
coauthor participation effortless. The intended next surface is a small local
or browser approval client that renders the PDF, byline, contributions, AI-use
statement, version, and exact digest, then emits either a direct signature or
this one-time delegation. A relay may transport encrypted request/response
objects, but verification must remain offline and independent of that relay.
