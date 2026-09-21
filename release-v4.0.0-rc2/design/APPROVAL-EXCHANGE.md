# Portable approval exchange

## Goal

Allow a corresponding author to assemble a candidate while every remote author
keeps their private key. The transport may be untrusted. Acceptance depends on
the existing exact approval target and bound public key, not on who delivered a
folder or on the transport manifest alone.

## Three protocol roles

1. `export-approval-request` validates the live candidate and snapshots it for
   exactly one still-uncovered author key. The folder contains `request.json`,
   `candidate/`, and `MANIFEST.sha256`; it contains no private key.
2. `respond-approval-request` verifies the manifest and all candidate bindings,
   checks that the supplied private key occupies the requested author slot,
   shows the ordinary author checklist, and requires explicit confirmation. It
   returns a minimal direct-approval response or an exact-target delegation.
3. `import-approval-response` verifies the response manifest, exact file set,
   WorkID, release digest, target digest, author slot, public-key binding and
   COSE payload before changing the live candidate. Replays and conflicting
   approval methods are rejected.

## Security boundary

The SHA-256 manifest detects accidental changes and an attacker who cannot
rewrite it. It is not an authority signature. If an attacker replaces the
candidate and regenerates the manifest, the normal release verifier still
checks the manuscript digest and cross-object bindings, and the author sees the
new exact target before deciding whether to sign. On return, regenerating a
manifest cannot repair a forged or target-replayed COSE signature.

The response metadata is routing information. The authority evidence is the
author signature over the canonical approval target, or the author signature
over a delegation object that itself closes that target and the distinct
delegate key. No response grants lineage transition, identity disclosure,
recovery, wildcard approval, or redelegation.

## Why directories

The current profile deliberately exchanges directories. A built-in archive
reader would need a new security policy for traversal, links, device names,
case-fold collisions, duplicate members, decompression limits and platform
metadata. Users may compress a request or response for transport and extract it
before ACSD verification; archive parsing is not part of the acceptance path.

## Coordinator batching and commit semantics

`export-approval-requests` emits one child request per author who is still
missing an action. Children use short slot-only names such as `slot-01`; the
full author key identifier remains bound inside the request and collection
manifest instead of lengthening every transported path. A slot with an
imported delegation but no delegated approval
is reported separately because the next action belongs to the coordinator's
agent key, not to that author.

`import-approval-responses` never incrementally edits the live candidate. It
copies the candidate into a same-parent staging directory, verifies and applies
every response there, and swaps the staged directory into place only after the
entire collection succeeds. A duplicate response or a late invalid signature
therefore cannot leave an earlier response half-committed.

`coordinator-finalize` extends the same transaction through final package
assembly and optional RFC 3161 acquisition. With repeatable `--delegate-key`
arguments it discovers every pending exact delegation addressed to those
agent keys and exercises them before finalization. Authors and coordinators do
not copy author key IDs. The standalone `approve-delegations` command offers
the same discovery and all-or-nothing write behavior without finalizing.

Finalization requires an explicit time policy: either a TSA URL or
`--allow-untimestamped`. A TSA failure discards the staging copy and leaves the
original candidate awaiting approvals. Neither command publishes the resulting
directory.

## Scripted role evaluation

`scripted_role_evaluation.py` executes a three-author exchange using the real
CLI: two direct responses, one exact delegation to a coordinator agent, one
transactional finalize, and independent verification. After key setup the
happy path uses seven commands, requires no JSON edits, transfers no private
keys, and copies no protocol identifiers. A second run changes one returned
signature and regenerates its transport manifest; batch import is rejected and
the live candidate retains zero approvals.

This is a scripted role-based evaluation with zero human participants, zero
production deployments, and zero external services. It supports workflow
executability and rollback claims only; it is not evidence of human usability
or adoption.
