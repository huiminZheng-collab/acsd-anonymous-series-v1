# Cross-paper disclosure isolation and key reuse

Checked 2026-09-14 against the post-v3.2 source tree. This note separates two
properties that are easy to conflate: verifier scope and public unlinkability.

## Boundary

An ACSD identity sidecar signs an exact release ID, WorkID, author slot, public
key ID, identity assertion, purpose, and optional publication reference. A
sidecar for release A therefore cannot establish the identity-assent outcome
for release B, even when both releases contain the same public key. The
executable verifier rejects that replay with `IDENTITY_RELEASE_MISMATCH`; the
Lean theorem `slot_assent_requires_exact_release` captures the corresponding
exact-subject obligation.

This scope isolation does **not** make A and B unlinkable. ACSD key identifiers
are deterministic identifiers of public-key material. If an author reuses one
public key in unrelated releases, equality of the public key and key ID is
already visible before any unblinding. Revealing an identity for A does not
cryptographically grant an identity claim for B, but an observer can still
link the two pseudonymous slots and may infer that they share key control.

## Operational policy

- Generate an independent key for each unrelated paper or intended-unlinkable
  lineage.
- Reuse or explicitly rotate keys only where public continuity is desired.
- Do not place a common identity root, deterministic child-key derivation
  proof, or public delegation across otherwise unlinkable releases; each would
  recreate a visible cross-paper edge.
- Treat later inference from key reuse as a privacy fact, not as a verifier-
  granted natural-person identity claim.

No later sidecar format can undo a public equality relation that was already
published. Recovery across independent anonymous lineages therefore needs a
privacy-preserving design if it is added at all; a common public recovery key
would defeat this policy.

## Executable experiment

Run:

```text
python design/cross_paper_isolation_runner.py \
  --check-report design/cross_paper_isolation_report.json
```

The runner creates only temporary keys and releases. It demonstrates both
sides of the boundary: a disclosure for A is rejected against B despite public
key reuse, while the two release records remain publicly linkable by equal key
IDs. A third release with an independently generated key has no such equality
edge. It exercises the product command directly; add `--fail-on-cross-work`
to make a detected cross-WorkID key group return exit code 1 in a release CI.
The experiment establishes this implementation property, not universal
anonymity against writing style, timing, network, repository, or social clues.
