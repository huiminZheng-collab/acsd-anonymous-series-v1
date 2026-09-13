# Lineage verification certificate v1

`acsd-lineage-verification-certificate/v1` is a claim-free transcript for one
purported predecessor-to-child edge. It is deliberately separate from the
cumulative approval/event/identity/time certificate profiles: a verifier that
only needs lineage succession need not parse unrelated disclosure or timestamp
facts.

## Adapter obligations

The Python and Node adapters independently read the same immutable package and
emit byte-identical canonical JSON. Before emitting a certificate, each adapter
checks:

- canonical parent and child release, PEC, governance, target, transition, and
  approval-set objects;
- the exact WorkID, parent/child release digests, line identifiers, versions,
  authorities, thresholds, and transition kind;
- every child approval signature and its bound public key;
- every predecessor transition-authorization signature and its bound public
  key when the authority changes; and
- the exact approval-set projection of those signature byte strings.

The certificate contains those appraised facts and exact input digests. It does
not contain `valid`, `accepted`, or a self-reported outcome field.

## Pure closure rule

The pure Python checker and the Lean checker derive one narrowly scoped
`AUTHORIZED_SUCCESSOR` claim only if all of the following hold:

1. the child is same-line version `n+1`, or a named branch at version 1;
2. the declared transition kind matches the structural and authority change;
3. the child target binds the exact transition;
4. all child-authority approvals bind the exact child target;
5. unchanged authority uses those same approvals to meet the predecessor
   threshold, while changed authority requires a predecessor-threshold subset
   over the exact transition;
6. every signature/public-key/object digest has one exact input role;
7. the approval set contains exactly the appraised child and predecessor
   signature entries; and
8. the child PEC policy permits `AUTHORIZED_SUCCESSOR`.

The claim subject includes the WorkID digest, exact parent/child release and PEC
digests, both line digests and versions, and the transition digest. An
authorization for one edge is therefore not reusable for another child.

## Checked example and adverse cases

`demo-lineage/` is a deterministic public fixture in which a two-of-two parent
authority authorizes a one-key child team at version 2. The checked transcript
is `design/lineage_verification_certificate_demo.json`.

`design/lineage_verification_certificate_diff.py` checks byte identity between
the Python and Node adapters. `design/lean_lineage_transcript_diff.py` compares
complete Python and Lean derivations across the valid fixture and mutations for
missing signatures, payload/input substitution, approval-set substitution,
unbound transitions, wrong mode/kind, policy absence, and nonconsecutive
versions. The formal soundness result is in
`formal/ACSD/LineageTranscript.lean`.

## Trust boundary

The transcript checkers validate closure of already appraised facts; they do
not themselves implement filesystem, COSE, or canonical-JSON cryptography.
The Python and Node adapters establish those facts independently, and the
certificate digest must remain bound to the exact adapter output being
evaluated. This separation makes the semantic decision surface small without
pretending that adapter correctness has been formally proved.
