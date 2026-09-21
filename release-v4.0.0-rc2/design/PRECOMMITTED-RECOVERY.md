# Precommitted recovery without retroactive revocation

Checked 2026-09-14 against the post-v3.2 source tree. This is a design and
experiment plan for the next source iteration; it is not part of the frozen
`release-v3.2.0-rc1` or `v3.3.0-rc1` public candidates.

## Security question

If the online predecessor threshold is unavailable, can an anonymously
published WorkID authorize one exact successor without accepting a recovery
authority invented after the loss?

The answer can be yes only when the predecessor release already committed to
an independent recovery key set and threshold. The narrower claim is
availability under a predeclared alternate authority. It is not retroactive
erasure of a historical signature and it is not a globally ordered revocation
service.

## Adjacent mechanisms and retained boundary

- The Update Framework requires each new root to satisfy the threshold of its
  immediate predecessor and its own threshold. It recommends offline root
  keys, and treats threshold-root compromise as requiring out-of-band recovery:
  <https://theupdateframework.github.io/specification/>.
- OpenPGP RFC 9580 defines key-revocation signatures and recommends escrow of a
  precomputed, specifically scoped revocation signature instead of generating
  a general third-party revocation key. It also distinguishes compromise from
  retirement because the effect on earlier signatures differs:
  <https://www.rfc-editor.org/rfc/rfc9580.html#section-13.9>.
- Certificate Transparency and the IETF Key Transparency architecture use
  append-only views, consistency proofs, monitoring, and gossip to expose
  conflicting views. They do not make an offline verifier's partial view
  globally complete: <https://www.rfc-editor.org/rfc/rfc9162.html> and
  <https://datatracker.ietf.org/doc/draft-ietf-keytrans-architecture/>.

These mechanisms support three separate conclusions:

1. an exact historical signature remains verifiable evidence;
2. a predecessor may precommit a distinct authority that can authorize a
   future exact transition; and
3. selecting a unique global head among withheld or conflicting transitions
   requires an additional publication, transparency, or observer policy.

ACSD should implement (2) without claiming (3) and without falsifying (1).

## Minimal wire design

An opt-in lineage authority uses `acsd-lineage-authority/v2` and retains the
ordinary author key set and threshold. It additionally contains:

```json
{
  "recovery": {
    "schema": "acsd-recovery-authority/v1",
    "key_ids": ["<sha256-key-id>"],
    "threshold": 1
  }
}
```

The recovery keys are public, sorted, unique, and disjoint from the online
author keys. Their public-key bytes live under `recovery-public-keys/`. A v1
authority has no recovery path; an old verifier therefore rejects the v2
schema instead of silently ignoring a security-relevant extension.

A recovery authorization signs the same canonical
`acsd-lineage-transition/v1` object as an ordinary predecessor authorization.
Consequently it binds the exact parent release and PEC, exact child release,
governance and PEC, both authority objects, WorkID, line, and version. The
candidate child's author keys must still unanimously approve the normal ACSD
approval target. Recovery therefore cannot choose unspecified future bytes or
skip child-side assent.

The two separate authorization directories are:

```text
lineage/authorizations/           ordinary predecessor-authority signatures
lineage/recovery-authorizations/  precommitted recovery-authority signatures
```

One transition uses exactly one path. Mixing nonempty ordinary and recovery
sets is rejected as an ambiguous construction. Recovery is permitted only for
a child that changes the online key set or threshold; changing only the
recovery configuration remains an ordinary predecessor-authorized transition.
Otherwise recovery adds no availability and needlessly exposes the offline key.

## Acceptance and non-claims

The verifier returns `RECOVERY_AUTHORIZED_TRANSITION` only if:

1. the parent release committed the exact recovery key set and threshold;
2. the child is a structurally valid consecutive successor or named branch;
3. the exact transition matches both releases and PECs;
4. a recovery quorum signed that exact transition;
5. no ordinary lineage-authorization set is mixed into the edge; and
6. every child author approved the exact child target.

This result does not mean that an old online key is cryptographically erased,
that the verifier has seen every competing child, or that this child is the
globally latest publication. If stolen online keys also authorize a same-slot
child, presenting both still yields a detectable fork with no protocol-selected
winner. A transparency or pinning policy may narrow that deployment boundary,
but is not silently imported into the offline profile.

## Smallest discriminating experiment

Use one parent online key, a two-of-two recovery authority, and one new child
key. Exercise:

- online keys unavailable, two recovery signatures: accept the exact rotated
  child;
- only one recovery signature: reject as incomplete;
- fresh uncommitted guardian: reject;
- recovery signature replayed onto different child bytes: reject;
- recovery keys presented for a v1/no-recovery parent: reject;
- both ordinary and recovery authorization files: reject ambiguity;
- an online-authorized and a recovery-authorized same-slot child: accept each
  edge independently and report equivocation when compared, with no winner.

The experiment establishes exact conditional authorization and exposes the
remaining view-completeness limit. It does not establish global revocation,
guardian honesty, secure hardware storage, or recovery usability.
