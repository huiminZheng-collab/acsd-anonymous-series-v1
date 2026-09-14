# Appraisal transcript v1

`acsd-appraisal-transcript/v1` is the narrow production boundary between
byte-level release verification and ACSD's evidence-to-claim kernel. It is
optional verifier output, not a new signed object and not a self-authenticating
certificate.

## Purpose

The filesystem, canonical-JSON, COSE, lineage, manifest, and RFC 3161 adapters
first inspect the immutable release bytes. Only after an adapter succeeds may
the release verifier construct an exact `AppraisedEvidence` atom. The
transcript serializes those atoms and the release's closed outcome policy. The
production verifier then strictly parses that serialization and derives its
displayed `granted_outcomes` from the parsed value.

This removes a former gap between the product and the formal model: the same
finite typed object that drives the user-visible decision can be independently
decoded by Lean. It does not remove adapter correctness, signature
unforgeability, hash collision resistance, trusted-time pinning, or filesystem
integrity from the assumptions.

## Closed wire shape

The top-level object has exactly three fields:

```json
{
  "schema": "acsd-appraisal-transcript/v1",
  "policy": {"permitted_outcomes": ["KEY_ASSENT"]},
  "evidence": [{
    "index": 0,
    "kind": "UNANIMOUS_APPROVAL",
    "subject": {
      "kind": "approval-target",
      "target_digest": "<64 lowercase hex characters>"
    },
    "certificate_digest": "<64 lowercase hex characters>"
  }]
}
```

The policy vocabulary and order are closed by `claim_derivation.WIRE_ORDER`.
Evidence indices must be the consecutive sequence `0..n-1`. Each of the seven
evidence kinds has one exact subject variant: approval target, target time,
approval-set time, event window, identity assertion, registered statement, or
lineage edge. Unknown and extra fields, wrong kind/subject pairs, duplicate
atoms, unsafe integers, invalid digests, and noncanonical JSON are rejected.
Multiple distinct certificates may support the same exact claim.

The transcript deliberately has no `valid`, `accepted`, `verdict`, `granted`,
or claim-list field. `permitted_outcomes` is policy input, not evidence that an
outcome was established.

## Derivation and formal connection

`release_verifier.verify_release_dir` builds this transcript after successful
adapters and immediately calls `appraisal_transcript.derive` on the strictly
parsed value. The pure `claim_derivation` table remains the only granting
kernel. `acsd verify RELEASE --emit-appraisal-transcript --json` exposes the
same value for audit; omitting the option preserves the normal output surface.

`formal/ACSD/AppraisalTranscriptJson.lean` independently decodes the canonical
wire form, reconstructs exact `AppraisedAtom` values, and filters candidate
requests through the proved `checkClaim` checker. Its soundness theorem states
that every emitted request has an `AppraisalDerives` derivation; the refinement
theorem maps every such exact derivation into the earlier abstract model under
an arbitrary subject projection.

The maintained Python/Lean differential includes complete evidence, policy
restriction, missing evidence, multiple support, kind/subject confusion,
duplicate and reordered evidence, unknown/extra fields, malformed digests,
unsafe numbers, invalid windows/slots/versions, and noncanonical bytes.

## Trust boundary

A copied or hand-written transcript can truthfully describe only itself. A
verifier must bind it to the adapter run and release bytes whose result it is
intended to summarize. ACSD's CLI does this operationally by constructing the
transcript in memory after those checks. The transcript alone does not prove
that a COSE signature, RFC 3161 response, identity mapping, or lineage edge was
validly appraised.
