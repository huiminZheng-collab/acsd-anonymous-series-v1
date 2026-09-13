# ACSD PEC and authorized-lineage profile v0.2

Status: v0.2 research profile with an executable v3.0 reference
implementation. The terms **MUST** and **MUST NOT** describe the profile
contract, not a deployed standard. The Python CLI implements the binding and
cryptographic packaging rules; Lean certifies a separate abstract composition
model rather than refining the executable parsers.

## 1. Purpose and narrow security goal

A Provenance Evidence Capsule (PEC) binds an exact scholarly release to:

1. an anonymous authorship-governance statement whose exact digest is covered
   by unanimous approval-target signatures;
2. a sequence of commitments to research materials such as a Git snapshot,
   a research note, or a key human--AI dialogue; and
3. optional, separately verified external receipts over the exact jointly
   signed approval-target digest.

It allows a later disclosure to prove that disclosed material matches an
earlier commitment.  It also prevents a verifier from upgrading the evidence
to a stronger claim than the policy authorizes.

It does **not** prove a natural person's identity, historical authorship,
truth of a contribution allocation, originality, causation of a paper by a
dialogue, legal non-repudiation, peer review, or a universal publication
priority.

## 2. Reused objects and profile boundary

PEC does not replace ACSD v1 objects.

- `PaperRelease` remains the exact, self-contained release object.
- `AuthorshipGovernanceStatement` records byline
  order, CRediT-role declarations, corresponding-author declaration, and
  AI-use declaration. Its member keys and its `manuscript_sha256` are
  jointly bound by the approval target and its coauthor signatures.
- `SeriesPackage` remains the optional object resolving stable WorkIDs to
  completed releases.
- RFC 3161, transparency-log, and witness receipts remain sidecars with their
  own trust anchors and verification rules.

A PEC only stores exact digests and policy references to those objects. It
MUST reject a governance statement or release object that is not independently
valid under its own profile.

## 3. Canonical bytes and identifiers

All signed PEC and disclosure bodies use the restricted ACSD canonical JSON
profile: recursive ASCII-key sorting, no insignificant whitespace, no
duplicate keys, and safe integers only.  Let `H` be SHA-256 over exact bytes.

```text
release_digest       = H(canonical PaperRelease bytes)
governance_digest    = H(canonical AuthorshipGovernanceStatement bytes)
event_digest         = H(canonical EvidenceEvent body)
pec_digest           = H(canonical PEC body)
approval_target_digest = H(canonical ApprovalTarget body)
disclosure_digest    = H(canonical Disclosure body)
```

All digest-bearing fields are lower-case hexadecimal SHA-256 values.  A
digest is an identifier for exact bytes, not an assertion about the factual
truth of those bytes.

`PEC body` and `Disclosure body` exclude their signature envelopes. An
envelope carries the digest of that already-canonical body as its subject;
the envelope is therefore a sidecar, not a recursively signed field.

## 4. PEC body

```json
{
  "schema": "acsd-pec/v0.2",
  "pec_id": "random-128-bit-or-longer-identifier",
  "subject": {
    "work_id": "stable WorkID from PaperRelease",
    "release_digest": "sha256 hex",
    "version": "v1",
    "line": "main",
    "predecessor_pec_digest": null,
    "series_package_digest": null
  },
  "governance": {
    "statement_digest": "sha256 hex",
    "manuscript_sha256": "sha256 hex",
    "required_pec_approval_key_ids": ["all released author key ids, sorted"],
    "ai_use_declaration_digest": "sha256 hex"
  },
  "events": [{"schema": "acsd-pec-event/v0.1"}],
  "claim_policy": "ClaimPolicy",
  "disclosure_policy": "DisclosurePolicy",
  "issuer_key_id": "one key from required_pec_approval_key_ids"
}
```

The CLI constructs an `acsd-approval-target/v2` object containing the work id,
release digest, governance digest, PEC digest, sorted required key ids, and the
lineage-transition digest (null only for a genesis release).
Every required key signs the exact same canonical target. For v0.2 this set
MUST equal the complete `PaperRelease.authors` key set; a subset policy is not
supported. A PEC is accepted only if every public key hashes to its declared
key id, all target signatures, referenced objects, event links, and policy
conditions verify. Mutable `state.json` is never an approval oracle.

The governance statement's `manuscript_sha256` MUST equal the exact
`PaperRelease.content.sha256`. Its byline member keys MUST map one-for-one to
the release author keys in the same order, and its corresponding-author and
AI-use fields are therefore bound to that release. This binds team assent to
the declaration; it does not make the declarations historically true.

`predecessor_pec_digest` is null for an initial capsule. For a second or later
release about the same line, it MUST equal the exact predecessor PEC
digest and the subject MUST name the exact predecessor release already named
by the underlying `PaperRelease`.  A later PEC may add evidence; it cannot
edit an earlier PEC.

## 5. Authorized lineage succession

### 5.1 Authority state

Every v3 release contains a signed authority object:

```json
{
  "schema": "acsd-lineage-authority/v1",
  "key_ids": ["sorted author key ids"],
  "threshold": 2
}
```

The key list MUST equal the release's complete author-key set, although the
threshold MAY be lower than the number of authors. The default is unanimity.
The threshold controls authorization of the *next* lineage edge; ordinary
approval of the current release remains unanimous. A verifier MUST use the
predecessor's signed threshold and MUST NOT accept a lower threshold supplied
only by the child. Legacy v1/v2 releases without this object migrate as if they
had listed every author key with a unanimous threshold.

### 5.2 Exact transition

Every non-genesis release carries an `acsd-lineage-transition/v1` body binding:

```json
{
  "schema": "acsd-lineage-transition/v1",
  "kind": "continuation | threshold-change | team-change | branch",
  "work_id": "urn:uuid:...",
  "parent": {
    "release_digest": "sha256 hex",
    "pec_digest": "sha256 hex",
    "line": "main",
    "version": 1,
    "authority": "exact predecessor authority object"
  },
  "child": {
    "release_digest": "sha256 hex",
    "governance_digest": "sha256 hex",
    "pec_digest": "sha256 hex",
    "line": "main",
    "version": 2,
    "authority": "exact child authority object"
  }
}
```

The example abbreviates the two authority objects for readability; real
canonical objects contain them, not strings. The child approval target binds
the exact transition digest. The transition in turn binds already-complete
child objects, so no digest cycle is created.

For an unchanged authority object, the child's ordinary unanimous approval signatures
also satisfy the predecessor threshold, because they cover the exact target
that binds the transition. When the key set or threshold changes, a predecessor-threshold
set MUST separately sign the canonical transition body, and every new child
author MUST sign the child approval target. This is old-authority authorization
plus new-team acceptance, not an indefinite delegation to an unscoped key.

### 5.3 Structural and conflict rules

A same-line child MUST keep the WorkID, name the exact predecessor release and
PEC digests, and increment the predecessor version by exactly one. A child on
a new line MUST keep the WorkID, name the exact predecessor, and begin at
version 1. Merely knowing the public WorkID, predecessor digests, and next
version number grants no succession right.

Authorization is relative to an exact accepted predecessor, not to the WorkID
string alone. A standalone verifier SHOULD pin the previously accepted
`parent_release_id`; the reference CLI accepts `--expected-parent-release-id`
and reports `PIN_MATCHED` or `UNPINNED_EXACT_PARENT`. Without such an anchor,
the verifier proves only that the embedded parent authority authorized this
edge. It cannot distinguish a separately fabricated genesis that copied a
public WorkID, just as signatures alone cannot establish natural-person identity.

An otherwise self-consistent child signed only by fresh attacker keys is
reported as `VALID_OBJECT_BUT_UNAUTHORIZED_SUCCESSOR`; it is not accepted as a
member of the predecessor's lineage. Two separately authorized, different
children of the same parent in the same line/version slot are reported as
`LINEAGE_EQUIVOCATION_DETECTED`. The verifier records no automatic winner.
Children on distinct lines are branches rather than slot conflicts.

Series membership is an additional decision: a series key may advertise an
authorized child as a head, but it MUST NOT manufacture predecessor-authority
approval. Deployments that require an official head therefore check both the
lineage edge and the signed series package.

### 5.4 Loss, rotation, and revocation boundary

Authorization signatures are immutable evidence. A later statement cannot
make an already valid historical transition cryptographically false. A current
authority can rotate prospectively through another exact successor, but after
an unconditional transfer the old authority cannot unilaterally revoke the new
authority. Concurrent authorized children produce a detectable fork whose
ordering requires an external transparency or governance policy.

If fewer than the predecessor threshold keys remain available, this profile
safely freezes the lineage. It has no post-hoc identity recovery rule: such a
rule would reopen the unauthorized-successor attack. A future profile may bind
a recovery authority in advance. Without that prior commitment, community or
institutional recognition creates a visibly separate social fork rather than
an automatically verified continuation.

## 6. Evidence events

Every event has a monotonically increasing `sequence`, a random `event_id`,
an exact predecessor digest, and a commitment:

```json
{
  "schema": "acsd-pec-event/v0.1",
  "sequence": 0,
  "event_id": "random-128-bit-or-longer-identifier",
  "previous_event_digest": null,
  "kind": "git_snapshot | dialogue_snapshot | research_note_snapshot | role_acknowledgement",
  "commitment": {
    "scheme": "salted-sha256-v1 | merkle-dialogue-v1 | ciphertext-sha256-v1",
    "digest": "sha256 hex",
    "disclosure_class": "public | revealable | sealed"
  },
  "asserted_relation": "optional narrow relation name"
}
```

The event commitment is over a domain-separated encoding containing the
event kind, `pec_id`, `event_id`, sequence, and raw evidence bytes.  A
`salted-sha256-v1` commitment MUST use an independently generated 256-bit
secret salt for material that could be guessed.  A bare hash of a short note,
prompt, or title MUST be treated as publicly guessable, not sealed.

For `dialogue_snapshot`, `merkle-dialogue-v1` commits separately salted,
ordered turns.  A disclosure may open a contiguous window with its leaf
values, salts, indices, and Merkle paths; it does not need to reveal other
turns.  This proves membership and position in the committed dialogue root,
not who typed a turn, which provider generated a turn, or that the dialogue
caused the paper.

For `git_snapshot`, the committed bytes MAY include a Git tree, commit, or
patch representation.  Git author and committer times are retained only as
self-asserted fields.  They never grant an external-time capability.

For `role_acknowledgement`, the event is an additional signed acknowledgement
of a named governance relation. It cannot replace the governance statement's
required member signatures or make contribution declarations true.

## 7. Claim policy

The policy declares which narrow outcomes may be emitted after verification.
It is included in the PEC body and therefore covered by every approval-target
signature, so neither an issuer nor a service can later change the meaning of
existing evidence while reusing those approvals.

| Outcome | Necessary evidence | Explicit non-claim |
|---|---|---|
| `KEY_ASSENT` | valid signature over exact PEC or referenced object | natural-person identity |
| `GOVERNANCE_ASSENT` | independently valid governance statement and required member approvals | contribution truth; legal authorship |
| `COMMITTED_EVIDENCE_MATCH` | valid disclosure that opens the exact event commitment | early creation; causal authorship |
| `EXTERNALLY_NOT_AFTER` | RFC 3161 receipt over the exact approval target, verified with an external signer pin | first creation; global priority; originality |

The policy MUST list at least these global non-claims:
`natural_person_authorship`, `contribution_truth`, `originality_truth`,
`legal_nonrepudiation`, and `peer_review`.

An implementation MUST NOT emit an outcome that is absent from the exact
policy or whose required capability is unavailable.  In particular,
`git_snapshot`, `dialogue_snapshot`, a local clock, a series rank, or a
witness observation cannot be relabelled `EXTERNALLY_NOT_AFTER`.

The policy is itself a closed, canonical object. Its minimum v0.1 form is:

```json
{
  "schema": "acsd-pec-claim-policy/v0.1",
  "permitted_outcomes": ["KEY_ASSENT", "COMMITTED_EVIDENCE_MATCH"],
  "required_capabilities": {
    "EXTERNALLY_NOT_AFTER": ["rfc3161-exact-approval-target-imprint"]
  },
  "global_non_claims": ["natural_person_authorship", "contribution_truth", "originality_truth", "legal_nonrepudiation", "peer_review"]
}
```

Absent outcomes and absent capability requirements are rejected rather than
given implementation-defined meanings.

## 8. Disclosure objects

```json
{
  "schema": "acsd-pec-disclosure/v0.1",
  "pec_digest": "sha256 hex",
  "event_id": "exact event id",
  "event_sequence": 3,
  "kind": "same kind as committed event",
  "disclosure_mode": "full | dialogue_window",
  "opened_material": "bytes or structured leaves",
  "opening_secret_or_merkle_paths": "as required by commitment scheme",
  "approval_key_ids": ["all required PEC approval key ids, sorted"]
}
```

The disclosure policy is a closed object inside the PEC. Its minimum v0.1
form is:

```json
{
  "schema": "acsd-pec-disclosure-policy/v0.1",
  "approval_rule": "unanimous-current-release-authors",
  "permitted_modes": {
    "git_snapshot": ["full"],
    "dialogue_snapshot": ["dialogue_window", "full"],
    "research_note_snapshot": ["full"],
    "role_acknowledgement": ["full"]
  }
}
```

Thus no corresponding author, first author, or PEC issuer may disclose team
material unilaterally in v0.1. A disclosure's separate approval-envelope set
MUST contain exactly one valid signature from every listed approval key over
the same canonical disclosure body. A disclosure MUST bind the exact PEC
digest, event id, sequence, kind, and commitment scheme. A verifier rejects a
disclosure that opens valid bytes for another PEC, another event, another
governance statement, or an unauthorized window.

PEC v0.1 supports direct commitment openings only.  It does not claim
zero-knowledge selective disclosure, anonymous credentials, redaction
soundness beyond the disclosed leaf proofs, or post-disclosure revocation.

## 9. External evidence sidecars

An external sidecar is not included in the immutable approval target. It names
`approval_target_digest`, has its own canonical bytes, and is verified under a
trust decision supplied independently by the verifier.

- **RFC 3161 sidecar:** retains the raw nonce-bearing request and response,
  verifies an exact signer-certificate/fingerprint pin and the message imprint
  over `approval_target_digest`, and
  permits only `EXTERNALLY_NOT_AFTER`.
- **Transparency/witness sidecar:** retains the signed statement, receipt,
  checkpoint, policy, and any required inclusion/consistency proof.  It
  permits only the policy's observation or equivocation outcomes.
- **Missing sidecar:** yields `INDETERMINATE` for the outcome requiring it;
  it does not invalidate the base PEC.

No receipt may be replayed from an old target to a revised target, because the
imprint and sidecar subject digest must equal the exact current
`approval_target_digest`. A certificate copied into the package is not its own
trust anchor. The reference CLI does exact signer pinning, not general PKIX
path construction or revocation checking.

## 10. Verification procedure

1. Parse canonical PEC bytes, re-canonicalize, and reject any byte mismatch.
2. Recompute the approval target and verify every approval signature and each referenced ACSD
   release/governance/series object; enforce the release--governance key,
   order, manuscript-hash, corresponding-author, and AI-use bindings.
3. For a non-genesis release, recompute the exact lineage transition. Enforce
   the predecessor's signed authority threshold, same-line increment or branch
   rule, old-authority transition signatures when keys change, and new-team
   approval signatures.
4. Recompute every event digest and enforce the event sequence and predecessor
   chain.
5. Recompute `approval_target_digest`; verify every time sidecar binds that
   digest exactly. Disclosures continue to bind their exact PEC/event scope.
6. Recompute the claim policy's required capabilities and emit only the
   allowed outcomes.  Retain all unmet obligations as residual evidence gaps.
7. Emit `INDETERMINATE` rather than an accusation when required evidence is
   unavailable, redacted, stale, or policy-inadequate.

Stable rejection codes for the first corpus include:
`PEC_NONCANONICAL`, `SUBJECT_RELEASE_MISMATCH`, `GOVERNANCE_BINDING_MISMATCH`,
`PEC_APPROVAL_MISSING`, `EVENT_CHAIN_BROKEN`, `DISCLOSURE_BINDING_MISMATCH`,
`DISCLOSURE_WINDOW_INVALID`, `DISCLOSURE_APPROVAL_MISSING`,
`RECEIPT_SUBJECT_MISMATCH`,
`TIME_CAPABILITY_MISSING`, `CLAIM_NOT_AUTHORIZED`,
`CLAIM_POLICY_UNKNOWN_OUTCOME`, `PUBLIC_KEY_ID_MISMATCH`, and
`APPROVAL_TARGET_BINDING_MISMATCH`, `LINEAGE_TRANSITION_MISMATCH`,
`UNAUTHORIZED_SUCCESSOR`, and `LINEAGE_AUTHORIZATION_SIGNATURE_INVALID`.

## 11. Formalization boundary

The Lean core models typed approval targets and approvals, exact digest reuse,
policy-authorized capability derivation, real predecessor-digest links, and a
decomposed time-evidence predicate. Hash collision resistance, signature
unforgeability, parser refinement, encryption secrecy, RFC 3161 operation, and
service governance remain assumptions attached to executable components.

The lineage extension additionally models exact transitions and predecessor
quorum evidence. It proves that accepted succession implies predecessor quorum,
fresh authority cannot use the continuity path, and an authorization for one
child digest cannot be reused for a different child. Threshold counting and
COSE verification are executable-boundary inputs, not parser-refinement
theorems.

The formal theorem is therefore: *under these authentication and policy
assumptions, acceptance does not produce an unauthorized claim*.  It is not a
theorem that a real person authored a paper.
