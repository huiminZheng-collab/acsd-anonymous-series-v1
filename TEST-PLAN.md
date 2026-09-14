# ACSD v3: minimum discriminating corpus

Implementation status: the semantic reference corpus covers 15 of the 17 frozen cases
below (see `fixtures.py`), spanning all four verifier paths
(`validate_pec`, `verify_legacy_disclosure_metadata`, `verify_dialogue_window`,
`verify_sidecar_subject`). The two series-layer cases
(`exclusive-slot-double-sign` -> `EQUIVOCATION` and `missing-sidecar` ->
`INDETERMINATE`) are v1 series-layer states, not PEC acceptance
predicates, and are documented out of scope here. The table remains the
acceptance contract for any future independent implementation.

This plan is frozen before implementation.  It distinguishes a valid
evidence-binding system from one that merely stores attractive metadata.
The signed approval envelope additionally has independent Python and Node
verification. Deterministic fixture keys and a local TSA are allowed only for
protocol testing and MUST be labelled non-external.

| ID | Fixture / mutation | Expected result | Security question separated |
|---|---|---|---|
| `pec-v1-valid` | two-member v1 release, valid governance statement, unanimous PEC approvals, sealed Git event, sealed dialogue root | `VALID` with `KEY_ASSENT`, `GOVERNANCE_ASSENT` | base binding, not authorship |
| `pec-v2-valid` | v2 release references exact v1 release and exact v1 PEC; adds one event | `VALID` | revision is additive |
| `role-order-mutated` | swap byline position after all signatures | `GOVERNANCE_BINDING_MISMATCH` | signatures bind order |
| `corresponding-mutated` | change corresponding slot | `GOVERNANCE_BINDING_MISMATCH` | role labels are not free metadata |
| `ai-disclosure-mutated` | change AI-use declaration digest | `GOVERNANCE_BINDING_MISMATCH` | AI statement is bound to team consent |
| `foreign-git-disclosure` | open P's Git event against copied release C | `DISCLOSURE_BINDING_MISMATCH` | evidence cannot be transplanted |
| `foreign-dialogue-disclosure` | open P's dialogue window under C's PEC | `DISCLOSURE_BINDING_MISMATCH` | dialogue root cannot be relabelled |
| `wrong-salt` | correct bytes, wrong secret salt | `DISCLOSURE_BINDING_MISMATCH` | hash opening is exact |
| `noncontiguous-dialogue` | omit an internal dialogue turn from disclosed window | `DISCLOSURE_WINDOW_INVALID` | window order is meaningful |
| `single-author-disclosure` | one otherwise valid author signature opens a team dialogue | `DISCLOSURE_APPROVAL_MISSING` | a corresponding author cannot disclose alone |
| `git-time-upgrade` | request legacy `EXTERNALLY_NOT_AFTER` with only Git timestamp | `TIME_CAPABILITY_MISSING` | Git time is not independent time |
| `witness-time-upgrade` | use a witness observation as a timestamp | `TIME_CAPABILITY_MISSING` | observation is not trusted wall clock |
| `valid-rfc3161-sidecar` | legacy nonce-bearing receipt over exact approval-target digest and an external signer pin | `VALID` plus legacy `EXTERNALLY_NOT_AFTER` | retained v0.1/v0.2 scope |
| `receipt-replayed-to-v2` | attach v1 receipt to v2 PEC | `RECEIPT_SUBJECT_MISMATCH` | no historical backfill |
| `exclusive-slot-double-sign` | two valid PECs for the same exclusive policy slot | `EQUIVOCATION` | cryptographic conflict, not human motive |
| `missing-sidecar` | policy requests external time but no receipt is supplied | `INDETERMINATE` / residual obligation | absence is not accusation |
| `social-claim-injected` | policy requests human authorship or contribution truth | `CLAIM_POLICY_UNKNOWN_OUTCOME` | the closed result vocabulary cannot be amplified |

## Authorized-lineage regression matrix

These cases are automated in `test_lineage_authorization.py` and exercise the
complete CLI rather than an object-only predicate.

| Attack or transition | Required result |
|---|---|
| same WorkID, exact parent, n+1 slot, fresh attacker key, complete child self-approval, no old authorization | `VALID_OBJECT_BUT_UNAUTHORIZED_SUCCESSOR` |
| unchanged author-key set signs the exact child target | `AUTHORIZED_CONTINUATION` |
| changed author-key set with old-threshold transition signatures and unanimous new-team target signatures | `AUTHORIZED_TRANSITION` |
| child declares a lower threshold but supplies fewer signatures than the parent's signed threshold | `LINEAGE_AUTHORIZATION_INCOMPLETE` |
| predecessor explicitly selected one-of-two threshold and one old key authorizes the exact transition | valid transition |
| copy an old transition signature to a different child content/digest | `COSE_PAYLOAD_MISMATCH` |
| same authority creates an explicitly named new line | valid branch beginning at version 1 |
| two valid distinct children occupy the same parent/line/version slot | `LINEAGE_EQUIVOCATION_DETECTED`, `winner=null` |

The last result is detection, not ordering. Timestamp or transparency policy is
required to rank competing valid statements, and no such policy is inferred by
the offline verifier.

## CLI security-regression matrix

These cases cross the semantic, key, envelope, package, and timestamp layers
and are automated in `test_cli_signing.py`, `test_cose.py`,
`test_node_approval.py`, and `test_tsa_security.py`.

| Attack | Required result |
|---|---|
| replace the public-key bytes while retaining the declared key id and path | `PUBLIC_KEY_ID_MISMATCH` |
| coherently replace governance and PEC after approval | `APPROVAL_TARGET_BINDING_MISMATCH` |
| recompute the unsigned target after that replacement and reuse old approvals | `COSE_PAYLOAD_MISMATCH` |
| use COSE algorithm -35, omit tag 18, duplicate a CBOR map key, or use a non-minimal encoding | reject before signature acceptance |
| replace a timestamp response and recompute the unsigned transport manifest | reject against the externally supplied signer pin |
| omit, alter, or replay the RFC 3161 nonce | `TSR_NONCE_MISMATCH` |
| use absent, non-critical, or non-exclusive timeStamping EKU | reject |
| use a non-TSTInfo CMS content type or mismatched signature algorithm | reject |
| verify a package certificate without an external trust argument | no `APPROVAL_SET_EXISTED_NOT_AFTER` |
| timestamp a target before adding author signatures | never `APPROVAL_SET_EXISTED_NOT_AFTER` |
| mutate or add a COSE approval after approval-set closure | approval-set mismatch |
| replay one slot identity disclosure to another release or slot | identity scope/key mismatch |
| present one valid slot disclosure as a complete byline | `PARTIAL_BYLINE_KEY_ASSENT` only |
| explicitly verify the built-in local TSA | `LOCAL_TEST_VERIFIED`, never external time |
| use an approval-target timestamp as evidence that the completed signature set existed | typed derivation denies the claim |
| substitute any of four accepted evidence kinds for another claim kind | all 12 off-diagonal combinations denied |
| add evidence sets whose components support no requested claim | union grants no claim without one matching verified atom |

## Verification-certificate differential matrix

`acsd-verification-certificate/v1` contains appraised byte-level facts, not a
verdict. Python and Node independently read canonical JSON, bind public-key
identifiers, verify every author/event COSE, verify the dialogue Merkle window,
and emit the same canonical transcript.

`acsd-verification-certificate/v2` preserves that closed v1 profile and adds
release-scoped, author-slot identity facts. Both adapters must emit the same v2
bytes, and Lean must independently require the exact release/slot/key,
identity-payload/signature, and COSE-input closure before deriving the narrow
slot-assent claim.

`acsd-verification-certificate/v3` preserves both earlier profiles and adds one
complete approval set, the exact RFC 3161 request/response/certificate/report
inputs, and an explicitly supplied signer pin and external-authority policy
fact. The time claim subject contains both the approval-set digest and the
normalized UTC time. Python performs the DER/CMS verification as an explicit
cryptographic oracle for both high-level adapters; Python and Node still
independently reconstruct and agree on the surrounding canonical transcript.

`acsd-lineage-verification-certificate/v1` is intentionally a separate profile
rather than a cumulative v4. It binds one exact parent-to-child edge, both
authorities, child approvals, any predecessor transition authorizations, the
complete approval set, and every relevant input digest. This keeps the checked
surface proportional to the requested service.

| Mutation | Adapter result | Pure checker result |
|---|---|---|
| unchanged two-author demo | byte-identical Python/Node certificate | approval and exact event evidence atoms |
| corrupt one event COSE byte | both adapters reject; no stdout certificate | not reached |
| remove one required approval COSE | both adapters reject; no partial certificate | not reached |
| delete one author signature fact from an already issued transcript | transcript remains parseable | approval claims disappear; event claim remains |
| delete one event signature fact | transcript remains parseable | event claim disappears; approval claims remain |
| substitute the Merkle fact window | transcript remains parseable | exact event claim disappears |
| append an extra Merkle fact | transcript remains parseable | event claim disappears; exact-set closure forbids ambiguity |
| substitute a COSE input digest | transcript remains parseable | only claims depending on that signature group disappear |
| empty a required signer set | both structural decoders reject | no vacuous unanimous approval |
| substitute event or policy PEC digest | both structural decoders reject | no cross-PEC claim projection |
| exceed the JavaScript safe-integer bound | both structural decoders reject | Python/Node/Lean numeric semantics remain aligned |
| populate an unimplemented extension array | both structural decoders reject | unsupported facts are never silently ignored |
| add whitespace to canonical JSON | Lean decoder rejects | checked bytes have one representation |
| substitute the disclosed author slot or author key in v2 | transcript remains parseable | only the identity claim disappears |
| substitute the identity COSE input, signed payload, or release digest | transcript remains parseable | only the identity claim disappears |
| remove the identity policy outcome | transcript remains parseable | verified identity evidence grants no claim |
| duplicate a disclosed identity slot | both structural decoders reject | ambiguous slot identity is never appraised |
| use slot zero or reuse one release author key in two slots | both structural decoders reject | malformed author-slot context is never appraised |
| substitute one v3 approval entry or its COSE input | transcript remains parseable or strict decoding rejects | approval-set time claim disappears |
| substitute the timestamp response, certificate pin, or report digest | transcript remains parseable | approval-set time claim disappears |
| mark the pinned TSA as local rather than external | transcript remains parseable | approval-set time claim disappears |
| change the approval target under an otherwise intact v3 set | strict decoder rejects | no cross-target time projection |
| omit the timestamp policy fact | transcript remains parseable | verified receipt grants no time claim |
| remove one predecessor authorization in the lineage profile | transcript remains parseable | no authorized-successor claim |
| substitute predecessor payload, COSE input, or public-key input | transcript remains parseable | no authorized-successor claim |
| remove one child approval or alter the approval-set projection | transcript remains parseable | no authorized-successor claim |
| substitute transition binding, mode, kind, or version | transcript remains parseable | no authorized-successor claim |
| omit lineage policy permission | transcript remains parseable | closed evidence grants no claim |

The dependency-substitution cases test precision, not adapter authenticity: a
standalone transcript is meaningful only when its exact digest is bound to the
raw adapter output being evaluated.

## Acceptance gates

1. Every valid case has a byte-stable manifest and a stable claim set.
2. Every mutation has at least one deterministic rejection code.
3. The independent verifier must re-canonicalize input rather than trust a
   parsed representation supplied by the generator.
4. A displayed result must carry both granted outcomes and explicit
   non-claims/residual evidence gaps.
5. The Lean model must prove policy non-amplification, exact target reuse
   resistance, unanimous-approval gating, external-time preconditions, and the
   correspondence between its executable appraisal checker and independent
   declarative rules over parameterized subjects.
6. The Lean transcript checker must require exact signer projections and one
   exact Merkle fact, and every accepted claim must have both transcript support
   and an explicit appraisal rule.
7. The executable Lean decoder must consume the canonical certificate itself;
   Python and Lean must agree on complete scoped derivations, including support
   digests, across the maintained mutation set.
8. V2 identity claims must depend on one exact release/slot/key/assertion tuple
   and one exact signature/input tuple; mutations may not disturb independent
   approval or event claims.
9. V3 approval-set time claims must depend on the complete exact author
   approval projection, receipt inputs, nonce, signer pin, external-authority
   policy, and exact `(approval_set_digest, not_after_utc)` subject.
10. A lineage claim must depend on one structural n+1/branch edge, the exact
    transition and target, complete child approval, predecessor-threshold
    authorization when authority changes, exact input roles, exact approval-set
    projection, and explicit child-policy permission.
11. The CLI and legacy PEC facade must reach one pure bundle validator and
    report the same first error for shared binding, event-chain, policy, and
    capability mutations; canonicalization and public-key identifiers each
    have one implementation.
12. Live code must use the pure release projection; v1 filesystem access, the
    optional Node subprocess, and metadata-only disclosure checks must remain
    confined to the named legacy adapter. Exit codes and human/JSON formatting
    must come from one application-independent output module and retain the
    published process contract.
13. Release, governance, PEC, approval-target, and lineage object construction
    and binding checks must remain in one I/O-free protocol-object layer. The
    CLI may re-export old names but must not copy their implementations, and
    independently built objects must not share mutable AI-use or contribution
    lists.
14. Canonical-file, key-material, lineage-signature, and release-verification
    adapters must form a one-way dependency chain into the protocol and claim
    kernels. None may import the CLI. Existing `acsd` helper/verifier names must
    be exact compatibility exports, and the installed CLI must preserve all
    success results, exit codes, and first-error results.
15. The formal appraisal layer must reuse the single declarative `Compatible`
    relation rather than copy its constructors. Strictly decoded ordinary and
    lineage certificates must lead to exact-subject derivations, and those
    derivations must refine the earlier digest-scoped abstraction under an
    arbitrary subject projection.

## Out-of-scope tests for the deterministic local suite

No offline corpus case asserts real TSA independence, real model-provider attestation,
anonymity against repository metadata, legal authorship, or the truth of a
team's contribution statement.  Those would require external participants or
governance evidence, not more fixture signatures. A checked-in freeTSA response
over the demo approval set is verified offline by deterministic tests. It is a
single interoperability existence check, not evidence about service reliability.
