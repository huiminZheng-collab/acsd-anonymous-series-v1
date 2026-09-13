# ACSD PEC v0.2: minimum discriminating corpus

Implementation status: the semantic reference corpus covers 15 of the 17 frozen cases
below (see `fixtures.py`), spanning all four verifier paths
(`validate_pec`, `verify_disclosure`, `verify_dialogue_window`,
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
| `git-time-upgrade` | request `EXTERNALLY_NOT_AFTER` with only Git timestamp | `TIME_CAPABILITY_MISSING` | Git time is not independent time |
| `witness-time-upgrade` | use a witness observation as a timestamp | `TIME_CAPABILITY_MISSING` | observation is not trusted wall clock |
| `valid-rfc3161-sidecar` | valid nonce-bearing receipt over exact approval-target digest and an external signer pin | `VALID` plus `EXTERNALLY_NOT_AFTER` | external time has exact scope |
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
| verify a package certificate without an external trust argument | no `EXTERNALLY_NOT_AFTER` |
| explicitly verify the built-in local TSA | `LOCAL_TEST_VERIFIED`, never external time |

## Acceptance gates

1. Every valid case has a byte-stable manifest and a stable claim set.
2. Every mutation has at least one deterministic rejection code.
3. The independent verifier must re-canonicalize input rather than trust a
   parsed representation supplied by the generator.
4. A displayed result must carry both granted outcomes and explicit
   non-claims/residual evidence gaps.
5. The Lean model must prove policy non-amplification, exact target reuse
   resistance, unanimous-approval gating, and external-time preconditions over
   the abstract fields used by the executable boundary.

## Out-of-scope tests for v0.2

No offline corpus case asserts real TSA independence, real model-provider attestation,
anonymity against repository metadata, legal authorship, or the truth of a
team's contribution statement.  Those would require external participants or
governance evidence, not more fixture signatures. A separate opt-in test has
verified one real freeTSA response; it is not part of deterministic CI.
