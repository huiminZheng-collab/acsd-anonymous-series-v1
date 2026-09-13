# Verification certificate v1/v2/v3 boundary

`acsd-verification-certificate/v1` is a claim-free transcript of facts checked
by the Python and Node byte-level adapters. It is not an authorship credential,
a timestamp, or an acceptance verdict.

`acsd-verification-certificate/v2` is the smallest strict extension of v1. It
adds one release context and one or more selectively disclosed author-slot
identity assertions. V1 remains closed and unchanged, so an old certificate
cannot acquire identity meaning through a permissive parser upgrade.

`acsd-verification-certificate/v3` adds one exact complete approval set and one
RFC 3161 time fact. Its subject is the pair `(approval_set_digest,
not_after_utc)`, not a generic timestamp label. It also binds the exact request,
response, signer certificate, acquisition report, author approval inputs,
externally supplied signer fingerprint, and external-authority policy input.
V1 and v2 remain closed and unchanged.

## Canonical input

- UTF-8 JSON uses sorted object keys, no insignificant whitespace, and either
  no final byte or one final LF byte after the canonical object.
- Every digest and key identifier is exactly 64 lowercase hexadecimal digits.
- Sequence and window values are JSON natural numbers no larger than
  `9007199254740991`, matching the JavaScript safe-integer boundary.
- Objects have exact field sets. Unknown input roles, signature purposes, and
  policy outcomes are rejected.
- Required key arrays are nonempty and duplicate-free. Adapter output orders
  required keys and signature facts canonically.
- `identity_assertions`, `timestamp_facts`, and `trusted_inputs` must be empty
  in v1. In v2, `timestamp_facts` and `trusted_inputs` remain empty, while each
  identity assertion is bound to an exact release digest, positive author slot,
  slot key, assertion digest, signed body, and COSE input.
- V2 release slots are nonempty and unique by both slot number and author key;
  disclosed identity slots and their COSE inputs are also duplicate-free.
- In v3, the approval-set entries must be exactly the verified author-signature
  facts, the set's target must be the certificate's exact approval target, and
  every request/response/certificate/report digest must project to one exact
  input role. The signer fingerprint must match both the certificate digest
  and the explicit trust input. Local authority cannot satisfy external time.

## Lean projection

`ACSD.TranscriptJson.decodeCertificateText` parses all three canonical schemas
directly.
It maps 256-bit hexadecimal strings injectively to arbitrary-precision Lean
natural numbers, preserves the event identifier as a string, and retains
separate approval, event, and policy PEC digests. The typed transcript also
retains COSE input digests separately for author approvals and event
disclosures.

The Lean executable then checks:

- nonempty, duplicate-free required signer sets;
- exact signer and signed-payload projections;
- exact COSE-digest input projections for each signature purpose;
- equality of approval, event, and policy PEC scopes;
- a nonempty, ordered event window;
- exactly one Merkle fact with the expected body, commitment, bounds, and leaf
  count; and
- an explicit policy rule for every emitted exact-subject claim.

For v2 it additionally checks the exact identity-signature projection, exact
identity-COSE input projection, release/slot/key membership, and uniqueness.
Only then can it emit the narrow claim that a particular release slot key
assented to a particular identity assertion. It does not turn that statement
into a claim about undisclosed coauthors or natural-person truth.

For v3 it additionally checks exact approval-set membership, timestamp input
projection, nonce, signer pin, authority class, receipt metadata, and the exact
UTC instant carried by the typed time subject. Only then can it emit that this
particular complete approval set existed no later than that instant.

Its output is `acsd-lean-transcript-result/v1`. Each result contains the full
claim subject and the digest supplied for the exact certificate bytes. The
caller computes that SHA-256 digest; Lean validates its representation but does
not recompute SHA-256 in this version.

## Assurance boundary

The Python and Node adapters independently reproduce identical canonical v1,
v2, and v3 certificate bytes from the demo bundle. Lean independently parses those
bytes and performs the structural appraisal. A differential runner compares
complete Python and Lean derivations under positive and adverse mutations,
including slot, key, release, payload, COSE-input, policy, duplicate-slot,
approval-set, receipt-input, signer-pin, authority-class, and time changes.

Python is the explicit RFC 3161 DER/CMS verification oracle for the v3 path;
the Node adapter invokes that oracle and independently reconstructs the
high-level transcript. Therefore byte agreement is not claimed as two
independent CMS implementations. The checked-in freeTSA fixture establishes
interoperability with one real response and remains fully offline-verifiable.

This establishes an executable refinement check from the current restricted
JSON transcript to the proved typed appraisal model. It does not prove the
correctness of SHA-256, Ed25519, COSE, Merkle hashing, filesystem snapshots, or
the adapter implementations. Those remain explicit assumptions. The Lean JSON
parser, compiler, runtime, and kernel are also part of the concrete checker's
trusted computing base.
