# Generalization gate: a bounded multi-premise appraisal experiment

Checked on 2026-09-14. This note records a formal-scope experiment in the live
source tree. It does **not** add a new ACSD release format, device-attestation
feature, parser, cryptographic adapter, or claim about a device's real-world
safety.

## Status and source check

The standards vocabulary is deliberately narrow. [RFC 9334](https://www.rfc-editor.org/rfc/rfc9334.html)
separates Evidence, an appraisal policy, and Attestation Results. [RFC
9711](https://www.rfc-editor.org/rfc/rfc9711.html) describes signed EAT claims
and a freshness mechanism. [RFC 9999](https://www.rfc-editor.org/rfc/rfc9999.html)
standardized a wrapper for RATS conceptual messages. None supplies this
project's Python or Lean implementation; they justify only the choice of a
compact, independently meaningful vocabulary.

Verified local result: `formal/ACSD/GenericAppraisal.lean` compiles a generic
finite multi-premise derivation relation, and
`formal/ACSD/RatsAppraisal.lean` instantiates it with five exact facts.
`formal/ACSD/RatsTranscriptJson.lean` then strictly decodes a deliberately
small canonical transcript, and the separate research-only executable agrees
with `design/rats_appraisal_transcript.py` on 22/22 complete, deletion,
substitution, policy, ordering, duplicate/unknown-field, safe-integer, and
noncanonical-input cases. The Lean build and `formal/AxiomAudit.lean` complete
without `sorry` or `admit`. This is a **proof/certification** result over an
abstract model, not empirical evidence of EAT interoperability or a
hardware-attestation deployment.

## Exact small instance

For one `RatsSubject`, a permitted `appraisalResult` requires all of:

1. a token-to-attester signature binding;
2. a token-to-measurement binding;
3. a token-to-nonce freshness binding;
4. a measurement-to-reference-value binding; and
5. a verifier-to-policy authorization binding.

The model proves a positive result when those exact premises are present, and
proves that a missing exact nonce, a different nonce, or an unpermitted result
cannot yield the appraisal result. Its only result constructor is an appraisal
result for that exact subject. In particular, it has no constructor for "the
device is safe", access authorization, or natural-person identity.

The identifiers are abstract natural numbers. They stand for values already
appraised by a parser/COSE/reference-value adapter; no claim is made that Lean
checks an EAT or its signature.

## Route ledger

| Approach | Target or obstruction | Evidence | Missing check | Cost | Status |
|---|---|---|---|---|---|
| Keep adding ACSD-specific one-off grant predicates | Would conceal whether the typed kernel has a reusable boundary | Existing roadmap documents vocabulary-drift risk | None; violates the one-kernel objective | low | ruled out |
| General-purpose recursive trust/policy language | More expressive, but introduces unneeded recursion, delegation, and a larger parser/policy surface | No ACSD or smallest RATS instance needs it | A future use case could reopen this route | high | ruled out for this gate |
| Generic finite multi-premise calculus plus a compact RATS instance | Test whether permission plus exact prerequisite closure survives outside scholarly release objects | Generic/RATS model, strict decoder, separate checker, 22/22 Python/Lean differential, build, and axiom audit | A second independently motivated profile, if a broader claim becomes necessary | medium | bounded validation complete |
| Parse full EAT and verify COSE inside this project | Could demonstrate interoperability, but is an adapter project rather than a kernel test | No local EAT parser, COSE profile, or hardware reference-value source is validated | A concrete deployment/use case | high | unexplored |
| Supply-chain provenance as a second instance | A plausible independent domain, but the current SCITT statement-registration fact is only one premise | Existing ACSD SCITT scope does not constitute a build-provenance instance | A compact provenance policy and source artifact | medium | unexplored |

## Decision and boundary

The selected route is intentionally one formal module and one five-premise
instance; it leaves the production ACSD verifier untouched. This prevents a
premature product abstraction from expanding the security decision surface.

The completed smallest validation is a claim-free canonical RATS appraisal
transcript with Python and Lean agreement under deletion and substitution of
each of the five premises. It validates one adapter-to-kernel boundary without
creating an ACSD product feature.

The supported claim is now still deliberately narrow: the finite
multi-premise calculus has one standards-aligned, strictly decoded abstract
second instance. It is not a general authorization language, an EAT/COSE
implementation, or an assertion that a device is safe. The v5 route audit
records the prior-art comparison and the stop condition for any larger claim.
