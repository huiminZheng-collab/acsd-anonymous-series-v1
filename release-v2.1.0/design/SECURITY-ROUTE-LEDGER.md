# ACSD v2 security route ledger

Checked against the local implementation and reproducible fixtures on
2026-09-12.  Status words follow the research-route audit protocol.

| Approach | Target or obstruction | Evidence | Missing check | Cost | Status |
|---|---|---|---|---|---|
| Sign only `release.json` | Does not bind governance or PEC claim policy | A PEC can be replaced while the old release endorsements remain valid | None; this is a direct requirement mismatch | low | ruled out |
| Sign the final package manifest | A timestamp receipt is created after the signed subject, while the manifest also wants to cover the receipt | Produces a circular or multi-stage envelope and complicates co-author approval | Could define a two-manifest protocol, but it adds no needed claim here | high | attempted |
| Sign a compact approval target containing the release, governance, and PEC digests | Freezes every claim-bearing author-controlled object before timestamping | The target is acyclic and can be checked independently of mutable state and packaging files | Implement cross-object negative tests and formal abstraction | low | attempted |
| Trust the TSA certificate and fingerprint shipped inside the package | An attacker can replace the certificate, response, report, and unsigned manifest together | All purported trust material currently has the same attacker-controlled origin | None; it lacks an external trust root by construction | low | ruled out |
| Require an externally supplied TSA signer-certificate or fingerprint pin | Gives offline verification a trust decision independent of the package | Exact-certificate pinning is simple, inspectable, and adequate for an opt-in service level | Enforce nonce, EKU, TSTInfo content type, and signer identifier | medium | attempted |
| Build full PKIX path validation into the minimal CLI | General Web-PKI/RFC 5280 validation is substantially larger than the ACSD core | `cryptography` exposes primitives, but policy, revocation, path construction, and validation time still need a profile | Select a mature path-validation dependency and interoperability corpus | high | unexplored |
| Accept tolerant/bare-array COSE | Multiple encodings and weak parsing enlarge the malleability and parser differential surface | The published v1 verifier requires tag 18 and standard EdDSA code point -8 | None; tolerance is unnecessary for this profile | low | ruled out |
| Strict deterministic COSE subset with EdDSA -8 | Small independently testable signature boundary | v1 Node verifier and vendored SCITT implementation both use -8/tag 18 | Add malformed-CBOR and cross-implementation vectors | low | attempted |
| Treat policy `permitted_outcomes` as granted results | An unsigned/mutable policy can amplify verifier output | Current verifier returns the whole list even before approvals or a trusted timestamp | None; permission is not evidence | low | ruled out |
| Derive a fixed allowlisted result set from verified capabilities | Prevents unknown claim names and separates authorization from establishment | `KEY_ASSENT`, `GOVERNANCE_ASSENT`, and time evidence have distinct witnesses | Formalize sound result projection | medium | attempted |

The selected next experiment is the smallest complete two-author package.  It
must reject: replacement of one public key under an existing key id,
replacement of PEC/governance followed by manifest regeneration, a bare or
wrong-algorithm COSE object, a self-generated TSA response without an external
pin, and a timestamp response with the wrong nonce.  Acceptance is an exact
test result, not a claim about natural-person authorship, originality, legal
nonrepudiation, or general PKIX correctness.
