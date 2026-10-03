# SRL Prototype: Sealed Research Lineage Evidence Engine

**Status**: Hardened Research Prototype (Profile v0.3.1; 55 Tests Passing; Lean 4 Verified (Abstract Projection))  
**Date**: 2026-10-03  
**Parent Framework**: ACSD (Anonymous Scholarly Claim and Disclosure)  
**Profile**: `ACSD.SealedLineageProfile` (Candidate Experimental Profile v0.3.1)  

**Maintenance policy**: v0.3.1 is a freeze candidate. Maintenance is limited to correctness,
interoperability, tests, and documentation; new protocol features require a separate threat-model
review and version decision.

> [!IMPORTANT]
> **v0.3.0 Breaking Change**: The public `appraise()` function signature no longer accepts
> `predecessor_verified`, `_predecessor_verified`, `_trusted_genesis_digest`, or `_depth` parameters.
> These were internal trust flags whose public exposure constituted a security vulnerability (S9/P1).
> The internal logic is now split into `_appraise_internal()` (private) and `appraise()` (public wrapper).
> Passing any of those old parameters to `appraise()` raises `TypeError` immediately.



---

## 1. Overview & Core Mission

This prototype implements the **Sealed Research Lineage (SRL)** evidence model. It provides mechanisms for verifiable, confidential research evolution (e.g. an expert progressively proving lemmas $L_1 \dots L_9$ toward conjecture $T$):

1. **Partial Opening without Premature Leakage**: An author can reveal lemma $L_1$ while keeping $L_2 \dots L_9$ sealed, with cryptographic proof that $L_1$ was part of a frozen lineage catalog.
2. **Computational Hiding**: Catalog items contain no raw material digests; they only expose salted commitments (`SHA-256(256bit_salt || material)`), defeating rainbow table and dictionary guessing. Length check enforces $\ge 32$ bytes salt (CSPRNG is an author-side security assumption).
3. **Position-Derived Merkle Inclusion & Anti-Relabeling**: Merkle path directions are mathematically deduced from $(idx, W)$ tree topology. Submitting identical leaves under different indices is prevented by position derivation failure, duplicate claim ID rejection, and duplicate leaf hash rejection.
4. **Signed Catalog Leaf Count & Exact Set Coverage**: `catalog_leaf_count` ($N$) is explicitly bound in the signed `ApprovalTarget`. Complete catalog opening requires proving the exact leaf index set $\{0, \dots, N-1\}$.
5. **Multi-Milestone Lineage Succession ($M_1 \to M_2 \to \dots \to M_k$)**: Lineage transitions support long-running research evolutions, verified either via nested predecessor proofs or sequential chain appraisal (`appraise_lineage_chain`).
6. **Genesis / Predecessor Pinning**: Pinning `expected_genesis_target_digest` prevents parallel rogue branches from masquerading under the same `lineage_id`.
7. **Predecessor Quorum Succession & Governance Consistency**: Fresh-key hijacking and governance substitution are prevented by requiring predecessor threshold signatures on `LineageTransition`, checking `hash(predecessor_proof.governance) == predecessor_proof.target.governance_digest`, and requiring the predecessor proof to self-verify.
8. **Slot-Key Non-Duplication**: Author slots must have unique `slot_id`s AND unique public keys. Reusing a single key across multiple slots to satisfy quorum is strictly rejected.
9. **No Retroactive Strengthening**: A late-stage unconditional theorem ($M_2$) cannot inherit an early conditional milestone timestamp ($M_1$).
10. **Real RFC 3161 DER Verification with Nonce Binding**: Validates authentic CMS SignedData, signing certificate EKU, message imprint, certificate fingerprint pin, and request nonce via ACSD's `tsa.py`.
11. **Timestamp Scope Split & Anti-Inflation (REG-14)**: Distinguishes `APPROVAL_TARGET_EXISTED_NOT_AFTER` from `ARCHIVE_DIGEST_EXISTED_NOT_AFTER`. An archive timestamp proves the encrypted payload existed, but is structurally prevented from upgrading to milestone or target existence.
12. **Conflicting Alias Rejection (REG-15)**: Rejects conflicting canonical and compatibility alias fields (`salt_commitment` vs `salted_commitment`, `public_key` vs `ed25519_public_key_hex`, transition digests).
13. **Recursion Depth Defense (REG-16)**: Nested predecessor proof recursion is capped at 32 depth, preventing stack exhaustion and recursion loops.
14. **Safe Transition Handling without Exceptions (REG-17)**: Invalid transition objects are rejected with `REJECTED_INVALID_TRANSITION_TARGET` without variable scoping errors (`UnboundLocalError`).
15. **Unified Public Key Alias Normalization (REG-18)**: Author slots, signatures, and transition authorizations support alias-only governance (`ed25519_public_key_hex`) while strictly rejecting conflicting aliases (`REJECTED_ALIAS_CONFLICT`).
16. **Flat Iterative Chain in O(1) Stack & Bounded Diagnostics (REG-19)**: Verifies 35+ milestone chains in sequential $O(1)$ stack space without re-recursion, with bounded diagnostic strings (< 300 bytes) eliminating exponential error blowup.
17. **Input Totality & Safe Hex/Digest Parsing (REG-20)**: Converts malformed hex, odd-length strings, and invalid digests to typed rejections (`REJECTED_MALFORMED_HEX`, `REJECTED_INVALID_DIGEST_LENGTH`) rather than raising uncaught `ValueError`s.
18. **Collection Nullability & Structural Robustness (REG-21)**: Null or non-list/non-dict inputs across signatures, opened_claims, audit_paths, and chain items are handled gracefully without `TypeError` or `AttributeError`.
19. **RFC 8785 Safe Serialization & Float Trapping (REG-22)**: Safely traps floats and non-JCS inputs via `safe_canonical_json_dumps` and `safe_compute_leaf_hash`, converting them to typed rejections without uncaught `ValueError`.
20. **Milestone Index Strict Bounds & Genesis Invariants (REG-23)**: Enforces integer milestone indices $\ge 1$; forbids predecessor digests on genesis $M_1$; mandates predecessor digests on $M > 1$.
21. **Bounded Leaf Count & Constant Memory Verification (REG-24)**: Limits `catalog_leaf_count \le 65536` and replaces `set(range(N))` with pigeonhole-based bijection checking in $O(1)$ extra memory, preventing memory exhaustion and OOM DOS attacks.
22. **Terminal-Credit Separation**: The verifier algebra structurally refuses to evaluate whether an independent later discoverer is "plagiarizing" or whether early intermediate progress constitutes "ownership of the final theorem".

---

## 2. File Structure

```text
research/srl_prototype/
├── srl_core.py                    # Strict JCS canonical JSON, safe hex/digest parsers, Merkle tree, Ed25519 signing
├── srl_verifier.py                # Pure-functional appraiser & flat O(1) chain appraisal engine
│                                  #   _appraise_internal() — internal; accepts trust flags (appraise_lineage_chain only)
│                                  #   appraise()           — public API; no trust flags; hard-coded safe defaults
│                                  #   appraise_lineage_chain() — iterative O(1) chain verifier
├── test_srl_fixtures.py           # Main test suite: FX-01~06, REG-01~24, DigiCert fixtures (32 tests)
├── test_regression_extended.py    # Adversarial regression: REG-25~38, including closure checks (23 tests)
├── SealedLineage.lean             # Lean 4 abstract projection: output algebra + security invariants (13 theorems, 0 errors)
└── README.md                      # Prototype documentation & reproduction guide
```

---

## 3. How to Reproduce & Run Tests

The test suite requires Python 3.9+ and the standard `cryptography` package.

From the repository root, the preferred full acceptance command is:

```powershell
.\verify_srl.ps1
```

It runs both Python test modules through discovery and then compiles the Lean model.
To run only the Python portion:

```powershell
# Run all 55 tests (discovers both test files automatically)
python -m unittest discover -s research/srl_prototype -p "test_*.py"
```

### Complete Test Coverage (55 Tests):
- **FX-01**: Baseline valid milestone M1 partial opening and M2 complete opening
- **FX-02**: Milestone M2 with authorized predecessor transition
- **FX-03**: Unauthorized predecessor transition rejected
- **FX-04**: Leaf membership proof verification and tampering rejection
- **FX-05**: Late enhancement and isolation (anti-strengthening)
- **FX-06**: Terminal credit adjudication refusal
- **REG-01**: Reject fake 1900-01-01 timestamp without valid TSA signature
- **REG-02**: Reject partial opening falsely claiming complete catalog
- **REG-03**: Reject fresh-key predecessor spoof
- **REG-04**: Reject zero-threshold or empty governance
- **REG-05**: Reject duplicate opening of same leaf attempting to complete catalog
- **REG-06**: Reject substituted predecessor governance
- **REG-07**: Reject duplicate-key multi-slot quorum bypass
- **REG-08**: Reject unverified predecessor proof in transition
- **REG-09**: Reject timestamp token with mismatched nonce
- **REG-10**: Reject same leaf relabeled with different indices
- **REG-11**: Three-milestone chain verification ($M_1 \to M_2 \to M_3$) via nested proof and iterative chain
- **REG-12**: Specification examples parse directly as implementation objects
- **REG-13**: Expected genesis/parent pin distinguishes and rejects parallel rogue lineage
- **REG-14**: Reject archive timestamp upgrading to approval target existence
- **REG-15**: Reject conflicting canonical and alias fields
- **REG-16**: Reject predecessor proof chains exceeding maximum recursion depth (32)
- **REG-17**: Reject invalid transition target/domain safely without `UnboundLocalError`
- **REG-18**: Normalize public key aliases across governance and transition auth, reject conflicting aliases
- **REG-19**: 35-milestone sequential verification in $O(1)$ stack space and bounded diagnostic error strings
- **REG-20**: Total input parsing converting malformed hex and digests to typed rejections without `ValueError`
- **REG-21**: Input totality handling null/scalar collections without `TypeError` or `AttributeError`
- **REG-22**: Strict RFC 8785 serialization converting floats/unsafe integers to typed rejections without unhandled exceptions
- **REG-23**: Milestone index type/bounds validation and genesis predecessor invariants ($M_1$ vs $M > 1$)
- **REG-24**: Merkle catalog leaf count bounds ($\le 65536$) and $O(1)$ memory allocation preventing DOS
- **DigiCert Appraise Fixture**: End-to-end `appraise()` execution verifying `ARCHIVE_DIGEST_EXISTED_NOT_AFTER` on genuine DigiCert RFC 3161 evidence
- **DigiCert TSR Fixture**: Direct low-level RFC 3161 DER verification of DigiCert token

- **REG-25 (S1)**: Hex case-mixed duplicate key bypass (e.g. `"AABB"` vs `"aabb"` same physical key)
- **REG-26 (S2)**: Lone-surrogate `material_content` without crash (`UnicodeEncodeError` → typed rejection)
- **REG-27 (S3)**: Malformed genesis traversal without crash (`AttributeError` → typed rejection)
- **REG-28 (S4)**: Milestone sequence skip via crafted transition with mismatched indices
- **REG-29 (S5)**: Chain timestamp monotonicity (non-monotonic chain rejected)
- **REG-30 (S6)**: Invalid `claim_status` value outside the allowlisted enum
- **REG-31 (S7)**: Alias-conflict dead-else branch that previously granted `AUTHORIZED_PREDECESSOR_TRANSITION`
- **REG-32 (S8)**: `bool` values bypassing `isinstance(x, int)` gates throughout
- **REG-33 (R1/S9)**: `appraise()` public API has no trust flag — passing one raises `TypeError`
- **REG-34 (R2)**: `bool` in transition milestone index (`True == 1` bypass of S4 cross-check)
- **REG-35 (R3)**: Timezone-aware datetime comparison correctly identifies non-monotonic cross-timezone timestamps
- **REG-36 (P1/S9)**: Forged multi-layer chain with real M1 at bottom rejected via full recursive re-appraisal
- **REG-37 (8 cases)**: `assumptions` and `proof_obligations_open` must be lists of unique, lexicographically sorted strings
- **REG-38 (3 cases)**: Circular canonicalization is rejected, oversized opening lists are bounded, and diagnostic strings are truncated

```text
Ran 55 tests in ~8s
OK
```

---

## 4. Lean 4 Abstract Projection — Compilation & Scope

### Running the compilation check

```powershell
# Option A: direct invocation (requires elan installed)
& "$HOME\.elan\bin\lean.exe" research/srl_prototype/SealedLineage.lean
# Expected: returncode 0, empty output (warningAsError true is set in the file)

# Option B: CI script (auto-locates lean.exe, fails build on any error/warning)
.\check_lean.ps1
```

The [`check_lean.ps1`](../../check_lean.ps1) script locates `lean.exe` via `LEAN_EXE` env var, `~/.elan/bin/lean.exe`, or PATH. Run it from the repo root; it exits 1 on any compiler error.

> [!IMPORTANT]
> There is currently **no lakefile and no automated CI trigger** — the `check_lean.ps1` script must be run whenever [`SealedLineage.lean`](SealedLineage.lean) is changed. The badge "Lean 4 Verified" only holds if this check is re-run after any edit to the proof file.

### Theorems (13 total, 0 errors)

**Part I — Output algebra boundaries (Thm 1–8)**
1. `srl_evidence_cannot_grant_terminal_credit`
2. `srl_evidence_cannot_grant_plagiarism_accusation`
3. `srl_evidence_cannot_grant_natural_authorship`
4. `partial_opening_cannot_grant_complete_lineage`
5. `srl_evidence_cannot_grant_retroactive_strengthening`
6. `target_timestamp_evidence_cannot_authorize_successor` / `archive_timestamp_evidence_cannot_authorize_successor`
7. `no_temporal_inversion`
8. `archive_timestamp_cannot_grant_target_existence` (REG-14)

**Part II — Security-invariant projection (Thm 9–13, v0.3.0 audit fixes)**
- Thm 9 (`public_api_predecessor_requires_compatible_evidence`): public `appraise()` cannot grant `predecessorAuthorized` without `Compatible` evidence — no trust-flag bypass path in the type (S9/P1)
- Thm 10 (`governance_wf_keys_unique`): `GovernanceWF` structurally enforces key uniqueness via `List.Nodup` (S1)
- Thm 11 (`transition_no_skip`): `LineageTransitionWF.h_seq` is a proof obligation — skip transitions are ill-typed (S4)
- Thm 12 (`backward_timestamp_not_monotone`, `timestamps_monotone_snoc`): full list induction on timestamp monotonicity (S5/R3)
- Thm 13 (`chain_granted_every_link_sig_valid`): every link in a `ChainGranted` list carries a valid signature — no link can be pre-trusted (P1/S9)

### Scope & Honest Boundaries

The file opens with an explicit Boundary Notice. Key limitations (per independent audit):

| Layer | What Lean proves | What Lean does NOT prove |
|---|---|---|
| Output algebra | Prohibited claims are structurally un-derivable | Actual Python predicate string matching |
| Key uniqueness (Thm 10) | `GovernanceWF` with `Nat`-keyed `Nodup` | Hex case normalisation (S1 fix lives in Python) |
| Sequence integrity (Thm 11) | `h_seq : succ = pred + 1` as construction obligation | `bool`/`float` coercion (Python type checks) |
| Monotonicity (Thm 12) | `List.Pairwise (≤)` on abstract `Nat` timestamps | ISO 8601 timezone parsing (R3 fix lives in Python) |
| Chain integrity (Thm 13) | No-pre-trust invariant for `Compatible`-gated chains | Quorum, governance, opening evidence in intermediate slots (F2: `ChainGranted` is a parallel model, not a full refinement of `appraise_lineage_chain`) |

It explicitly **does not** formalize SHA-256 collision resistance, Ed25519 EUF-CMA, DER/ASN.1 parsing, or physical-world priority. Those guarantees are provided by the hardened Python implementation and standard cryptographic assumptions.

