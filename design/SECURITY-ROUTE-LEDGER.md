# ACSD v3 security route ledger

Checked against the local implementation and reproducible fixtures on
2026-09-14.  Status words follow the research-route audit protocol.

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

## 2026-09-13 review decisions

| Approach | Target or obstruction | Evidence | Missing check | Cost | Status |
|---|---|---|---|---|---|
| Explain the approval mechanism as its own paper subsection | Remove the terminology and threat-model gap | Executable target binding and substitution regressions already pass | External reviewer reread | low | attempted |
| Rename “capability algebra” to “closed capability calculus” | Avoid claiming algebraic structure absent from the model | Lean `Granted` is a three-part inference predicate over a closed outcome type | Richer algebraic laws, if ever needed | low | attempted |
| Merge the v1 53 and v2 16 theorem counts | Would obscure proof scope by producing one larger headline number | The theorem sets concern distinct models and the v1 core is separately published | A future unified import/refinement layer | medium | ruled out |
| Treat one freeTSA response as reliability evidence | Evidence is insufficient to generalize real-service behavior | Only one existence run was performed | Multiple services, repetitions, failure statistics | medium | ruled out |
| Record benchmark environment and retain smoke-test framing | Make the scale numbers interpretable | Local CPU, RAM, OS and Python version are available | Variance and cross-platform study | low | attempted |

## 2026-09-13 authorized-lineage decision

| Approach | Target or obstruction | Evidence | Missing check | Cost | Status |
|---|---|---|---|---|---|
| Treat the first visible n+1 as the successor | No globally reliable first observation; enables race capture | Git time is mutable and offline peers may see different orders | None; authorization cannot be replaced by arrival order | low | ruled out |
| Accept exact parent digest plus child self-signatures | Binds structure but lets fresh attacker keys claim the next slot | Executable fresh-key n+1 fixture reaches a self-consistent child | None; wrong authorization principal | low | ruled out |
| Give a new key set an unscoped permanent delegation | Reduces signing work but authorizes unknown future bytes and complicates revocation | Delegation survives beyond the candidate child | A bounded delegation language could be studied later | medium | ruled out |
| Require predecessor quorum over every exact parent-to-child authority change | Prevent fresh-key lineage capture while allowing deliberate team/key rotation | `test_lineage_authorization.py`; Python/Node independently produce the claim-free edge certificate; Python/Lean agree on 15/15 derivation/rejection cases | Real-team usability study | medium | attempted |
| Reuse child approvals when the authority key set is unchanged | Avoid duplicate signatures while still binding exact child bytes | Child target contains transition digest and is signed by every child/old key; lineage transcript models continuity separately from transition | Real-team usability study | low | attempted |
| Use predecessor-signed threshold, default unanimous | Make safety/liveness choice explicit and prevent child-side threshold downgrade | Two-of-two failure and one-of-two success fixtures | Usability study for real coauthor teams | low | attempted |
| Let series key alone create lineage authority | One compromised aggregation key could rewrite authorship succession | Series signature proves series control, not predecessor-author assent | None; separation of duties is required | low | ruled out |
| Precommit recovery authority | Avoid permanent freeze after key loss without post-hoc impersonation | TUF-style threshold/rotation patterns show the design family | Concrete privacy-preserving recovery policy and fixtures | high | unexplored |
| Retroactively revoke a valid transition | Cryptographic evidence of a past signature cannot be erased | Competing later statements can only add evidence or fork | External ordering/governance policy | high | ruled out |
| Detect two authorized same-slot children without choosing one | Preserve a checkable equivocation fact without inventing global time | `compare-successors` returns conflict and `winner=null` | Transparency-log deployment for ordering | low | attempted |

The smallest distinguishing object is one valid parent plus a child with the
same WorkID, exact parent digests, consecutive version, fresh keys, and complete
new-key approval. Acceptance would falsify the v3 security goal; the current
verifier rejects it specifically as an unauthorized successor. This is an
empirical executable result. The Lean result separately proves the abstract
implication from accepted succession to predecessor quorum under typed inputs.

## 2026-09-13 evidence-closure and scoped-disclosure decisions

| Approach | Target or obstruction | Evidence | Missing check | Cost | Status |
|---|---|---|---|---|---|
| Timestamp the unsigned approval target | Proves target existence, but signatures may be added after the timestamp | Temporal-confusion regression and typed Lean target/set distinction | None; it cannot establish approval completion | low | ruled out |
| Timestamp a canonical set of exact approval-signature bytes | Establishes that the complete accepted signature set existed no later than TSA time | `approval_set.py`, CLI TSA flow, mutation tests, typed Lean time subject | Multiple external TSA interoperability runs | low | attempted |
| Carry only an approval-set digest in a time claim subject | Loses the authenticated not-after instant at the semantic boundary and lets callers supply an unrelated display time | Earlier generic subject representation exposed this mismatch | None; the UTC instant must be part of the typed subject | low | ruled out |
| Bind `(approval_set_digest, not_after_utc)` through receipt verification, transcript, and Lean appraisal | Preserves the exact RFC 3161 assertion across every decision layer | Checked-in freeTSA fixture; v3 Python/Node certificate agreement; Python/Lean adverse differential cases | Second-domain instance | medium | attempted |
| Reimplement RFC 3161 DER/CMS independently in every transcript adapter | Enlarges the cryptographic parsing surface without strengthening the high-level closure model | Python already performs the strict receipt profile and emits exact support facts | A genuinely independent RFC 3161 implementation could be evaluated separately | high | ruled out for current kernel |
| Use one explicit RFC 3161 verification oracle while independently rebuilding the high-level transcript | Keeps the receipt-verification assumption visible and the typed closure small | Node invokes the Python oracle; both adapters independently construct byte-identical v3 transcript objects | Independent CMS implementation, if later justified by threat model | low | attempted |
| Trust `approval_key_ids` self-reported inside a disclosure | Lets an object claim its own authorization without proving signatures | Earlier demo accepted identifiers without signature envelopes | None; circular authorization source | low | ruled out |
| Atomically verify disclosure policy, event scope, Merkle opening, bound public keys, and all signatures | Prevents a valid opening or signature from being detached and relabelled | `event_disclosure.py`, real-signature demo, replay/policy/opening/key tests | More event kinds and editor workflow | medium | attempted |
| Put identity unblinding inside the frozen release | Mutates the priority artifact and forces unnecessary coauthor disclosure | Manifest closure and conference workflow require historical byte stability | None; external sidecar is the required boundary | low | ruled out |
| Sign an external identity mapping with the exact release-slot key | Supports selective unblinding without certifying natural-person truth or other slots | CLI commands, slot/release/type-confusion tests, Lean partial/full-byline result | Venue workflow study and identifier validation profiles | low | attempted |
| Implement offline revocation without a precommitted authority or global ordering source | A stolen key and its original holder can both make valid later statements; an offline verifier cannot know the globally latest one | Same-slot fork model and absence of an independent freshness oracle | Transparency/recovery deployment model | high | ruled out |

## 2026-09-13 typed-composition and release-gate decisions

| Approach | Target or obstruction | Evidence | Missing check | Cost | Status |
|---|---|---|---|---|---|
| Let any verified evidence satisfy any policy-permitted claim | Recreates semantic amplification above otherwise correct cryptographic checks | The executable 4-by-4 challenge would accept off-diagonal substitutions | None; evidence/claim compatibility must be closed | low | ruled out |
| Keep separate PEC/policy rule copies in the CLI and reference core | Small edits can make two nominally equivalent verifiers accept different bundles or report different first failures | The two functions had already diverged in slot, governance, and legacy-capability checks | None; duplication is the obstruction | low | ruled out |
| Delegate both public facades to one dependency-light bundle validator | Keeps compatibility while making PEC/governance/event/policy acceptance single-source | 13 shared adverse mutations compare exact first errors; all 156 Python tests pass | None in the current wire profile | low | attempted |
| Keep v1 filesystem, Node subprocess, and metadata-only checks in `pec_core` | Makes an apparently pure core import I/O and obsolete non-granting paths | Import-graph audit identified all three responsibilities | None; this obscures the trust boundary | low | ruled out |
| Isolate old wire behavior in a named legacy adapter with lazy compatibility facades | Keeps published imports working while the live path depends only on a pure release projection | architecture and v1 fixture/Node tests; wheel smoke test | Remove facades only in a future breaking release | low | attempted |
| Define exit codes and JSON/human output inside the command orchestrator | Couples a stable process contract to a large mutation-prone module | Existing CLI corpus fixes the exact outputs | None; single-source serialization is simpler | low | ruled out |
| Centralize the process contract in `cli_output.py` | Keeps six exit meanings and two renderings independently testable without changing CLI behavior | output-contract unit tests and full CLI subprocess corpus | Structured internal exception taxonomy remains optional | low | attempted |
| Keep protocol schemas/builders/binding checks embedded in the command module | Forces verification adapters and fixture generators to depend on the entire CLI and obscures the I/O boundary | import graph and external-module imports exposed the reverse dependency | None; it blocks a clean verifier split | low | ruled out |
| Move exact protocol objects into an I/O-free module and re-export old names | Gives command, verifier, and fixture paths one acyclic object layer without breaking callers | identity/architecture tests and the full CLI/lineage corpus; this first extraction reduced `acsd.py` to about 1142 lines | None for the object layer; the later verifier row records the completed I/O split | low | attempted |
| Keep full offline verification embedded in the authoring CLI | Makes independent verifier reuse depend on argparse, private-key workflows, and timestamp acquisition code | source call graph showed the verifier already had a closed read-only input surface | None; the coupling is unnecessary | low | ruled out |
| Compose canonical-file, key, and lineage adapters under a CLI-independent release verifier | Makes read-only verification reusable and exposes the exact external-to-kernel dependency chain | adapter identity tests, architecture import audit, 156-test corpus, installed-wheel gate | Independent parser/crypto implementations remain separate assurance work | low | attempted |
| Reuse nested AI-use or contribution lists across built objects | A caller mutating one object can silently alter another object or its input team | regression test demonstrates isolation requirement | None; create fresh nested values | low | ruled out |
| Recompute public-key identifiers independently in each disclosure adapter | Equivalent formulas can drift at a security boundary | Three identical implementations existed | None; one shared definition is simpler | low | ruled out |
| Centralize the DER-SPKI SHA-256 key identifier | Gives CLI, event, identity, and certificate adapters one wire identity rule | `key_identity.py`; existing substitution and disclosure tests | Alternative key algorithms would need a versioned identifier profile | low | attempted |
| Derive a claim only from a verified, exact-subject, compatible evidence atom | Makes every grant traceable to one typed support item | `claim_derivation.py`; the live verifier round-trips `acsd-appraisal-transcript/v1`; Python/Lean agree on 19/19 cases | Adapter soundness remains outside the transcript kernel | low | implemented for live release verification |
| Keep separate `Compatible` and `AppraisalRule` inductive relations with identical constructors | Allows the coarse and exact formal semantics to drift while appearing equivalent | Source audit found the duplicated eight-rule tables | None; duplicate semantics have no value | low | ruled out |
| Reuse one declarative compatibility relation and prove exact-to-abstract refinement for any subject projection | Makes the exact model a conservative strengthening of the coarse skeleton and connects strict text decoding to both levels | 84-theorem Lean build, 52-theorem axiom audit, formal-architecture regression | Production adapter facts remain an explicit assumption | low | attempted |
| Treat union of accepted evidence sets as implicit support for new claims | Two harmless inputs could combine into an unintended capability | Lean `derivation_over_union_has_component_support` theorem | Richer multi-premise rules would require explicit constructors | low | ruled out |
| Snapshot only Git-tracked files during the read-only gate | Ignored or generated payload corruption could escape mutation detection | Whole-tree file/type/mode snapshot before and after the gate | Cross-platform CI completion | low | ruled out |
| Install a built wheel and exercise the console script outside the checkout | Distinguishes packaging success from source-import success | Temporary venv runs version, keygen, release, and verify | Installer-binary UX | low | attempted |
| Let an evidence package verifier depend on its source checkout | Archive cannot independently establish its own integrity | Candidate includes the builder and an artifact-mode gate with strict manifest pre/post checks | Independent third-party reproduction | low | ruled out |

## 2026-09-14 submission-lifecycle decisions

| Approach | Target or obstruction | Evidence | Missing check | Cost | Status |
|---|---|---|---|---|---|
| Add an author-controlled `accepted: true` or `rejected: true` field | A valid author signature would be misread as evidence of a venue's independent act | The venue is neither a signer nor a checked registry in the current profile | None; self-assertion cannot establish the external fact | low | ruled out |
| Treat private submission or rejection as no public ACSD transition | Preserves privacy and avoids inventing externally unverifiable state | The lifecycle runner verifies the existing release and confirms its complete tree is unchanged | Venue receipts remain a separate possible evidence profile | low | attempted |
| Force an unchanged named manuscript to occupy version `n+1` | Conflates identity disclosure with scientific revision and creates a redundant lineage node | Existing per-slot sidecars bind an exact release and publication reference without rewriting it | None; a new release is needed only when committed bytes change | low | ruled out |
| Use predecessor-authorized revision for changed camera-ready bytes and signed per-slot sidecars for later identity crosswalks | Separates content lineage from selective unblinding while retaining exact release/slot/key scope | Executable two-author workflow derives `AUTHORIZED_SUCCESSOR` and `FULL_BYLINE_KEY_ASSENT`; cross-release replay and publication-reference mutation fail | Real venue policy/usability study and separately authenticated venue evidence | low | attempted |

## 2026-09-14 cross-paper privacy decisions

| Approach | Target or obstruction | Evidence | Missing check | Cost | Status |
|---|---|---|---|---|---|
| Reuse one public signing key across unrelated papers while claiming unlinkability | Deterministic public key and key-ID equality creates a visible cross-paper edge before disclosure | The executable isolation experiment observes equal key IDs in two independently packaged releases | None; later sidecars cannot erase already public equality | low | ruled out |
| Treat exact release-bound identity assent as if it identified every occurrence of the same key | Amplifies one scoped author assertion into unsupported natural-person claims about other works | Cross-release replay fails with `IDENTITY_RELEASE_MISMATCH`; Lean requires exact release equality for slot assent | None; observer inference is not a verifier grant | low | ruled out |
| Generate an independent key per unrelated lineage | Removes the direct equality edge while preserving normal exact-release verification | The third experimental release exposes a distinct key ID; `audit-key-reuse --fail-on-cross-work` enforces the policy across fully verified inputs | Recovery/privacy study and optional workspace-registry integration | low | attempted |
