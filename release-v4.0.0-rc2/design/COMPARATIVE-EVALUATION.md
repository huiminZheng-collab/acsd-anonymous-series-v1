# ACSD: security and operational-cost comparison

Empirical local evaluation, protocol fixed 2026-09-15 and cleanly rerun
2026-09-16. Protocol:
[COMPARISON-PROTOCOL.md](COMPARISON-PROTOCOL.md).
Raw measurements and command logs:
[results.json](comparison-run-20260915-b/results.json);
[timestamp-results.json](comparison-run-20260915-b/timestamp-results.json).

## Findings

1. Actual GnuPG and ACSD both reject changes to signed manuscript bytes.
   A hand-signed exact predecessor transition also works: our positive GPG
   control validates it and rejects mutation of its child binding. ACSD's
   succession decision can be assembled with ordinary signatures.
2. ACSD supplies the maintained release/authority/approval-completion/disclosure
   policy around those signatures. The simple recipes measured here have lower
   storage overhead and often lower verification latency; that is an expected
   cost of checking fewer relations, not evidence that one signature is safer.
3. Local verification is subsecond at the reported median for the sampled
   configurations, but variation is substantial. The data do not establish a
   scaling law, throughput guarantee, or general speed advantage.
4. One real freeTSA receipt verifies offline. Checking its ACSD approval-set
   binding adds a separately measured path. Network service latency, provider
   reliability and independent human use were not measured.

## Implementation and measurement

Windows 11 build 26200, Python 3.12.14, Intel Family 6 Model 186, 16 logical
CPUs; GnuPG 2.4.9 and libgcrypt 1.12.2. The raw report records versions and
SHA-256 hashes of production Python sources, the runner and experiment protocol.
Ed25519 is used in all recipes; OpenPGP and ACSD use different signed envelopes.
GPG runs from the installed Git distribution. An isolated author keyring and
an isolated reader keyring contain synthetic identities. The Python baseline
uses the same cryptography library as ACSD, with an independent minimal client.

There are 18 configurations (3 recipes x 3 byte sizes x 2 team sizes), each
with one warm-up and five measured repetitions: 108 recorded samples, 90
measured samples. Recipe order is deterministically shuffled. Both creation
and verification include process launch, serialization and filesystem work.
Creation includes manuscript copying and packaging public keys. Key creation
and reader key import are recorded setup costs, excluded from timed samples.
No private-key file is included in artifact counts or retained raw reports.

### 1 MiB manuscript: measured latency and storage

All latency columns are milliseconds. Dispersion is sample standard deviation,
reported beside the median as a separate quantity, not a confidence interval.
Other input sizes, minima/maxima and every sample remain in the raw JSON.

| Recipe | Authors | Create median | Create SD | Verify median | Verify SD | Extra bytes over manuscript | Files |
|---|---:|---:|---:|---:|---:|---:|---:|
| Detached Ed25519 | 1 | 256.50 | 38.44 | 261.98 | 43.52 | 177 | 3 |
| GnuPG | 1 | 244.92 | 42.90 | 80.56 | 14.74 | 348 | 3 |
| ACSD | 1 | 463.68 | 30.74 | 361.95 | 58.10 | 6,284 | 11 |
| Detached Ed25519 | 3 | 227.77 | 22.74 | 214.26 | 39.05 | 531 | 7 |
| GnuPG | 3 | 682.30 | 37.11 | 252.26 | 22.08 | 1,044 | 7 |
| ACSD | 3 | 480.46 | 90.83 | 340.60 | 95.75 | 10,934 | 15 |

GPG creation uses one sign and one public-key export command per author;
verification uses one command per required signature. ACSD and the custom
baseline each expose one creation and one verification invocation. GPG exports
could be batched or cached, and OpenPGP multi-signature packaging could be
optimized; these command counts describe this explicit recipe, not a lower
bound on GPG usability. A single wrapper command does not remove team review,
key distribution or coordination work. The raw timings include ordinary host
activity; the nonmonotonic size trend cautions against performance rankings.

### Timestamp verification: a separate cost stratum

The same 4,649-byte real RFC 3161 receipt is checked in twelve subprocess runs:
one warm-up and five samples for each path. Receipt-only median is 272.15 ms
(SD 15.52); ACSD binding-plus-receipt median is 294.94 ms (SD 27.60).
The former verifies the receipt against the request imprint, nonce and pinned
signer. The latter also reconstructs the approval-set binding. Neither timing
includes production manuscript signature verification; these are incremental
time-evidence checks, not total end-to-end verification times. Their overlapping
variation does not support an estimate of a statistically resolved overhead.
The real receipt is a previously obtained fixture; this run made zero network
requests and does not measure request-to-confirmation latency.

## Security comparison

The table uses precise claims rather than a security score. “Requires added
policy” means ordinary signatures can support the property if the application
defines and checks that policy; it is not a cryptographic deficiency.

| Scenario / claim | Bare signatures, required keys supplied by caller | Signatures plus independent time | Exact manual predecessor transition | ACSD | Evidence |
|---|---|---|---|---|---|
| Changed manuscript bytes | Rejected | Signature layer rejects | Signature layer rejects | Rejected | Actual GPG, Ed25519 and ACSD runs |
| All three named keys signed | Established when all pinned signatures checked | Same signature condition | Requires declared team/threshold policy | Required team approval checked | GPG positive/missing signature; ACSD release |
| Fresh key signs apparent n+1 | Signature valid under self-declared key; succession unspecified | Time adds no predecessor authority | Rejected without old-authority signature | Unauthorized successor | Ed25519/ACSD adjacent run; GPG self-declared versus pinned key |
| Authorized key change | Fixed old-key pin alone rejects it | Timestamp does not repair the pin | Accepted with exact signed transition | Accepted | Adjacent positive control; GPG signed statement |
| Authorization reused for another child | Requires added transition policy | Requires added transition policy | Altered signed transition rejected | Rejected | Adjacent and actual GPG replay cases |
| Partial author reveal promoted to full byline | Requires release/slot policy | Requires release/slot policy | Outside this transition recipe | Partial remains partial | Fresh ACSD 1/3, 2/3, 3/3 disclosure run |
| Identity sidecar replayed on another release | Requires signed scope and scope check | Requires signed scope and scope check | Outside this transition recipe | Rejected | ACSD cross-paper and lifecycle runs |
| Signatures appended after timestamp of unsigned target | Target time alone cannot establish completed signatures | Must timestamp complete signature bundle | Same completion requirement | Approval-set binding rejects substitution | Real receipt checks and approval-set tests |

The GPG manual transition is a small canonical JSON statement containing parent
digest, child digest and successor fingerprint, signed by the pinned predecessor.
This experiment checks its positive signature and rejects the changed statement.
The existing independent Ed25519 baseline additionally reconstructs the exact
transition from the proposed child before checking it. No GPG lineage parser,
threshold/recovery protocol or disclosure client has been implemented here;
the GPG example is a statement-binding control, not a complete equivalent client.

Four existing workflow experiments were executed afresh and their full reports
are embedded in results.json: adjacent lineage policies, submission lifecycle,
three-author unblinding and cross-paper isolation. The timestamp supplement
reran 16 tests, all passing, covering receipt mutation, wrong nonce/pin,
untrusted signer, RFC-profile constraints and approval-set membership/closure.
These finite attacks support the stated cases; they do not constitute a proof
against every possible composition error. Existing Lean proofs remain the
separate evidence for the model's quantified invariants.

## External systems: capability analysis, not measured latency

| Recipe/service | Supported purpose and additional requirements | Measurement status |
|---|---|---|
| GPG + RFC 3161 over completed bundle | Signed bytes plus not-after evidence; needs signer trust, complete bundle binding and application authorization policy | Actual GPG and actual RFC receipt checked separately; no combined GPG/TSA workflow timing |
| OpenTimestamps | Bitcoin-anchored time proof; author assent requires separate signatures | Official-client documentation reviewed; no client/service benchmark |
| GPG + OpenTimestamps | Sign first, timestamp a complete bundle; pending confirmation and later proof completion must be recorded separately | Not run |
| Zenodo | Archival records, author metadata and identifiers; added cryptographic policy needed for ACSD-style succession | Documentation reviewed; no deposit or download timing |
| Software Heritage | Software archival and intrinsic object identification; scholarly byline and succession need an application profile | No archival experiment; not used for latency claims |

OpenTimestamps' official CLI documentation requires a local Bitcoin Core node
for its verification path and distinguishes pending calendar attestations from
confirmed proofs. A third-party explorer would add another trust dependency;
it must be declared if used in a subsequent comparison. Archival services can
also store an ACSD or hand-built signed package, so they are complementary
backends rather than mutually exclusive competitors.

Sources: [GnuPG commands](https://www.gnupg.org/documentation/manuals/gnupg/Operational-GPG-Commands.html),
[OpenTimestamps client](https://github.com/opentimestamps/opentimestamps-client),
[Zenodo record metadata](https://help.zenodo.org/docs/deposit/describe-records/),
[RFC 3161](https://www.rfc-editor.org/rfc/rfc3161.html).

## Protocol deviations and limits

* Git's MSYS GPG initially rejected Windows-style paths before generating any
  key or collecting any measurement. The successful runner translates GPG path
  arguments to MSYS paths. No failed timing sample was discarded from a
  completed configuration.
* Contrary to the protocol's phrase “only the required keys”, the isolated
  reader ring contains three author keys and one attacker key. Each verification
  additionally checks VALIDSIG against its caller-required fingerprint; merely
  having an attacker key in the ring does not authorize it.
* No network isolation mechanism was applied. The GPG commands require no
  downloads; the complete path uses local files and pre-imported keys. This is
  evidence of local operation, not a clean-machine or independent-person trial.
* ACSD genesis verification here uses its declared author set. GPG and the
  custom baseline use caller-pinned expected keys. No experiment identifies the
  true human author from a genesis key. Parent pinning and transitions are tested
  separately in the lineage experiment.
* Only release creation and verification received repeated workflow timings.
  Succession and disclosure received functional/adversarial evaluation. Human
  operation time, retry/recovery usability and service costs remain open.

## Reproduce

From the project root, with project dependencies and an installed GPG:

```text
python design/comparative_evaluation.py --gpg <path-to-gpg> --output <new-run-directory>
python design/timestamp_comparison.py --output <new-run-directory>/timestamp-results.json
```

The main runner refuses an existing output directory. Temporary synthetic
keys are removed after the run; output retains command metadata and decisions.
The second runner refuses to overwrite an existing result. Reproductions should
retain their own measurements rather than replacing this run. The experiment
adds no public upload, DOI, network timestamp request, or protocol feature.

## Consequence for the paper introduction

The introduction should explicitly concede that ordinary signatures, independent
timestamps and a correctly specified manual predecessor transition can reproduce
the relevant core guarantees. It should immediately identify the remaining
application contract: jointly approved metadata, completion-before-time,
predecessor authority and typed disclosure claims. The measured ACSD costs
belong with that contract. The current data support a reusable executable
profile and tested boundaries; they do not support cryptographic superiority
over GPG or a claim that alternative implementations are impossible.
