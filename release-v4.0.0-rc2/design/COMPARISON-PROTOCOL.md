# Comparative evaluation protocol

Protocol fixed before the first performance run, 2026-09-15.

## Questions and units

R1: What security conclusions can a reader obtain from each recipe?
R2: What local latency, commands and public artifact bytes does that recipe cost?
R3: What additional policy is required for succession and scoped disclosure?

The experimental unit is one synthetic manuscript, one or three signing keys,
and a separate verification command. Inputs are 64 KiB, 1 MiB and 8 MiB.
Each configuration receives one warm-up and five measured repetitions.
Recipe order is shuffled with seed 20260915 in every repetition. Store every
timing, command, return code, artifact count and byte count. Report median,
minimum, maximum and sample standard deviation. No significance test or
throughput extrapolation is planned for this small single-machine experiment.

Key generation and verifier key import are setup, excluded from latency but
recorded in the command log. Creation includes copying the manuscript into a
self-contained package. Verification includes process startup and disk reads.
Caches are warm; every invocation launches a new process. Memory is not measured.
Command counts count actual process calls, not user typing effort. Encrypted
key custody, manual review, team coordination and network latency are excluded.

## Recipes

* ACSD: production CLI `release`, `verify`; all author keys required.
* Detached Ed25519: independent small client; signs exact bytes with each key,
  verifies every signature against caller-pinned public keys.
* GnuPG: installed actual client; Ed25519 detached signatures; each signature
  checked in an isolated verifier keyring containing only the required keys,
  with VALIDSIG fingerprint checked against its required signer. Separate
  keyrings model a third-party verifier. No public-key retrieval is needed.

These recipes have different output semantics. Bytes and latency are costs for
each declared recipe, not a ranking at equal security. The hand-built exact
predecessor-transition baseline is retained as a positive control: it should
match ACSD on authorized rotation and reject transition replay.

## Security evidence

Run the existing adjacent baseline, submission lifecycle, three-author
unblinding and cross-paper isolation experiments afresh. Preserve their full
reports. Add real GPG positive verification, manuscript tampering, missing
coauthor signature, fresh attacker key, and a hand-signed predecessor transition
positive/replay case. A valid attacker signature is not classified as a GPG bug:
the absent property is predecessor authorization under the self-declared policy.

Security results are categorical: established / rejected / outside recipe.
Do not invent a numerical security score or count unsupported semantics as
cryptographic failures. Expected results must be asserted by the runner.

## External validity and service stratum

Signature plus RFC 3161 and signature plus OpenTimestamps must cover the
completed signature bundle to support a claim about completion. Timestamp-only
recipes support a time claim, not team assent or successor authority.
Zenodo and Software Heritage are archival services; archival metadata must not
be equated to a predecessor-authorized transition. Their API/network timing and
public deployment are separate experiments, reported as unmeasured until run.
Independent human use and clean-machine replication remain unmeasured.

Sources checked 2026-09-15:

* https://www.acsac.org/2026/submissions/papers/
* https://www.gnupg.org/documentation/manuals/gnupg/Operational-GPG-Commands.html
* https://opentimestamps.org/
* https://help.zenodo.org/docs/deposit/describe-records/

## Route ledger

| Approach | Target | Evidence | Missing check | Cost | Status |
|---|---|---|---|---|---|
| Controlled Ed25519 and actual GPG local benchmark | Byte integrity and operation cost | Existing baseline; installed GPG | Recorded repeated measurements | low | attempted |
| Manual signed transition positive control | Avoid weak succession baseline | Existing exact transition experiment | Actual GPG transition execution | low | attempted |
| Network timestamp/archive comparison | Time and archival service costs | Official service documentation | Installed-client service runs | medium | unexplored |
| Independent user study | Adoption and comprehension | No participants | Recruitment and study protocol | high | unexplored |

Pre-mortem: unequal semantics require explicit claim columns; warmed caches
require explicit labeling; subprocess overhead is part of the measurement;
unsigned required-key lists require caller pins; key setup must not contaminate
one recipe's timings; generated public logs must not contain private keys.
