# Adjacent baseline evaluation

Checked 2026-09-14 against the post-v3.2 source tree and the current official
documentation for GnuPG, OpenTimestamps, Software Heritage, and Zenodo.

## Question and scope

The smallest useful comparison is not whether ACSD can also verify a digital
signature. Detached signatures already do that. The discriminating question is
what additional signed structure is required to accept an authorized successor
key while rejecting a fresh attacker key that makes the same self-signature
claim.

`adjacent_baseline_runner.py` therefore compares ACSD with a deliberately
minimal detached-Ed25519 baseline using the same signature primitive. It
constructs one parent plus three apparent `n+1` objects:

1. an unchanged-authority successor;
2. a legitimate key rotation; and
3. a fresh-key capture attempt.

The baseline evaluates three explicit policies: verify against the key declared
by the child, pin the predecessor key, or require a predecessor signature over
an unambiguous parent digest, child digest, and child key. This is an empirical
controlled mechanism comparison, not a proof about every possible
signed-statement protocol.

## Result

Both the bare signature and ACSD detect mutation of signed exact bytes. The
child-declared-key policy accepts the signatures on both the legitimate
rotation and the attacker child. The predecessor-key-pin policy rejects both.
The manual exact-transition policy correctly accepts the authorized rotation
and rejects replay of that authorization onto the attacker child. ACSD reaches
the same core lineage decision while also defining canonical objects,
threshold authority, approval-set closure, governance binding, and typed claim
outputs.

This result deliberately avoids claiming that predecessor authorization is
unique to ACSD. It isolates the contribution as a maintained authorization
profile and claim-scoped composition rather than a new signature primitive.
File counts in the report expose the additional artifact surface rather than
hiding ACSD's heavier machinery; they are not a usability or throughput
measurement.

## Adjacent systems and excluded comparisons

- GnuPG supports detached signatures and requires the verifier to identify the
  signed data and evaluate signer/key trust. This experiment does not measure
  GnuPG's UI, keyring, Web-of-Trust, or performance.
- OpenTimestamps creates and verifies blockchain timestamp proofs. It addresses
  existence-before time, not predecessor authority; no live calendar request is
  made here.
- Software Heritage archives and intrinsically identifies source objects. A
  Save-Code-Now deployment run would test archival availability, not ACSD's
  author-slot or lineage rules.
- Zenodo creates versioned repository records and DOI metadata after an
  authorized deposit/publish action. No Zenodo record is created or mutated by
  this experiment.

Primary documentation checked:

- <https://gnupg.org/documentation/manuals/gnupg26/gpg.1.html>
- <https://opentimestamps.org/>
- <https://docs.softwareheritage.org/user/faq/>
- <https://developers.zenodo.org/>

## Remaining external-validity gap

The next distinct evidence is an operational task comparison using installed
upstream clients, followed by an independently executed author/verifier pilot.
Those studies need protocol-parity rules, current tool versions, consent where
human participants are involved, and reported variance. They must not be
inferred from this deterministic runner.
