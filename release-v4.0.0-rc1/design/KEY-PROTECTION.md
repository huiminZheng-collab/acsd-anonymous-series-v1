# Local private-key protection profile

Checked 2026-09-14. This document defines the first author-side key-storage
service level. It is deliberately outside the signed release and Lean
authorization kernel: the protocol consumes a public key and a signature, not
the private-key storage backend.

## Selected profile

`acsd keygen --encrypt` generates the ordinary Ed25519 key pair but serializes
the PKCS#8 private key with the maintained `cryptography` library's
`BestAvailableEncryption` profile. The passphrase is read twice from an
interactive terminal; it is not an argument, environment variable, JSON field,
release file, manifest member, or log field.

When a signing command encounters such a key, it prompts only on an interactive
terminal. A one-command `release` or `revise` keeps a per-process, per-path
in-memory cache only long enough to avoid repeating a prompt for the same key.
The cache is not serialized and ceases to be reachable when the command exits.
No claim is made that a managed-language runtime can securely zero every copy
of a passphrase from memory.

An encrypted key presented without an interactive terminal fails closed as
`PRIVATE_KEY_PASSPHRASE_REQUIRED`; a wrong passphrase produces
`PRIVATE_KEY_PASSPHRASE_INVALID`; cancellation and mismatched generation
confirmation are distinct usage errors. The legacy default remains an
unencrypted PKCS#8 PEM for compatibility, but is explicitly a lower protection
level rather than a recommended author profile.

## Route decision

| Approach | Target or obstruction | Evidence | Missing check | Cost | Status |
|---|---|---|---|---|---|
| Interactive encrypted PKCS#8 | Protect a local private-key file at rest without changing public wire objects | `cryptography` 50.0.1 exposes PKCS#8 load/serialization and `BestAvailableEncryption`; encrypted keygen, release, wrong-passphrase, and noninteractive tests | Cross-platform terminal and backup usability | low | attempted |
| Passphrase in argv, environment, release data, or machine JSON | Makes secrets visible to shell history, process inspection, logs, artifacts, or CI records | Public CLI contract and negative tests never accept such an option | None; the exposure violates the profile | low | ruled out |
| OS keystore or FIDO2/HSM | Keep key material outside an ordinary file and enable stronger local policies | No portable adapter yet | Cross-platform abstraction, recovery/export policy, hardware tests | high | unexplored |
| Automatic in-place migration of old plaintext keys | Convenient upgrade path | Could overwrite the sole key before a verified backup and needs durable migration UX | Backup and rollback design | medium | deferred |

## Scope and non-claims

This profile does not establish user identity, secure passphrase choice,
protection from malware or a compromised running account, backups, remote
signing, unattended automation, HSM custody, or recovery guardian custody. It
does not alter any ACSD release, signature, WorkID, lineage, or verification
claim. Public verification remains password-free.
