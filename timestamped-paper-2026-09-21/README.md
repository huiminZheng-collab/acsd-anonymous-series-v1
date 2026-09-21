# ACSD final-paper timestamp package

This additive package preserves the content-anonymous manuscript titled
"ACSD: An Executable Evidence Profile for Evolving Pseudonymous Scholarly
Releases" and supplies independent RFC 3161 time evidence for its exact bytes.

The timestamp subject is `RELEASE-MANIFEST.sha256`. That manifest binds
`acsd-profile.pdf` by SHA-256. The timestamp was obtained after the manuscript
had already been prepared, so it establishes only that this exact manifest
existed no later than **2026-09-21 05:30:27 UTC**. It is not a backdated claim
about earlier repository commits.

## Verify

First verify the paper against the manifest:

```sh
sha256sum -c RELEASE-MANIFEST.sha256
```

Then verify the RFC 3161 response with OpenSSL:

```sh
openssl ts -verify \
  -queryfile RELEASE-MANIFEST.sha256.tsq \
  -in RELEASE-MANIFEST.sha256.tsr \
  -CAfile sigstore-tsa-certchain.pem
```

The expected result is `Verification: OK`. See
`TIMESTAMP-VERIFICATION.txt` for the recorded hashes, policy, serial number,
certificate fingerprints, and the precise evidentiary boundary.
