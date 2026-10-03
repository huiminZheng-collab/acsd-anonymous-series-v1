# Historical DigiCert interoperability fixture

These files are a previously issued DigiCert RFC 3161 response used by the SRL
test suite to exercise real DER/CMS verification. The timestamp subject is the
ACSD v4.0.0-rc2 manifest recorded in `report.json`.

This fixture is **not** the publication timestamp for SRL v0.3.1 and must not be
used to date the SRL approval target, source tree, or release manifest. The
separate top-level `timestamp/` directory contains the RFC 3161 evidence for
the exact SRL v0.3.1 `RELEASE-MANIFEST.sha256` bytes.

Offline fixture verification:

```powershell
openssl ts -verify `
  -queryfile release-v4.0.0-rc2.timestamp/manifest.tsq `
  -in release-v4.0.0-rc2.timestamp/response.tsr `
  -CAfile release-v4.0.0-rc2.timestamp/trust-anchor.pem `
  -untrusted release-v4.0.0-rc2.timestamp/tsa-chain.pem
```

Expected final line: `Verification: OK`. `report.json` records the fixture
subject, digests, policy, serial, signer fingerprint, and generation time.
