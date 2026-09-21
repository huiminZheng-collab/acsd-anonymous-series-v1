# ACSD v4.0.0-rc2 RFC 3161 evidence

This directory contains an externally issued RFC 3161 timestamp for the exact
`release-v4.0.0-rc2/MANIFEST.sha256` file.

- Timestamp subject: `release-v4.0.0-rc2/MANIFEST.sha256`
- Subject SHA-256: `22a41aedb7fc4737d584833e593fdcb825345acea7f1f9c6aee7aafe589a753c`
- Authority: DigiCert public RFC 3161 service
- Endpoint: `http://timestamp.digicert.com`
- Generation time: `2026-09-21T13:38:52Z`
- Policy OID: `2.16.840.1.114412.7.1`
- Serial: `9ea95e6abc7d6eccc96d6e84642bc1ff`
- Nonce: `20f22a89d9b99785`
- Request SHA-256: `4222c3f36ea63f5529dfc7293eeed58cf538b0e0fc839af41104b9b6c2b5d55b`
- Response SHA-256: `5d32e20fd3fbe5dd2de7ec6aa8a084bdffe5ec94f2337a14cd38406af18fc833`
- Signer certificate SHA-256 fingerprint: `2da09da7f4131f9fe72db6c5e6e9c9656755af043f1ea742cc0d2120e141ebfc`
- Trust anchor SHA-256 fingerprint: `3e9099b5015e8f486c00bcea9d111ee721faba355a89bcf1df69561e3dc6325c`

The response was verified against the original request and the explicit trust
anchor in this directory. OpenSSL reported `Verification: OK`; this checks the
signed response, certificate path, message imprint, and request nonce.

## Offline verification

From the project root, run:

```powershell
openssl ts -verify `
  -queryfile release-v4.0.0-rc2.timestamp/manifest.tsq `
  -in release-v4.0.0-rc2.timestamp/response.tsr `
  -CAfile release-v4.0.0-rc2.timestamp/trust-anchor.pem `
  -untrusted release-v4.0.0-rc2.timestamp/tsa-chain.pem
```

Expected final line: `Verification: OK`.

`report.json` records the same facts and artifact digests in machine-readable
form. The timestamp establishes that this exact manifest existed no later than
the stated generation time; it does not establish authorship or publication.
