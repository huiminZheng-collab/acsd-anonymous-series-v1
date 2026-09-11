# ACSD RFC 3161 receipt adapter (v1.3.3)

This experiment replaces the synthetic enrollment timestamp in v1.3.2 with a real RFC 3161 request, CMS timestamp token, and offline verification path. It intentionally uses a locally generated test CA/TSA so that no irreversible public submission occurs.

Run on this Windows workspace:

```powershell
node .\generate-local-rfc3161.cjs
```

The script defaults to Git for Windows' OpenSSL at `C:\Program Files\Git\usr\bin\openssl.exe`. Override it with `ACSD_OPENSSL` if needed.

To verify and wrap a receipt returned by a separately selected TSA:

```powershell
node .\verify-rfc3161.cjs --subject-digest <sha256> --query <request.tsq> --response <response.tsr> --ca <pinned-root.pem> --out <evidence.json>
```

`artifacts/public-submission-envelope.json` records the prepared HTTP media types and acceptance policy. It deliberately has no endpoint and performs no network action.

Important boundary: a local TSA demonstrates protocol and adapter correctness only. It is not an independent time witness. Production evidence must pin a separately governed TSA trust anchor (or a separately governed transparency log), retain the raw request and response, and validate the full nonce-bearing query rather than only the digest.

Generated test private keys are placed under `private-test-keys/` and are not production credentials. The public-facing evidence files are under `artifacts/`; adversarial fixtures are under `adversarial/`.
