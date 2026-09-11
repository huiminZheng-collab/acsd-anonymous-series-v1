# Build and verification notes

The final public payload is the set of files listed in
`RELEASE-MANIFEST.sha256`. The manifest excludes only itself and Git's local
metadata. It covers the paper PDF, the release scripts, all public artifact
fixtures, formal source, and the RFC 3161 adapter.

To verify a checkout without regenerating anything:

```powershell
node .\verify-release-manifest.cjs
```

To replay the executable artifact and then verify the resulting public tree:

```powershell
.\verify.ps1
```

`verify.ps1` creates ignored runtime directories such as `artifact/.deps/` and
`formal-core/out/`. They are not public payload. The verifier rejects a
manifest that omits or adds any non-ignored public file, and rejects a manifest
that names paths reserved for private keys or build caches.

The paper source and LaTeX build logs are intentionally not published. This
reduces the anonymity surface; the PDF is the canonical manuscript byte
sequence for this release.
