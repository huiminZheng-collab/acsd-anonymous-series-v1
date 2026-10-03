# Sealed Research Lineage Profile v0.3.1

This is the frozen research-prototype release of the ACSD Sealed Research
Lineage (SRL) experimental profile. It contains the normative profile,
executable Python verifier, adversarial regression suite, Lean abstract
projection, and an external RFC 3161 timestamp over the final release manifest.

## Verify

From this directory on Windows PowerShell:

```powershell
.\verify_srl.ps1
```

The command runs all 55 Python tests and compiles the Lean model. The Python
tests require the `cryptography` package. Lean is located through `LEAN_EXE`,
the default elan installation, or `PATH`.

Verify the release file inventory with:

```powershell
Get-Content RELEASE-MANIFEST.sha256 | ForEach-Object {
  $hash, $path = $_ -split '  ', 2
  if ((Get-FileHash -Algorithm SHA256 -LiteralPath $path).Hash.ToLower() -ne $hash) {
    throw "Hash mismatch: $path"
  }
}
```

The `timestamp/` directory records an RFC 3161 response over the exact bytes of
`RELEASE-MANIFEST.sha256`. Its verification report identifies the TSA signer,
policy, serial number, time, message imprint, and locally pinned certificate
fingerprint.

## Scope

SRL records exact cryptographic evidence about sealed research milestones,
selective openings, and authorized lineage transitions. It does not determine
scientific correctness, independent discovery, plagiarism, natural-person
identity, legal ownership, or final academic credit.

This is a research prototype, not a production security service.

## Publication and anonymity

This package is content-anonymous: the files do not intentionally identify an
author. The hosting GitHub account and repository history may nevertheless be
linkable. No claim of author-unlinkable double-blind publication is made.

## License

See `LICENSE`.
