# Toolchain provenance

The source pins Lean through `lean-toolchain`:

```text
leanprover/lean4:v4.33.1
```

For the local verification on 2026-09-10, the official Windows release archive
was downloaded from:

```text
https://github.com/leanprover/lean4/releases/download/v4.33.1/lean-4.33.1-windows.tar.zst
```

Its SHA-256 was checked before extraction:

```text
f63029c0e1e6daed0f4807481b6fcd8f8b77fbce6d63f205c7f9191072387a7a
```

The extracted executable reported:

```text
Lean (version 4.33.1, x86_64-w64-windows-gnu,
commit 819816b2e0a3bf405af45ae5c7af2491d8f5bee6, Release)
```

The archive and extracted toolchain are deliberately local runtime artifacts
under `tools/` and are excluded from source control.  Reproducers should obtain
the pinned release independently, verify the published digest, and run
`scripts/check-proofs.ps1`.
