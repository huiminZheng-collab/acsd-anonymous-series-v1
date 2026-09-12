# ACSD v2 Provenance Evidence Capsule

This directory contains the specification and reference implementation for the ACSD v2
**Provenance Evidence Capsule** (PEC).  It is deliberately not a deployment,
not a claim of authorship proof, and contains no private research materials or
production keys.

- `SPEC.md` fixes the object model, accepted outputs, and non-claims.
- `TEST-PLAN.md` fixes the smallest positive and adversarial corpus that a
  later reference generator and independent verifier must implement.

The v2 implementation may reuse the existing ACSD release, team-governance,
dialogue-checkpoint, RFC 3161, and assurance-profile fixtures.  It must not
silently treat their synthetic test keys or local timestamp services as real
external evidence.

The first reference implementation is now present in `pec_core.py`, with a
generated attack corpus and a standard-library suite of 19 test methods (16
pass by default; 3 v1-integration tests skip unless a v1 fixture workspace is
present). It validates exact
canonical bindings, unanimous approval, event-chain integrity, claim-policy
non-amplification, and delegates v1 COSE verification to the audited Node
verifier.

Generate and verify the end-to-end demo locally:

```powershell
python .\generate_demo.py
python .\verify_demo.py
python .\verify_pec.py
```

The demo writes `demo/pec.json`, `demo/dialogue-disclosure.json`, and a
two-entry `demo/MANIFEST.sha256`.

The combined PowerShell gate is `./run_all.ps1`; it runs all local tests, the
demo verifier, and the standalone Lean project in `formal/`. It reports
`PENDING_TOOLCHAIN` rather than silently skipping Lean when `lake` is
unavailable. The formal project pins Lean 4.33.1. If `lake` is not on `PATH`,
set `ACSD_LAKE` to the full path of `lake.exe` before running the gate.

For a packaged release, verify the complete file set and every payload digest
before executing anything:

```powershell
python .\verify_release.py .
```

The current paper draft is [`paper/acsd-v2.tex`](paper/acsd-v2.tex); its local
two-pass PDF build is `paper/build/acsd-v2.pdf`. The draft is
content-anonymous, not author-unlinkable. Build it from `paper/` with:

```powershell
pdflatex -interaction=nonstopmode -halt-on-error -output-directory=build acsd-v2.tex
pdflatex -interaction=nonstopmode -halt-on-error -output-directory=build acsd-v2.tex
```
