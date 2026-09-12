# ACSD v2 Provenance Evidence Capsule

This directory contains the specification and reference implementation for the ACSD v2
**Provenance Evidence Capsule** (PEC), plus a working command-line tool
(`acsd.py`).  It is deliberately not a deployment, not a claim of authorship
proof, and contains no private research materials or production keys.

- `SPEC.md` fixes the object model, accepted outputs, and non-claims.
- `TEST-PLAN.md` fixes the smallest positive and adversarial corpus.
- `design/` holds the canonical-JSON spec, differential test assets, the CLI
  spec, the test matrix, and the attack/misuse list.

The reference core is in `pec_core.py`; the CLI is in `acsd.py` with a
minimal COSE Sign1 module (`cose.py`) and RFC 3161 support (`tsa.py`). The
canonical/digest/binding core is dependency-free; signing and timestamping use
the `cryptography` package.

## Install

```powershell
python -m pip install .      # installs the `acsd` command and its dependency
```

Dependencies: Python 3.9+ and `cryptography`. The core verification path
(canonical JSON, digests, bindings, manifest) has no third-party dependency.

## CLI quick start

```powershell
python .\acsd.py --help
```

Commands: `keygen`, `init`, `approve`, `finalize`, `verify`, `inspect`.

Single-author release:

```powershell
python .\acsd.py keygen --name alice --out-dir keys
# build team.json with alice's public key (see keygen output's public_key field)
python .\acsd.py init paper.pdf --team team.json --out release-dir
python .\acsd.py approve release-dir --key keys\alice.key
python .\acsd.py finalize release-dir              # or: --tsa https://... 
python .\acsd.py verify release-dir
```

Multi-author release (each author signs on their own machine):

```powershell
# coordinator
python .\acsd.py init paper.pdf --team team.json --out release-dir
# author 1 (on their machine)
python .\acsd.py approve release-dir --key author-1.key
# author 2 (on their machine)
python .\acsd.py approve release-dir --key author-2.key
# coordinator
python .\acsd.py finalize release-dir --tsa https://tsa.example
python .\acsd.py verify release-dir
```

Private keys never enter the release directory; only public keys and
endorsements (COSE Sign1) do. `finalize --tsa <url>` timestamps the exact PEC
digest (RFC 3161); `--tsa local` uses a built-in test TSA that is **not**
independent time evidence. If the TSA is unreachable, `finalize` fails with
exit code 4 unless `--allow-untimestamped` is given, in which case the package
is explicitly marked `finalized-untimestamped`.

`verify` reports exactly what the policy authorizes (e.g. `KEY_ASSENT`,
`GOVERNANCE_ASSENT`, `EXTERNALLY_NOT_AFTER`) alongside the non-claims
(`natural_person_authorship`, `contribution_truth`, `originality_truth`,
`legal_nonrepudiation`, `peer_review`). Use `--json` for machine-readable
output.

## Demo fixture

Generate and verify the end-to-end demo locally:

```powershell
python .\generate_demo.py
python .\verify_pec.py
```

The demo writes `demo/manuscript.txt`, `demo/release.json`,
`demo/governance.json`, `demo/pec.json`, `demo/dialogue-disclosure.json`, and a
five-entry `demo/MANIFEST.sha256`. The demo binds real manuscript bytes and
real digests (no placeholders), but uses synthetic author identifiers.

## Tests

The standard-library suite has 30 test methods: 27 pass by default, and 3
v1-integration tests skip unless a v1 fixture workspace is present (via
`ACSD_V1_ROOT`). The differential canonical tests live in
`design/canonical_diff_runner.py` (Python vs Node, 64 vectors).

```powershell
python -m unittest
python .\design\canonical_diff_runner.py
```

## Combined gate and release

The combined PowerShell gate is `./run_all.ps1`; it runs all local tests, the
demo verifier, and the standalone Lean project in `formal/`. It reports
`PENDING_TOOLCHAIN` rather than silently skipping Lean when `lake` is
unavailable. The formal project pins Lean 4.33.1; set `ACSD_LAKE` to the full
path of `lake.exe` if it is not on `PATH`.

For a packaged release, verify the complete file set and every payload digest
before executing anything:

```powershell
python .\build_release.py
python .\verify_release.py release-v2.0.0
```

## Paper

The current paper draft is [`paper/acsd-v2.tex`](paper/acsd-v2.tex); its local
two-pass PDF build is `paper/build/acsd-v2.pdf`. The draft is
content-anonymous, not author-unlinkable. Build it from `paper/` with:

```powershell
pdflatex -interaction=nonstopmode -halt-on-error -output-directory=build acsd-v2.tex
pdflatex -interaction=nonstopmode -halt-on-error -output-directory=build acsd-v2.tex
```
