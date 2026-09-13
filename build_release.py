"""Build the deterministic, cache-free ACSD v3 release directory."""

from __future__ import annotations

import hashlib
import argparse
import shutil
from pathlib import Path


ROOT = Path(__file__).resolve().parent
DEST = ROOT / "release-v3.0.0"
FILES = (
    "ACCEPTANCE-MATRIX.md",
    "ANONYMITY.md",
    "CITATION.cff",
    "LICENSE",
    "acsd.py",
    "cose.py",
    "fixtures.py",
    "generate_demo.py",
    "install-lean.ps1",
    "pec_core.py",
    "pyproject.toml",
    "README.md",
    "run_all.ps1",
    "run_all.sh",
    "SPEC.md",
    "STATUS.md",
    "TEST-PLAN.md",
    "test_cli.py",
    "test_cli_signing.py",
    "test_cose.py",
    "test_corpus.py",
    "test_demo.py",
    "test_dialogue_merkle.py",
    "test_lineage_authorization.py",
    "test_node_integration.py",
    "test_node_approval.py",
    "test_package_adapter.py",
    "test_pec_core.py",
    "test_sidecar.py",
    "test_tsa_interop.py",
    "test_tsa_security.py",
    "test_v1_adapter.py",
    "tsa.py",
    "verify_demo.py",
    "verify_pec.py",
    "verify_release.py",
    "verify_v1_fixture.py",
    ".github/workflows/ci.yml",
    "design/ATTACK-MISUSE.md",
    "design/CANONICAL-SPEC.md",
    "design/CLI-SPEC.md",
    "design/CLI-TEST-MATRIX.md",
    "design/IMPLEMENTATION-NOTES.md",
    "design/SECURITY-ROUTE-LEDGER.md",
    "design/canonical_diff_runner.py",
    "design/canonical_diff_report.json",
    "design/canonical_diff_vectors.json",
    "design/canonical_fuzz_runner.py",
    "design/canonical_fuzz_report.json",
    "design/canonical_ref.cjs",
    "design/benchmark_core.py",
    "design/performance_report.json",
    "design/verify_approval.cjs",
    "demo/dialogue-disclosure.json",
    "demo/governance.json",
    "demo/MANIFEST.sha256",
    "demo/manuscript.txt",
    "demo/pec.json",
    "demo/release.json",
    "formal/ACSD.lean",
    "formal/AxiomAudit.lean",
    "formal/ACSD/Core.lean",
    "formal/ACSD/PEC.lean",
    "formal/ACSD/Lineage.lean",
    "formal/lake-manifest.json",
    "formal/lakefile.toml",
    "formal/lean-toolchain",
    "paper/acsd-v3.tex",
    "paper/build/acsd-v3.pdf",
)

# Directories copied recursively (with exclusions). The v1 fixture corpus is
# the inherited reference implementation whose evaluation numbers the paper
# quotes; it is shipped as a frozen snapshot so those numbers are reproducible.
DIRS = (
    ("v1-fixture", (".deps", "node_modules", "__pycache__", ".npm-cache", "private-test-keys")),
)


def _copy_tree(source: Path, target: Path, exclude: tuple[str, ...]) -> None:
    for entry in source.iterdir():
        if entry.name in exclude:
            continue
        dest = target / entry.name
        if entry.is_dir():
            dest.mkdir(parents=True, exist_ok=True)
            _copy_tree(entry, dest, exclude)
        else:
            # byte-exact: the v1 fixture snapshot's digests and manifest depend
            # on exact bytes (including binary .whl/.zip/.scitt/.pem files).
            dest.write_bytes(entry.read_bytes())


def _build(staging: Path) -> int:
    if staging.exists():
        shutil.rmtree(staging)
    for relative in FILES:
        source = ROOT / relative
        if not source.is_file():
            raise FileNotFoundError(relative)
        target = staging / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        if source.suffix.lower() == ".pdf":
            shutil.copy2(source, target)
        else:
            target.write_bytes(source.read_bytes().replace(b"\r\n", b"\n"))
    for relative, exclude in DIRS:
        source = ROOT / relative
        if not source.is_dir():
            raise FileNotFoundError(relative)
        target = staging / relative
        target.mkdir(parents=True, exist_ok=True)
        _copy_tree(source, target, exclude)
    entries = []
    for path in sorted(staging.rglob("*")):
        if path.is_file():
            relative = path.relative_to(staging).as_posix()
            entries.append(f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {relative}")
    (staging / "MANIFEST.sha256").write_bytes(("\n".join(entries) + "\n").encode("ascii"))
    return len(entries)


def _same_tree(left: Path, right: Path) -> bool:
    left_files = {p.relative_to(left).as_posix(): p for p in left.rglob("*") if p.is_file()}
    right_files = {p.relative_to(right).as_posix(): p for p in right.rglob("*") if p.is_file()}
    if left_files.keys() != right_files.keys():
        return False
    return all(left_files[name].read_bytes() == right_files[name].read_bytes() for name in left_files)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true", help="rebuild separately and compare with the candidate")
    args = parser.parse_args()
    staging = ROOT / "release-v3.0.0.staging"
    if args.check:
        if not DEST.is_dir():
            raise FileNotFoundError(DEST.name)
        count = _build(staging)
        try:
            if not _same_tree(staging, DEST):
                raise ValueError("RELEASE_TREE_NOT_REPRODUCIBLE")
        finally:
            if staging.exists():
                shutil.rmtree(staging)
        print(f"verified {DEST.name}: {count} payload files plus MANIFEST.sha256")
        return
    if DEST.exists():
        raise FileExistsError(f"refusing to overwrite {DEST}; choose a new release version")
    count = _build(staging)
    staging.replace(DEST)
    print(f"built {DEST.name}: {count} payload files plus MANIFEST.sha256")


if __name__ == "__main__":
    main()
