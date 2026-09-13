"""Build or reproduce an immutable ACSD evidence package.

The installable wheel is a separate artifact (`python -m build`).  This script
builds the paper/source/evidence snapshot and never overwrites a destination.
"""

from __future__ import annotations

import argparse
import hashlib
import os
import shutil
import tempfile
from pathlib import Path

from package_manifest import verify_manifest, write_manifest


ROOT = Path(__file__).resolve().parent
FILES = (
    "ACCEPTANCE-MATRIX.md",
    "ANONYMITY.md",
    "CITATION.cff",
    "LICENSE",
    "acsd.py",
    "acsd_version.py",
    "approval_set.py",
    "build_release.py",
    "claim_derivation.py",
    "event_disclosure.py",
    "identity_disclosure.py",
    "package_manifest.py",
    "check.py",
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
    "test_approval_set.py",
    "test_architecture.py",
    "test_build_release.py",
    "test_claim_derivation.py",
    "test_cose.py",
    "test_corpus.py",
    "test_demo.py",
    "test_dialogue_merkle.py",
    "test_event_disclosure.py",
    "test_identity_disclosure.py",
    "test_lineage_authorization.py",
    "test_node_integration.py",
    "test_node_approval.py",
    "test_package_adapter.py",
    "test_package_manifest.py",
    "test_pec_core.py",
    "test_sidecar.py",
    "test_tsa_interop.py",
    "test_tsa_security.py",
    "test_v1_adapter.py",
    "test_verification_certificate.py",
    "tsa.py",
    "verify_demo.py",
    "verify_pec.py",
    "verify_release.py",
    "verify_v1_fixture.py",
    "verification_transcript.py",
    ".github/workflows/ci.yml",
    "design/ATTACK-MISUSE.md",
    "design/CANONICAL-SPEC.md",
    "design/CLI-SPEC.md",
    "design/CLI-TEST-MATRIX.md",
    "design/IMPLEMENTATION-NOTES.md",
    "design/SECURITY-ROUTE-LEDGER.md",
    "design/TRUSTED-KERNEL-ROADMAP.md",
    "design/VERIFICATION-CERTIFICATE-V1.md",
    "design/canonical_diff_runner.py",
    "design/canonical_diff_report.json",
    "design/canonical_diff_vectors.json",
    "design/canonical_fuzz_runner.py",
    "design/canonical_fuzz_report.json",
    "design/canonical_ref.cjs",
    "design/benchmark_core.py",
    "design/performance_report.json",
    "design/semantic_confusion_report.json",
    "design/semantic_confusion_runner.py",
    "design/verify_approval.cjs",
    "design/verification_certificate.py",
    "design/verification_certificate.cjs",
    "design/verification_certificate_diff.py",
    "design/lean_transcript_diff.py",
    "design/verification_certificate_demo.json",
    "demo/release.json",
    "formal/ACSD.lean",
    "formal/AxiomAudit.lean",
    "formal/ACSD/Core.lean",
    "formal/ACSD/PEC.lean",
    "formal/ACSD/Lineage.lean",
    "formal/ACSD/ScopedClaims.lean",
    "formal/ACSD/Appraisal.lean",
    "formal/ACSD/Transcript.lean",
    "formal/ACSD/TranscriptJson.lean",
    "formal/TranscriptCli.lean",
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
    ("demo", ("__pycache__",)),
)


def _copy_tree(source: Path, target: Path, exclude: tuple[str, ...]) -> None:
    for entry in source.iterdir():
        if entry.name in exclude:
            continue
        if entry.is_symlink():
            raise ValueError(f"SOURCE_SYMLINK_REJECTED:{entry}")
        dest = target / entry.name
        if entry.is_dir():
            dest.mkdir(parents=True, exist_ok=True)
            _copy_tree(entry, dest, exclude)
        elif entry.is_file():
            # byte-exact: the v1 fixture snapshot's digests and manifest depend
            # on exact bytes (including binary .whl/.zip/.scitt/.pem files).
            dest.write_bytes(entry.read_bytes())
        else:
            raise ValueError(f"SOURCE_NONREGULAR_FILE:{entry}")


def _build(staging: Path) -> int:
    if staging.exists():
        shutil.rmtree(staging)
    for relative in FILES:
        source = ROOT / relative
        if source.is_symlink():
            raise ValueError(f"SOURCE_SYMLINK_REJECTED:{source}")
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
    write_manifest(staging)
    return verify_manifest(staging)


def _tree_signature(root: Path):
    signature = {}
    for directory, names, files in os.walk(root, topdown=True, followlinks=False):
        base = Path(directory)
        for name in names + files:
            path = base / name
            relative = path.relative_to(root).as_posix()
            if path.is_symlink():
                signature[relative] = ("symlink", os.readlink(path))
            elif path.is_dir():
                signature[relative] = ("directory",)
            elif path.is_file():
                signature[relative] = ("file", hashlib.sha256(path.read_bytes()).hexdigest())
            else:
                signature[relative] = ("other",)
    return signature


def _same_tree(left: Path, right: Path) -> bool:
    return _tree_signature(left) == _tree_signature(right)


def _reject_recursive_output(path: Path) -> None:
    resolved = path.resolve()
    for relative, _ in DIRS:
        recursive_source = (ROOT / relative).resolve()
        try:
            resolved.relative_to(recursive_source)
        except ValueError:
            continue
        raise ValueError(f"OUTPUT_INSIDE_RECURSIVE_SOURCE:{relative}")


def main() -> None:
    parser = argparse.ArgumentParser()
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--out", help="new evidence-package directory")
    mode.add_argument("--check", metavar="DIRECTORY", help="rebuild in a temporary directory and compare byte-for-byte")
    args = parser.parse_args()
    if args.check:
        destination = Path(args.check)
        if not destination.is_absolute():
            destination = ROOT / destination
        if not destination.is_dir():
            raise FileNotFoundError(destination)
        verify_manifest(destination)
        with tempfile.TemporaryDirectory() as temporary:
            staging = Path(temporary) / "evidence-package"
            count = _build(staging)
            if not _same_tree(staging, destination):
                raise ValueError("RELEASE_TREE_NOT_REPRODUCIBLE")
        print(f"verified {destination.name}: {count} payload files plus MANIFEST.sha256")
        return
    destination = Path(args.out)
    if not destination.is_absolute():
        destination = ROOT / destination
    staging = destination.with_name(destination.name + ".staging")
    _reject_recursive_output(destination)
    _reject_recursive_output(staging)
    if destination.exists():
        raise FileExistsError(f"refusing to overwrite {destination}")
    if staging.exists():
        raise FileExistsError(f"refusing to overwrite stale staging directory {staging}")
    count = _build(staging)
    staging.replace(destination)
    print(f"built {destination.name}: {count} payload files plus MANIFEST.sha256")


if __name__ == "__main__":
    main()
