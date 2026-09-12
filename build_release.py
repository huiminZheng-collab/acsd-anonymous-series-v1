"""Build the deterministic, cache-free ACSD v2 release directory."""

from __future__ import annotations

import hashlib
import shutil
from pathlib import Path


ROOT = Path(__file__).resolve().parent
DEST = ROOT / "release-v2.0.0"
FILES = (
    "ACCEPTANCE-MATRIX.md",
    "acsd.py",
    "cose.py",
    "fixtures.py",
    "generate_demo.py",
    "install-lean.ps1",
    "pec_core.py",
    "pyproject.toml",
    "README.md",
    "run_all.ps1",
    "SPEC.md",
    "STATUS.md",
    "TEST-PLAN.md",
    "test_cli.py",
    "test_cli_signing.py",
    "test_corpus.py",
    "test_demo.py",
    "test_dialogue_merkle.py",
    "test_node_integration.py",
    "test_package_adapter.py",
    "test_pec_core.py",
    "test_sidecar.py",
    "test_tsa_interop.py",
    "test_v1_adapter.py",
    "tsa.py",
    "verify_demo.py",
    "verify_pec.py",
    "verify_release.py",
    "verify_v1_fixture.py",
    "demo/dialogue-disclosure.json",
    "demo/governance.json",
    "demo/MANIFEST.sha256",
    "demo/manuscript.txt",
    "demo/pec.json",
    "demo/release.json",
    "formal/ACSD.lean",
    "formal/ACSD/Core.lean",
    "formal/ACSD/PEC.lean",
    "formal/lake-manifest.json",
    "formal/lakefile.toml",
    "formal/lean-toolchain",
    "paper/acsd-v2.tex",
    "paper/build/acsd-v2.pdf",
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


def main() -> None:
    staging = ROOT / "release-v2.0.0.staging"
    for target in (staging, DEST):
        if target.exists():
            shutil.rmtree(target)
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
    staging.replace(DEST)
    print(f"built {DEST.name}: {len(entries)} payload files plus MANIFEST.sha256")


if __name__ == "__main__":
    main()
