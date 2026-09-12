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
    "fixtures.py",
    "generate_demo.py",
    "install-lean.ps1",
    "pec_core.py",
    "README.md",
    "run_all.ps1",
    "SPEC.md",
    "STATUS.md",
    "TEST-PLAN.md",
    "test_cli.py",
    "test_corpus.py",
    "test_demo.py",
    "test_dialogue_merkle.py",
    "test_node_integration.py",
    "test_package_adapter.py",
    "test_pec_core.py",
    "test_sidecar.py",
    "test_v1_adapter.py",
    "verify_demo.py",
    "verify_pec.py",
    "verify_release.py",
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
