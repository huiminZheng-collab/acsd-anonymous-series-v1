"""Verify an ACSD release directory against its complete SHA-256 manifest."""

from __future__ import annotations

import sys
from pathlib import Path

from package_manifest import verify_manifest


def verify(root: Path) -> int:
    return verify_manifest(root)


if __name__ == "__main__":
    target = Path(sys.argv[1]) if len(sys.argv) > 1 else Path.cwd()
    print(f"MANIFEST VALID: {verify(target)} files")
