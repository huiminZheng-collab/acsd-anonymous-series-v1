"""Verify an ACSD release directory against its complete SHA-256 manifest."""

from __future__ import annotations

import hashlib
import re
import sys
from pathlib import Path, PurePosixPath


def verify(root: Path) -> int:
    root = root.resolve()
    lines = (root / "MANIFEST.sha256").read_text(encoding="ascii").splitlines()
    expected: dict[str, str] = {}
    for line in lines:
        match = re.fullmatch(r"([0-9a-f]{64})  (.+)", line)
        if not match:
            raise ValueError("MANIFEST_LINE_INVALID")
        digest, name = match.groups()
        path = PurePosixPath(name)
        if path.is_absolute() or ".." in path.parts or name in expected:
            raise ValueError("MANIFEST_PATH_INVALID")
        expected[name] = digest
    actual = {
        relative
        for path in root.rglob("*")
        if path.is_file()
        for relative in (path.relative_to(root).as_posix(),)
        if relative != "MANIFEST.sha256"
    }
    if actual != set(expected):
        raise ValueError("MANIFEST_SET_MISMATCH")
    for name, wanted in expected.items():
        if hashlib.sha256((root / name).read_bytes()).hexdigest() != wanted:
            raise ValueError(f"MANIFEST_HASH_MISMATCH:{name}")
    return len(expected)


if __name__ == "__main__":
    target = Path(sys.argv[1]) if len(sys.argv) > 1 else Path.cwd()
    print(f"MANIFEST VALID: {verify(target)} files")
