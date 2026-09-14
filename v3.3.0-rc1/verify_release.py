"""Verify an ACSD release directory against its complete SHA-256 manifest."""

from __future__ import annotations

import sys
from pathlib import Path

# A verifier executed from inside the artifact must not create __pycache__
# before checking the artifact's closed file set.
sys.dont_write_bytecode = True

from package_manifest import verify_manifest


def verify(root: Path) -> int:
    return verify_manifest(root)


if __name__ == "__main__":
    target = Path(sys.argv[1]) if len(sys.argv) > 1 else Path.cwd()
    try:
        print(f"MANIFEST VALID: {verify(target)} files")
    except FileNotFoundError:
        print("MANIFEST INVALID: MANIFEST_MISSING", file=sys.stderr)
        raise SystemExit(1)
    except UnicodeError:
        print("MANIFEST INVALID: MANIFEST_ENCODING", file=sys.stderr)
        raise SystemExit(1)
    except ValueError as exc:
        print(f"MANIFEST INVALID: {exc}", file=sys.stderr)
        raise SystemExit(1)
    except OSError:
        print("MANIFEST INVALID: MANIFEST_IO_ERROR", file=sys.stderr)
        raise SystemExit(1)
