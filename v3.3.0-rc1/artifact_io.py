"""Canonical file and path boundary for mutable ACSD workspaces."""

import json
from pathlib import Path

from canonical_json import canonical


def read_canonical(path):
    """Read one newline-tolerant file and require exact canonical JSON bytes."""
    path = Path(path)
    raw = path.read_bytes()
    if raw.endswith(b"\n"):
        raw = raw[:-1]
    try:
        value = json.loads(raw)
    except ValueError as exc:
        raise ValueError(f"NONCANONICAL:{path.name}") from exc
    if canonical(value) != raw:
        raise ValueError(f"NONCANONICAL:{path.name}")
    return value


def write_canonical(path, value):
    """Write one canonical JSON value with the repository newline convention."""
    Path(path).write_bytes(canonical(value) + b"\n")


def path_is_within(path, directory):
    """Return whether the resolved path is inside the resolved directory."""
    try:
        Path(path).resolve().relative_to(Path(directory).resolve())
        return True
    except ValueError:
        return False
