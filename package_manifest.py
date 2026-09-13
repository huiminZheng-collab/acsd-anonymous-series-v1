"""Strict, portable SHA-256 manifests for ACSD directory artifacts.

The manifest is intentionally simpler than an archive format: one lowercase
SHA-256 digest, two ASCII spaces, and one normalized POSIX relative path per
line.  Only the root ``MANIFEST.sha256`` is excluded.  Symlinks and paths that
resolve outside the artifact root are rejected before any bytes are read.
"""

from __future__ import annotations

import hashlib
import pathlib
import re
from typing import Dict, Iterable, Tuple


MANIFEST_NAME = "MANIFEST.sha256"
_LINE = re.compile(r"([0-9a-f]{64})  ([^\r\n]+)")
_WINDOWS_DRIVE = re.compile(r"[A-Za-z]:")


def validate_relative_name(name: str) -> str:
    """Return *name* if it is one canonical, portable relative path."""
    if not isinstance(name, str) or not name or "\\" in name or "\x00" in name:
        raise ValueError("MANIFEST_PATH_INVALID")
    if name.startswith("/") or name.endswith("/") or "//" in name:
        raise ValueError("MANIFEST_PATH_INVALID")
    parts = name.split("/")
    if any(part in {"", ".", ".."} for part in parts):
        raise ValueError("MANIFEST_PATH_INVALID")
    if _WINDOWS_DRIVE.fullmatch(parts[0]) or any(":" in part for part in parts):
        raise ValueError("MANIFEST_PATH_INVALID")
    if name == MANIFEST_NAME:
        raise ValueError("MANIFEST_PATH_INVALID")
    return name


def payload_path(root: pathlib.Path, name: str) -> pathlib.Path:
    """Resolve a manifest-style path without permitting a link escape."""
    name = validate_relative_name(name)
    root = pathlib.Path(root)
    if root.is_symlink():
        raise ValueError("PACKAGE_SYMLINK_REJECTED")
    candidate = root.joinpath(*name.split("/"))
    cursor = root
    for part in name.split("/"):
        cursor = cursor / part
        if cursor.is_symlink():
            raise ValueError("PACKAGE_SYMLINK_REJECTED")
    try:
        candidate.resolve().relative_to(root.resolve())
    except ValueError as exc:
        raise ValueError("MANIFEST_PATH_INVALID") from exc
    return candidate


def iter_payload_files(root: pathlib.Path) -> Iterable[Tuple[str, pathlib.Path]]:
    """Yield the strict artifact file set, excluding only the root manifest."""
    root = pathlib.Path(root)
    if root.is_symlink() or not root.is_dir():
        raise ValueError("PACKAGE_ROOT_INVALID")
    resolved_root = root.resolve()
    for path in sorted(root.rglob("*")):
        if path.is_symlink():
            raise ValueError("PACKAGE_SYMLINK_REJECTED")
        try:
            path.resolve().relative_to(resolved_root)
        except ValueError as exc:
            raise ValueError("PACKAGE_PATH_ESCAPE") from exc
        if path.is_dir():
            continue
        if not path.is_file():
            raise ValueError("PACKAGE_NONREGULAR_FILE")
        name = path.relative_to(root).as_posix()
        if name == MANIFEST_NAME:
            continue
        validate_relative_name(name)
        yield name, path


def build_manifest_text(root: pathlib.Path) -> str:
    entries = [
        f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {name}"
        for name, path in iter_payload_files(root)
    ]
    return "\n".join(entries) + "\n"


def parse_manifest(text: str) -> Dict[str, str]:
    if not isinstance(text, str) or not text.endswith("\n"):
        raise ValueError("MANIFEST_LINE_INVALID")
    expected: Dict[str, str] = {}
    for line in text.splitlines():
        match = _LINE.fullmatch(line)
        if match is None:
            raise ValueError("MANIFEST_LINE_INVALID")
        wanted, name = match.groups()
        validate_relative_name(name)
        if name in expected:
            raise ValueError("MANIFEST_PATH_INVALID")
        expected[name] = wanted
    return expected


def verify_manifest(root: pathlib.Path) -> int:
    root = pathlib.Path(root)
    manifest_path = root / MANIFEST_NAME
    if manifest_path.is_symlink():
        raise ValueError("PACKAGE_SYMLINK_REJECTED")
    expected = parse_manifest(manifest_path.read_text(encoding="ascii"))
    actual = dict(iter_payload_files(root))
    if set(actual) != set(expected):
        raise ValueError("MANIFEST_SET_MISMATCH")
    for name, wanted in expected.items():
        if hashlib.sha256(actual[name].read_bytes()).hexdigest() != wanted:
            raise ValueError(f"MANIFEST_HASH_MISMATCH:{name}")
    return len(expected)
