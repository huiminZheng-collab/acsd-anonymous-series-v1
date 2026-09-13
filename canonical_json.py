"""Restricted canonical JSON and digest helpers shared by ACSD adapters."""

import hashlib
import json
import re


HEX = re.compile(r"^[0-9a-f]{64}$")
MAX_SAFE_INTEGER = 9_007_199_254_740_991


def _check_json(value, depth=0):
    if depth > 200:
        raise ValueError("JSON_TOO_DEEP")
    if isinstance(value, bool) or value is None:
        return
    if isinstance(value, str):
        if any(0xD800 <= ord(character) <= 0xDFFF for character in value):
            raise ValueError("LONE_SURROGATE")
        return
    if isinstance(value, int):
        if abs(value) > MAX_SAFE_INTEGER:
            raise ValueError("UNSAFE_INTEGER")
        return
    if isinstance(value, float):
        raise ValueError("FLOAT_FORBIDDEN")
    if isinstance(value, list):
        for item in value:
            _check_json(item, depth + 1)
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise ValueError("JSON_KEY_TYPE_FORBIDDEN")
            if any(ord(character) > 127 for character in key):
                raise ValueError("NONASCII_KEY")
            _check_json(item, depth + 1)
        return
    raise ValueError("JSON_TYPE_FORBIDDEN")


def canonical(obj):
    """Encode the restricted JSON value as one deterministic UTF-8 image."""
    _check_json(obj)
    return json.dumps(
        obj,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def digest(obj):
    return hashlib.sha256(canonical(obj)).hexdigest()


def require(condition, code):
    if not condition:
        raise ValueError(code)
