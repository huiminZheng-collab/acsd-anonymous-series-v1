"""One definition of ACSD public-key identifiers and their wire syntax."""

import hashlib
import re

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


KEY_ID_RE = re.compile(r"^[0-9a-f]{64}$")


def key_id_of(public_key: Ed25519PublicKey) -> str:
    der = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return hashlib.sha256(der).hexdigest()


def validate_key_id(value) -> str:
    if not isinstance(value, str) or not KEY_ID_RE.fullmatch(value):
        raise ValueError("KEY_ID_INVALID")
    return value
