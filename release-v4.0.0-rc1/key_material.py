"""Filesystem and serialization boundary for ACSD key material."""

from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import serialization

from canonical_json import require
from key_identity import key_id_of, validate_key_id


class PrivateKeyPassphraseRequired(ValueError):
    """Raised when an encrypted private key needs an interactive passphrase."""


class PrivateKeyPassphraseInvalid(ValueError):
    """Raised when an encrypted private key cannot be decrypted."""


def load_private_key(path, password=None):
    """Load one PKCS#8 PEM key, preserving the encrypted-key distinction."""
    key_path = Path(path)
    if not key_path.is_file():
        raise ValueError("PRIVATE_KEY_NOT_FILE")
    try:
        data = key_path.read_bytes()
    except OSError as exc:
        raise ValueError("PRIVATE_KEY_UNREADABLE") from exc
    try:
        return serialization.load_pem_private_key(data, password=password)
    except TypeError as exc:
        message = str(exc).lower()
        if password is None and "private key is encrypted" in message:
            raise PrivateKeyPassphraseRequired(
                "PRIVATE_KEY_PASSPHRASE_REQUIRED"
            ) from exc
        raise ValueError("PRIVATE_KEY_INVALID") from exc
    except ValueError as exc:
        if password is not None:
            raise PrivateKeyPassphraseInvalid(
                "PRIVATE_KEY_PASSPHRASE_INVALID"
            ) from exc
        raise ValueError("PRIVATE_KEY_INVALID") from exc


def load_public_key_bytes(data):
    return serialization.load_pem_public_key(data)


def public_pem(public_key):
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def load_certificate_der(path):
    raw = Path(path).read_bytes()
    try:
        certificate = x509.load_pem_x509_certificate(raw)
    except ValueError:
        certificate = x509.load_der_x509_certificate(raw)
    return certificate.public_bytes(serialization.Encoding.DER)


def load_bound_public_key(root, key_id):
    """Load a stored public key and verify its filename-to-key binding."""
    validate_key_id(key_id)
    public_key = load_public_key_bytes(
        (Path(root) / f"public-keys/{key_id}.pub").read_bytes()
    )
    require(key_id_of(public_key) == key_id, "PUBLIC_KEY_ID_MISMATCH")
    return public_key


def check_release_key_paths(release):
    """Require every release key path to be the canonical key-id path."""
    for author in release.get("authors", []):
        key_id = validate_key_id(author.get("key_id"))
        require(
            author.get("public_key_path") == f"public-keys/{key_id}.pub",
            "PUBLIC_KEY_PATH_MISMATCH",
        )
