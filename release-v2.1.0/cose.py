"""Minimal CBOR + COSE Sign1 (EdDSA/Ed25519) — RFC 9052/9053 subset.

Implements just enough CBOR to build and parse a COSE_Sign1 object carrying an
EdDSA signature (alg -8), plus its Sig_structure, so that a release can be
endorsed and independently verified. The cryptographic primitive is
`cryptography`'s Ed25519; everything here is deterministic byte assembly.
"""
from __future__ import annotations

import struct

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

ALG_EDDSA = -8
CTX_SIGN1 = "Signature1"
MAX_COSE_BYTES = 1024 * 1024

# --- CBOR encoding ---------------------------------------------------------


def _head(major: int, n: int) -> bytes:
    if n < 24:
        return bytes([(major << 5) | n])
    if n < 256:
        return bytes([(major << 5) | 24, n])
    if n < 65536:
        return bytes([(major << 5) | 25]) + struct.pack(">H", n)
    if n < 2**32:
        return bytes([(major << 5) | 26]) + struct.pack(">I", n)
    return bytes([(major << 5) | 27]) + struct.pack(">Q", n)


def cbor_int(n: int) -> bytes:
    if n < 0:
        return _head(1, -1 - n)
    return _head(0, n)


def cbor_bstr(b: bytes) -> bytes:
    return _head(2, len(b)) + b


def cbor_tstr(s: str) -> bytes:
    b = s.encode("utf-8")
    return _head(3, len(b)) + b


def cbor_array(items: list) -> bytes:
    return _head(4, len(items)) + b"".join(items)


def cbor_map(pairs: list) -> bytes:
    # pairs: list of (key_cbor_bytes, value_cbor_bytes)
    return _head(5, len(pairs)) + b"".join(k + v for k, v in pairs)


# --- CBOR decoding ---------------------------------------------------------


def _decode(bs: bytes, off: int):
    if off >= len(bs):
        raise ValueError("CBOR_TRUNCATED")
    major = bs[off] >> 5
    ai = bs[off] & 0x1F
    off += 1
    if ai < 24:
        n = ai
    elif ai == 24:
        if off + 1 > len(bs):
            raise ValueError("CBOR_TRUNCATED")
        n = bs[off]
        off += 1
        if n < 24:
            raise ValueError("CBOR_NONMINIMAL_INTEGER")
    elif ai == 25:
        if off + 2 > len(bs):
            raise ValueError("CBOR_TRUNCATED")
        n = struct.unpack(">H", bs[off:off + 2])[0]
        off += 2
        if n < 256:
            raise ValueError("CBOR_NONMINIMAL_INTEGER")
    elif ai == 26:
        if off + 4 > len(bs):
            raise ValueError("CBOR_TRUNCATED")
        n = struct.unpack(">I", bs[off:off + 4])[0]
        off += 4
        if n < 65536:
            raise ValueError("CBOR_NONMINIMAL_INTEGER")
    elif ai == 27:
        if off + 8 > len(bs):
            raise ValueError("CBOR_TRUNCATED")
        n = struct.unpack(">Q", bs[off:off + 8])[0]
        off += 8
        if n < 2**32:
            raise ValueError("CBOR_NONMINIMAL_INTEGER")
    else:
        raise ValueError("CBOR_INDEFINITE_UNSUPPORTED")

    if major == 0:
        return n, off
    if major == 1:
        return -1 - n, off
    if major == 2:
        if off + n > len(bs):
            raise ValueError("CBOR_TRUNCATED")
        return bs[off:off + n], off + n
    if major == 3:
        if off + n > len(bs):
            raise ValueError("CBOR_TRUNCATED")
        try:
            value = bs[off:off + n].decode("utf-8")
        except UnicodeDecodeError as e:
            raise ValueError("CBOR_INVALID_UTF8") from e
        return value, off + n
    if major == 4:
        items = []
        for _ in range(n):
            item, off = _decode(bs, off)
            items.append(item)
        return items, off
    if major == 5:
        pairs = {}
        for _ in range(n):
            k, off = _decode(bs, off)
            v, off = _decode(bs, off)
            try:
                duplicate = k in pairs
            except TypeError as e:
                raise ValueError("CBOR_MAP_KEY_UNSUPPORTED") from e
            if duplicate:
                raise ValueError("CBOR_DUPLICATE_MAP_KEY")
            pairs[k] = v
        return pairs, off
    raise ValueError(f"CBOR_MAJOR_{major}_UNSUPPORTED")


def decode(bs: bytes):
    if not isinstance(bs, bytes):
        raise ValueError("CBOR_BYTES_REQUIRED")
    value, off = _decode(bs, 0)
    if off != len(bs):
        raise ValueError("CBOR_TRAILING_BYTES")
    return value


# --- COSE Sign1 ------------------------------------------------------------


def _protected_header() -> bytes:
    # { 1: -8 }  (alg = EdDSA; RFC 9053, COSE Algorithms registry)
    return cbor_map([(cbor_int(1), cbor_int(ALG_EDDSA))])


def sig_structure(protected: bytes, payload: bytes) -> bytes:
    return cbor_array([
        cbor_tstr(CTX_SIGN1),
        cbor_bstr(protected),
        cbor_bstr(b""),  # external_aad
        cbor_bstr(payload),
    ])


def cose_sign1(payload: bytes, private_key: Ed25519PrivateKey) -> bytes:
    protected = _protected_header()
    sig = private_key.sign(sig_structure(protected, payload))
    # COSE_Sign1 is CBOR tag 18 wrapping a 4-element array (RFC 9052 §4.2).
    return b"\xd2" + cbor_array([
        cbor_bstr(protected),
        cbor_map([]),  # unprotected header: empty
        cbor_bstr(payload),
        cbor_bstr(sig),
    ])


def cose_verify(cose_bytes: bytes, public_key: Ed25519PublicKey, expected_payload: bytes = None) -> bytes:
    if not isinstance(cose_bytes, bytes):
        raise ValueError("COSE_BYTES_REQUIRED")
    if len(cose_bytes) > MAX_COSE_BYTES:
        raise ValueError("COSE_TOO_LARGE")
    # This profile requires the registered COSE_Sign1 tag 18.  Accepting a
    # bare array would create a second byte representation for the same object.
    if not cose_bytes or cose_bytes[0] != 0xD2:
        raise ValueError("COSE_SIGN1_TAG_REQUIRED")
    cose_bytes = cose_bytes[1:]
    arr = decode(cose_bytes)
    if not isinstance(arr, list) or len(arr) != 4:
        raise ValueError("COSE_SIGN1_STRUCTURE")
    protected, unprotected, payload, signature = arr
    if (not isinstance(protected, bytes) or not isinstance(unprotected, dict)
            or not isinstance(payload, bytes) or not isinstance(signature, bytes)):
        raise ValueError("COSE_SIGN1_STRUCTURE")
    header = decode(protected)
    if not isinstance(header, dict) or header != {1: ALG_EDDSA}:
        raise ValueError("COSE_ALG_NOT_EDDSA")
    if protected != _protected_header():
        raise ValueError("COSE_PROTECTED_HEADER_NONCANONICAL")
    if unprotected:
        raise ValueError("COSE_UNPROTECTED_HEADER_FORBIDDEN")
    if len(signature) != 64:
        raise ValueError("COSE_SIGNATURE_LENGTH")
    if expected_payload is not None and payload != expected_payload:
        raise ValueError("COSE_PAYLOAD_MISMATCH")
    public_key.verify(signature, sig_structure(protected, payload))
    return payload
