"""Minimal CBOR + COSE Sign1 (EdDSA/Ed25519) — RFC 9052/9053 subset.

Implements just enough CBOR to build and parse a COSE_Sign1 object carrying an
EdDSA signature (alg -35), plus its Sig_structure, so that a release can be
endorsed and independently verified. The cryptographic primitive is
`cryptography`'s Ed25519; everything here is deterministic byte assembly.
"""
from __future__ import annotations

import struct

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

ALG_EDDSA = -35
CTX_SIGN1 = "Signature1"

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
        n = bs[off]
        off += 1
    elif ai == 25:
        n = struct.unpack(">H", bs[off:off + 2])[0]
        off += 2
    elif ai == 26:
        n = struct.unpack(">I", bs[off:off + 4])[0]
        off += 4
    elif ai == 27:
        n = struct.unpack(">Q", bs[off:off + 8])[0]
        off += 8
    else:
        raise ValueError("CBOR_INDEFINITE_UNSUPPORTED")

    if major == 0:
        return n, off
    if major == 1:
        return -1 - n, off
    if major == 2:
        return bs[off:off + n], off + n
    if major == 3:
        return bs[off:off + n].decode("utf-8"), off + n
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
            pairs[k] = v
        return pairs, off
    raise ValueError(f"CBOR_MAJOR_{major}_UNSUPPORTED")


def decode(bs: bytes):
    value, off = _decode(bs, 0)
    if off != len(bs):
        raise ValueError("CBOR_TRAILING_BYTES")
    return value


# --- COSE Sign1 ------------------------------------------------------------


def _protected_header() -> bytes:
    # { 1: -35 }  (alg = EdDSA)
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
    # accept both tagged (RFC 9052) and bare-array encodings for tolerance
    if cose_bytes and cose_bytes[0] == 0xD2:
        cose_bytes = cose_bytes[1:]
    arr = decode(cose_bytes)
    if not isinstance(arr, list) or len(arr) != 4:
        raise ValueError("COSE_SIGN1_STRUCTURE")
    protected, unprotected, payload, signature = arr
    if not isinstance(protected, bytes) or not isinstance(payload, bytes) or not isinstance(signature, bytes):
        raise ValueError("COSE_SIGN1_STRUCTURE")
    header = decode(protected)
    if not isinstance(header, dict) or header.get(1) != ALG_EDDSA:
        raise ValueError("COSE_ALG_NOT_EDDSA")
    if expected_payload is not None and payload != expected_payload:
        raise ValueError("COSE_PAYLOAD_MISMATCH")
    public_key.verify(signature, sig_structure(protected, payload))
    return payload
