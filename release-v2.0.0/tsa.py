"""RFC 3161 timestamp support — TimeStampReq construction and a local test TSA.

This module implements the DER encoding needed to build a TimeStampReq and to
extract the TSTInfo fields (message imprint and genTime) from a response. A
local test TSA is included for protocol testing only; it is NOT independent
time evidence (mirrors the existing v1 local-TSA disclaimer).

Full CMS signature-chain verification is deliberately out of scope for the
MVP: verify_tsr checks the imprint binding and reads genTime, but does not yet
validate the signer chain. That remains an explicit security boundary.
"""
from __future__ import annotations

import struct
from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import pkcs7
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

SHA256_OID = "2.16.840.1.101.3.4.2.1"
OID_SIGNED_DATA = "1.2.840.113549.1.7.2"


# --- minimal DER encode -----------------------------------------------------


def _len(n: int) -> bytes:
    if n < 128:
        return bytes([n])
    bs = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(bs)]) + bs


def _tag(t: int, content: bytes) -> bytes:
    return bytes([t]) + _len(len(content)) + content


def _seq(content: bytes) -> bytes:
    return _tag(0x30, content)


def _int(n: int) -> bytes:
    if n == 0:
        return b"\x02\x01\x00"
    bs = n.to_bytes((n.bit_length() + 7) // 8, "big")
    if bs[0] & 0x80:
        bs = b"\x00" + bs
    return _tag(0x02, bs)


def _octet(b: bytes) -> bytes:
    return _tag(0x04, b)


def _oid_comp(n: int) -> bytes:
    out = bytes([n & 0x7F])
    n >>= 7
    while n:
        out = bytes([0x80 | (n & 0x7F)]) + out
        n >>= 7
    return out


def _oid(oid: str) -> bytes:
    parts = [int(x) for x in oid.split(".")]
    body = bytes([parts[0] * 40 + parts[1]])
    for p in parts[2:]:
        body += _oid_comp(p)
    return _tag(0x06, body)


def build_tsq(imprint: bytes, nonce: bytes) -> bytes:
    """Build a TimeStampReq DER: sha256 imprint + nonce, version v1."""
    alg_id = _seq(_oid(SHA256_OID))
    message_imprint = _seq(alg_id + _octet(imprint))
    return _seq(_int(1) + message_imprint + _int(int.from_bytes(nonce, "big")))


# --- minimal DER decode -----------------------------------------------------


def _read_tlv(bs: bytes, off: int):
    tag = bs[off]
    off += 1
    length = bs[off]
    off += 1
    if length & 0x80:
        n = length & 0x7F
        length = int.from_bytes(bs[off:off + n], "big")
        off += n
    value = bs[off:off + length]
    off += length
    return tag, value, off


def _children(value: bytes):
    """Yield (tag, child_value) for a SEQUENCE/SET body."""
    off = 0
    while off < len(value):
        tag, child, off = _read_tlv(value, off)
        yield tag, child


def _generalized_time_to_dt(value: bytes) -> datetime:
    s = value.decode("ascii")
    # RFC 3161 genTime: YYYYMMDDHHMMSS[.fff]Z
    return datetime.strptime(s[:14], "%Y%m%d%H%M%S").replace(tzinfo=timezone.utc)


def parse_tstinfo(tstinfo_der: bytes):
    """Extract {imprint, genTime} from a TSTInfo DER."""
    _, body, _ = _read_tlv(tstinfo_der, 0)
    kids = list(_children(body))
    # kids: [0]=version, [1]=policy, [2]=messageImprint(SEQ), [3]=serial, [4]=genTime
    imprint = None
    gen_time = None
    if len(kids) > 2 and kids[2][0] == 0x30:
        sub = list(_children(kids[2][1]))  # messageImprint = SEQ { algId, OCTET STRING }
        if len(sub) >= 2 and sub[1][0] == 0x04:
            imprint = sub[1][1]
    for tag, child in kids:
        if tag == 0x18:
            gen_time = _generalized_time_to_dt(child)
    return {"imprint": imprint, "genTime": gen_time}


def _extract_tstinfo_from_cms(cms_der: bytes) -> bytes:
    """Pull the encapContentInfo eContent (TSTInfo DER) out of a SignedData."""
    _, ci_body, _ = _read_tlv(cms_der, 0)
    # ci_body = OID(signedData) + [0] EXPLICIT SignedData
    parts = list(_children(ci_body))
    # parts[0] = OID, parts[1] = A0 wrapped SignedData
    _, sd_wrap, _ = _read_tlv(parts[1][1], 0)
    sd_parts = list(_children(sd_wrap))
    # sd_parts[2] = encapContentInfo SEQ { eContentType OID, [0] EXPLICIT OCTET STRING }
    eci = sd_parts[2][1]
    eci_parts = list(_children(eci))
    econtent = eci_parts[1][1]  # A0 wrapped OCTET STRING
    _, tstinfo_der, _ = _read_tlv(econtent, 0)
    return tstinfo_der


def verify_tsr(tsr: bytes, expected_imprint: bytes):
    """Verify imprint binding and return genTime. Signature-chain verification
    is intentionally not performed here (MVP boundary)."""
    tstinfo = _extract_tstinfo_from_cms(tsr)
    info = parse_tstinfo(tstinfo)
    if info["imprint"] != expected_imprint:
        raise ValueError("TSR_IMPRINT_MISMATCH")
    if info["genTime"] is None:
        raise ValueError("TSR_GENTIME_MISSING")
    return info


# --- local test TSA (protocol test only, not independent evidence) ----------


class LocalTSA:
    """A self-signed RSA TSA for local protocol tests."""

    def __init__(self):
        self._key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "ACSD Test TSA")])
        self.cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(self._key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.now(timezone.utc) - timedelta(minutes=1))
            .not_valid_after(datetime.now(timezone.utc) + timedelta(days=365))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.TIME_STAMPING]), critical=False)
            .sign(self._key, hashes.SHA256())
        )
        self._serial = 1

    def respond(self, tsq: bytes) -> bytes:
        # parse imprint + nonce out of the request
        _, body, _ = _read_tlv(tsq, 0)
        parts = list(_children(body))
        imprint_seq = _seq(parts[1][1])  # full messageImprint SEQUENCE
        tstinfo = _seq(
            _int(1)
            + _oid("1.2.3.4.1")  # test policy OID
            + imprint_seq
            + _int(self._serial)
            + _tag(0x18, datetime.now(timezone.utc).strftime("%Y%m%d%H%M%SZ").encode())
        )
        self._serial += 1
        builder = pkcs7.PKCS7SignatureBuilder().set_data(tstinfo).add_signer(self.cert, self._key, hashes.SHA256())
        return builder.sign(serialization.Encoding.DER, [])
