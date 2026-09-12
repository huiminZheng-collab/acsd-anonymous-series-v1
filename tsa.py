"""RFC 3161 timestamp support — TimeStampReq construction and a local test TSA.

This module implements the DER encoding needed to build a TimeStampReq and to
extract the TSTInfo fields (message imprint and genTime) from a response. A
local test TSA is included for protocol testing only; it is NOT independent
time evidence (mirrors the existing v1 local-TSA disclaimer).

verify_tsr validates the imprint binding, the signer certificate (validity and
trust-anchor fingerprint pinning), the signedAttrs messageDigest over the
TSTInfo, and the CMS signature itself.
"""
from __future__ import annotations

import hashlib
import struct
from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
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


def _read_full_tlv(bs: bytes, off: int):
    """Like _read_tlv but returns the full tag+length+value bytes."""
    start = off
    tag = bs[off]
    off += 1
    length = bs[off]
    off += 1
    if length & 0x80:
        n = length & 0x7F
        length = int.from_bytes(bs[off:off + n], "big")
        off += n
    return tag, bs[start:off + length], off + length


OID_MESSAGE_DIGEST = "1.2.840.113549.1.9.4"


def _oid_bytes_to_str(b: bytes) -> str:
    if not b:
        return ""
    first = b[0]
    parts = [first // 40, first % 40]
    val = 0
    for byte in b[1:]:
        val = (val << 7) | (byte & 0x7F)
        if not (byte & 0x80):
            parts.append(val)
            val = 0
    return ".".join(str(p) for p in parts)


def _parse_signed_attrs(sa_der: bytes) -> dict:
    """Parse signedAttrs [0] IMPLICIT SET OF Attribute -> {oid: value}."""
    _, body, _ = _read_tlv(sa_der, 0)
    attrs = {}
    off = 0
    while off < len(body):
        _, attr_val, off = _read_tlv(body, off)
        ap = list(_children(attr_val))
        oid = _oid_bytes_to_str(ap[0][1])
        vals = list(_children(ap[1][1]))
        attrs[oid] = vals[0][1] if vals else None
    return attrs


def _parse_tsr(tsr: bytes):
    """Parse a TimeStampResp: SEQUENCE { PKIStatusInfo, ContentInfo OPTIONAL }.
    Returns (status, cms_der)."""
    _, body, _ = _read_tlv(tsr, 0)
    parts = []
    off = 0
    while off < len(body):
        tag, full, off = _read_full_tlv(body, off)
        parts.append((tag, full))
    status_info = parts[0][1]
    _, si_body, _ = _read_tlv(status_info, 0)
    si_parts = list(_children(si_body))
    status = int.from_bytes(si_parts[0][1], "big") if si_parts else -1
    cms_der = parts[1][1] if len(parts) > 1 else None
    return status, cms_der


def _parse_cms(cms_der: bytes) -> dict:
    """Extract TSTInfo, signer certificate, signedAttrs and signature from a
    CMS SignedData. Assumes a single signer (cryptography's builder output)."""
    _, ci_body, _ = _read_tlv(cms_der, 0)
    ci = []
    off = 0
    while off < len(ci_body):
        tag, full, off = _read_full_tlv(ci_body, off)
        ci.append((tag, full))
    sd_full = ci[1][1]  # [0] SignedData
    _, sd_inner, _ = _read_tlv(sd_full, 0)  # strip 0xA0 -> SignedData DER (0x30...)
    _, sd_body, _ = _read_tlv(sd_inner, 0)  # strip 0x30 -> SignedData body
    sd = []
    off = 0
    while off < len(sd_body):
        tag, full, off = _read_full_tlv(sd_body, off)
        sd.append((tag, full))
    # sd: [0]=version [1]=digestAlgs [2]=encapContentInfo [3]=certificates [4]=signerInfos
    eci = sd[2][1]
    _, eci_body, _ = _read_tlv(eci, 0)
    eci_c = []
    off = 0
    while off < len(eci_body):
        tag, full, off = _read_full_tlv(eci_body, off)
        eci_c.append((tag, full))
    _, octet_der, _ = _read_tlv(eci_c[1][1], 0)  # strip 0xA0 -> OCTET STRING DER
    _, tstinfo, _ = _read_tlv(octet_der, 0)  # strip 0x04 -> TSTInfo DER

    # certificates [0] (0xA0) is optional; if absent, sd[3] is signerInfos
    cert_der = None
    if sd[3][0] == 0xA0:
        _, certs_body, _ = _read_tlv(sd[3][1], 0)
        _, cert_der, _ = _read_full_tlv(certs_body, 0)  # first certificate, full DER
        si_idx = 4
    else:
        si_idx = 3

    _, si_body, _ = _read_tlv(sd[si_idx][1], 0)
    _, si_full, _ = _read_full_tlv(si_body, 0)
    _, si_inner, _ = _read_tlv(si_full, 0)
    si = []
    off = 0
    while off < len(si_inner):
        tag, full, off = _read_full_tlv(si_inner, off)
        si.append((tag, full))
    # si: [0]=version [1]=sid [2]=digestAlg [3]=signedAttrs [4]=sigAlg [5]=signature
    signed_attrs_der = si[3][1]
    _, signature, _ = _read_tlv(si[5][1], 0)
    _, da_body, _ = _read_tlv(si[2][1], 0)
    digest_alg_oid = _oid_bytes_to_str(list(_children(da_body))[0][1])
    return {
        "tstinfo": tstinfo,
        "cert_der": cert_der,
        "signed_attrs_der": signed_attrs_der,
        "signed_attrs": _parse_signed_attrs(signed_attrs_der),
        "signature": signature,
        "digest_alg_oid": digest_alg_oid,
    }


_HASH_BY_OID = {
    "2.16.840.1.101.3.4.2.1": hashes.SHA256,
    "2.16.840.1.101.3.4.2.2": hashes.SHA384,
    "2.16.840.1.101.3.4.2.3": hashes.SHA512,
    "1.3.14.3.2.26": hashes.SHA1,
}


def _verify_sig(pub, signature, data, hash_obj):
    if isinstance(pub, rsa.RSAPublicKey):
        pub.verify(signature, data, padding.PKCS1v15(), hash_obj)
    elif isinstance(pub, ec.EllipticCurvePublicKey):
        pub.verify(signature, data, ec.ECDSA(hash_obj))
    else:
        raise ValueError("TSR_UNSUPPORTED_KEY")


def verify_tsr(tsr: bytes, expected_imprint: bytes, trusted_cert_der: bytes = None, trusted_fingerprint: str = None, allow_self_signed: bool = False):
    """Verify a TimeStampResp: PKI status, imprint binding, signer certificate
    validity, messageDigest over the TSTInfo, and the CMS signature (RSA or
    ECDSA). The signer certificate is taken from the CMS when embedded,
    otherwise from trusted_cert_der.

    Trust anchoring: a SHA-256 fingerprint pin is the only default trust
    anchor. Without one, a self-signed certificate is accepted only with
    `allow_self_signed=True` (for the local test TSA); otherwise the response
    is rejected as untrusted."""
    status, cms_der = _parse_tsr(tsr)
    if status != 0:
        raise ValueError(f"TSR_STATUS_{status}")
    if cms_der is None:
        raise ValueError("TSR_NO_TOKEN")
    parsed = _parse_cms(cms_der)
    info = parse_tstinfo(parsed["tstinfo"])
    if info["imprint"] != expected_imprint:
        raise ValueError("TSR_IMPRINT_MISMATCH")
    if info["genTime"] is None:
        raise ValueError("TSR_GENTIME_MISSING")

    cert_der = parsed["cert_der"] if parsed["cert_der"] is not None else trusted_cert_der
    if cert_der is None:
        raise ValueError("TSR_NO_SIGNER_CERT")
    cert = x509.load_der_x509_certificate(cert_der)
    now = datetime.now(timezone.utc)
    if now < cert.not_valid_before_utc or now > cert.not_valid_after_utc:
        raise ValueError("TSR_CERT_EXPIRED")
    if trusted_fingerprint is not None:
        if cert.fingerprint(hashes.SHA256()).hex() != trusted_fingerprint:
            raise ValueError("TSR_UNTRUSTED_SIGNER")
    elif cert.subject == cert.issuer and allow_self_signed:
        _verify_sig(cert.public_key(), cert.signature, cert.tbs_certificate_bytes, cert.signature_hash_algorithm)
    else:
        raise ValueError("TSR_UNTRUSTED_SIGNER")

    hash_cls = _HASH_BY_OID.get(parsed["digest_alg_oid"])
    if hash_cls is None:
        raise ValueError("TSR_UNSUPPORTED_DIGEST")
    md = parsed["signed_attrs"].get(OID_MESSAGE_DIGEST)
    h = hashes.Hash(hash_cls())
    h.update(parsed["tstinfo"])
    if md != h.finalize():
        raise ValueError("TSR_MESSAGE_DIGEST_MISMATCH")

    pub = cert.public_key()
    _, sa_body, _ = _read_tlv(parsed["signed_attrs_der"], 0)
    for candidate in (parsed["signed_attrs_der"], _tag(0x31, sa_body)):
        try:
            _verify_sig(pub, parsed["signature"], candidate, hash_cls())
            break
        except (InvalidSignature, ValueError):
            continue
    else:
        raise ValueError("TSR_SIGNATURE_INVALID")
    return info


def _set(content: bytes) -> bytes:
    return _tag(0x31, content)


def _build_cms(tstinfo: bytes, cert: x509.Certificate, key) -> bytes:
    """Build a single-signer CMS SignedData (RSA/SHA-256) around tstinfo.

    cryptography's PKCS7SignatureBuilder rewrites 0x0A (LF) bytes in the
    content to 0x0D 0x0A (CRLF) (OpenSSL text-mode normalization), which
    corrupts a TSTInfo whose imprint happens to contain 0x0A. We build the
    SignedData ourselves so the content bytes stay exact.
    """
    oid_id_data = "1.2.840.113549.1.7.1"
    oid_content_type = "1.2.840.113549.1.9.3"
    oid_message_digest = "1.2.840.113549.1.9.4"
    oid_sha256_with_rsa = "1.2.840.113549.1.1.11"

    digest = hashlib.sha256(tstinfo).digest()
    # signedAttrs [0] IMPLICIT SET OF { contentType, messageDigest }
    content_type_attr = _seq(_oid(oid_content_type) + _set(_oid(oid_id_data)))
    message_digest_attr = _seq(_oid(oid_message_digest) + _set(_octet(digest)))
    signed_attrs = _tag(0xA0, content_type_attr + message_digest_attr)
    signature = key.sign(signed_attrs, padding.PKCS1v15(), hashes.SHA256())

    issuer_der = cert.issuer.public_bytes()
    sid = _seq(issuer_der + _int(cert.serial_number))
    signer_info = _seq(
        _int(1)
        + sid
        + _seq(_oid(SHA256_OID))
        + signed_attrs
        + _seq(_oid(oid_sha256_with_rsa))
        + _octet(signature)
    )

    encap_content_info = _seq(_oid(oid_id_data) + _tag(0xA0, _octet(tstinfo)))
    cert_der = cert.public_bytes(serialization.Encoding.DER)
    signed_data = _seq(
        _int(1)
        + _set(_seq(_oid(SHA256_OID)))
        + encap_content_info
        + _tag(0xA0, cert_der)
        + _set(signer_info)
    )
    return _seq(_oid(OID_SIGNED_DATA) + _tag(0xA0, signed_data))


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
        cms = _build_cms(tstinfo, self.cert, self._key)
        # TimeStampResp = SEQUENCE { PKIStatusInfo (granted), ContentInfo }
        return _seq(_seq(_int(0)) + cms)