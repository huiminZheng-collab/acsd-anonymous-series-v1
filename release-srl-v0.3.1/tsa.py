"""RFC 3161 timestamp support — TimeStampReq construction and a local test TSA.

This module implements the DER encoding needed to build a TimeStampReq and to
extract the TSTInfo fields (message imprint and genTime) from a response. A
local test TSA is included for protocol testing only; it is NOT independent
time evidence (mirrors the existing v1 local-TSA disclaimer).

verify_tsr validates the imprint/nonce binding, exact signer-certificate pin,
timestamping EKU, CMS/TSTInfo content types, ESS certificate identifier,
signedAttrs messageDigest, signer identifier, and CMS signature.  It does not
perform general PKIX path construction or revocation checking.
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
OID_TSTINFO = "1.2.840.113549.1.9.16.1.4"
OID_CONTENT_TYPE = "1.2.840.113549.1.9.3"
OID_MESSAGE_DIGEST = "1.2.840.113549.1.9.4"
OID_SIGNING_CERTIFICATE = "1.2.840.113549.1.9.16.2.12"
OID_SIGNING_CERTIFICATE_V2 = "1.2.840.113549.1.9.16.2.47"


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


def build_tsq(imprint: bytes, nonce: bytes, cert_req: bool = True) -> bytes:
    """Build a TimeStampReq DER: sha256 imprint + nonce, version v1."""
    if len(imprint) != 32:
        raise ValueError("TSQ_SHA256_IMPRINT_LENGTH")
    if not nonce:
        raise ValueError("TSQ_NONCE_REQUIRED")
    alg_id = _seq(_oid(SHA256_OID))
    message_imprint = _seq(alg_id + _octet(imprint))
    cert_req_der = b"\x01\x01\xff" if cert_req else b""
    return _seq(_int(1) + message_imprint + _int(int.from_bytes(nonce, "big")) + cert_req_der)


# --- minimal DER decode -----------------------------------------------------


def _read_tlv(bs: bytes, off: int):
    if off < 0 or off + 2 > len(bs):
        raise ValueError("DER_TRUNCATED")
    tag = bs[off]
    off += 1
    length = bs[off]
    off += 1
    if length & 0x80:
        n = length & 0x7F
        if n == 0:
            raise ValueError("DER_INDEFINITE_LENGTH")
        if n > 4 or off + n > len(bs):
            raise ValueError("DER_TRUNCATED")
        if n > 1 and bs[off] == 0:
            raise ValueError("DER_NONMINIMAL_LENGTH")
        length = int.from_bytes(bs[off:off + n], "big")
        off += n
        if length < 128:
            raise ValueError("DER_NONMINIMAL_LENGTH")
    if off + length > len(bs):
        raise ValueError("DER_TRUNCATED")
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
    if not s.endswith("Z"):
        raise ValueError("TSR_GENTIME_NOT_UTC")
    fmt = "%Y%m%d%H%M%S.%fZ" if "." in s else "%Y%m%d%H%M%SZ"
    return datetime.strptime(s, fmt).replace(tzinfo=timezone.utc)


def _positive_int(value: bytes, code: str) -> int:
    if not value or value[0] & 0x80:
        raise ValueError(code)
    if len(value) > 1 and value[0] == 0 and not (value[1] & 0x80):
        raise ValueError(code)
    return int.from_bytes(value, "big")


def parse_tsq(tsq_der: bytes):
    """Parse the strict subset emitted by :func:`build_tsq`."""
    tag, body, off = _read_tlv(tsq_der, 0)
    if tag != 0x30 or off != len(tsq_der):
        raise ValueError("TSQ_STRUCTURE")
    kids = list(_children(body))
    if len(kids) not in (3, 4) or kids[0][0] != 0x02 or kids[1][0] != 0x30 or kids[2][0] != 0x02:
        raise ValueError("TSQ_STRUCTURE")
    if _positive_int(kids[0][1], "TSQ_VERSION") != 1:
        raise ValueError("TSQ_VERSION")
    imprint_parts = list(_children(kids[1][1]))
    if len(imprint_parts) != 2 or imprint_parts[0][0] != 0x30 or imprint_parts[1][0] != 0x04:
        raise ValueError("TSQ_IMPRINT_STRUCTURE")
    alg_parts = list(_children(imprint_parts[0][1]))
    if not alg_parts or alg_parts[0][0] != 0x06:
        raise ValueError("TSQ_IMPRINT_STRUCTURE")
    algorithm = _oid_bytes_to_str(alg_parts[0][1])
    if algorithm != SHA256_OID or len(imprint_parts[1][1]) != 32:
        raise ValueError("TSQ_IMPRINT_ALGORITHM")
    if len(kids) == 4 and (kids[3][0] != 0x01 or kids[3][1] != b"\xff"):
        raise ValueError("TSQ_CERTREQ")
    return {
        "imprint_algorithm": algorithm,
        "imprint": imprint_parts[1][1],
        "nonce": _positive_int(kids[2][1], "TSQ_NONCE"),
        "cert_req": len(kids) == 4,
    }


def parse_tstinfo(tstinfo_der: bytes):
    """Extract the security-relevant fields from a DER TSTInfo."""
    tag, body, off = _read_tlv(tstinfo_der, 0)
    if tag != 0x30 or off != len(tstinfo_der):
        raise ValueError("TSR_TSTINFO_STRUCTURE")
    kids = list(_children(body))
    # kids: [0]=version, [1]=policy, [2]=messageImprint(SEQ), [3]=serial, [4]=genTime
    imprint = None
    imprint_algorithm = None
    policy_oid = None
    serial = None
    gen_time = None
    nonce = None
    if len(kids) > 2 and kids[2][0] == 0x30:
        sub = list(_children(kids[2][1]))  # messageImprint = SEQ { algId, OCTET STRING }
        if len(sub) >= 2 and sub[1][0] == 0x04:
            imprint = sub[1][1]
            alg = list(_children(sub[0][1])) if sub[0][0] == 0x30 else []
            if alg and alg[0][0] == 0x06:
                imprint_algorithm = _oid_bytes_to_str(alg[0][1])
    if len(kids) > 1 and kids[1][0] == 0x06:
        policy_oid = _oid_bytes_to_str(kids[1][1])
    if len(kids) > 3 and kids[3][0] == 0x02:
        serial = _positive_int(kids[3][1], "TSR_SERIAL_INVALID")
    for index, (tag, child) in enumerate(kids):
        if tag == 0x18:
            gen_time = _generalized_time_to_dt(child)
        elif index > 4 and tag == 0x02:
            nonce = _positive_int(child, "TSR_NONCE_INVALID")
    return {
        "version": _positive_int(kids[0][1], "TSR_VERSION") if kids and kids[0][0] == 0x02 else None,
        "imprint_algorithm": imprint_algorithm,
        "policy_oid": policy_oid,
        "serial": serial,
        "imprint": imprint,
        "genTime": gen_time,
        "nonce": nonce,
    }


def _read_full_tlv(bs: bytes, off: int):
    """Like _read_tlv but returns the full tag+length+value bytes."""
    start = off
    tag, _, end = _read_tlv(bs, off)
    return tag, bs[start:end], end


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
    """Parse signedAttrs [0] IMPLICIT SET OF Attribute.

    Values are returned as ``(ASN.1 tag, content bytes)`` so callers can
    distinguish an OCTET STRING digest from an OBJECT IDENTIFIER content type.
    """
    tag, body, off = _read_tlv(sa_der, 0)
    if tag != 0xA0 or off != len(sa_der):
        raise ValueError("TSR_SIGNED_ATTRS_STRUCTURE")
    attrs = {}
    off = 0
    while off < len(body):
        attr_tag, attr_val, off = _read_tlv(body, off)
        if attr_tag != 0x30:
            raise ValueError("TSR_SIGNED_ATTRS_STRUCTURE")
        ap = list(_children(attr_val))
        if len(ap) != 2 or ap[0][0] != 0x06 or ap[1][0] != 0x31:
            raise ValueError("TSR_SIGNED_ATTRS_STRUCTURE")
        oid = _oid_bytes_to_str(ap[0][1])
        vals = list(_children(ap[1][1]))
        if oid in attrs:
            raise ValueError("TSR_DUPLICATE_SIGNED_ATTRIBUTE")
        if len(vals) != 1:
            raise ValueError("TSR_SIGNED_ATTRIBUTE_CARDINALITY")
        attrs[oid] = vals[0]
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


def extract_signer_cert_der(tsr: bytes):
    """Return the embedded signer certificate, or ``None`` when omitted."""
    status, cms_der = _parse_tsr(tsr)
    if status not in (0, 1) or cms_der is None:
        return None
    return _parse_cms(cms_der)["cert_der"]


def _parse_cms(cms_der: bytes) -> dict:
    """Extract TSTInfo, signer certificate, signedAttrs and signature from a
    CMS SignedData. Assumes a single signer (cryptography's builder output)."""
    _, ci_body, _ = _read_tlv(cms_der, 0)
    ci = []
    off = 0
    while off < len(ci_body):
        tag, full, off = _read_full_tlv(ci_body, off)
        ci.append((tag, full))
    if len(ci) != 2 or ci[0][0] != 0x06 or ci[1][0] != 0xA0:
        raise ValueError("TSR_CMS_STRUCTURE")
    _, ci_oid, _ = _read_tlv(ci[0][1], 0)
    if _oid_bytes_to_str(ci_oid) != OID_SIGNED_DATA:
        raise ValueError("TSR_CMS_CONTENT_TYPE")
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
    if len(eci_c) != 2 or eci_c[0][0] != 0x06 or eci_c[1][0] != 0xA0:
        raise ValueError("TSR_ECONTENT_STRUCTURE")
    _, econtent_oid, _ = _read_tlv(eci_c[0][1], 0)
    econtent_type_oid = _oid_bytes_to_str(econtent_oid)
    _, octet_der, _ = _read_tlv(eci_c[1][1], 0)  # strip 0xA0 -> OCTET STRING DER
    _, tstinfo, _ = _read_tlv(octet_der, 0)  # strip 0x04 -> TSTInfo DER

    # certificates [0] (0xA0) is optional; if absent, sd[3] is signerInfos
    cert_ders = []
    if sd[3][0] == 0xA0:
        _, certs_body, _ = _read_tlv(sd[3][1], 0)
        cert_off = 0
        while cert_off < len(certs_body):
            cert_tag, cert_der, cert_off = _read_full_tlv(certs_body, cert_off)
            if cert_tag == 0x30:  # ignore unsupported non-certificate choices
                cert_ders.append(cert_der)
        si_idx = 4
    else:
        si_idx = 3

    si_set_tag, si_body, si_set_off = _read_tlv(sd[si_idx][1], 0)
    if si_set_tag != 0x31 or si_set_off != len(sd[si_idx][1]):
        raise ValueError("TSR_SIGNERINFO_STRUCTURE")
    si_tag, si_full, si_end = _read_full_tlv(si_body, 0)
    if si_tag != 0x30 or si_end != len(si_body):
        raise ValueError("TSR_MULTIPLE_SIGNERS")
    _, si_inner, _ = _read_tlv(si_full, 0)
    si = []
    off = 0
    while off < len(si_inner):
        tag, full, off = _read_full_tlv(si_inner, off)
        si.append((tag, full))
    # si: [0]=version [1]=sid [2]=digestAlg [3]=signedAttrs [4]=sigAlg [5]=signature
    if len(si) != 6 or si[1][0] != 0x30 or si[3][0] != 0xA0 or si[5][0] != 0x04:
        raise ValueError("TSR_SIGNERINFO_STRUCTURE")
    signed_attrs_der = si[3][1]
    _, signature, _ = _read_tlv(si[5][1], 0)
    _, da_body, _ = _read_tlv(si[2][1], 0)
    digest_alg_oid = _oid_bytes_to_str(list(_children(da_body))[0][1])
    _, sig_alg_body, _ = _read_tlv(si[4][1], 0)
    signature_alg_oid = _oid_bytes_to_str(list(_children(sig_alg_body))[0][1])

    _, sid_body, _ = _read_tlv(si[1][1], 0)
    sid_issuer_tag, sid_issuer_der, sid_off = _read_full_tlv(sid_body, 0)
    sid_serial_tag, sid_serial_value, sid_off = _read_tlv(sid_body, sid_off)
    if sid_issuer_tag != 0x30 or sid_serial_tag != 0x02 or sid_off != len(sid_body):
        raise ValueError("TSR_SIGNER_ID_STRUCTURE")
    signer_serial = _positive_int(sid_serial_value, "TSR_SIGNER_ID_STRUCTURE")
    cert_der = None
    for candidate in cert_ders:
        candidate_cert = x509.load_der_x509_certificate(candidate)
        if candidate_cert.issuer.public_bytes() == sid_issuer_der and candidate_cert.serial_number == signer_serial:
            cert_der = candidate
            break
    if cert_ders and cert_der is None:
        raise ValueError("TSR_SIGNER_ID_MISMATCH")
    return {
        "tstinfo": tstinfo,
        "cert_der": cert_der,
        "signed_attrs_der": signed_attrs_der,
        "signed_attrs": _parse_signed_attrs(signed_attrs_der),
        "signature": signature,
        "digest_alg_oid": digest_alg_oid,
        "signature_alg_oid": signature_alg_oid,
        "econtent_type_oid": econtent_type_oid,
        "signer_issuer_der": sid_issuer_der,
        "signer_serial": signer_serial,
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


def _check_signature_algorithm(pub, digest_oid: str, signature_oid: str):
    rsa_oids = {
        SHA256_OID: {"1.2.840.113549.1.1.1", "1.2.840.113549.1.1.11"},
        "2.16.840.1.101.3.4.2.2": {"1.2.840.113549.1.1.1", "1.2.840.113549.1.1.12"},
        "2.16.840.1.101.3.4.2.3": {"1.2.840.113549.1.1.1", "1.2.840.113549.1.1.13"},
        "1.3.14.3.2.26": {"1.2.840.113549.1.1.1", "1.2.840.113549.1.1.5"},
    }
    ec_oids = {
        SHA256_OID: "1.2.840.10045.4.3.2",
        "2.16.840.1.101.3.4.2.2": "1.2.840.10045.4.3.3",
        "2.16.840.1.101.3.4.2.3": "1.2.840.10045.4.3.4",
        "1.3.14.3.2.26": "1.2.840.10045.4.1",
    }
    if isinstance(pub, rsa.RSAPublicKey):
        valid = signature_oid in rsa_oids.get(digest_oid, set())
    elif isinstance(pub, ec.EllipticCurvePublicKey):
        valid = signature_oid == ec_oids.get(digest_oid)
    else:
        valid = False
    if not valid:
        raise ValueError("TSR_SIGNATURE_ALGORITHM_MISMATCH")


def _verify_signing_certificate_attribute(attrs: dict, cert_der: bytes):
    """Verify ESSCertID (RFC 2634) or ESSCertIDv2 (RFC 5035) certificate hash."""
    attr = attrs.get(OID_SIGNING_CERTIFICATE)
    hash_cls = hashes.SHA1
    if attr is None:
        attr = attrs.get(OID_SIGNING_CERTIFICATE_V2)
        hash_cls = hashes.SHA256
    if attr is None or attr[0] != 0x30:
        raise ValueError("TSR_SIGNING_CERTIFICATE_ATTRIBUTE_MISSING")
    signing_certificate = list(_children(attr[1]))
    if not signing_certificate or signing_certificate[0][0] != 0x30:
        raise ValueError("TSR_SIGNING_CERTIFICATE_ATTRIBUTE_INVALID")
    certs = list(_children(signing_certificate[0][1]))
    if not certs or certs[0][0] != 0x30:
        raise ValueError("TSR_SIGNING_CERTIFICATE_ATTRIBUTE_INVALID")
    ess = list(_children(certs[0][1]))
    if not ess:
        raise ValueError("TSR_SIGNING_CERTIFICATE_ATTRIBUTE_INVALID")
    index = 0
    if attr is not None and attrs.get(OID_SIGNING_CERTIFICATE_V2) is attr and ess[0][0] == 0x30:
        alg = list(_children(ess[0][1]))
        if not alg or alg[0][0] != 0x06:
            raise ValueError("TSR_SIGNING_CERTIFICATE_ATTRIBUTE_INVALID")
        hash_cls = _HASH_BY_OID.get(_oid_bytes_to_str(alg[0][1]))
        if hash_cls is None:
            raise ValueError("TSR_UNSUPPORTED_DIGEST")
        index = 1
    if index >= len(ess) or ess[index][0] != 0x04:
        raise ValueError("TSR_SIGNING_CERTIFICATE_ATTRIBUTE_INVALID")
    h = hashes.Hash(hash_cls())
    h.update(cert_der)
    if ess[index][1] != h.finalize():
        raise ValueError("TSR_SIGNING_CERTIFICATE_MISMATCH")


def verify_tsr(tsr: bytes, expected_imprint: bytes, trusted_cert_der: bytes = None,
               trusted_fingerprint: str = None, expected_nonce: int = None,
               allow_self_signed: bool = False):
    """Verify the ACSD RFC 3161 profile with an explicit signer pin.

    ``trusted_cert_der`` is an out-of-band exact signer-certificate pin, not a
    general PKIX root.  Alternatively, ``trusted_fingerprint`` can pin an
    embedded signer certificate.  General path construction, revocation, and
    policy qualification are deliberately outside this small verifier.
    """
    status, cms_der = _parse_tsr(tsr)
    if status not in (0, 1):
        raise ValueError(f"TSR_STATUS_{status}")
    if cms_der is None:
        raise ValueError("TSR_NO_TOKEN")
    parsed = _parse_cms(cms_der)
    info = parse_tstinfo(parsed["tstinfo"])
    if info["version"] != 1:
        raise ValueError("TSR_VERSION")
    if info["imprint_algorithm"] != SHA256_OID or len(expected_imprint) != 32:
        raise ValueError("TSR_IMPRINT_ALGORITHM")
    if info["imprint"] != expected_imprint:
        raise ValueError("TSR_IMPRINT_MISMATCH")
    if expected_nonce is not None and info["nonce"] != expected_nonce:
        raise ValueError("TSR_NONCE_MISMATCH")
    if info["genTime"] is None:
        raise ValueError("TSR_GENTIME_MISSING")
    if parsed["econtent_type_oid"] != OID_TSTINFO:
        raise ValueError("TSR_ECONTENT_TYPE")

    embedded_cert_der = parsed["cert_der"]
    if trusted_cert_der is not None:
        cert_der = trusted_cert_der
        if embedded_cert_der is not None:
            embedded_fp = x509.load_der_x509_certificate(embedded_cert_der).fingerprint(hashes.SHA256())
            trusted_fp = x509.load_der_x509_certificate(trusted_cert_der).fingerprint(hashes.SHA256())
            if embedded_fp != trusted_fp:
                raise ValueError("TSR_EMBEDDED_CERT_MISMATCH")
    else:
        cert_der = embedded_cert_der
    if cert_der is None:
        raise ValueError("TSR_NO_SIGNER_CERT")
    cert = x509.load_der_x509_certificate(cert_der)
    gen_time = info["genTime"]
    if gen_time < cert.not_valid_before_utc or gen_time > cert.not_valid_after_utc:
        raise ValueError("TSR_CERT_INVALID_AT_GENTIME")

    cert_fp = cert.fingerprint(hashes.SHA256()).hex()
    externally_pinned = trusted_cert_der is not None or trusted_fingerprint is not None
    if trusted_fingerprint is not None:
        normalized_pin = trusted_fingerprint.lower().replace(":", "")
        if cert_fp != normalized_pin:
            raise ValueError("TSR_UNTRUSTED_SIGNER")
    elif trusted_cert_der is not None:
        pass  # exact DER certificate supplied out of band
    elif cert.subject == cert.issuer and allow_self_signed:
        _verify_sig(cert.public_key(), cert.signature, cert.tbs_certificate_bytes, cert.signature_hash_algorithm)
    else:
        raise ValueError("TSR_UNTRUSTED_SIGNER")

    try:
        eku_ext = cert.extensions.get_extension_for_oid(x509.ExtensionOID.EXTENDED_KEY_USAGE)
    except x509.ExtensionNotFound as e:
        raise ValueError("TSR_TIMESTAMPING_EKU_MISSING") from e
    if not eku_ext.critical or list(eku_ext.value) != [ExtendedKeyUsageOID.TIME_STAMPING]:
        raise ValueError("TSR_TIMESTAMPING_EKU_INVALID")

    if cert.issuer.public_bytes() != parsed["signer_issuer_der"] or cert.serial_number != parsed["signer_serial"]:
        raise ValueError("TSR_SIGNER_ID_MISMATCH")

    hash_cls = _HASH_BY_OID.get(parsed["digest_alg_oid"])
    if hash_cls is None:
        raise ValueError("TSR_UNSUPPORTED_DIGEST")
    md_attr = parsed["signed_attrs"].get(OID_MESSAGE_DIGEST)
    if md_attr is None or md_attr[0] != 0x04:
        raise ValueError("TSR_MESSAGE_DIGEST_MISSING")
    md = md_attr[1]
    ct_attr = parsed["signed_attrs"].get(OID_CONTENT_TYPE)
    if ct_attr is None or ct_attr[0] != 0x06 or _oid_bytes_to_str(ct_attr[1]) != OID_TSTINFO:
        raise ValueError("TSR_SIGNED_CONTENT_TYPE")
    h = hashes.Hash(hash_cls())
    h.update(parsed["tstinfo"])
    if md != h.finalize():
        raise ValueError("TSR_MESSAGE_DIGEST_MISMATCH")

    pub = cert.public_key()
    _check_signature_algorithm(pub, parsed["digest_alg_oid"], parsed["signature_alg_oid"])
    _verify_signing_certificate_attribute(parsed["signed_attrs"], cert_der)
    _, sa_body, _ = _read_tlv(parsed["signed_attrs_der"], 0)
    try:
        # CMS signs the DER SET OF form, not the context-specific [0] tag that
        # carries signedAttrs inside SignerInfo (RFC 5652 section 5.4).
        _verify_sig(pub, parsed["signature"], _tag(0x31, sa_body), hash_cls())
    except (InvalidSignature, ValueError) as e:
        raise ValueError("TSR_SIGNATURE_INVALID")
    info["signer_fingerprint"] = cert_fp
    info["trust_model"] = "exact-signer-pin" if externally_pinned else "local-self-signed-test"
    info["status"] = status
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
    oid_sha256_with_rsa = "1.2.840.113549.1.1.11"

    digest = hashlib.sha256(tstinfo).digest()
    cert_der = cert.public_bytes(serialization.Encoding.DER)
    # signedAttrs [0] IMPLICIT SET OF { contentType, messageDigest }
    content_type_attr = _seq(_oid(OID_CONTENT_TYPE) + _set(_oid(OID_TSTINFO)))
    message_digest_attr = _seq(_oid(OID_MESSAGE_DIGEST) + _set(_octet(digest)))
    # ESSCertIDv2 defaults to SHA-256 when hashAlgorithm is omitted.
    ess_cert_id_v2 = _seq(_octet(hashlib.sha256(cert_der).digest()))
    signing_certificate_v2 = _seq(_seq(ess_cert_id_v2))
    signing_certificate_attr = _seq(
        _oid(OID_SIGNING_CERTIFICATE_V2) + _set(signing_certificate_v2)
    )
    attrs_body = b"".join(sorted((
        content_type_attr, message_digest_attr, signing_certificate_attr,
    )))
    signed_attrs = _tag(0xA0, attrs_body)
    signature = key.sign(_set(attrs_body), padding.PKCS1v15(), hashes.SHA256())

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

    encap_content_info = _seq(_oid(OID_TSTINFO) + _tag(0xA0, _octet(tstinfo)))
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
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.TIME_STAMPING]), critical=True)
            .sign(self._key, hashes.SHA256())
        )
        self._serial = 1

    def respond(self, tsq: bytes) -> bytes:
        # parse imprint + nonce out of the request
        _, body, _ = _read_tlv(tsq, 0)
        parts = list(_children(body))
        imprint_seq = _seq(parts[1][1])  # full messageImprint SEQUENCE
        nonce_der = _tag(parts[2][0], parts[2][1])
        tstinfo = _seq(
            _int(1)
            + _oid("1.2.3.4.1")  # test policy OID
            + imprint_seq
            + _int(self._serial)
            + _tag(0x18, datetime.now(timezone.utc).strftime("%Y%m%d%H%M%SZ").encode())
            + nonce_der
        )
        self._serial += 1
        cms = _build_cms(tstinfo, self.cert, self._key)
        # TimeStampResp = SEQUENCE { PKIStatusInfo (granted), ContentInfo }
        return _seq(_seq(_int(0)) + cms)
