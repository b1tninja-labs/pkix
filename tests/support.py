"""Synthetic certificates for the signature tests, minted with `cryptography` (dev-only).

pkix never signs, so every certificate here is signed by a different implementation than the one
under test, which is what makes a pass mean something. Nothing in `pkix/` imports this module or
`cryptography`.
"""

from __future__ import annotations

import datetime
from dataclasses import dataclass
from typing import Any

import asn1core
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed25519, rsa
from cryptography.x509.oid import NameOID

NOT_BEFORE = datetime.datetime(2024, 1, 1)

type PrivateKey = (
    rsa.RSAPrivateKey | ec.EllipticCurvePrivateKey | ed25519.Ed25519PrivateKey | dsa.DSAPrivateKey
)


@dataclass(frozen=True)
class Minted:
    der: bytes
    certificate: asn1core.Certificate
    key: PrivateKey


def _name(text: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, text)])


def mint(
    subject_key: PrivateKey,
    issuer_key: PrivateKey,
    *,
    hash_algorithm: Any = None,
    rsa_padding: Any = None,
    subject: str = "subject",
    issuer: str = "issuer",
    not_before: datetime.datetime = NOT_BEFORE,
    not_after: datetime.datetime | None = None,
) -> Minted:
    """A v3 certificate for `subject_key` signed by `issuer_key`."""
    builder = (
        x509.CertificateBuilder()
        .subject_name(_name(subject))
        .issuer_name(_name(issuer))
        .public_key(subject_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after or not_before + datetime.timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
    )
    if isinstance(issuer_key, ed25519.Ed25519PrivateKey):
        issued = builder.sign(issuer_key, None)
    elif isinstance(issuer_key, rsa.RSAPrivateKey) and rsa_padding is not None:
        issued = builder.sign(
            issuer_key, hash_algorithm or hashes.SHA256(), rsa_padding=rsa_padding
        )
    else:
        issued = builder.sign(issuer_key, hash_algorithm or hashes.SHA256())
    der = issued.public_bytes(serialization.Encoding.DER)
    return Minted(der, asn1core.parse_certificate(der), subject_key)


def tlv(tag: int, content: bytes) -> bytes:
    return bytes([tag]) + asn1core.encode_length(len(content)) + content


def parts(der: bytes) -> tuple[bytes, bytes]:
    """(tbsCertificate content octets, the signatureAlgorithm and signatureValue TLVs)."""
    top, _ = asn1core.decode(der, der=True)
    tbs, algorithm, signature = top.children
    return tbs.content(), algorithm.raw + signature.raw


def join(tbs_content: bytes, rest: bytes) -> bytes:
    """Reassemble a certificate from edited parts, with every enclosing length recomputed."""
    return tlv(0x30, tlv(0x30, tbs_content) + rest)


def replace_everywhere(der: bytes, old: bytes, new: bytes) -> bytes:
    """Replace a byte string in both the tbsCertificate and the outer fields, fixing the lengths.

    Used to edit an AlgorithmIdentifier, which appears twice and must stay equal to itself.
    """
    tbs_content, rest = parts(der)
    if old not in tbs_content or old not in rest:
        raise ValueError("the bytes to replace are not in both places")
    return join(tbs_content.replace(old, new), rest.replace(old, new))
