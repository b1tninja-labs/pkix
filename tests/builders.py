"""Certificates with chosen extensions, minted with `cryptography` (a dev dependency, never imported by pkix).

The signatures here are never verified by the tests that use these builders: path-processing rules
(names, policies, key usage) read extensions and do not need a genuine signature. One P-256 key
signs everything, which keeps the suite fast.
"""

from __future__ import annotations

import datetime
from collections.abc import Sequence

import asn1core
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import NameOID

KEY = ec.generate_private_key(ec.SECP256R1())
NOT_BEFORE = datetime.datetime(2024, 1, 1)

type Extension = tuple[x509.ExtensionType, bool]


def dn(*parts: str, email: str | None = None) -> x509.Name:
    attrs = [x509.NameAttribute(NameOID.COMMON_NAME, p) for p in parts]
    if email is not None:
        attrs.append(x509.NameAttribute(NameOID.EMAIL_ADDRESS, email))
    return x509.Name(attrs)


def certificate(
    subject: x509.Name,
    issuer: x509.Name,
    extensions: Sequence[Extension] = (),
) -> asn1core.Certificate:
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(KEY.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(NOT_BEFORE)
        .not_valid_after(NOT_BEFORE + datetime.timedelta(days=3650))
    )
    for value, critical in extensions:
        builder = builder.add_extension(value, critical)
    return asn1core.parse_certificate(builder.sign(KEY, hashes.SHA256()).public_bytes(Encoding.DER))


def oid(dotted: str) -> x509.ObjectIdentifier:
    return x509.ObjectIdentifier(dotted)
