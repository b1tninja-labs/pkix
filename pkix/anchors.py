"""trust anchor selection, including name restrictions and certificates only sets (RFC 5280
sec. 6.1).

A trust anchor is not "a certificate you trust"; sec. 6.1.1(d) names four things -- the trusted
issuer name, the trusted public key algorithm, the trusted public key, and optionally that
algorithm's parameters -- and offers a certificate as one way of supplying them. The distinction
bites where implementations get it wrong: the trusted issuer name comes from the *subject*, and
the key algorithm comes from the *subjectPublicKeyInfo*, and neither is the field a caller would
reach for first.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from typing import TYPE_CHECKING

from cryptography import x509
from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives import serialization

if TYPE_CHECKING:
    from cryptography.hazmat.primitives.asymmetric.types import PublicKeyTypes

__all__ = ["Subtree", "TrustAnchor", "load_anchor"]

# sec. 6.1.1(h) gives a set of subtree roots "for each name type (e.g., X.500 distinguished
# names, email addresses, or IP addresses)". Spelled the way GeneralName spells them, so a
# caller that reads the extension later sees the same words.
DIRECTORY_NAME = "directoryName"
RFC822_NAME = "rfc822Name"
IP_ADDRESS = "IPAddress"

_PREFIXES = {"dn": DIRECTORY_NAME, "email": RFC822_NAME, "ip": IP_ADDRESS}

_SEQUENCE = 0x30
_OID = 0x06
_NULL = 0x05


@dataclass(frozen=True)
class Subtree:
    """One permitted-subtree root of sec. 6.1.1(h), kept with the name type it belongs to.

    The name type is not decoration. A string that means a mailbox under one name type must not
    be compared against distinguished names under another.
    """

    name_type: str
    base: str


@dataclass(frozen=True)
class TrustAnchor:
    """The trust anchor information sec. 6.1.1(d) asks the path processing logic for.

    Fields are commented with the numbering the section uses, so checking this code against the
    document does not require translating between two sets of names.
    """

    #: (1) the trusted issuer name: the certificate's subject, not its issuer.
    issuer: str
    #: (2) the trusted public key algorithm, as the OID the SPKI carries.
    algorithm: str
    #: (3) the trusted public key.
    public_key: PublicKeyTypes
    #: (4) the algorithm parameters, when the algorithm has any. NULL and absent both read as
    #: None, because an RSA SPKI's NULL carries nothing a verifier needs.
    parameters: bytes | None
    #: The certificate the anchor was loaded from, when it was supplied as one.
    certificate: bytes | None
    #: Whether that certificate is its own issuer and verifies under its own key. Recorded,
    #: never required: sec. 6.1.1 permits a self-signed certificate, it does not demand one,
    #: and a cross-certificate is a legal anchor.
    self_signed: bool
    #: initial-permitted-subtrees, sec. 6.1.1(h).
    permitted_subtrees: tuple[Subtree, ...] = ()


def _read_tlv(data: bytes, offset: int) -> tuple[int, bytes, int]:
    """Return (tag, value, offset just past the element) for the TLV at `offset`.

    This walks one known structure rather than parsing arbitrary DER, and it refuses what it
    cannot make sense of instead of skipping it: a silently skipped field is how a parser ends
    up reporting a signature algorithm as a key algorithm.
    """
    if offset >= len(data):
        raise ValueError("truncated DER: element starts past the end")
    tag = data[offset]
    cursor = offset + 1
    if tag & 0x1F == 0x1F:  # high-tag-number form: trailing-bit-continued octets
        while cursor < len(data) and data[cursor] & 0x80:
            cursor += 1
        cursor += 1
    if cursor >= len(data):
        raise ValueError("truncated DER: no length octets")
    first = data[cursor]
    cursor += 1
    if first & 0x80:
        count = first & 0x7F
        if count == 0 or count > 4:
            raise ValueError("unsupported DER length encoding")
        length = int.from_bytes(data[cursor : cursor + count], "big")
        cursor += count
    else:
        length = first
    value = data[cursor : cursor + length]
    if len(value) != length:
        raise ValueError("truncated DER: value shorter than its length")
    return tag, value, cursor + length


def _decode_oid(value: bytes) -> str:
    """A DER OBJECT IDENTIFIER value, in dotted-decimal form."""
    if not value:
        raise ValueError("empty OBJECT IDENTIFIER")
    first_octet = value[0]
    if first_octet < 40:
        parts = [0, first_octet]
    elif first_octet < 80:
        parts = [1, first_octet - 40]
    else:
        parts = [2, first_octet - 80]
    accumulator = 0
    started = False
    for byte in value[1:]:
        accumulator = (accumulator << 7) | (byte & 0x7F)
        started = True
        if not byte & 0x80:
            parts.append(accumulator)
            accumulator = 0
            started = False
    if started or accumulator:
        raise ValueError("unterminated OBJECT IDENTIFIER subidentifier")
    return ".".join(str(part) for part in parts)


def _spki_algorithm(spki: bytes) -> tuple[str, bytes | None]:
    """The AlgorithmIdentifier of a DER SubjectPublicKeyInfo: (algorithm OID, parameters).

    Why read from the bytes instead of asked of the key object: this version of cryptography
    reports the algorithm that *signed* a certificate, not the algorithm its key carries, and
    sec. 6.1.1(d)(2) wants the second. On a cross-certificate they differ -- ISRG Root X2's
    cross-certificate is signed with RSA by X1 while carrying an EC key -- so confusing the two
    is a bug that only shows up on the anchors a path builder most needs right.
    """
    tag, spki_body, _ = _read_tlv(spki, 0)
    if tag != _SEQUENCE:
        raise ValueError("malformed SubjectPublicKeyInfo: not a SEQUENCE")
    tag, algorithm_block, _ = _read_tlv(spki_body, 0)
    if tag != _SEQUENCE:
        raise ValueError("malformed SubjectPublicKeyInfo: algorithm is not a SEQUENCE")
    tag, oid_value, after_oid = _read_tlv(algorithm_block, 0)
    if tag != _OID:
        raise ValueError("malformed SubjectPublicKeyInfo: algorithm is not an OID")
    algorithm = _decode_oid(oid_value)
    parameters = algorithm_block[after_oid:]
    if not parameters:
        return algorithm, None
    parameter_tag, _, _ = _read_tlv(parameters, 0)
    if parameter_tag == _NULL:
        return algorithm, None
    return algorithm, parameters


def _self_signed(certificate: x509.Certificate) -> bool:
    """Whether the certificate is issued by itself, checked rather than inferred.

    The names matching is not sufficient: a re-issuance under the same subject would look
    self-signed and not be. So the signature is verified under the certificate's own key. This
    is a fact reported to the caller, not a condition for loading -- sec. 6.1.1 does not require
    a trust anchor to be self-signed.
    """
    if certificate.issuer != certificate.subject:
        return False
    try:
        certificate.verify_directly_issued_by(certificate)
    except (InvalidSignature, UnsupportedAlgorithm, TypeError, ValueError):
        return False
    return True


def _permitted_subtree(restriction: str) -> Subtree:
    """Resolve one restriction string to a name type, or refuse.

    The guess exists because the argument is a single string while sec. 6.1.1(h) is not: it
    wants a set per name type. Where the text says which type it means, that wins. Where it
    could be two, the caller is asked, because applying a subtree to the wrong name type
    quietly constrains either nothing or everything.
    """
    text = restriction.strip()
    if not text:
        raise ValueError("an empty name restriction restricts nothing")
    head, sep, tail = text.partition(":")
    if sep and head.lower() in _PREFIXES:
        if not tail.strip():
            raise ValueError(f"name restriction {restriction!r} gives a type but no name")
        return Subtree(_PREFIXES[head.lower()], tail.strip())
    try:
        ipaddress.ip_network(text, strict=False)
    except ValueError:
        pass
    else:
        return Subtree(IP_ADDRESS, text)
    if "@" in text:
        if " " in text:
            raise ValueError(f"cannot tell which name type {restriction!r} is")
        return Subtree(RFC822_NAME, text)
    if "=" in text:
        return Subtree(DIRECTORY_NAME, text)
    raise ValueError(
        f"cannot tell which name type {restriction!r} is: sec. 6.1.1(h) names X.500 "
        "distinguished names, email addresses and IP addresses, so say which one this is "
        "with a dn:, email: or ip: prefix"
    )


def load_anchor(cert_der: bytes, name_restriction: str | None = None) -> TrustAnchor:
    """Build the trust anchor information of RFC 5280 sec. 6.1 from a certificate.

    The trusted issuer name is the certificate's subject, and the algorithm and key come from
    its subjectPublicKeyInfo, both because sec. 6.1.1(d) says so and because neither is the
    field a caller would grab first.

    The certificate is not validated here, and must not be. Sec. 6.1.1 makes the anchor trusted
    by how it was delivered -- "some trustworthy out-of-band procedure" -- and the path
    algorithm applies none of its checks to the anchor itself. A caller who wants to know
    whether the anchor is a root or a cross-certificate reads `self_signed`.

    `name_restriction`, when given, becomes one permitted-subtree root of sec. 6.1.1(h); see
    `_permitted_subtree` for how its name type is decided.
    """
    try:
        certificate = x509.load_der_x509_certificate(bytes(cert_der))
    except Exception as exc:
        raise ValueError(f"not a DER certificate: {exc}") from exc

    key = certificate.public_key()
    spki = key.public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    algorithm, parameters = _spki_algorithm(spki)

    subtrees: tuple[Subtree, ...] = ()
    if name_restriction is not None:
        subtrees = (_permitted_subtree(name_restriction),)

    return TrustAnchor(
        issuer=certificate.subject.rfc4514_string(),
        algorithm=algorithm,
        public_key=key,
        parameters=parameters,
        certificate=bytes(cert_der),
        self_signed=_self_signed(certificate),
        permitted_subtrees=subtrees,
    )
