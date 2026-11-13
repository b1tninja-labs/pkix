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

import asn1core
import sigwire.verify

from . import _algorithms as alg
from .errors import MalformedCertificate, PkixError
from .validity import SignatureResult, check_signature_with_spki

__all__ = ["Subtree", "TrustAnchor", "load_anchor"]

# sec. 6.1.1(h) gives a set of subtree roots "for each name type (e.g., X.500 distinguished
# names, email addresses, or IP addresses)". Spelled the way GeneralName spells them, so a
# caller that reads the extension later sees the same words.
DIRECTORY_NAME = "directoryName"
RFC822_NAME = "rfc822Name"
IP_ADDRESS = "IPAddress"

_PREFIXES = {"dn": DIRECTORY_NAME, "email": RFC822_NAME, "ip": IP_ADDRESS}


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
    document does not require translating between two sets of names. Everything here was read by
    `asn1core`, and every byte string is a slice of the document that arrived.
    """

    #: (1) the trusted issuer name: the certificate's subject, not its issuer. Equality on it is
    #: the RFC 5280 section 7.1 match, so spelling differences do not make two names differ.
    issuer: asn1core.Name
    #: (2) the trusted public key algorithm, as the dotted OID the SPKI carries.
    algorithm: str
    #: (3) the trusted public key: the subjectPublicKey octets, without the BIT STRING's
    #: unused-bits octet. `spki` is the whole stored SubjectPublicKeyInfo.
    public_key: bytes
    #: (4) the algorithm parameters as the stored TLV, when the algorithm has any. NULL and absent
    #: both read as None, because an RSA SPKI's NULL carries nothing a verifier needs.
    parameters: bytes | None
    #: The stored SubjectPublicKeyInfo TLV: what `verify` checks signatures against.
    spki: bytes
    #: The certificate the anchor was loaded from, and its stored tbsCertificate.
    certificate: bytes | None
    tbs: bytes | None
    #: Whether the certificate's issuer and subject names match (RFC 5280 section 3.3, section
    #: 7.1 comparison). Recorded, never required: sec. 6.1.1 permits a self-signed certificate,
    #: it does not demand one, and a cross-certificate is a legal anchor.
    self_issued: bool
    #: Whether it is self-issued and its signature verifies under its own key, checked with the
    #: legacy signature policy because a root's age is a fact to record, not a reason to refuse
    #: to load it. False also when the algorithm is one pkix cannot verify yet; `verify` says why.
    self_signed: bool
    #: initial-permitted-subtrees, sec. 6.1.1(h).
    permitted_subtrees: tuple[Subtree, ...] = ()

    def verify(
        self,
        certificate: bytes | asn1core.Certificate,
        *,
        policy: sigwire.verify.Policy = sigwire.verify.DEFAULT,
    ) -> SignatureResult:
        """Check that `certificate` was signed by this anchor's key (RFC 5280 section 6.1.3 (a)(1)).

        Raises what `validity.check_signature` raises. Until the anchor's key algorithm is one pkix
        verifies, that is `SignatureUnsupported`, loudly, and never a quiet pass.
        """
        return check_signature_with_spki(certificate, self.spki, policy=policy)


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
    raw = bytes(cert_der)
    try:
        certificate = asn1core.parse_certificate(raw)
    except asn1core.Asn1Error as exc:
        raise MalformedCertificate(f"not a DER certificate: {exc}") from exc

    spki = certificate.subject_public_key_info
    try:
        algorithm, key_octets = alg.split_spki(spki)
    except PkixError as exc:
        raise MalformedCertificate(f"not a usable subjectPublicKeyInfo: {exc}") from exc
    parameters = algorithm.parameters
    parameter_bytes = None if parameters is None or alg.is_null(parameters) else parameters.raw

    subtrees: tuple[Subtree, ...] = ()
    if name_restriction is not None:
        subtrees = (_permitted_subtree(name_restriction),)

    self_issued = certificate.self_issued
    self_signed = False
    if self_issued:
        try:
            check_signature_with_spki(certificate, spki, policy=sigwire.verify.LEGACY)
        except PkixError:
            self_signed = False
        else:
            self_signed = True

    return TrustAnchor(
        issuer=certificate.subject,
        algorithm=algorithm.oid,
        public_key=key_octets,
        parameters=parameter_bytes,
        spki=spki,
        certificate=raw,
        tbs=certificate.tbs_certificate,
        self_issued=self_issued,
        self_signed=self_signed,
        permitted_subtrees=subtrees,
    )
