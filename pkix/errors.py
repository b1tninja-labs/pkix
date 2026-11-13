"""The named failures pkix raises on purpose.

A verifier that answers `False` for every way a signature can fail throws away the one fact a caller
needs: whether the signature is wrong, whether the algorithm is one this library does not do, or
whether a policy declined to look. The classes below keep those apart, and every one of them is a
`PkixError`, so one `except` catches what pkix refuses without catching a bug.
"""

from __future__ import annotations

__all__ = [
    "MalformedAlgorithm",
    "MalformedCertificate",
    "MalformedExtension",
    "PkixError",
    "SignatureInvalid",
    "SignaturePolicyRefused",
    "SignatureUnsupported",
    "UnsignedCertificate",
    "UnsupportedConstraint",
]


class PkixError(Exception):
    """Base class for everything pkix raises deliberately."""


class MalformedCertificate(PkixError, ValueError):
    """The bytes are not a DER certificate. The `asn1core` error that said so is the `__cause__`."""


class MalformedAlgorithm(PkixError, ValueError):
    """An AlgorithmIdentifier or SubjectPublicKeyInfo that breaks the document defining its algorithm.

    Examples: ECDSA parameters present where RFC 5758 section 3.2 says they MUST be omitted, an
    EC key whose point starts with an octet RFC 5480 section 2.2 says MUST be rejected, an
    RSASSA-PSS trailerField other than 1.
    """


class SignatureInvalid(PkixError):
    """The signature does not verify, or the certificate contradicts itself about how it is signed."""


class SignatureUnsupported(PkixError):
    """A signature or key algorithm this version of pkix does not verify.

    That is a statement about pkix and not about the certificate: do not read it as "forged", and do
    not read it as "fine". A path containing it has not been validated.
    """


class UnsignedCertificate(SignatureUnsupported):
    """The signature algorithm is id-alg-unsigned, which RFC 9925 section 4 says is always invalid.

    A subclass of `SignatureUnsupported` because RFC 9925 section 4 recommends treating the
    placeholder as an unrecognised algorithm; it is its own class so a caller that wants to
    classify a locally configured unsigned certificate can tell it from an unknown OID.
    """


class SignaturePolicyRefused(PkixError):
    """The signature may well be genuine, but the signature policy in force refuses the algorithm.

    A 1024-bit RSA key or a SHA-1 digest under the default policy lands here. The caller who needs to
    verify history passes a more permissive `sigwire[verify]` policy and gets the answer with the refusal
    reported rather than silently waived.
    """


class MalformedExtension(PkixError, ValueError):
    """An extension's value does not have the syntax its defining document gives it.

    Raised by `pkix.extensions` and `pkix.names` when a decoder is handed bytes that are not a
    well-formed value of the extension's type. A caller must not read it as "the extension is
    absent": a path with a malformed extension has not been validated.
    """


class UnsupportedConstraint(PkixError):
    """A name constraint this version of pkix cannot evaluate, so it refuses instead of guessing.

    RFC 5280 section 4.2.1.10 says that where a critical name constraint covers a name form that
    appears in a later certificate, the application "MUST either process the constraint or reject the
    certificate". This is the rejection, and it is distinct from "the name violates the constraint".
    """
