"""Basic certificate processing, RFC 5280 section 6.1.3 step (a): signature and validity period.

Step (a)(1) is `check_signature`: "The signature on the certificate can be verified using
working_public_key_algorithm, the working_public_key, and the working_public_key_parameters."
Step (a)(2) is `check_validity`: "The certificate validity period includes the current time."
Step (a)(3), revocation, is `revocation.status_of`; step (a)(4), the issuer name, is `chain`.

The arithmetic of step (a)(1) is `sigwire[verify]`'s (verify-only RSA, ECDSA and Ed25519 over integers and
bytes); this module reads the certificate with `asn1core`, decides which verification the
signatureAlgorithm asks for, and refuses everything it cannot decide. `cryptography` is not used.

This cited section 6.2 until 2026-11-07; section 6.2 is "Using the Path Validation Algorithm", and the
per-certificate checks are step (a) of section 6.1.3 (outline and text read through rfclib).
"""

from __future__ import annotations

import datetime
from dataclasses import dataclass
from typing import Literal

import asn1core
import sigwire.verify

from . import _algorithms as alg
from .errors import (
    MalformedAlgorithm,
    MalformedCertificate,
    SignatureInvalid,
    SignaturePolicyRefused,
    SignatureUnsupported,
)

__all__ = [
    "SignatureResult",
    "ValidityResult",
    "check_signature",
    "check_signature_with_spki",
    "check_validity",
]

type CertificateInput = bytes | asn1core.Certificate


def _certificate(value: object, role: str) -> asn1core.Certificate:
    if isinstance(value, asn1core.Certificate):
        return value
    if isinstance(value, bytes):
        try:
            return asn1core.parse_certificate(value)
        except asn1core.Asn1Error as exc:
            raise MalformedCertificate(f"{role} is not a DER certificate: {exc}") from exc
    raise TypeError(
        f"{role} must be DER bytes or an asn1core.Certificate, not {type(value).__name__}"
    )


@dataclass(frozen=True, slots=True)
class ValidityResult:
    """The answer to RFC 5280 section 6.1.3 step (a)(2), with the facts it was decided from."""

    ok: bool
    reason: Literal["ok", "not_yet_valid", "expired"]
    at: datetime.datetime
    not_before: datetime.datetime
    not_after: datetime.datetime
    #: notAfter is 99991231235959Z, which RFC 5280 section 4.1.2.5 reads as "no well-defined
    #: expiration date": the certificate cannot expire, and nothing here says its status is kept.
    no_expiration: bool
    #: Why the dates are spelled against section 4.1.2.5, or None. Described and not refused: it
    #: constrains issuance, and real CAs have issued such certificates.
    encoding_issue: str | None


def check_validity(cert: CertificateInput, at: datetime.datetime) -> ValidityResult:
    """RFC 5280 section 6.1.3 step (a)(2): the validity period includes the current time.

    The period "is the period of time from notBefore through notAfter, inclusive" (section
    4.1.2.5), so `at == notBefore` and `at == notAfter` are both valid, and one second either side
    is not. The clock is `at`: this function never reads one, so every boundary is testable without
    sleeping, and a caller validating at a past instant says so in the argument.

    `at` must be timezone-aware; a naive datetime raises `ValueError`, because guessing a zone
    decides a certificate's validity by up to a day. A document that is not a DER certificate
    raises `MalformedCertificate`.
    """
    if not isinstance(at, datetime.datetime):
        raise TypeError(f"at must be a datetime, not {type(at).__name__}")
    if at.tzinfo is None or at.utcoffset() is None:
        raise ValueError("at must be timezone-aware: a naive datetime has no instant to compare")
    certificate = _certificate(cert, "cert")
    window = certificate.validity
    if at < window.not_before:
        reason: Literal["ok", "not_yet_valid", "expired"] = "not_yet_valid"
    elif at > window.not_after:
        reason = "expired"
    else:
        reason = "ok"
    return ValidityResult(
        ok=reason == "ok",
        reason=reason,
        at=at,
        not_before=window.not_before,
        not_after=window.not_after,
        no_expiration=window.not_after == asn1core.NO_EXPIRATION,
        encoding_issue=asn1core.validity_encoding_issue(certificate.raw),
    )


@dataclass(frozen=True, slots=True)
class SignatureResult:
    """What a successful signature check established. Failure is an exception, never a result."""

    #: The signatureAlgorithm OID, dotted.
    algorithm: str
    #: One of "rsa-pkcs1v15", "rsa-pss", "ecdsa", "ed25519".
    scheme: str
    hash_name: str | None
    #: "RSA-2048", "P-256", "Ed25519": the issuer key that verified it.
    key: str
    #: The hash is one the policy in force reports as deprecated (only possible under a looser
    #: policy than the default).
    deprecated: bool


def _inner_signature_algorithm(certificate: asn1core.Certificate) -> bytes:
    """TBSCertificate.signature, RFC 5280 section 4.1.2.3, as the TLV that arrived."""
    try:
        tbs, _ = asn1core.decode(certificate.tbs_certificate, der=True)
    except asn1core.Asn1Error as exc:  # pragma: no cover - parse_certificate already decoded it
        raise MalformedCertificate(f"tbsCertificate is not DER: {exc}") from exc
    fields = list(tbs.children)
    if fields and fields[0].tag.is_context(0):
        fields.pop(0)
    return fields[1].raw  # serialNumber, then signature


def check_signature(
    cert: CertificateInput,
    issuer: CertificateInput,
    *,
    policy: sigwire.verify.Policy = sigwire.verify.DEFAULT,
) -> SignatureResult:
    """RFC 5280 section 6.1.3 step (a)(1): `cert`'s signature verifies under `issuer`'s key.

    The signature covers "the ASN.1 DER encoded tbsCertificate" (section 4.1.1.3), which is the
    stored slice `asn1core` kept and never a re-encoding. The issuer contributes only its
    subjectPublicKeyInfo: matching names (step (a)(4)), constraints and key usage are other rows.

    Returns a `SignatureResult` when the signature is genuine. Otherwise it raises, and which class
    is the answer: `SignatureInvalid` (does not verify, or the certificate's two signature
    algorithm fields disagree, which section 4.1.1.2 forbids), `SignatureUnsupported` (an algorithm
    pkix does not verify, including RFC 9925's id-alg-unsigned as `UnsignedCertificate`),
    `SignaturePolicyRefused` (`policy` declines the key size, curve or hash) and
    `MalformedAlgorithm` (parameters or a key that break the document defining them).

    `policy` is a `sigwire.verify.Policy`; the default refuses RSA under 2048 bits and SHA-1.
    """
    return check_signature_with_spki(
        cert, _certificate(issuer, "issuer").subject_public_key_info, policy=policy
    )


def check_signature_with_spki(
    cert: CertificateInput,
    spki: bytes,
    *,
    policy: sigwire.verify.Policy = sigwire.verify.DEFAULT,
) -> SignatureResult:
    """`check_signature` for an issuer given as a stored SubjectPublicKeyInfo.

    RFC 5280 section 6.1.1(d) lets a trust anchor be a name and a key rather than a certificate,
    and section 6.1.3 step (a)(1) only ever needs the key, so a trust anchor verifies through here.
    """
    certificate = _certificate(cert, "cert")

    # RFC 5280 section 4.1.1.2: the outer field "MUST contain the same algorithm identifier as the
    # signature field in the sequence tbsCertificate". Byte equality is the strict reading; a CA
    # that spells NULL parameters differently in the two places is refused rather than excused.
    if certificate.signature_algorithm_raw != _inner_signature_algorithm(certificate):
        raise SignatureInvalid(
            "signatureAlgorithm differs from TBSCertificate.signature (RFC 5280 section 4.1.1.2)"
        )
    scheme = alg.decode_signature_algorithm(certificate.signature_algorithm_raw)
    key = alg.decode_public_key(spki)

    try:
        valid, description = _verify(
            scheme, key, certificate.tbs_certificate, certificate.signature_value, policy
        )
    except sigwire.verify.PolicyRefusal as exc:
        raise SignaturePolicyRefused(str(exc)) from exc
    except sigwire.verify.Unsupported as exc:
        raise SignatureUnsupported(str(exc)) from exc
    except sigwire.verify.MalformedInput as exc:
        raise MalformedAlgorithm(f"issuer key unusable for {scheme.scheme}: {exc}") from exc
    if not valid:
        raise SignatureInvalid(f"the {scheme.scheme} signature does not verify under {description}")

    rule = policy.rules.get(_POLICY_NAMES[scheme.scheme])
    return SignatureResult(
        algorithm=scheme.algorithm.oid,
        scheme=scheme.scheme,
        hash_name=scheme.hash_name,
        key=description,
        deprecated=(
            rule is not None
            and scheme.hash_name is not None
            and scheme.hash_name in rule.deprecated_hashes
        ),
    )


_POLICY_NAMES = {
    alg.RSA_PKCS1V15: sigwire.verify.policy.RSA_PKCS1V15,
    alg.RSA_PSS: sigwire.verify.policy.RSA_PSS,
    alg.ECDSA: sigwire.verify.policy.ECDSA,
    alg.ED25519: sigwire.verify.policy.ED25519,
}


def _verify(
    scheme: alg.SignatureScheme,
    key: alg.PublicKey,
    message: bytes,
    signature: bytes,
    policy: sigwire.verify.Policy,
) -> tuple[bool, str]:
    """Run the verification `scheme` names against `key`; a key of another family cannot verify."""
    if scheme.scheme in (alg.RSA_PKCS1V15, alg.RSA_PSS):
        if not isinstance(key, alg.RsaKey):
            raise SignatureInvalid(f"{scheme.scheme} signature but the issuer key is not RSA")
        if scheme.hash_name is None:
            raise MalformedAlgorithm(f"{scheme.scheme} signature algorithm names no hash")
        description = f"RSA-{key.n.bit_length()}"
        if scheme.scheme == alg.RSA_PKCS1V15:
            return (
                sigwire.verify.rsa.verify_pkcs1v15(
                    key.n, key.e, message, signature, scheme.hash_name, policy=policy
                ),
                description,
            )
        if scheme.salt_length is None:
            raise MalformedAlgorithm("RSASSA-PSS signature algorithm names no salt length")
        return (
            sigwire.verify.rsa.verify_pss(
                key.n,
                key.e,
                message,
                signature,
                scheme.hash_name,
                salt_length=scheme.salt_length,
                mgf_hash=scheme.mgf_hash,
                policy=policy,
            ),
            description,
        )
    if scheme.scheme == alg.ECDSA:
        if not isinstance(key, alg.EcKey):
            raise SignatureInvalid("ecdsa signature but the issuer key is not an EC key")
        if scheme.hash_name is None:
            raise MalformedAlgorithm("ecdsa signature algorithm names no hash")
        pair = alg.decode_ecdsa_signature(signature)
        if pair is None:
            return False, key.curve
        digest = sigwire.verify.hashes.lookup(scheme.hash_name).digest(message)
        return (
            sigwire.verify.ecdsa.verify(
                key.curve,
                key.x,
                key.y,
                digest,
                pair[0],
                pair[1],
                hash_name=scheme.hash_name,
                policy=policy,
            ),
            key.curve,
        )
    if not isinstance(key, alg.Ed25519Key):
        raise SignatureInvalid("ed25519 signature but the issuer key is not Ed25519")
    return (
        sigwire.verify.eddsa.verify_ed25519(key.public, message, signature, policy=policy),
        "Ed25519",
    )
