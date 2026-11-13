"""Revocation: the pieces of RFC 5280 sections 6.1.3(a)(3) and 6.3 that need no network or store.

What is implemented here is the decision logic that does not depend on where a CRL or an OCSP
response came from:

* `skips_revocation`: RFC 9608 section 4 amends step (a)(3) of RFC 5280 section 6.1.3, "If the
  noRevAvail certificate extension ... is present or the ocsp-nocheck certificate extension
  [RFC6960] is present, then Step (a)(3) is skipped", and section 3 of the same document lists the
  profile a noRevAvail certificate must keep, "if any of the above are violated ... the relying
  party MUST consider the certificate invalid".
* `check_crl_issuer_key_usage`: RFC 10007 section 4 replaces step (f) of RFC 5280 section 6.3.3: for
  a v3 CRL issuer certificate the keyUsage extension must be present and carry cRLSign; a v1 or v2
  certificate has no extensions and is exempt.
* `check_crl_signature`: RFC 5280 section 5.1.1 and 6.3.3, the signature on a CRL, through the same
  seam as certificates (`sigwire[verify]`).

`status_of`, which fetches and matches, is still a stub and says so.
"""

from __future__ import annotations

import datetime as _dt
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from typing import TYPE_CHECKING, Literal

import asn1core
import asn1core.extensions
import sigwire.verify

from . import validity
from .errors import MalformedExtension, PkixError, SignaturePolicyRefused, SignatureUnsupported
from .extensions import KEY_USAGE, parse_basic_constraints, parse_key_usage

if TYPE_CHECKING:
    from datetime import datetime
    from typing import Any

    Certificate = Any  # placeholder: give it a real type in the milestone that needs it
    Status = Any  # placeholder: give it a real type in the milestone that needs it

__all__ = [
    "CrlChecker",
    "CrlIssuerCheck",
    "ProfileViolationError",
    "RevocationAnswer",
    "RevocationChecker",
    "RevocationRequest",
    "RevocationStatus",
    "check_crl_issuer_key_usage",
    "check_crl_signature",
    "skips_revocation",
    "status_of",
]

NO_REV_AVAIL = "2.5.29.56"  # RFC 9608 section 2: { id-ce 56 }
OCSP_NOCHECK = "1.3.6.1.5.5.7.48.1.5"  # RFC 6960 section 4.2.2.2.1, id-pkix-ocsp-nocheck
CRL_DISTRIBUTION_POINTS = "2.5.29.31"
FRESHEST_CRL = "2.5.29.46"
AUTHORITY_INFO_ACCESS = "1.3.6.1.5.5.7.1.1"
ID_AD_OCSP = (1, 3, 6, 1, 5, 5, 7, 48, 1)
_VERSION_V3 = 2  # asn1core reports the encoded version: 0 is v1, 2 is v3


class ProfileViolationError(PkixError):
    """A certificate breaks a MUST of the profile that an extension it carries imposes.

    RFC 9608 section 3: "If any of the above are violated in a certificate, then the relying party
    MUST consider the certificate invalid." It is raised and not returned because there is no honest
    value to answer: the certificate is not one whose revocation status can be skipped or checked.
    """


def skips_revocation(certificate: asn1core.Certificate) -> str | None:
    """RFC 9608 section 4: the extension that lets step (a)(3) be skipped, or None.

    Returns "noRevAvail" or "ocsp-nocheck" (checked in that order) when the certificate carries it.
    A certificate that carries noRevAvail but breaks section 3's profile (cA TRUE, a CRL
    distribution points or freshest CRL extension, an id-ad-ocsp access method) raises
    `ProfileViolationError`, and a noRevAvail whose value is not the DER NULL `0500` raises
    `MalformedExtension`. The ocsp-nocheck extension is accepted as the RFC 9608 text says, without
    a profile check of its own: RFC 6960's constraints on it are not this function's.
    """
    ext = certificate.extension(NO_REV_AVAIL)
    if ext is not None:
        if ext.value != b"\x05\x00":
            raise MalformedExtension("noRevAvail is not the DER NULL 0500 (RFC 9608 section 2)")
        bc = parse_basic_constraints(certificate.extension("2.5.29.19"))
        if bc is not None and bc.ca:
            raise ProfileViolationError("noRevAvail on a CA certificate (RFC 9608 section 3)")
        if certificate.extension(CRL_DISTRIBUTION_POINTS) is not None:
            raise ProfileViolationError(
                "noRevAvail with CRL distribution points (RFC 9608 section 3)"
            )
        if certificate.extension(FRESHEST_CRL) is not None:
            raise ProfileViolationError("noRevAvail with freshest CRL (RFC 9608 section 3)")
        aia = certificate.extension(AUTHORITY_INFO_ACCESS)
        if aia is not None and _has_ocsp_method(aia):
            raise ProfileViolationError(
                "noRevAvail with an id-ad-ocsp access method (RFC 9608 section 3)"
            )
        return "noRevAvail"
    if certificate.extension(OCSP_NOCHECK) is not None:
        return "ocsp-nocheck"
    return None


def _has_ocsp_method(aia: asn1core.Extension) -> bool:
    try:
        node, end = asn1core.decode(aia.value, der=True)
    except asn1core.Asn1Error as exc:
        raise MalformedExtension(f"authorityInfoAccess is not DER: {exc}") from exc
    if end != len(aia.value) or not node.constructed:
        raise MalformedExtension("authorityInfoAccess is not a SEQUENCE")
    for description in node.children:
        method = description.children[0] if description.children else None
        if method is None or method.payload is None:
            raise MalformedExtension("an AccessDescription starts with an accessMethod OID")
        if asn1core.decode_oid(method.payload) == ID_AD_OCSP:
            return True
    return False


@dataclass(frozen=True, slots=True)
class CrlIssuerCheck:
    """The answer to RFC 10007 section 4's amended step (f), with what it was decided from."""

    ok: bool
    #: "ok", "exempt_v1_v2" (no extensions field exists), "no_key_usage" or "no_crl_sign".
    reason: str


def check_crl_issuer_key_usage(issuer: asn1core.Certificate) -> CrlIssuerCheck:
    """RFC 10007 section 4: "If the version of the CRL issuer's certificate is version 3 (v3), then
    verify that the key usage extension is present and verify that the cRLSign bit is set."

    A v1 or v2 issuer is exempt, "as these versions do not have an extensions field". The old step
    (f) of RFC 5280 section 6.3.3 accepted an absent keyUsage, which is the hole this closes: an
    issuer certificate with no keyUsage now fails.
    """
    if issuer.version != _VERSION_V3:
        return CrlIssuerCheck(True, "exempt_v1_v2")
    usage = parse_key_usage(issuer.extension(KEY_USAGE))
    if usage is None:
        return CrlIssuerCheck(False, "no_key_usage")
    if "cRLSign" not in usage:
        return CrlIssuerCheck(False, "no_crl_sign")
    return CrlIssuerCheck(True, "ok")


def check_crl_signature(
    crl: asn1core.Crl,
    issuer_spki: bytes,
    *,
    policy: sigwire.verify.Policy = sigwire.verify.DEFAULT,
) -> validity.SignatureResult:
    """RFC 5280 section 5.1.1 and 6.3.3: the CRL's signature verifies under the issuer's key.

    The signed bytes are the stored `tbsCertList` slice. Failures are the exceptions
    `validity.check_signature` raises, with the same meaning: `SignatureInvalid`,
    `SignatureUnsupported`, `SignaturePolicyRefused`, `MalformedAlgorithm`.
    """
    try:
        tbs, _ = asn1core.decode(crl.tbs_cert_list, der=True)
    except asn1core.Asn1Error as exc:  # pragma: no cover - parse_crl already decoded it
        raise MalformedExtension(f"tbsCertList is not DER: {exc}") from exc
    fields = list(tbs.children)
    if fields and fields[0].tag.is_universal() and fields[0].tag.number == 2:
        fields.pop(0)  # version, present only in a v2 CRL
    return validity.check_signed_data(
        crl.tbs_cert_list,
        crl.signature_algorithm_raw,
        fields[0].raw,
        crl.signature_value,
        issuer_spki,
        policy=policy,
        what="CRL",
    )


@dataclass(frozen=True, slots=True)
class RevocationRequest:
    """What step (a)(3) of RFC 5280 section 6.1.3 knows when it asks about certificate i.

    `issuer_spki` is the working_public_key the certificate's signature verified under, and
    `issuer_certificate` the certificate that carried it, or None when that is a trust anchor given
    without one. `index` is i, numbered as section 6.1 numbers it (1 nearest the anchor).
    """

    certificate: asn1core.Certificate
    issuer_name: asn1core.Name
    issuer_spki: bytes
    issuer_certificate: asn1core.Certificate | None
    at: _dt.datetime
    index: int


type RevocationStatus = Literal["good", "revoked", "undetermined", "unsupported"]


@dataclass(frozen=True, slots=True)
class RevocationAnswer:
    """The answer to step (a)(3), and why.

    "undetermined" is RFC 5280 section 6.3.3's UNDETERMINED: no usable CRL settled it, and a path
    with it fails (fail closed). "unsupported" says the evidence exists but needs processing pkix
    does not do yet (an issuing distribution point, an indirect CRL, a separate CRL signing key):
    it also fails the path, and says it is pkix's limit and not the certificate's fault.
    """

    status: RevocationStatus
    reason: str


type RevocationChecker = Callable[[RevocationRequest], RevocationAnswer]

# RFC 5280 section 5.2: the CRL extensions this checker processes, or knows to need nothing from.
_AUTHORITY_KEY_IDENTIFIER = "2.5.29.35"
_SUBJECT_KEY_IDENTIFIER = "2.5.29.14"
_CRL_NUMBER = "2.5.29.20"
_DELTA_CRL_INDICATOR = "2.5.29.27"
_ISSUING_DISTRIBUTION_POINT = "2.5.29.28"
_ISSUER_ALT_NAME = "2.5.29.18"
_KNOWN_CRL_EXTENSIONS = frozenset(
    {
        _AUTHORITY_KEY_IDENTIFIER,
        _CRL_NUMBER,
        _DELTA_CRL_INDICATOR,
        _ISSUING_DISTRIBUTION_POINT,
        FRESHEST_CRL,
        _ISSUER_ALT_NAME,
    }
)
# RFC 5280 section 5.3: reasonCode, invalidityDate, certificateIssuer.
_REASON_CODE = "2.5.29.21"
_INVALIDITY_DATE = "2.5.29.24"
_CERTIFICATE_ISSUER = "2.5.29.29"
_KNOWN_ENTRY_EXTENSIONS = frozenset({_REASON_CODE, _INVALIDITY_DATE, _CERTIFICATE_ISSUER})
_REMOVE_FROM_CRL = 8  # RFC 5280 section 5.3.1, CRLReason removeFromCRL


class CrlChecker:
    """A `RevocationChecker` over a fixed set of complete CRLs: RFC 5280 section 6.3.3, scoped.

    What it does, by the steps of section 6.3.3: (b)(1) a CRL counts when its issuer is the
    certificate's issuer (section 7.1 name comparison); (a)(1) a CRL whose nextUpdate is before
    `at`, or whose thisUpdate is after it, is not used; section 5.2's rule that a CRL with a critical
    extension the application cannot process "MUST NOT" be used, and section 5.3's same rule for
    entries; (f) as RFC 10007 section 4 amends it, through `check_crl_issuer_key_usage`; (g) the
    signature, under the issuer key the path already validated; (j) the serial number lookup;
    (k) removeFromCRL is unrevoked. A CRL that fails any of these is skipped, and when none is left
    the answer is UNDETERMINED, never "good".

    What it does not do, each answered "unsupported" rather than guessed: an issuing distribution
    point (steps (b)(2), (d)), a certificate whose distribution point names a cRLIssuer (an indirect
    CRL, step (b)(1)), a certificateIssuer entry extension, a CRL whose authorityKeyIdentifier names
    a key other than the issuer's (step (f) for a separate CRL signing key). Delta CRLs (steps (c),
    (h), (i)) are not merged, and a delta CRL is never used as a complete one.
    """

    def __init__(
        self,
        crls: Iterable[bytes | asn1core.Crl],
        *,
        policy: sigwire.verify.Policy = sigwire.verify.DEFAULT,
    ) -> None:
        parsed: list[asn1core.Crl] = []
        unreadable: list[str] = []
        for item in crls:
            if isinstance(item, asn1core.Crl):
                parsed.append(item)
                continue
            try:
                parsed.append(asn1core.parse_crl(item))
            except asn1core.Asn1Error as exc:
                # Not evidence of anything: it cannot be matched to an issuer, so it is never used.
                unreadable.append(str(exc))
        self.crls = tuple(parsed)
        #: Why each CRL that could not be read was refused; such a CRL never answers "good".
        self.unreadable = tuple(unreadable)
        self.policy = policy

    def __call__(self, request: RevocationRequest) -> RevocationAnswer:
        certificate = request.certificate
        dps = certificate.extension(CRL_DISTRIBUTION_POINTS)
        if dps is not None:
            try:
                points = asn1core.extensions.parse_crl_distribution_points(dps.value)
            except asn1core.Asn1Error as exc:
                raise MalformedExtension(f"cRLDistributionPoints: {exc}") from exc
            if any(point.crl_issuer is not None for point in points):
                return RevocationAnswer(
                    "unsupported", "a distribution point names a cRLIssuer (indirect CRL)"
                )
        skipped: list[str] = []
        unsupported: list[str] = []
        good: list[RevocationAnswer] = []
        held: RevocationAnswer | None = None
        deltas = certificate.extension(FRESHEST_CRL) is not None
        for crl in self.crls:
            if not asn1core.names_equal(crl.issuer, certificate.issuer):
                continue
            extensions = {ext.dotted_oid for ext in crl.extensions}
            if _DELTA_CRL_INDICATOR in extensions:
                deltas = True
                skipped.append("a delta CRL is not a complete CRL (RFC 5280 sec. 5.2.4)")
                continue
            deltas |= FRESHEST_CRL in extensions
            verdict = self._one(crl, request)
            if isinstance(verdict, RevocationAnswer):
                if verdict.status == "revoked" and verdict.reason.endswith("certificateHold"):
                    held = verdict  # a delta CRL can still take a hold off (section 5.3.1)
                elif verdict.status == "revoked":
                    return verdict  # one complete CRL that revokes settles it
                else:
                    good.append(verdict)
                continue
            kind, why = verdict
            (unsupported if kind == "unsupported" else skipped).append(why)
        if deltas and (good or held is not None):
            # RFC 5280 sec. 6.3.3 steps (c), (h), (i): a delta CRL can revoke what the complete CRL
            # does not list, or remove a hold. Delta CRLs are not merged here, so neither "good"
            # nor a hold is the whole answer.
            return RevocationAnswer(
                "unsupported", "delta CRLs exist for this issuer and are not merged (sec. 5.2.4)"
            )
        if held is not None:
            return held
        if good:
            return good[0]
        skipped.extend(f"unreadable CRL: {why}" for why in self.unreadable)
        if unsupported:
            return RevocationAnswer("unsupported", "; ".join(unsupported))
        if skipped:
            return RevocationAnswer(
                "undetermined", "no usable CRL (RFC 5280 sec. 6.3.3): " + "; ".join(skipped)
            )
        return RevocationAnswer("undetermined", "no CRL from the certificate's issuer")

    def _one(
        self, crl: asn1core.Crl, request: RevocationRequest
    ) -> RevocationAnswer | tuple[str, str]:
        extensions = {ext.dotted_oid: ext for ext in crl.extensions}
        unknown = [
            oid
            for oid, ext in extensions.items()
            if ext.critical and oid not in _KNOWN_CRL_EXTENSIONS
        ]
        if unknown:
            return "skip", f"critical CRL extension {unknown[0]} not processed (RFC 5280 sec. 5.2)"
        if _ISSUING_DISTRIBUTION_POINT in extensions:
            return "unsupported", "issuing distribution point (RFC 5280 sec. 6.3.3(b)(2))"
        if crl.this_update > request.at:
            return "skip", "thisUpdate is after the validation time"
        if crl.next_update is not None and request.at > crl.next_update:
            return "skip", "nextUpdate is before the validation time (RFC 5280 sec. 6.3.3(a)(1))"
        issuer = request.issuer_certificate
        aki = extensions.get(_AUTHORITY_KEY_IDENTIFIER)
        ski = None if issuer is None else issuer.extension(_SUBJECT_KEY_IDENTIFIER)
        if aki is not None and ski is not None:
            try:
                key_id = asn1core.extensions.parse_authority_key_identifier(aki.value)
                issuer_key_id = asn1core.extensions.parse_subject_key_identifier(ski.value)
            except asn1core.Asn1Error as exc:
                raise MalformedExtension(f"key identifier: {exc}") from exc
            if key_id.key_identifier is not None and key_id.key_identifier != issuer_key_id:
                return (
                    "unsupported",
                    "the CRL is signed by a key other than the certificate issuer's "
                    "(RFC 5280 sec. 6.3.3(f), separate CRL signer)",
                )
        if issuer is not None:
            usage = check_crl_issuer_key_usage(issuer)
            if not usage.ok:
                return "skip", f"CRL issuer certificate: {usage.reason} (RFC 10007 sec. 4)"
        try:
            check_crl_signature(crl, request.issuer_spki, policy=self.policy)
        except (SignatureUnsupported, SignaturePolicyRefused) as exc:
            return "unsupported", f"CRL signature: {exc}"
        except PkixError as exc:
            return "skip", f"CRL signature: {exc} (RFC 5280 sec. 6.3.3(g))"
        for revoked in crl.revoked:
            entry_ext = {ext.dotted_oid: ext for ext in revoked.extensions}
            if _CERTIFICATE_ISSUER in entry_ext:
                return "unsupported", "certificateIssuer CRL entry extension (indirect CRL)"
            if any(e.critical and o not in _KNOWN_ENTRY_EXTENSIONS for o, e in entry_ext.items()):
                return (
                    "skip",
                    "a CRL entry has a critical extension not processed (RFC 5280 sec. 5.3)",
                )
        entry = crl.revoked_by_serial(request.certificate.serial)
        if entry is not None and entry.reason != _REMOVE_FROM_CRL:
            return RevocationAnswer(
                "revoked",
                f"serial {request.certificate.serial} is on the CRL, reason {entry.reason_name}",
            )
        return RevocationAnswer("good", f"not on the CRL of thisUpdate {crl.this_update:%Y-%m-%d}")


def status_of(cert: Certificate, issuer: Certificate, at: datetime) -> Status:
    """Pending behaviour defined by RFC 5280.

    Not implemented yet. See the ``revocation.status_of()`` row in ROADMAP.md; this stub
    raises on purpose so nothing downstream mistakes it for working code.
    """
    raise NotImplementedError("status_of() is not implemented: RFC 5280")
