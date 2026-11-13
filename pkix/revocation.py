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
* `CrlChecker`: the CRL processing algorithm of RFC 5280 section 6.3.3 over CRLs and certificates
  the caller holds, with issuing distribution points, reason masks, indirect CRLs, CRL signers
  whose path is validated separately (step (f)) and delta CRLs.

`status_of`, which fetches and matches, is still a stub and says so.
"""

from __future__ import annotations

import datetime as _dt
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from typing import TYPE_CHECKING, Literal

import asn1core
import asn1core.extensions
import asn1core.keys
import sigwire.verify

from . import _algorithms as alg
from . import validity
from .errors import MalformedExtension, PkixError, SignaturePolicyRefused, SignatureUnsupported
from .extensions import KEY_USAGE, parse_basic_constraints, parse_key_usage

if TYPE_CHECKING:
    from datetime import datetime
    from typing import Any

    from .anchors import TrustAnchor

    Certificate = Any  # placeholder: give it a real type in the milestone that needs it
    Status = Any  # placeholder: give it a real type in the milestone that needs it

__all__ = [
    "ALL_REASONS",
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
    parameters: asn1core.keys.DsaParameters | None = None,
) -> validity.SignatureResult:
    """RFC 5280 section 5.1.1 and 6.3.3: the CRL's signature verifies under the issuer's key.

    The signed bytes are the stored `tbsCertList` slice. Failures are the exceptions
    `validity.check_signature` raises, with the same meaning: `SignatureInvalid`,
    `SignatureUnsupported`, `SignaturePolicyRefused`, `MalformedAlgorithm`. `parameters` are the
    inherited DSA parameters of the issuer key, as in `validity.check_signed_data`.
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
        parameters=parameters,
    )


@dataclass(frozen=True, slots=True)
class RevocationRequest:
    """What step (a)(3) of RFC 5280 section 6.1.3 knows when it asks about certificate i.

    `issuer_spki` is the working_public_key the certificate's signature verified under, and
    `issuer_certificate` the certificate that carried it, or None when that is a trust anchor given
    without one. `index` is i, numbered as section 6.1 numbers it (1 nearest the anchor).
    `anchor` is the trust anchor of the path, which section 6.3.3 step (f) requires of a CRL
    issuer's own path, and `issuer_parameters` the working_public_key_parameters (DSA only).
    """

    certificate: asn1core.Certificate
    issuer_name: asn1core.Name
    issuer_spki: bytes
    issuer_certificate: asn1core.Certificate | None
    at: _dt.datetime
    index: int
    anchor: TrustAnchor | None = None
    issuer_parameters: asn1core.keys.DsaParameters | None = None


type RevocationStatus = Literal["good", "revoked", "undetermined", "unsupported"]


@dataclass(frozen=True, slots=True)
class RevocationAnswer:
    """The answer to step (a)(3), and why.

    "undetermined" is RFC 5280 section 6.3.3's UNDETERMINED: no usable CRL settled it, and a path
    with it fails (fail closed). "unsupported" says the evidence exists but needs processing pkix
    does not do (a signature algorithm it does not verify, a trust anchor it was not given): it
    also fails the path, and says it is pkix's limit and not the certificate's fault.
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


#: "all-reasons" of RFC 5280 section 6.3.3: the ReasonFlags of section 4.2.1.13 that name a reason.
#: Bit 0, "unused", is left out, a reading and not a quotation: section 5.2.5 says that on a CRL
#: with onlySomeReasons "every certificate in the scope of the CRL that is revoked MUST be assigned
#: a revocation reason other than unspecified", so no revocation can be filed under bit 0, and a
#: partition of the reasons that omits it (cryptography cannot even set it) still covers them all.
#: A mask that asserts it, as PKITS 4.14.15 does, is accepted and the extra bit changes nothing.
ALL_REASONS = frozenset(
    {
        "keyCompromise",
        "cACompromise",
        "affiliationChanged",
        "superseded",
        "cessationOfOperation",
        "certificateHold",
        "privilegeWithdrawn",
        "aACompromise",
    }
)
# How deep a CRL issuer's path may itself need a CRL issuer's path (step (f) inside step (f)). Not a
# number the document gives; section 6.2 lets an implementation "further limit" the paths it
# accepts, and a bound keeps a hostile pool from recursing without end.
_MAX_SIGNER_DEPTH = 4
_ID_DSA = "1.2.840.10040.4.1"  # RFC 3279 section 2.3.2


@dataclass(frozen=True, slots=True)
class _DistributionPoint:
    """One DistributionPoint as section 6.3.3 reads it, its name resolved (section 4.2.1.13).

    `names` is None when the distributionPoint field is omitted. `assumed` marks the DP of the
    last paragraph of section 6.3.3, built for CRLs no distribution point names.
    """

    names: tuple[asn1core.extensions.GeneralName, ...] | None
    reasons: frozenset[str] | None
    crl_issuer: tuple[asn1core.extensions.GeneralName, ...] | None
    assumed: bool = False


@dataclass(frozen=True, slots=True)
class _Entry:
    revoked: asn1core.Revoked
    #: The certificate issuer the entry belongs to (section 5.3.3): the CRL issuer until a
    #: certificateIssuer entry extension says otherwise, then that, until the next one.
    issuer: tuple[asn1core.extensions.GeneralName, ...]


@dataclass(frozen=True, slots=True)
class _CrlFacts:
    """A CRL with the extensions section 6.3.3 reads, decoded once."""

    crl: asn1core.Crl
    idp: asn1core.extensions.IssuingDistributionPoint | None
    idp_raw: bytes | None
    aki_raw: bytes | None
    aki_key_id: bytes | None
    number: int | None
    #: BaseCRLNumber when this is a delta CRL (section 5.2.4), None for a complete CRL.
    base: int | None
    freshest: bool
    entries: tuple[_Entry, ...]
    #: Why the CRL cannot be used at all, or None.
    problem: str | None

    @property
    def when(self) -> str:
        return f"{self.crl.this_update:%Y-%m-%d}"


@dataclass(frozen=True, slots=True)
class _Signer:
    """The key validated in step (f), and how it was found."""

    spki: bytes
    parameters: asn1core.keys.DsaParameters | None
    how: str


@dataclass(frozen=True, slots=True)
class _Skip:
    """A CRL that does not answer for this certificate. `unsupported` marks pkix's own limit."""

    why: str
    unsupported: bool = False
    #: Not worth reporting: the CRL simply belongs to another issuer.
    quiet: bool = False


@dataclass(frozen=True, slots=True)
class _Found:
    #: cert_status after steps (i) to (k): None is UNREVOKED.
    entry: asn1core.Revoked | None
    on_delta: bool
    interim: frozenset[str]
    detail: str


def _directory(name: asn1core.Name) -> asn1core.extensions.GeneralName:
    return asn1core.extensions.GeneralName("directoryName", name, name.raw)


def _same_name(
    left: asn1core.extensions.GeneralName, right: asn1core.extensions.GeneralName
) -> bool:
    if left.kind != right.kind:
        return False
    if left.kind == "directoryName":
        a, b = left.value, right.value
        return (
            isinstance(a, asn1core.Name)
            and isinstance(b, asn1core.Name)
            and asn1core.names_equal(a, b)
        )
    return left.value == right.value


def _any_match(
    left: Iterable[asn1core.extensions.GeneralName],
    right: Iterable[asn1core.extensions.GeneralName],
) -> bool:
    others = tuple(right)
    return any(_same_name(a, b) for a in left for b in others)


def _decoded(ext: asn1core.Extension | None, decoder: Callable[[bytes], Any]) -> Any:
    if ext is None:
        return None
    try:
        return decoder(ext.value)
    except asn1core.Asn1Error as exc:
        raise MalformedExtension(f"{ext.dotted_oid}: {exc}") from exc


def _facts(crl: asn1core.Crl) -> _CrlFacts:
    ext = {e.dotted_oid: e for e in crl.extensions}
    problem: str | None = None
    unknown = [o for o, e in ext.items() if e.critical and o not in _KNOWN_CRL_EXTENSIONS]
    if unknown:
        problem = f"critical CRL extension {unknown[0]} not processed (RFC 5280 sec. 5.2)"
    idp = number = base = None
    aki_key_id = None
    entries: list[_Entry] = []
    try:
        idp = _decoded(
            ext.get(_ISSUING_DISTRIBUTION_POINT),
            asn1core.extensions.parse_issuing_distribution_point,
        )
        number = _decoded(ext.get(_CRL_NUMBER), asn1core.extensions.parse_crl_number)
        base = _decoded(
            ext.get(_DELTA_CRL_INDICATOR), asn1core.extensions.parse_delta_crl_indicator
        )
        aki = _decoded(
            ext.get(_AUTHORITY_KEY_IDENTIFIER),
            asn1core.extensions.parse_authority_key_identifier,
        )
        aki_key_id = None if aki is None else aki.key_identifier
        issuer: tuple[asn1core.extensions.GeneralName, ...] = (_directory(crl.issuer),)
        for revoked in crl.revoked:
            entry_ext = {e.dotted_oid: e for e in revoked.extensions}
            if any(e.critical and o not in _KNOWN_ENTRY_EXTENSIONS for o, e in entry_ext.items()):
                problem = problem or (
                    "a CRL entry has a critical extension not processed (RFC 5280 sec. 5.3)"
                )
            named = _decoded(
                entry_ext.get(_CERTIFICATE_ISSUER), asn1core.extensions.parse_certificate_issuer
            )
            if named is not None:
                issuer = named
            entries.append(_Entry(revoked, issuer))
    except MalformedExtension as exc:
        problem = problem or f"malformed CRL extension: {exc}"
    return _CrlFacts(
        crl=crl,
        idp=idp,
        idp_raw=None
        if _ISSUING_DISTRIBUTION_POINT not in ext
        else ext[_ISSUING_DISTRIBUTION_POINT].value,
        aki_raw=None
        if _AUTHORITY_KEY_IDENTIFIER not in ext
        else ext[_AUTHORITY_KEY_IDENTIFIER].value,
        aki_key_id=aki_key_id,
        number=number,
        base=base,
        freshest=FRESHEST_CRL in ext,
        entries=tuple(entries),
        problem=problem,
    )


def _entry_for(facts: _CrlFacts, certificate: asn1core.Certificate) -> asn1core.Revoked | None:
    """Section 6.3.3 steps (i) and (j): an entry "that matches the certificate issuer and serial
    number as described in Section 5.3.3"."""
    issuer_names = (_directory(certificate.issuer), *_issuer_alt_names(certificate))
    for entry in facts.entries:
        if entry.revoked.serial == certificate.serial and _any_match(entry.issuer, issuer_names):
            return entry.revoked
    return None


def _issuer_alt_names(
    certificate: asn1core.Certificate,
) -> tuple[asn1core.extensions.GeneralName, ...]:
    ext = certificate.extension(_ISSUER_ALT_NAME)
    if ext is None:
        return ()
    try:
        node, _ = asn1core.decode(ext.value, der=True)
        return asn1core.extensions.parse_general_names(node, "IssuerAltName")
    except asn1core.Asn1Error as exc:
        raise MalformedExtension(f"issuerAltName: {exc}") from exc


def _is_ca(certificate: asn1core.Certificate) -> bool:
    basic = parse_basic_constraints(certificate.extension("2.5.29.19"))
    return basic is not None and basic.ca


def _distribution_points(certificate: asn1core.Certificate) -> list[_DistributionPoint]:
    """The certificate's DPs, then the DP the last paragraph of section 6.3.3 assumes."""
    points: list[_DistributionPoint] = []
    ext = certificate.extension(CRL_DISTRIBUTION_POINTS)
    if ext is not None:
        for point in _decoded(ext, asn1core.extensions.parse_crl_distribution_points):
            # Section 4.2.1.13: a relative name is appended to the cRLIssuer's DN when the DP has
            # one, and to the certificate issuer's otherwise.
            base = certificate.issuer
            for name in point.crl_issuer or ():
                if name.kind == "directoryName" and isinstance(name.value, asn1core.Name):
                    base = name.value
                    break
            names = None
            if point.full_name is not None or point.relative_name is not None:
                names = asn1core.extensions.distribution_point_names(
                    point.full_name, point.relative_name, base
                )
            points.append(_DistributionPoint(names, point.reasons, point.crl_issuer))
    # "assume a DP with both the reasons and the cRLIssuer fields omitted and a distribution point
    # name of the certificate issuer ... generated from the certificate issuer field as well as
    # the certificate issuerAltName extension."
    assumed = (_directory(certificate.issuer), *_issuer_alt_names(certificate))
    points.append(_DistributionPoint(assumed, None, None, assumed=True))
    return points


class CrlChecker:
    """A `RevocationChecker` over CRLs and certificates the caller holds: RFC 5280 section 6.3.3.

    For each distribution point of the certificate, then for the DP the section's last paragraph
    assumes, each complete CRL is taken through the steps of section 6.3.3 until the reasons_mask
    is all-reasons or the certificate is found:

    * (a)(1): a CRL whose nextUpdate is before `at`, or whose thisUpdate is after it, is not used;
    * (b)(1): the CRL issuer is the certificate's issuer, or, when the DP names a cRLIssuer, that
      name, with an issuing distribution point asserting indirectCRL;
    * (b)(2): the IDP's distribution point name matches the DP's (or its cRLIssuer when the DP has
      no name), and onlyContainsUserCerts, onlyContainsCACerts and onlyContainsAttributeCerts
      hold for this certificate;
    * (d), (e): interim_reasons_mask, and a CRL that adds no reason is not used;
    * (f) as RFC 10007 section 4 amends it, (g): the CRL is verified under the key that issued the
      certificate when that key signed it; otherwise a certificate from `certificates` named as the
      CRL issuer whose key verifies the CRL is the CRL signer, and its own path is validated from
      the same trust anchor (`RevocationRequest.anchor`), revocation included, with this checker;
    * (c), (h), (i): with `use_deltas`, a delta CRL that matches issuer, scope and authority key
      identifier and can update the complete CRL (section 5.2.4 (a) to (d)) is verified under the
      same key and searched first;
    * (j), (k), (l): the complete CRL is searched (entries attributed by section 5.3.3's
      certificateIssuer rule), removeFromCRL is UNREVOKED, and the mask grows.

    Section 5.2's rule that a CRL with a critical extension the application cannot process "MUST
    NOT" be used, and section 5.3's for entries, take a CRL out of consideration. When the mask
    does not reach all-reasons and nothing revoked the certificate, the answer is UNDETERMINED,
    never "good".

    Decisions the text leaves open, taken here: CRLs are tried newest thisUpdate first; a CRL
    without an IDP corresponds to every DP of its issuer; a CRL signer's path is validated with the
    default policy inputs of section 6.1.1 and this checker's signature policy; and a CRL whose
    signer's path is being validated is not used while validating it, which is what ends the
    circle of a self-issued CRL signing key (PKITS 4.5.6).
    """

    def __init__(
        self,
        crls: Iterable[bytes | asn1core.Crl],
        *,
        certificates: Iterable[bytes | asn1core.Certificate] = (),
        policy: sigwire.verify.Policy = sigwire.verify.DEFAULT,
        use_deltas: bool = True,
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
        pool: list[asn1core.Certificate] = []
        for cert in certificates:
            if isinstance(cert, asn1core.Certificate):
                pool.append(cert)
                continue
            try:
                pool.append(asn1core.parse_certificate(cert))
            except asn1core.Asn1Error:
                continue  # an unreadable certificate cannot sign anything
        self.crls = tuple(parsed)
        #: Why each CRL that could not be read was refused; such a CRL never answers "good".
        self.unreadable = tuple(unreadable)
        #: Certificates that may be CRL signers, or intermediates on a CRL signer's path.
        self.certificates = tuple(pool)
        self.policy = policy
        self.use_deltas = use_deltas
        self._facts = tuple(_facts(crl) for crl in parsed)
        #: CRLs whose signer's path is being validated, each with the key it is provisionally
        #: verified under (see `_child`).
        self._active: dict[bytes, _Signer | None] = {}
        self._depth = 0

    def _child(self, crl: asn1core.Crl, provisional: _Signer | None) -> CrlChecker:
        """This checker, for validating the path of `crl`'s signer.

        While that path is validated, `crl` is verified under the candidate signer's key without
        validating the path a second time: the path in question is the one under validation, and
        asking for it again would not end. This is what lets a CRL issuer's certificate be covered
        by the indirect CRL it signs, which PKITS 4.14.30 expects to validate. Such a CRL is tried
        after every other CRL (`__call__`), so a CRL from elsewhere that covers all reasons is
        preferred to one vouching for its own signer.
        """
        child = object.__new__(CrlChecker)
        child.crls = self.crls
        child.unreadable = self.unreadable
        child.certificates = self.certificates
        child.policy = self.policy
        child.use_deltas = self.use_deltas
        child._facts = self._facts
        child._active = {**self._active, crl.raw: provisional}
        child._depth = self._depth + 1
        return child

    def __call__(self, request: RevocationRequest) -> RevocationAnswer:
        certificate = request.certificate
        points = _distribution_points(certificate)
        complete = sorted(
            (f for f in self._facts if f.base is None),
            key=lambda f: f.crl.this_update,
            reverse=True,
        )
        complete.sort(key=lambda f: f.crl.raw in self._active)  # stable: provisional ones last
        reasons_mask: frozenset[str] = frozenset()
        notes: list[str] = []
        unsupported: list[str] = []
        covered: list[str] = []
        for point in points:
            for facts in complete:
                if reasons_mask >= ALL_REASONS:
                    break
                outcome = self._process(facts, point, request, reasons_mask)
                if isinstance(outcome, _Skip):
                    if outcome.unsupported:
                        unsupported.append(outcome.why)
                    elif not outcome.quiet and outcome.why not in notes:
                        notes.append(outcome.why)
                    continue
                if outcome.entry is not None:
                    where = "delta CRL" if outcome.on_delta else "CRL"
                    return RevocationAnswer(
                        "revoked",
                        f"serial {certificate.serial} is on the {where} of thisUpdate "
                        f"{outcome.detail}, reason {outcome.entry.reason_name}",
                    )
                reasons_mask |= outcome.interim
                covered.append(outcome.detail)
        if reasons_mask >= ALL_REASONS:
            return RevocationAnswer("good", "not on the CRL of thisUpdate " + ", ".join(covered))
        notes.extend(f"unreadable CRL: {why}" for why in self.unreadable)
        if unsupported:
            return RevocationAnswer("unsupported", "; ".join(dict.fromkeys(unsupported)))
        if covered:
            missing = ", ".join(sorted(ALL_REASONS - reasons_mask))
            notes.insert(0, f"no usable CRL covers the reasons {missing}")
        if any(
            f.base is not None and asn1core.names_equal(f.crl.issuer, certificate.issuer)
            for f in self._facts
        ):
            notes.append("a delta CRL is never used as a complete CRL (sec. 5.2.4)")
        if notes:
            return RevocationAnswer(
                "undetermined", "no usable CRL (RFC 5280 sec. 6.3.3): " + "; ".join(notes)
            )
        return RevocationAnswer("undetermined", "no CRL from the certificate's issuer")

    def _process(
        self,
        facts: _CrlFacts,
        point: _DistributionPoint,
        request: RevocationRequest,
        reasons_mask: frozenset[str],
    ) -> _Skip | _Found:
        crl, certificate = facts.crl, request.certificate
        # (b)(1): whose CRL this is.
        if point.crl_issuer is not None:
            named = [n for n in point.crl_issuer if n.kind == "directoryName"]
            if not _any_match(named, (_directory(crl.issuer),)):
                return _Skip("the CRL issuer is not the DP's cRLIssuer", quiet=True)
            if facts.idp is None or not facts.idp.indirect_crl:
                return _Skip("a cRLIssuer's CRL without indirectCRL (RFC 5280 sec. 6.3.3(b)(1))")
        elif not asn1core.names_equal(crl.issuer, certificate.issuer):
            return _Skip("another issuer's CRL", quiet=True)
        if facts.problem is not None:
            return _Skip(facts.problem)
        # (a)(1): no newer CRL can be obtained here, so a stale one is simply not used.
        if crl.this_update > request.at:
            return _Skip("thisUpdate is after the validation time")
        if crl.next_update is not None and request.at > crl.next_update:
            return _Skip("nextUpdate is before the validation time (RFC 5280 sec. 6.3.3(a)(1))")
        # (b)(2): the scope of the CRL.
        idp = facts.idp
        if idp is not None:
            if idp.distribution_point_present:
                names = asn1core.extensions.distribution_point_names(
                    idp.full_name, idp.relative_name, crl.issuer
                )
                targets = point.names if point.names is not None else (point.crl_issuer or ())
                if not _any_match(names, targets):
                    return _Skip(
                        "the IDP names another distribution point (RFC 5280 sec. 6.3.3(b)(2)(i))"
                    )
            if idp.only_contains_user_certs and _is_ca(certificate):
                return _Skip("onlyContainsUserCerts and the certificate is a CA (b)(2)(ii)")
            if idp.only_contains_ca_certs and not _is_ca(certificate):
                return _Skip("onlyContainsCACerts and the certificate is not a CA (b)(2)(iii)")
            if idp.only_contains_attribute_certs:
                return _Skip("onlyContainsAttributeCerts is asserted (b)(2)(iv)")
        # (d), (e)
        only_some = None if idp is None else idp.only_some_reasons
        if only_some is not None and point.reasons is not None:
            interim = only_some & point.reasons
        elif only_some is not None:
            interim = only_some
        elif point.reasons is not None:
            interim = point.reasons
        else:
            interim = ALL_REASONS
        if not interim - reasons_mask:
            return _Skip("the CRL covers no reason not already covered (sec. 6.3.3(e))", quiet=True)
        # (f), (g)
        signer = self._signer(facts, request)
        if isinstance(signer, _Skip):
            return signer
        # (c), (h), (i)
        delta: _CrlFacts | None = None
        wants_delta = facts.freshest or certificate.extension(FRESHEST_CRL) is not None
        if self.use_deltas and wants_delta:
            delta = self._delta_for(facts, signer, request)
        entry = None if delta is None else _entry_for(delta, certificate)
        on_delta = entry is not None
        if entry is None:  # (j)
            entry = _entry_for(facts, certificate)
        if entry is not None and entry.reason == _REMOVE_FROM_CRL:  # (k)
            entry = None
        detail = facts.when + ("" if delta is None else f" with delta {delta.when}")
        return _Found(entry, on_delta, interim, detail + f" ({signer.how})")

    def _verify(
        self, facts: _CrlFacts, spki: bytes, parameters: asn1core.keys.DsaParameters | None
    ) -> _Skip | None:
        try:
            check_crl_signature(facts.crl, spki, policy=self.policy, parameters=parameters)
        except (SignatureUnsupported, SignaturePolicyRefused) as exc:
            return _Skip(f"CRL signature: {exc}", unsupported=True)
        except PkixError as exc:
            return _Skip(f"CRL signature: {exc} (RFC 5280 sec. 6.3.3(g))")
        return None

    def _signer(self, facts: _CrlFacts, request: RevocationRequest) -> _Signer | _Skip:
        """Steps (f) and (g): the validated key the CRL verifies under."""
        crl = facts.crl
        if crl.raw in self._active:
            provisional = self._active[crl.raw]
            if provisional is None:
                return _Skip("the CRL whose signer's path is being validated", quiet=True)
            return provisional
        first: _Skip | None = None
        if asn1core.names_equal(crl.issuer, request.issuer_name):
            # The key that issued the certificate: its path is the one being validated.
            failed = self._verify(facts, request.issuer_spki, request.issuer_parameters)
            if failed is None:
                issuer = request.issuer_certificate
                if issuer is None:
                    return _Signer(request.issuer_spki, request.issuer_parameters, "anchor key")
                usage = check_crl_issuer_key_usage(issuer)
                if usage.ok:
                    return _Signer(
                        request.issuer_spki, request.issuer_parameters, "certificate issuer's key"
                    )
                failed = _Skip(f"CRL issuer certificate: {usage.reason} (RFC 10007 sec. 4)")
            first = failed
        anchor = request.anchor
        if (
            anchor is not None
            and anchor.spki != request.issuer_spki
            and asn1core.names_equal(crl.issuer, anchor.issuer)
            and self._verify(facts, anchor.spki, None) is None
        ):
            return _Signer(anchor.spki, None, "trust anchor key")
        # A separate CRL signer (section 6.3.3(f)): a certificate for the CRL issuer's name whose
        # key verifies the CRL, whose own path then has to validate. The authority key identifier
        # orders the search; it is never trusted on its own.
        candidates = [
            c
            for c in self.certificates
            if asn1core.names_equal(c.subject, crl.issuer)
            and c.subject_public_key_info != request.issuer_spki
        ]
        candidates.sort(key=lambda c: _subject_key_id(c) != facts.aki_key_id)
        # The reason reported is the most telling one: pkix's own limit first, then a signer whose
        # key verified the CRL but whose certificate or path failed, then the certificate issuer's
        # key not verifying, and last a candidate whose key does not verify the CRL either.
        reasons: list[tuple[int, _Skip]] = [] if first is None else [(1, first)]
        for candidate in candidates:
            answer, verified = self._separate_signer(facts, candidate, request)
            if isinstance(answer, _Signer):
                return answer
            reasons.append((3 if answer.unsupported else 2 if verified else 0, answer))
        if reasons:
            return max(reasons, key=lambda pair: pair[0])[1]
        return _Skip("no certificate for the CRL issuer verifies the CRL (sec. 6.3.3(f))")

    def _separate_signer(
        self, facts: _CrlFacts, candidate: asn1core.Certificate, request: RevocationRequest
    ) -> tuple[_Signer | _Skip, bool]:
        """A candidate CRL signer, and whether its key verified the CRL."""
        spki = candidate.subject_public_key_info
        own_parameters = alg.dsa_parameters_of(spki)
        # A DSA key without parameters inherits them along its own path (RFC 5280 sec. 6.1.4(e)).
        needs_path_first = alg.key_algorithm_of(spki) == _ID_DSA and own_parameters is None
        if not needs_path_first:
            failed = self._verify(facts, spki, own_parameters)
            if failed is not None:
                return failed, False
        verified = not needs_path_first
        usage = check_crl_issuer_key_usage(candidate)
        if not usage.ok:
            return _Skip(f"CRL signer certificate: {usage.reason} (RFC 10007 sec. 4)"), verified
        if request.anchor is None:
            return _Skip(
                "a separate CRL signer needs the path's trust anchor (RFC 5280 sec. 6.3.3(f))",
                unsupported=True,
            ), verified
        if self._depth >= _MAX_SIGNER_DEPTH:
            return _Skip("CRL signer paths nest too deeply", unsupported=True), verified
        from .result import PathInputs, validate  # result imports this module

        # The CRL's signature under this key was checked above, unless the key's parameters are
        # inherited; then nothing vouches for it yet and it is not used provisionally.
        provisional = None
        if not needs_path_first:
            provisional = _Signer(
                spki, own_parameters, "the CRL signer's key, its path in progress"
            )
        path = validate(
            candidate,
            [request.anchor],
            request.at,
            PathInputs(
                signature_policy=self.policy, revocation=self._child(facts.crl, provisional)
            ),
            intermediates=self.certificates,
        )
        if path.status == "unsupported":
            reason = path.failure.detail if path.failure is not None else "unsupported"
            return _Skip(f"CRL signer path: {reason}", unsupported=True), verified
        if not path.valid:
            reason = path.failure.detail if path.failure is not None else "invalid"
            return _Skip(f"CRL signer path does not validate (sec. 6.3.3(f)): {reason}"), verified
        parameters = path.working_public_key_parameters
        if needs_path_first:
            failed = self._verify(facts, spki, parameters)
            if failed is not None:
                return failed, False
        return _Signer(spki, parameters, f"separate CRL signer, serial {candidate.serial}"), True

    def _delta_for(
        self, complete: _CrlFacts, signer: _Signer, request: RevocationRequest
    ) -> _CrlFacts | None:
        """Steps (c) and (h), and section 5.2.4's conditions for combining: the current delta CRL
        that updates `complete`, verified under the step (f) key, or None."""
        found: _CrlFacts | None = None
        for delta in self._facts:
            if delta.base is None or delta.problem is not None or delta.crl.raw in self._active:
                continue
            if not asn1core.names_equal(delta.crl.issuer, complete.crl.issuer):  # (c)(1)
                continue
            if delta.idp_raw != complete.idp_raw:  # (c)(2), sec. 5.2.4(b)
                continue
            if delta.aki_raw != complete.aki_raw:  # (c)(3)
                continue
            if complete.number is None or delta.number is None:
                continue  # sec. 5.2.4(c) and (d) need both numbers
            if not delta.base <= complete.number < delta.number:
                continue
            if delta.crl.this_update > request.at or (
                delta.crl.next_update is not None and request.at > delta.crl.next_update
            ):
                continue  # sec. 5.2.4: current is between thisUpdate and nextUpdate
            if self._verify(delta, signer.spki, signer.parameters) is not None:  # (h)
                continue
            if found is None or delta.crl.this_update > found.crl.this_update:
                found = delta  # "the one with the latest value in thisUpdate"
        return found


def _subject_key_id(certificate: asn1core.Certificate) -> bytes | None:
    ext = certificate.extension(_SUBJECT_KEY_IDENTIFIER)
    if ext is None:
        return None
    try:
        return asn1core.extensions.parse_subject_key_identifier(ext.value)
    except asn1core.Asn1Error:
        return None


def status_of(cert: Certificate, issuer: Certificate, at: datetime) -> Status:
    """Pending behaviour defined by RFC 5280.

    Not implemented yet. See the ``revocation.status_of()`` row in ROADMAP.md; this stub
    raises on purpose so nothing downstream mistakes it for working code.
    """
    raise NotImplementedError("status_of() is not implemented: RFC 5280")
