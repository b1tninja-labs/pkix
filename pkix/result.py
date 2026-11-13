"""The path walk of RFC 5280 section 6.1, and the outcome object with provenance for every decision.

`path_walk` is sections 6.1.2 to 6.1.5 as one pass over a prospective path: for each certificate the
basic processing of section 6.1.3, then the preparation of section 6.1.4 for every certificate but
the last, then the wrap-up of section 6.1.5. It joins pieces that each have their own module and
tests: signatures and dates (`validity`), revocation (`revocation`), name constraints (`names`),
policies as RFC 9618 replaces the policy tree with a graph (`policy`), and the extension decoders
(`extensions`, reading through `asn1core`).

Every check that ran is recorded as a `Step`, in order, so the answer carries the reasoning: which
certificate, which step of which section, and what it saw. The walk stops at the first step that
fails, because section 6.1.4 says "the procedure terminates, returning a failure indication and an
appropriate reason", and the steps after a failure would describe a path that is already rejected.

Three outcomes, never two. "valid" and "invalid" are the algorithm's answers. "unsupported" says the
path needs something pkix does not do yet (a signature algorithm, a name form, a CRL feature): it is
not valid, and it is not a finding against the certificate either.
"""

from __future__ import annotations

import datetime
from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Literal

import asn1core
import asn1core.keys
import sigwire.verify

from . import _algorithms as alg
from . import validity
from .anchors import TrustAnchor
from .chain import candidates
from .errors import (
    MalformedAlgorithm,
    MalformedCertificate,
    MalformedExtension,
    SignatureInvalid,
    SignaturePolicyRefused,
    SignatureUnsupported,
    UnsignedCertificate,
    UnsupportedConstraint,
)
from .extensions import (
    BASIC_CONSTRAINTS,
    CERTIFICATE_POLICIES,
    INHIBIT_ANY_POLICY,
    KEY_USAGE,
    POLICY_CONSTRAINTS,
    POLICY_MAPPINGS,
    parse_basic_constraints,
    parse_key_usage,
)
from .names import (
    NAME_CONSTRAINTS,
    SUBJECT_ALT_NAME,
    NameConstraints,
    check_certificate,
    parse_name_constraints,
)
from .policy import PolicyOutcome, resolve
from .revocation import (
    AUTHORITY_INFO_ACCESS,
    CRL_DISTRIBUTION_POINTS,
    FRESHEST_CRL,
    NO_REV_AVAIL,
    OCSP_NOCHECK,
    ProfileViolationError,
    RevocationChecker,
    RevocationRequest,
    skips_revocation,
)

__all__ = [
    "PROCESSED_EXTENSIONS",
    "PathInputs",
    "PathResult",
    "Step",
    "path_walk",
    "validate",
]

type Outcome = Literal["ok", "failed", "unsupported", "skipped"]
type PathStatus = Literal["valid", "invalid", "unsupported"]

_VERSION_V3 = 2  # asn1core reports the encoded version: 0 is v1, 2 is v3

# Section 6.1.4(o) and 6.1.5(f): "Recognize and process any other critical extension". These are
# the extensions the walk processes, or whose meaning puts nothing on path validation and is the
# application's (extendedKeyUsage, the key identifiers, the access descriptions). A critical
# extension outside this set fails the path, as section 4.2 requires.
PROCESSED_EXTENSIONS = frozenset(
    {
        BASIC_CONSTRAINTS,
        KEY_USAGE,
        CERTIFICATE_POLICIES,
        POLICY_MAPPINGS,
        POLICY_CONSTRAINTS,
        INHIBIT_ANY_POLICY,
        NAME_CONSTRAINTS,
        SUBJECT_ALT_NAME,
        NO_REV_AVAIL,
        OCSP_NOCHECK,
        CRL_DISTRIBUTION_POINTS,
        FRESHEST_CRL,
        AUTHORITY_INFO_ACCESS,
        "2.5.29.14",  # subjectKeyIdentifier, section 4.2.1.2
        "2.5.29.35",  # authorityKeyIdentifier, section 4.2.1.1
        "2.5.29.18",  # issuerAltName, section 4.2.1.7
        "2.5.29.37",  # extKeyUsage, section 4.2.1.12: a purpose check is the application's
        "1.3.6.1.5.5.7.1.11",  # subjectInfoAccess, section 4.2.2.2
    }
)


@dataclass(frozen=True, slots=True)
class PathInputs:
    """The inputs of RFC 5280 section 6.1.1 other than the path, the anchor and the time.

    `user_initial_policy_set` is (c), as dotted OIDs, None meaning any-policy. The three flags are
    (e) initial-policy-mapping-inhibit, (f) initial-explicit-policy and (g)
    initial-any-policy-inhibit. `initial_name_constraints` is (h) and (i) together.

    `revocation` answers step (a)(3) of section 6.1.3. None means the caller decided not to check
    revocation, and the result says so in `revocation_checked`; it is never read as "not revoked".
    """

    user_initial_policy_set: frozenset[str] | None = None
    initial_policy_mapping_inhibit: bool = False
    initial_explicit_policy: bool = False
    initial_any_policy_inhibit: bool = False
    initial_name_constraints: NameConstraints = field(default_factory=NameConstraints)
    signature_policy: sigwire.verify.Policy = sigwire.verify.DEFAULT
    revocation: RevocationChecker | None = None
    #: RFC 9618 sections 6.2 and 6.3: reject a path longer than this, or whose policy graph grows
    #: past this many nodes. None means no bound; the document names no number.
    policy_max_depth: int | None = None
    policy_max_nodes: int | None = None


@dataclass(frozen=True, slots=True)
class Step:
    """One decision of the walk: certificate i (0 for the whole path), the step, the outcome."""

    index: int
    step: str
    outcome: Outcome
    detail: str = ""


@dataclass(frozen=True, slots=True)
class PathResult:
    """What section 6.1.6 returns, plus the provenance of every check that produced it."""

    status: PathStatus
    steps: tuple[Step, ...]
    #: The policy outputs of section 6.1.6 as RFC 9618 section 5.6 rewrites them, when processing
    #: reached the policy step.
    policy: PolicyOutcome | None
    #: Whether step (a)(3) was answered for every certificate that needed it.
    revocation_checked: bool
    #: The target's subjectPublicKeyInfo, the working_public_key of section 6.1.5(c), on success.
    working_public_key: bytes | None
    #: working_public_key_parameters of section 6.1.5(d) for a DSA key, inherited when the
    #: target's own SPKI omits them; None for every other algorithm.
    working_public_key_parameters: asn1core.keys.DsaParameters | None = None

    @property
    def valid(self) -> bool:
        return self.status == "valid"

    @property
    def failure(self) -> Step | None:
        """The step that decided a non-valid answer, or None."""
        for step in self.steps:
            if step.outcome in ("failed", "unsupported"):
                return step
        return None


class _Stop(Exception):  # noqa: N818 - control flow inside the walk; never escapes it
    pass


class _Walk:
    def __init__(self) -> None:
        self.steps: list[Step] = []

    def ok(self, i: int, step: str, detail: str = "") -> None:
        self.steps.append(Step(i, step, "ok", detail))

    def skipped(self, i: int, step: str, detail: str) -> None:
        self.steps.append(Step(i, step, "skipped", detail))

    def fail(self, i: int, step: str, detail: str) -> _Stop:
        self.steps.append(Step(i, step, "failed", detail))
        return _Stop(detail)

    def unsupported(self, i: int, step: str, detail: str) -> _Stop:
        self.steps.append(Step(i, step, "unsupported", detail))
        return _Stop(detail)


def _signature(
    walk: _Walk,
    i: int,
    certificate: asn1core.Certificate,
    spki: bytes,
    inputs: PathInputs,
    parameters: asn1core.keys.DsaParameters | None,
) -> None:
    step = "6.1.3(a)(1) signature"
    try:
        found = validity.check_signature_with_spki(
            certificate, spki, policy=inputs.signature_policy, parameters=parameters
        )
    except UnsignedCertificate as exc:
        raise walk.fail(
            i, step, f"id-alg-unsigned never verifies (RFC 9925 sec. 4): {exc}"
        ) from exc
    except SignatureUnsupported as exc:
        raise walk.unsupported(i, step, str(exc)) from exc
    except SignaturePolicyRefused as exc:
        raise walk.fail(i, step, f"refused by the signature policy: {exc}") from exc
    except (SignatureInvalid, MalformedAlgorithm, MalformedCertificate) as exc:
        raise walk.fail(i, step, str(exc)) from exc
    walk.ok(i, step, f"{found.scheme} {found.hash_name or '-'} under {found.key}")


def _revocation(walk: _Walk, i: int, request: RevocationRequest, inputs: PathInputs) -> bool:
    step = "6.1.3(a)(3) revocation"
    try:
        skip = skips_revocation(request.certificate)
    except ProfileViolationError as exc:
        raise walk.fail(i, step, str(exc)) from exc
    if skip is not None:
        walk.skipped(i, step, f"{skip} (RFC 9608 sec. 4)")
        return True
    if inputs.revocation is None:
        walk.skipped(i, step, "no revocation checker given; status not checked")
        return False
    answer = inputs.revocation(request)
    if answer.status == "good":
        walk.ok(i, step, answer.reason)
        return True
    if answer.status == "unsupported":
        raise walk.unsupported(i, step, answer.reason)
    raise walk.fail(i, step, f"{answer.status}: {answer.reason}")


def _critical(walk: _Walk, i: int, certificate: asn1core.Certificate, step: str) -> None:
    for ext in certificate.extensions:
        if ext.critical and ext.dotted_oid not in PROCESSED_EXTENSIONS:
            raise walk.fail(i, step, f"critical extension {ext.dotted_oid} is not processed")
    walk.ok(i, step)


def _prepare(walk: _Walk, i: int, certificate: asn1core.Certificate, max_path_length: int) -> int:
    """Section 6.1.4 steps (k) to (o) for certificate i; returns the new max_path_length."""
    if certificate.version != _VERSION_V3:
        raise walk.fail(
            i,
            "6.1.4(k) CA certificate",
            "a version 1 or 2 intermediate is rejected, as section 6.1.4(k) permits",
        )
    basic = parse_basic_constraints(certificate.extension(BASIC_CONSTRAINTS))
    if basic is None or not basic.ca:
        raise walk.fail(i, "6.1.4(k) CA certificate", "basicConstraints cA is not TRUE")
    walk.ok(i, "6.1.4(k) CA certificate")
    if not certificate.self_issued:  # (l)
        if max_path_length <= 0:
            raise walk.fail(i, "6.1.4(l) path length", "max_path_length is 0")
        max_path_length -= 1
    if basic.path_length is not None and basic.path_length < max_path_length:  # (m)
        max_path_length = basic.path_length
    walk.ok(i, "6.1.4(l)-(m) path length", f"max_path_length {max_path_length}")
    usage = parse_key_usage(certificate.extension(KEY_USAGE))
    if usage is not None and "keyCertSign" not in usage:  # (n)
        raise walk.fail(i, "6.1.4(n) key usage", "keyUsage lacks keyCertSign")
    walk.ok(i, "6.1.4(n) key usage")
    _critical(walk, i, certificate, "6.1.4(o) critical extensions")
    return max_path_length


def path_walk(
    path: Sequence[bytes | asn1core.Certificate],
    anchor: TrustAnchor,
    at: datetime.datetime,
    inputs: PathInputs | None = None,
) -> PathResult:
    """RFC 5280 sec. 6.1.2 to 6.1.5 over one prospective path, with RFC 9618 policy processing.

    `path` is target first and excludes the trust anchor, the order `chain.candidates()` returns;
    section 6.1 numbers the certificate nearest the anchor 1 and the target n, and so does every
    `Step.index` (0 is the whole path). `anchor` supplies the trusted name and key of section
    6.1.1(d); `at` is the current time of section 6.1.1(b), timezone-aware.

    Does not raise for a property of the certificates: a malformed extension or an unreadable
    certificate is an invalid path, and the step that found it says so.
    """
    inputs = inputs or PathInputs()
    if not path:
        raise ValueError("a path has at least one certificate: RFC 5280 sec. 6.1.1(a)")
    try:
        certificates = [
            c if isinstance(c, asn1core.Certificate) else asn1core.parse_certificate(c)
            for c in path
        ]
    except asn1core.Asn1Error as exc:
        step = Step(0, "6.1.1(a) path", "failed", f"not a DER certificate: {exc}")
        return PathResult("invalid", (step,), None, False, None)
    n = len(certificates)
    walk = _Walk()
    # Section 6.1.2: the state variables, from the trust anchor.
    working_spki = anchor.spki
    working_issuer_name = anchor.issuer
    working_issuer: asn1core.Certificate | None = (
        None if anchor.certificate is None else asn1core.parse_certificate(anchor.certificate)
    )
    # (d) to (f) of section 6.1.2: working_public_key_algorithm and _parameters. Only DSA among the
    # algorithms pkix verifies inherits parameters, so only Dss-Parms are carried.
    working_algorithm = alg.key_algorithm_of(working_spki)
    working_parameters = alg.dsa_parameters_of(working_spki)
    constraints = inputs.initial_name_constraints
    max_path_length = n  # (k)
    revocation_checked = True
    outcome: PolicyOutcome | None = None
    try:
        for i, certificate in enumerate(reversed(certificates), start=1):
            # ---- 6.1.3 basic certificate processing
            _signature(walk, i, certificate, working_spki, inputs, working_parameters)
            window = validity.check_validity(certificate, at)
            if not window.ok:
                raise walk.fail(i, "6.1.3(a)(2) validity", window.reason)
            walk.ok(i, "6.1.3(a)(2) validity")
            request = RevocationRequest(
                certificate,
                working_issuer_name,
                working_spki,
                working_issuer,
                at,
                i,
                anchor=anchor,
                issuer_parameters=working_parameters,
            )
            revocation_checked &= _revocation(walk, i, request, inputs)
            if not asn1core.names_equal(certificate.issuer, working_issuer_name):
                raise walk.fail(i, "6.1.3(a)(4) issuer name", "issuer is not working_issuer_name")
            walk.ok(i, "6.1.3(a)(4) issuer name")
            try:
                violations = check_certificate(certificate, constraints, final=i == n)
            except UnsupportedConstraint as exc:
                raise walk.unsupported(i, "6.1.3(b)-(c) name constraints", str(exc)) from exc
            if violations:
                first = violations[0]
                raise walk.fail(
                    i,
                    "6.1.3(b)-(c) name constraints",
                    f"{first.name.kind} {first.reason.replace('_', ' ')}",
                )
            walk.ok(i, "6.1.3(b)-(c) name constraints")
            if i == n:
                break
            # ---- 6.1.4 preparation for certificate i+1, steps (c) to (g) then (k) to (o)
            working_issuer_name = certificate.subject
            working_spki = certificate.subject_public_key_info
            working_issuer = certificate
            # (e) and (f): non-null parameters replace working_public_key_parameters; omitted or
            # NULL ones keep them only while the algorithm stays the same.
            own_parameters = alg.dsa_parameters_of(working_spki)
            algorithm = alg.key_algorithm_of(working_spki)
            if own_parameters is not None:
                working_parameters = own_parameters
            elif algorithm != working_algorithm:
                working_parameters = None
            working_algorithm = algorithm
            extension = parse_name_constraints(certificate.extension(NAME_CONSTRAINTS))
            if extension is not None:
                constraints = constraints.restrict(extension)
            max_path_length = _prepare(walk, i, certificate, max_path_length)
        # ---- 6.1.5 wrap-up for certificate n
        _critical(walk, n, certificates[0], "6.1.5(f) critical extensions")
        # Policy processing of sections 6.1.3(d)-(f), 6.1.4(a)-(b), (h)-(j) and 6.1.5(a)-(b), (g),
        # as RFC 9618 section 5 replaces them, over the whole path at once.
        initial = inputs.user_initial_policy_set
        outcome = resolve(
            certificates,
            None if initial is None else set(initial),
            initial_explicit_policy=inputs.initial_explicit_policy,
            initial_policy_mapping_inhibit=inputs.initial_policy_mapping_inhibit,
            initial_inhibit_any_policy=inputs.initial_any_policy_inhibit,
            max_depth=inputs.policy_max_depth,
            max_nodes=inputs.policy_max_nodes,
        )
        if not outcome.succeeded:
            raise walk.fail(0, "6.1.3(d)-6.1.5(g) policy (RFC 9618)", outcome.reason or "")
        walk.ok(
            0,
            "6.1.3(d)-6.1.5(g) policy (RFC 9618)",
            "user-constrained set: " + (", ".join(sorted(outcome.user_constrained)) or "{}"),
        )
    except _Stop:
        status: PathStatus = "unsupported" if walk.steps[-1].outcome == "unsupported" else "invalid"
        return PathResult(status, tuple(walk.steps), outcome, revocation_checked, None)
    except (MalformedExtension, MalformedCertificate, MalformedAlgorithm) as exc:
        walk.steps.append(Step(0, "extension syntax", "failed", str(exc)))
        return PathResult("invalid", tuple(walk.steps), outcome, revocation_checked, None)
    # Section 6.1.5(c) to (e): the target's key, with its parameters or the inherited ones.
    target_spki = certificates[0].subject_public_key_info
    target_parameters = alg.dsa_parameters_of(target_spki)
    if target_parameters is None and alg.key_algorithm_of(target_spki) == working_algorithm:
        target_parameters = working_parameters
    return PathResult(
        "valid",
        tuple(walk.steps),
        outcome,
        revocation_checked,
        target_spki,
        target_parameters,
    )


def validate(
    leaf: bytes | asn1core.Certificate,
    anchors: Sequence[TrustAnchor],
    at: datetime.datetime,
    inputs: PathInputs | None = None,
    *,
    intermediates: Sequence[bytes | asn1core.Certificate] = (),
) -> PathResult:
    """Discover and validate, RFC 5280 sec. 6: `chain.candidates()`, then `path_walk()` per path.

    Returns the first candidate path that validates. When none does, the answer is the shortest
    candidate's, except that an "unsupported" answer is preferred to an "invalid" one, so a caller
    is told when pkix could not decide. When no candidate path exists, an invalid result says so.
    """
    paths = candidates(leaf, intermediates, [anchor.issuer for anchor in anchors])
    best: PathResult | None = None
    for path in paths:
        for anchor in anchors:
            if not asn1core.names_equal(anchor.issuer, path[-1].issuer):
                continue
            result = path_walk(path, anchor, at, inputs)
            if result.valid:
                return result
            if best is None or (best.status == "invalid" and result.status == "unsupported"):
                best = result
    if best is not None:
        return best
    step = Step(0, "6.1.1(a) path discovery", "failed", "no candidate path reaches a trust anchor")
    return PathResult("invalid", (step,), None, False, None)
