"""candidate path discovery against a store or a directory of intermediates (RFC 5280 sec. 6.1).

Discovery is the part of path validation that happens before any rule bites: sec. 6.1.1(a) asks the
processing logic for "a prospective certification path of length n", and this module is what supplies
one. Three clauses shape it, and each is quoted where it is used rather than summarised:

* sec. 6.1.3(a)(4) requires "The certificate issuer name is the working_issuer_name", so a path is
  linked by name -- and sec. 7.1 defines that equality through the RFC 4518 preparation and
  `caseIgnoreMatch`, which is why matching goes through `asn1core.names_equal` instead of `==` on
  bytes or on somebody else's name object.
* sec. 4.2.1.9 forbids using a public key "to verify certificate signatures" when the `cA` boolean
  is not asserted, so a pool certificate that is not a CA cannot be a path member.
* sec. 6.1: "A certificate MUST NOT appear more than once in a prospective certification path."

Nothing here validates. Signatures, dates, revocation and constraints belong to sec. 6.1.3 and to
their own rows, so a candidate path may well be one that validation will reject -- which is the point
of a candidate. An empty answer is therefore a real answer, not the silence this module used to warn
about: it says an exhaustive search of a bounded pool found nothing, whereas the stub it replaced
raised because it could not search at all.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence

import asn1core

__all__ = ["Anchor", "Path", "candidates", "may_issue"]

# sec. 6.1.1(d) allows a trust anchor to be named rather than served as a certificate: the anchor
# information is the issuer name, the algorithm, the key and optionally the parameters. A caller
# that holds the certificate gets the name from its subject here.
type Anchor = asn1core.Certificate | asn1core.Name

# One path: the target certificate first, then each issuer's certificate down to, but not
# including, the trust anchor -- sec. 6.1.1(a) and sec. 6.1.1(d) keep those two inputs separate.
type Path = list[asn1core.Certificate]

_BASIC_CONSTRAINTS = "2.5.29.19"
_VERSION_V3 = 2
_TAG_BOOLEAN = 1
_TAG_TRUE = b"\xff"

# Not an input the document names. sec. 6.2 permits it: "An implementation MAY augment the
# algorithm presented in Section 6.1 to further limit the set of valid certification paths", and a
# search over an attacker-chosen pool needs a bound to be worth running.
_DEFAULT_MAX_DEPTH = 8


def _certificate(value: object, role: str) -> asn1core.Certificate:
    """Accept DER or an `asn1core` certificate; refuse everything else, loudly.

    The refusal names the seam it is guarding. `pkix` spent a while taking `cryptography` objects,
    whose parser re-encodes what it read and whose name comparison is its own; README records that
    role as scheduled out, so a caller handing one over gets told what to parse it with rather than
    an AttributeError from three frames away.
    """
    if isinstance(value, asn1core.Certificate):
        return value
    if isinstance(value, bytes):
        return asn1core.parse_certificate(value)
    raise TypeError(
        f"{role} must be DER bytes or an asn1core.Certificate, not {type(value).__name__}: "
        "parse with asn1core.parse_certificate() so the bytes a signature covers "
        "stay the bytes received"
    )


def _anchor_name(anchor: Anchor) -> asn1core.Name:
    if isinstance(anchor, asn1core.Name):
        return anchor
    if isinstance(anchor, asn1core.Certificate):
        return anchor.subject
    raise TypeError(
        f"an anchor must be an asn1core.Name or an asn1core.Certificate, not {type(anchor).__name__}"
    )


def may_issue(certificate: asn1core.Certificate) -> bool:
    """Whether this certificate's key may certify another certificate at all.

    sec. 4.2.1.9: "If the basic constraints extension is not present in a version 3 certificate, or
    the extension is present but the cA boolean is not asserted, then the certified public key MUST
    NOT be used to verify certificate signatures." An empty `SEQUENCE {}` is the asserted-absent
    case: `cA BOOLEAN DEFAULT FALSE` means omission says no, not that nothing was said, and the leaf
    in `tests/fixtures/chains` is a real certificate that spells it exactly that way.

    A version 1 or version 2 certificate is refused rather than waved through. The clause above is
    written about version 3, so the text does not decide the older case, and `ROADMAP.md` records
    that as an open question; failing closed is the alternative to deciding it by accident.
    """
    if certificate.version != _VERSION_V3:
        return False
    extension = certificate.extension(_BASIC_CONSTRAINTS)
    if extension is None:
        return False
    node, _ = asn1core.decode(extension.value)
    if not node.constructed or not node.children:
        return False
    first = node.children[0]
    return first.tag.number == _TAG_BOOLEAN and first.payload == _TAG_TRUE


def candidates(
    leaf: bytes | asn1core.Certificate,
    intermediates: Iterable[bytes | asn1core.Certificate],
    anchors: Sequence[Anchor],
    *,
    max_depth: int = _DEFAULT_MAX_DEPTH,
) -> list[Path]:
    """Every prospective certification path from `leaf` to one of `anchors` (RFC 5280 sec. 6.1).

    Paths come back per sec. 6.1.1(a): length n, beginning with `leaf`, and excluding the trust
    anchor, which sec. 6.1.1(d) keeps as a separate input to validation. Shortest first; within a
    length, pool order. Neither ordering is a claim about validity -- it is the cheapest candidate
    tried first, and sec. 6.2 leaves ordering to the implementation.

    An empty list means the search was exhaustive and found nothing. That is the honest answer to
    "no path exists", and the difference from the stub this replaced is that this function looks.
    """
    if max_depth < 1:
        raise ValueError(f"max_depth must be at least 1, got {max_depth}")

    target = _certificate(leaf, "leaf")
    # A pool is a set of certificates, so a listing that repeats one is still one certificate --
    # sec. 6.1 forbids it appearing twice in a path, and without collapsing the duplicate the same
    # path is found twice and the search pays for a candidate that cannot differ.
    pool: list[asn1core.Certificate] = []
    for item in intermediates:
        certificate = _certificate(item, "pool entry")
        if all(seen_certificate.raw != certificate.raw for seen_certificate in pool):
            pool.append(certificate)
    names = [_anchor_name(anchor) for anchor in anchors]
    if not names:
        return []

    found: list[Path] = []

    def walk(path: Path, working_issuer: asn1core.Name, seen: frozenset[bytes]) -> None:
        # sec. 6.1.3(a)(4) read with sec. 7.1's comparison: the name decides the link, and the
        # spelling does not. Reaching an anchor records a candidate without ending the search,
        # because a longer path through the same name may be the one that validates.
        if any(asn1core.names_equal(working_issuer, name) for name in names):
            found.append(list(path))
        if len(path) >= max_depth:
            return
        for certificate in pool:
            # sec. 6.1: "A certificate MUST NOT appear more than once in a prospective
            # certification path." The bytes are its identity, so two cross-certificates that share
            # a subject and an issuer stay distinct: they are different certificates.
            uid = certificate.raw
            if uid in seen:
                continue
            if not asn1core.names_equal(certificate.subject, working_issuer):
                continue
            if not may_issue(certificate):
                continue
            walk([*path, certificate], certificate.issuer, seen | {uid})

    walk([target], target.issuer, frozenset({target.raw}))
    found.sort(key=len)
    return found
